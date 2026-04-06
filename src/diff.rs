//! Differential execution runner for `sci-fuzz diff`.
//!
//! MVP scope: two local implementations, identical generated calls,
//! reproducible divergence reporting.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use alloy_dyn_abi::FunctionExt as _;
use alloy_json_abi::{Function, JsonAbi};
use anyhow::{bail, Context, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use revm::primitives::{AccountInfo, Bytecode};
use serde::{Deserialize, Serialize};

use crate::mutator::TxMutator;
use crate::project::Project;
use crate::shrinker::SequenceShrinker;
use crate::types::{Address, ContractInfo, Finding, Severity, Transaction, B256, U256};

#[derive(Debug, Clone)]
pub struct DiffConfig {
    pub timeout: Duration,
    pub seed: u64,
    pub max_execs: u64,
    pub depth: u32,
    pub shrink: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DivergenceKind {
    SuccessRevertMismatch,
    DecodedOutputMismatch,
    RawOutputMismatch,
    LogSignatureMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffFinding {
    pub impl_a: String,
    pub impl_b: String,
    pub mismatch: DivergenceKind,
    pub function: Option<String>,
    pub selector: Option<[u8; 4]>,
    pub sequence: Vec<Transaction>,
    pub note: String,
}

impl DiffFinding {
    pub fn to_finding(&self, contract: Address) -> Finding {
        let sel = self
            .selector
            .map(|s| format!("0x{}", hex::encode(s)))
            .unwrap_or_else(|| "<unknown>".to_string());
        let fname = self
            .function
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        Finding {
            severity: Severity::Info,
            title: format!(
                "Differential divergence: {:?} at {} ({})",
                self.mismatch, fname, sel
            ),
            description: format!(
                "Observed divergence between `{}` and `{}`. {}",
                self.impl_a, self.impl_b, self.note
            ),
            contract,
            reproducer: self.sequence.clone(),
            exploit_profit: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiffReport {
    pub impl_a: String,
    pub impl_b: String,
    pub shared_functions: Vec<String>,
    pub skipped_functions: Vec<String>,
    pub execs: u64,
    pub divergence: Option<DiffFinding>,
}

impl DiffReport {
    pub fn save_to_dir(&self, dir: &Path) -> crate::error::Result<std::path::PathBuf> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("diff_report.json");
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        Ok(path)
    }
}

#[derive(Debug, Clone)]
struct SharedFn {
    signature: String,
    function_name: String,
    selector: [u8; 4],
    decode_outputs: bool,
    func_a: Function,
    func_b: Function,
}

pub fn run_project_diff(
    project_root: &Path,
    impl_a: &str,
    impl_b: &str,
    match_contract: Option<&str>,
    config: DiffConfig,
) -> Result<DiffReport> {
    let (project, _bootstrap, artifact_count) = Project::build_and_select_targets(project_root)
        .with_context(|| format!("build/ingest failed for {}", project_root.display()))?;
    if artifact_count == 0 {
        bail!(
            "no Foundry artifacts discovered in {}",
            project_root.display()
        );
    }

    let mut candidates = project.select_runtime_targets();
    if let Some(pat) = match_contract {
        candidates.retain(|c| c.name.as_deref().map(|n| n.contains(pat)).unwrap_or(false));
    }

    let a = resolve_target(&candidates, impl_a)?;
    let b = resolve_target(&candidates, impl_b)?;
    run_contract_diff(a, b, config)
}

fn resolve_target(candidates: &[ContractInfo], needle: &str) -> Result<ContractInfo> {
    if needle.starts_with("0x") {
        bail!(
            "unsupported input mode for MVP: `{needle}` looks like an address; use Foundry artifact targets"
        );
    }

    let mut matches: Vec<&ContractInfo> = candidates
        .iter()
        .filter(|c| {
            let name = c.name.as_deref().unwrap_or_default();
            let source = c.source_path.as_deref().unwrap_or_default();
            let full = format!("{source}:{name}");
            name == needle || full == needle
        })
        .collect();

    if matches.is_empty() {
        let available: Vec<String> = candidates
            .iter()
            .map(|c| {
                format!(
                    "{}:{}",
                    c.source_path.as_deref().unwrap_or("?"),
                    c.name.as_deref().unwrap_or("?")
                )
            })
            .collect();
        bail!(
            "contract target `{needle}` not found. available targets: {}",
            available.join(", ")
        );
    }
    if matches.len() > 1 {
        matches.sort_by_key(|c| c.source_path.clone());
        let details: Vec<String> = matches
            .iter()
            .map(|c| {
                format!(
                    "{}:{}",
                    c.source_path.as_deref().unwrap_or("?"),
                    c.name.as_deref().unwrap_or("?")
                )
            })
            .collect();
        bail!(
            "contract target `{needle}` is ambiguous. use source.sol:Contract. matches: {}",
            details.join(", ")
        );
    }

    Ok(matches.remove(0).clone())
}

pub fn run_contract_diff(
    a: ContractInfo,
    b: ContractInfo,
    config: DiffConfig,
) -> Result<DiffReport> {
    let name_a = a.name.clone().unwrap_or_else(|| "impl_a".to_string());
    let name_b = b.name.clone().unwrap_or_else(|| "impl_b".to_string());

    let (shared, skipped) = collect_shared_functions(&a, &b)?;
    if shared.is_empty() {
        bail!(
            "no comparable shared ABI functions between `{}` and `{}`",
            name_a,
            name_b
        );
    }

    let mut synth = a.clone();
    synth.address = Address::from([0x11; 20]);
    synth.abi = Some(shared_abi_for_mutation(&shared));

    let mut mutator = TxMutator::new(vec![synth]);
    let caller = Address::from([0x42; 20]);
    mutator.add_to_address_pool(caller);

    let mut exec_a = crate::evm::EvmExecutor::new();
    let mut exec_b = crate::evm::EvmExecutor::new();
    exec_a.set_balance(caller, U256::from(100_000_000_000_000_000u128));
    exec_b.set_balance(caller, U256::from(100_000_000_000_000_000u128));

    let deployed_a = prepare_target(&mut exec_a, &a, caller)
        .with_context(|| format!("failed to deploy/setup {}", name_a))?;
    let deployed_b = prepare_target(&mut exec_b, &b, caller)
        .with_context(|| format!("failed to deploy/setup {}", name_b))?;

    let root_a = exec_a.snapshot();
    let root_b = exec_b.snapshot();

    let shared_by_selector: HashMap<[u8; 4], SharedFn> =
        shared.iter().map(|s| (s.selector, s.clone())).collect();

    let mut rng = StdRng::seed_from_u64(config.seed);
    let mut current_seq: Vec<Transaction> = Vec::new();
    let mut prev_sender: Option<Address> = None;
    let start = Instant::now();

    let mut execs = 0_u64;
    while execs < config.max_execs && start.elapsed() < config.timeout {
        let mut tx = mutator.generate_in_sequence(prev_sender, &mut rng);
        tx.to = Some(deployed_a);

        let mut tx_b = tx.clone();
        tx_b.to = Some(deployed_b);

        let res_a = exec_a.execute(&tx)?;
        let res_b = exec_b.execute(&tx_b)?;

        current_seq.push(tx.clone());
        execs += 1;
        prev_sender = Some(tx.sender);

        if let Some(mut finding) = compare_step(
            &name_a,
            &name_b,
            &tx,
            &res_a,
            &res_b,
            &shared_by_selector,
            &current_seq,
        ) {
            if config.shrink {
                let shrinker = SequenceShrinker::new();
                let seq = current_seq.clone();
                let root_a2 = root_a.clone();
                let root_b2 = root_b.clone();
                let shrink_pred = |cand: &[Transaction]| {
                    sequence_diverges(
                        cand,
                        deployed_a,
                        deployed_b,
                        &root_a2,
                        &root_b2,
                        &shared_by_selector,
                    )
                    .unwrap_or(false)
                };
                finding.sequence = shrinker.shrink(&seq, shrink_pred);
            }

            return Ok(DiffReport {
                impl_a: name_a,
                impl_b: name_b,
                shared_functions: shared.iter().map(|s| s.signature.clone()).collect(),
                skipped_functions: skipped,
                execs,
                divergence: Some(finding),
            });
        }

        let should_reset = current_seq.len() >= config.depth as usize || rng.gen_bool(0.2);
        if should_reset {
            exec_a.restore(root_a.clone());
            exec_b.restore(root_b.clone());
            current_seq.clear();
            prev_sender = None;
        }
    }

    Ok(DiffReport {
        impl_a: name_a,
        impl_b: name_b,
        shared_functions: shared.iter().map(|s| s.signature.clone()).collect(),
        skipped_functions: skipped,
        execs,
        divergence: None,
    })
}

fn shared_abi_for_mutation(shared: &[SharedFn]) -> serde_json::Value {
    let mut out = Vec::new();
    for s in shared {
        let v = serde_json::to_value(&s.func_a).unwrap_or(serde_json::Value::Null);
        if v.is_object() {
            out.push(v);
        }
    }
    serde_json::Value::Array(out)
}

fn prepare_target(
    exec: &mut crate::evm::EvmExecutor,
    info: &ContractInfo,
    caller: Address,
) -> Result<Address> {
    if let Some(init) = info.creation_bytecode.as_ref().filter(|b| !b.is_empty()) {
        return exec.deploy(caller, init.clone());
    }

    if info.address.is_zero() {
        bail!(
            "unsupported constructor/setup shape: target {} has no creation bytecode and no predeployed address",
            info.name.as_deref().unwrap_or("<unnamed>")
        );
    }

    let runtime = info.deployed_bytecode.clone();
    if runtime.is_empty() {
        bail!(
            "target {} has no runtime bytecode",
            info.name.as_deref().unwrap_or("<unnamed>")
        );
    }

    exec.insert_account_info(
        info.address,
        AccountInfo {
            code: Some(Bytecode::new_legacy(runtime)),
            ..Default::default()
        },
    );
    Ok(info.address)
}

fn compare_step(
    impl_a: &str,
    impl_b: &str,
    tx: &Transaction,
    a: &crate::types::ExecutionResult,
    b: &crate::types::ExecutionResult,
    shared: &HashMap<[u8; 4], SharedFn>,
    sequence: &[Transaction],
) -> Option<DiffFinding> {
    let selector = tx.data.get(0..4).map(|s| [s[0], s[1], s[2], s[3]]);
    let meta = selector.and_then(|s| shared.get(&s));

    if a.success != b.success {
        return Some(DiffFinding {
            impl_a: impl_a.to_string(),
            impl_b: impl_b.to_string(),
            mismatch: DivergenceKind::SuccessRevertMismatch,
            function: meta.map(|m| m.function_name.clone()),
            selector,
            sequence: sequence.to_vec(),
            note: format!(
                "success mismatch: {} returned {}, {} returned {}",
                impl_a, a.success, impl_b, b.success
            ),
        });
    }

    if let Some(m) = meta {
        if m.decode_outputs && a.output != b.output {
            let dec_a = m.func_a.abi_decode_output(a.output.as_ref(), true);
            let dec_b = m.func_b.abi_decode_output(b.output.as_ref(), true);
            match (dec_a, dec_b) {
                (Ok(x), Ok(y)) if x != y => {
                    return Some(DiffFinding {
                        impl_a: impl_a.to_string(),
                        impl_b: impl_b.to_string(),
                        mismatch: DivergenceKind::DecodedOutputMismatch,
                        function: Some(m.function_name.clone()),
                        selector,
                        sequence: sequence.to_vec(),
                        note: format!("decoded outputs differ: {:?} vs {:?}", x, y),
                    });
                }
                _ if a.output != b.output => {
                    return Some(DiffFinding {
                        impl_a: impl_a.to_string(),
                        impl_b: impl_b.to_string(),
                        mismatch: DivergenceKind::RawOutputMismatch,
                        function: Some(m.function_name.clone()),
                        selector,
                        sequence: sequence.to_vec(),
                        note: "raw return-data differs; ABI decode unavailable or failed"
                            .to_string(),
                    });
                }
                _ => {}
            }
        }
    } else if a.output != b.output {
        return Some(DiffFinding {
            impl_a: impl_a.to_string(),
            impl_b: impl_b.to_string(),
            mismatch: DivergenceKind::RawOutputMismatch,
            function: None,
            selector,
            sequence: sequence.to_vec(),
            note: "raw return-data differs (no shared ABI metadata for selector)".to_string(),
        });
    }

    let logs_a: Vec<Option<B256>> = a.logs.iter().map(|l| l.topics.first().copied()).collect();
    let logs_b: Vec<Option<B256>> = b.logs.iter().map(|l| l.topics.first().copied()).collect();
    if logs_a != logs_b {
        return Some(DiffFinding {
            impl_a: impl_a.to_string(),
            impl_b: impl_b.to_string(),
            mismatch: DivergenceKind::LogSignatureMismatch,
            function: meta.map(|m| m.function_name.clone()),
            selector,
            sequence: sequence.to_vec(),
            note: format!(
                "topic0 sequence/count differs: {:?} vs {:?}",
                logs_a, logs_b
            ),
        });
    }

    None
}

fn sequence_diverges(
    seq: &[Transaction],
    addr_a: Address,
    addr_b: Address,
    root_a: &revm::db::CacheDB<crate::rpc::FuzzerDatabase>,
    root_b: &revm::db::CacheDB<crate::rpc::FuzzerDatabase>,
    shared: &HashMap<[u8; 4], SharedFn>,
) -> Result<bool> {
    let mut ex_a = crate::evm::EvmExecutor::new();
    let mut ex_b = crate::evm::EvmExecutor::new();
    ex_a.restore(root_a.clone());
    ex_b.restore(root_b.clone());

    let mut replay: Vec<Transaction> = Vec::new();
    for tx in seq {
        let mut ta = tx.clone();
        ta.to = Some(addr_a);
        let mut tb = tx.clone();
        tb.to = Some(addr_b);
        let ra = ex_a.execute(&ta)?;
        let rb = ex_b.execute(&tb)?;
        replay.push(ta.clone());
        if compare_step("a", "b", &ta, &ra, &rb, shared, &replay).is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn collect_shared_functions(
    a: &ContractInfo,
    b: &ContractInfo,
) -> Result<(Vec<SharedFn>, Vec<String>)> {
    let abi_a: JsonAbi = serde_json::from_value(a.abi.clone().context("impl_a missing ABI")?)
        .context("invalid impl_a ABI")?;
    let abi_b: JsonAbi = serde_json::from_value(b.abi.clone().context("impl_b missing ABI")?)
        .context("invalid impl_b ABI")?;

    let mut by_sig_a: HashMap<String, Function> = HashMap::new();
    let mut by_sig_b: HashMap<String, Function> = HashMap::new();

    for funcs in abi_a.functions.values() {
        for f in funcs {
            by_sig_a.insert(f.signature(), f.clone());
        }
    }
    for funcs in abi_b.functions.values() {
        for f in funcs {
            by_sig_b.insert(f.signature(), f.clone());
        }
    }

    let mut shared = Vec::new();
    let mut skipped = Vec::new();

    for (sig, fa) in by_sig_a {
        let Some(fb) = by_sig_b.get(&sig).cloned() else {
            continue;
        };

        if fa.inputs != fb.inputs {
            skipped.push(format!("{sig} (input incompatibility)"));
            continue;
        }

        let decode_outputs = fa.outputs == fb.outputs;
        if !decode_outputs {
            skipped.push(format!("{sig} (output ABI differs; raw compare only)"));
        }

        shared.push(SharedFn {
            signature: sig,
            function_name: fa.name.clone(),
            selector: *fa.selector(),
            decode_outputs,
            func_a: fa,
            func_b: fb,
        });
    }

    shared.sort_by(|x, y| x.signature.cmp(&y.signature));
    skipped.sort();
    Ok((shared, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abi_foo_uint() -> serde_json::Value {
        serde_json::json!([
            {
                "type": "function",
                "name": "foo",
                "stateMutability": "nonpayable",
                "inputs": [{"name": "x", "type": "uint256"}],
                "outputs": [{"name": "", "type": "uint256"}]
            }
        ])
    }

    fn contract(name: &str, runtime_hex: &str) -> ContractInfo {
        ContractInfo {
            address: Address::from([name.as_bytes()[0]; 20]),
            deployed_bytecode: crate::types::Bytes::from(hex::decode(runtime_hex).unwrap()),
            creation_bytecode: None,
            name: Some(name.to_string()),
            source_path: Some(format!("src/{name}.sol")),
            abi: Some(abi_foo_uint()),
        }
    }

    fn cfg(max_execs: u64) -> DiffConfig {
        DiffConfig {
            timeout: Duration::from_secs(2),
            seed: 7,
            max_execs,
            depth: 4,
            shrink: true,
        }
    }

    #[test]
    fn same_behavior_reports_no_divergence() {
        let a = contract("A", "600160005260206000f3");
        let b = contract("B", "600160005260206000f3");
        let out = run_contract_diff(a, b, cfg(16)).unwrap();
        assert!(out.divergence.is_none());
    }

    #[test]
    fn success_vs_revert_divergence_found() {
        let a = contract("A", "600160005260206000f3");
        let b = contract("B", "60006000fd");
        let out = run_contract_diff(a, b, cfg(8)).unwrap();
        let d = out.divergence.expect("expected divergence");
        assert_eq!(d.mismatch, DivergenceKind::SuccessRevertMismatch);
    }

    #[test]
    fn decoded_output_divergence_found() {
        let a = contract("A", "600160005260206000f3");
        let b = contract("B", "600260005260206000f3");
        let out = run_contract_diff(a, b, cfg(8)).unwrap();
        let d = out.divergence.expect("expected divergence");
        assert_eq!(d.mismatch, DivergenceKind::DecodedOutputMismatch);
    }

    #[test]
    fn raw_output_fallback_when_decode_unavailable() {
        let a = contract("A", "60aa6000526001601ff3");
        let b = contract("B", "60ab6000526001601ff3");
        let out = run_contract_diff(a, b, cfg(8)).unwrap();
        let d = out.divergence.expect("expected divergence");
        assert_eq!(d.mismatch, DivergenceKind::RawOutputMismatch);
    }

    #[test]
    fn unsupported_input_mode_fails_clearly() {
        let err = resolve_target(&[], "0x1234").unwrap_err();
        assert!(err.to_string().contains("unsupported input mode for MVP"));
    }

    #[test]
    fn shrinking_preserves_divergence() {
        let a = contract("A", "600160005260206000f3");
        let b = contract("B", "600260005260206000f3");
        let out = run_contract_diff(a, b, cfg(32)).unwrap();
        let d = out.divergence.expect("expected divergence");
        assert!(!d.sequence.is_empty());
    }
}
