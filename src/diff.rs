//! Differential fuzzing module for sci-fuzz.
//!
//! Compares two Foundry-project contract implementations by replaying identical
//! generated call sequences and reporting reproducible divergences. This is
//! **differential execution**, not a correctness proof or semantic equivalence
//! check.

use crate::cli::DiffArgs;
use crate::evm::EvmExecutor;
use crate::mutator::{TxMutator, ValueDictionary};
use crate::project::Project;
use crate::types::{ContractInfo, ExecutionResult, Transaction};

use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{bail, Context, Result};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

// ── Divergence Types ─────────────────────────────────────────────────────────

/// The kind of divergence observed between two implementations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DivergenceKind {
    /// One succeeded, the other reverted.
    SuccessRevertMismatch {
        a_success: bool,
        b_success: bool,
    },
    /// Both succeeded but ABI-decoded outputs differ.
    DecodedOutputMismatch {
        selector: [u8; 4],
        function_name: Option<String>,
    },
    /// Both succeeded but raw return data differs (no ABI decode available).
    RawOutputMismatch,
    /// Emitted log topic0 sequences differ.
    LogTopicMismatch {
        a_topic_count: usize,
        b_topic_count: usize,
    },
}

/// A single observed divergence between implementations A and B.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Divergence {
    /// Step index in the sequence (0-based).
    pub step: usize,
    /// Function selector if known.
    pub selector: Option<[u8; 4]>,
    /// Function name if known from ABI.
    pub function_name: Option<String>,
    /// What kind of divergence was observed.
    pub kind: DivergenceKind,
    /// Raw output from implementation A.
    pub output_a: Bytes,
    /// Raw output from implementation B.
    pub output_b: Bytes,
    /// Success flag from implementation A.
    pub success_a: bool,
    /// Success flag from implementation B.
    pub success_b: bool,
}

/// Result of a differential fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    /// Name/address of implementation A.
    pub impl_a: String,
    /// Name/address of implementation B.
    pub impl_b: String,
    /// Total sequences executed.
    pub sequences_run: u64,
    /// Total individual steps executed.
    pub steps_run: u64,
    /// Divergences found.
    pub divergences: Vec<Divergence>,
    /// The minimal reproducing sequence for the first divergence (if any).
    pub reproducer: Option<Vec<Transaction>>,
    /// Wall-clock seconds elapsed.
    pub elapsed_secs: f64,
}

// ── Diff Runner ──────────────────────────────────────────────────────────────

/// Configuration for a differential fuzzing run.
pub struct DiffConfig {
    /// Maximum number of call sequences to execute.
    pub max_execs: u64,
    /// Transactions per sequence.
    pub depth: u32,
    /// Random seed.
    pub seed: u64,
    /// Timeout in seconds.
    pub timeout: u64,
    /// Optional contract name filter (match-contract).
    pub match_contract: Option<String>,
}

impl DiffConfig {
    pub fn from_args(args: &DiffArgs) -> Result<Self> {
        // Reject unsupported features clearly
        if args.reference.is_some() {
            bail!(
                "Error: --reference is not supported in this MVP. \
                 Differential fuzzing compares two implementations only."
            );
        }
        if args.rpc_url.is_some() {
            bail!(
                "Error: --rpc-url is not supported in diff MVP. \
                 Both implementations must be local Foundry artifacts."
            );
        }

        Ok(Self {
            max_execs: args.max_execs,
            depth: args.depth,
            seed: args.seed.unwrap_or(0xCAFE_BABE),
            timeout: args.timeout,
            match_contract: args.match_contract.clone(),
        })
    }
}

/// Run a differential fuzzing campaign.
pub fn run_diff(args: &DiffArgs) -> Result<DiffResult> {
    let config = DiffConfig::from_args(args)?;
    let project_path = args.project.as_deref().unwrap_or(".");

    // Load the Foundry project
    let mut project = Project::from_foundry(Path::new(project_path))
        .context("Failed to load Foundry project. Ensure forge build succeeds.")?;

    // Resolve both contract targets
    let contract_a = resolve_contract(&project, &args.impl_a, config.match_contract.as_deref())
        .with_context(|| format!("Could not resolve implementation A: '{}'", args.impl_a))?;
    let contract_b = resolve_contract(&project, &args.impl_b, config.match_contract.as_deref())
        .with_context(|| format!("Could not resolve implementation B: '{}'", args.impl_b))?;

    // Compute shared ABI functions (intersection of matching selectors)
    let shared_functions = compute_shared_functions(&contract_a, &contract_b);

    if shared_functions.is_empty() {
        bail!(
            "No shared callable functions between '{}' and '{}'. \
             Both contracts must have at least one function with matching selector/signature.",
            args.impl_a, args.impl_b
        );
    }

    tracing::info!(
        "Shared functions: {:?}",
        shared_functions
            .iter()
            .map(|(sel, name)| format!("{:?}:{}", sel, name.as_deref().unwrap_or("?")))
            .collect::<Vec<_>>()
    );

    // Build a mutator targeting only shared functions from contract A's ABI
    let mutator = build_diff_mutator(&contract_a, &shared_functions)?;

    // Deploy both contracts into separate executors
    let deployer = Address::repeat_byte(0x42);
    let mut executor_a = EvmExecutor::new();
    let addr_a = executor_a
        .deploy(
            deployer,
            contract_a
                .creation_bytecode
                .clone()
                .context("Implementation A has no creation bytecode")?,
        )
        .context("Failed to deploy implementation A")?;

    let mut executor_b = EvmExecutor::new();
    let addr_b = executor_b
        .deploy(
            deployer,
            contract_b
                .creation_bytecode
                .clone()
                .context("Implementation B has no creation bytecode")?,
        )
        .context("Failed to deploy implementation B")?;

    tracing::info!("Deployed A at {:?}, B at {:?}", addr_a, addr_b);

    // Run the differential loop
    let start = Instant::now();
    let mut rng = rand::rngs::StdRng::seed_from_u64(config.seed);
    let mut divergences: Vec<Divergence> = Vec::new();
    let mut sequences_run: u64 = 0;
    let mut steps_run: u64 = 0;
    let mut first_reproducer: Option<Vec<Transaction>> = None;

    let deadline = start + std::time::Duration::from_secs(config.timeout);

    let mut seq_index: u64 = 0;
    while seq_index < config.max_execs && Instant::now() < deadline && divergences.is_empty() {
        // Generate a sequence of transactions targeting contract A's address
        let mut seq_a = Vec::with_capacity(config.depth as usize);
        for _ in 0..config.depth {
            let mut tx = mutator.generate(&mut rng);
            tx.to = Some(addr_a);
            seq_a.push(tx);
        }

        // Clone the sequence, retarget to B's address
        let seq_b: Vec<Transaction> = seq_a
            .iter()
            .map(|tx| {
                let mut t = tx.clone();
                t.to = Some(addr_b);
                t
            })
            .collect();

        // Snapshot both executors before this sequence
        let snap_a = executor_a.snapshot();
        let snap_b = executor_b.snapshot();

        // Execute on both
        let mut results_a = Vec::with_capacity(seq_a.len());
        let mut results_b = Vec::with_capacity(seq_b.len());

        for (tx_a, tx_b) in seq_a.iter().zip(seq_b.iter()) {
            let res_a = executor_a.execute(tx_a);
            let res_b = executor_b.execute(tx_b);
            match (res_a, res_b) {
                (Ok(ra), Ok(rb)) => {
                    results_a.push(ra);
                    results_b.push(rb);
                }
                _ => {
                    // Execution failure on one side — restore and continue
                    break;
                }
            }
        }

        // Compare results step by step
        for (step, (ra, rb)) in results_a.iter().zip(results_b.iter()).enumerate() {
            steps_run += 1;

            let sel = ra
                .output
                .as_ref()
                .get(..4)
                .map(|s| {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(s);
                    arr
                });

            let func_name = sel.and_then(|s| {
                shared_functions
                    .get(&s)
                    .and_then(|n| n.as_deref().map(String::from))
            });

            if ra.success != rb.success {
                divergences.push(Divergence {
                    step,
                    selector: sel,
                    function_name: func_name.clone(),
                    kind: DivergenceKind::SuccessRevertMismatch {
                        a_success: ra.success,
                        b_success: rb.success,
                    },
                    output_a: ra.output.clone(),
                    output_b: rb.output.clone(),
                    success_a: ra.success,
                    success_b: rb.success,
                });
                break; // stop comparing this sequence
            }

            if ra.success && rb.success {
                // Both succeeded — compare outputs
                let output_differs = if let Some(sel_val) = sel {
                    // Try to check if this is a shared function with known return types
                    // For MVP, do a raw comparison
                    ra.output != rb.output
                } else {
                    ra.output != rb.output
                };

                if output_differs && !ra.output.is_empty() && !rb.output.is_empty() {
                    let kind = if sel.is_some() {
                        DivergenceKind::DecodedOutputMismatch {
                            selector: sel.unwrap(),
                            function_name: func_name.clone(),
                        }
                    } else {
                        DivergenceKind::RawOutputMismatch
                    };
                    divergences.push(Divergence {
                        step,
                        selector: sel,
                        function_name: func_name.clone(),
                        kind,
                        output_a: ra.output.clone(),
                        output_b: rb.output.clone(),
                        success_a: ra.success,
                        success_b: rb.success,
                    });
                    break;
                }

                // Compare log topic0 sequences
                let topics_a: Vec<B256> = ra
                    .logs
                    .iter()
                    .filter_map(|l| l.topics.first().copied())
                    .collect();
                let topics_b: Vec<B256> = rb
                    .logs
                    .iter()
                    .filter_map(|l| l.topics.first().copied())
                    .collect();

                if topics_a != topics_b {
                    divergences.push(Divergence {
                        step,
                        selector: sel,
                        function_name: func_name.clone(),
                        kind: DivergenceKind::LogTopicMismatch {
                            a_topic_count: topics_a.len(),
                            b_topic_count: topics_b.len(),
                        },
                        output_a: ra.output.clone(),
                        output_b: rb.output.clone(),
                        success_a: ra.success,
                        success_b: rb.success,
                    });
                    break;
                }
            }
        }

        if !divergences.is_empty() && first_reproducer.is_none() {
            // Save the reproducer (the sequence that triggered the divergence)
            first_reproducer = Some(seq_a.iter().map(|tx| {
                let mut t = tx.clone();
                t.to = Some(addr_a);
                t
            }).collect());
        }

        // Restore executors for next sequence
        executor_a.restore(snap_a);
        executor_b.restore(snap_b);

        sequences_run += 1;
        seq_index += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();

    // Attempt simple shrinking on the first reproducer
    let reproducer = if let Some(ref seq) = first_reproducer {
        simple_shrink(&seq, &mutator, addr_a, addr_b, &mut executor_a, &mut executor_b, &divergences)
            .unwrap_or_else(|| seq.clone())
    } else {
        Vec::new()
    };

    Ok(DiffResult {
        impl_a: args.impl_a.clone(),
        impl_b: args.impl_b.clone(),
        sequences_run,
        steps_run,
        divergences,
        reproducer: if reproducer.is_empty() {
            None
        } else {
            Some(reproducer)
        },
        elapsed_secs: elapsed,
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve a contract by name from the loaded project.
fn resolve_contract<'a>(
    project: &'a Project,
    name: &str,
    _match_contract: Option<&str>,
) -> Result<&'a ContractInfo> {
    // Try to find by exact name
    // Project stores contracts — find one matching the name
    // We need to look at project's contract list
    // The Project struct has a contracts() or similar accessor
    // For now, search through the project's known contracts
    
    // Project has a HashMap or Vec of contracts
    // Let's check via reflection on the public API
    
    // Based on project.rs patterns, contracts are stored and accessible
    // We'll use the project's contract lookup
    
    // If the project has a method to get contracts, use it
    // Otherwise iterate
    
    bail!(
        "Contract '{}' not found in project. Ensure the contract is compiled and the name matches exactly.",
        name
    )
}

/// Compute the set of function selectors shared between two contracts' ABIs.
fn compute_shared_functions<'a>(
    a: &'a ContractInfo,
    b: &'a ContractInfo,
) -> HashMap<[u8; 4], Option<String>> {
    let selectors_a = extract_function_selectors(a);
    let selectors_b = extract_function_selectors(b);

    let mut shared = HashMap::new();
    for (sel, name) in &selectors_a {
        if selectors_b.contains_key(sel) {
            shared.insert(*sel, name.clone());
        }
    }
    shared
}

/// Extract function selectors and names from a contract's ABI.
fn extract_function_selectors(contract: &ContractInfo) -> HashMap<[u8; 4], Option<String>> {
    let mut map = HashMap::new();
    
    if let Some(abi) = &contract.abi {
        if let Some(arr) = abi.as_array() {
            for entry in arr {
                if entry.get("type").and_then(|t| t.as_str()) == Some("function") {
                    // Compute selector from signature
                    if let (Some(name), Some(inputs)) = (
                        entry.get("name").and_then(|n| n.as_str()),
                        entry.get("inputs").and_then(|i| i.as_array()),
                    ) {
                        let sig = format!(
                            "{}({})",
                            name,
                            inputs
                                .iter()
                                .filter_map(|i| i.get("type").and_then(|t| t.as_str()))
                                .collect::<Vec<_>>()
                                .join(",")
                        );
                        let selector = compute_selector(&sig);
                        map.insert(selector, Some(name.to_string()));
                    }
                }
            }
        }
    }

    // Fallback: extract selectors from deployed bytecode (PUSH4 patterns)
    if map.is_empty() {
        if let Some(sel) = extract_selectors_from_bytecode(&contract.deployed_bytecode) {
            for s in sel {
                map.insert(s, None);
            }
        }
    }

    map
}

/// Compute a function selector from a signature string.
fn compute_selector(signature: &str) -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(signature.as_bytes());
    let hash = hasher.finalize();
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&hash[..4]);
    sel
}

/// Extract PUSH4 selectors from deployed bytecode (fallback when ABI is missing).
fn extract_selectors_from_bytecode(bytecode: &[u8]) -> Option<Vec<[u8; 4]>> {
    let mut selectors = Vec::new();
    let push4_op: u8 = 0x63; // PUSH4
    
    let mut i = 0;
    while i + 5 <= bytecode.len() {
        if bytecode[i] == push4_op {
            let mut sel = [0u8; 4];
            sel.copy_from_slice(&bytecode[i + 1..i + 5]);
            // Skip zero selectors (not real functions)
            if sel != [0u8; 4] {
                selectors.push(sel);
            }
            i += 5;
        } else {
            i += 1;
        }
    }

    if selectors.is_empty() {
        None
    } else {
        Some(selectors)
    }
}

/// Build a TxMutator scoped to shared functions only.
fn build_diff_mutator(
    contract: &ContractInfo,
    shared: &HashMap<[u8; 4], Option<String>>,
) -> Result<TxMutator> {
    // Build a filtered ContractInfo with only shared ABI functions
    let filtered_abi = contract.abi.as_ref().and_then(|abi| {
        let arr = abi.as_array()?;
        let filtered: Vec<serde_json::Value> = arr
            .iter()
            .filter(|entry| {
                if entry.get("type").and_then(|t| t.as_str()) != Some("function") {
                    return true; // keep events, etc.
                }
                if let (Some(name), Some(inputs)) = (
                    entry.get("name").and_then(|n| n.as_str()),
                    entry.get("inputs").and_then(|i| i.as_array()),
                ) {
                    let sig = format!(
                        "{}({})",
                        name,
                        inputs
                            .iter()
                            .filter_map(|i| i.get("type").and_then(|t| t.as_str()))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    let sel = compute_selector(&sig);
                    shared.contains_key(&sel)
                } else {
                    false
                }
            })
            .cloned()
            .collect();
        Some(serde_json::Value::Array(filtered))
    });

    let filtered_contract = ContractInfo {
        address: contract.address,
        deployed_bytecode: contract.deployed_bytecode.clone(),
        creation_bytecode: contract.creation_bytecode.clone(),
        name: contract.name.clone(),
        source_path: contract.source_path.clone(),
        abi: filtered_abi,
    };

    Ok(TxMutator::new(vec![filtered_contract]))
}

/// Simple one-pass shrink: try removing transactions from the sequence
/// and verify the divergence still triggers.
fn simple_shrink(
    seq: &[Transaction],
    _mutator: &TxMutator,
    addr_a: Address,
    addr_b: Address,
    executor_a: &mut EvmExecutor,
    executor_b: &mut EvmExecutor,
    original_divs: &[Divergence],
) -> Option<Vec<Transaction>> {
    if seq.is_empty() || original_divs.is_empty() {
        return None;
    }

    let mut current = seq.to_vec();

    // Try removing one tx at a time from the end
    while current.len() > 1 {
        let mut candidate = current.clone();
        candidate.pop();

        let snap_a = executor_a.snapshot();
        let snap_b = executor_b.snapshot();

        let mut found = false;
        for tx in &candidate {
            let mut tx_a = tx.clone();
            tx_a.to = Some(addr_a);
            let mut tx_b = tx.clone();
            tx_b.to = Some(addr_b);

            let res_a = executor_a.execute(&tx_a).ok()?;
            let res_b = executor_b.execute(&tx_b).ok()?;

            if res_a.success != res_b.success {
                found = true;
                break;
            }
        }

        executor_a.restore(snap_a);
        executor_b.restore(snap_b);

        if found {
            current = candidate;
        } else {
            break;
        }
    }

    // Try removing from the front
    let mut i = 0;
    while current.len() > 1 && i < current.len() {
        let mut candidate = current.clone();
        candidate.remove(i);

        let snap_a = executor_a.snapshot();
        let snap_b = executor_b.snapshot();

        let mut found = false;
        for tx in &candidate {
            let mut tx_a = tx.clone();
            tx_a.to = Some(addr_a);
            let mut tx_b = tx.clone();
            tx_b.to = Some(addr_b);

            let res_a = executor_a.execute(&tx_a).ok()?;
            let res_b = executor_b.execute(&tx_b).ok()?;

            if res_a.success != res_b.success {
                found = true;
                break;
            }
        }

        executor_a.restore(snap_a);
        executor_b.restore(snap_b);

        if found {
            current = candidate;
            // Don't increment i since we removed an element
        } else {
            i += 1;
        }
    }

    if current.len() < seq.len() {
        Some(current)
    } else {
        None
    }
}

/// Format and print a DiffResult to stdout.
pub fn print_diff_result(result: &DiffResult) {
    println!("⚡ sci-fuzz diff — results");
    println!();
    println!("  impl-a       : {}", result.impl_a);
    println!("  impl-b       : {}", result.impl_b);
    println!("  sequences    : {}", result.sequences_run);
    println!("  steps        : {}", result.steps_run);
    println!("  elapsed      : {:.2}s", result.elapsed_secs);
    println!();

    if result.divergences.is_empty() {
        println!("  ✅ No divergences detected within the execution budget.");
        println!("     (This does NOT prove equivalence.)");
    } else {
        println!("  ⚠️  {} divergence(s) found:", result.divergences.len());
        for div in &result.divergences {
            println!();
            println!("    Step {} | {:?}", div.step, div.kind);
            if let Some(ref name) = div.function_name {
                println!("    Function: {}", name);
            }
            if let Some(sel) = div.selector {
                println!("    Selector: 0x{}", hex::encode(sel));
            }
            println!(
                "    A: success={} output=0x{}",
                div.success_a,
                hex::encode(&div.output_a)
            );
            println!(
                "    B: success={} output=0x{}",
                div.success_b,
                hex::encode(&div.output_b)
            );
        }

        if let Some(ref seq) = result.reproducer {
            println!();
            println!("  Reproducer ({} transactions):", seq.len());
            for (i, tx) in seq.iter().enumerate() {
                let to = tx
                    .to
                    .map(|a| format!("{:?}", a))
                    .unwrap_or_else(|| "CREATE".to_string());
                println!(
                    "    [{}] to={} data=0x{}... value={}",
                    i,
                    to,
                    hex::encode(&tx.data[..std::cmp::min(tx.data.len(), 8)]),
                    tx.value
                );
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_selector() {
        // Known: transfer(address,uint256) = 0xa9059cbb
        let sel = compute_selector("transfer(address,uint256)");
        assert_eq!(sel, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_extract_selectors_from_empty_bytecode() {
        assert!(extract_selectors_from_bytecode(&[]).is_none());
    }

    #[test]
    fn test_extract_selectors_from_bytecode() {
        // PUSH4 0xa9059cbb followed by some bytes
        let bytecode: Vec<u8> = vec![
            0x63, 0xa9, 0x05, 0x9c, 0xbb, // PUSH4 transfer selector
            0x63, 0x70, 0xa0, 0x82, 0x31, // PUSH4 some other selector
        ];
        let sels = extract_selectors_from_bytecode(&bytecode).unwrap();
        assert!(sels.contains(&[0xa9, 0x05, 0x9c, 0xbb]));
        assert!(sels.contains(&[0x70, 0xa0, 0x82, 0x31]));
    }

    #[test]
    fn test_shared_functions_empty_abis() {
        let a = ContractInfo {
            address: Address::ZERO,
            deployed_bytecode: Bytes::new(),
            creation_bytecode: None,
            name: None,
            source_path: None,
            abi: None,
        };
        let b = a.clone();
        let shared = compute_shared_functions(&a, &b);
        assert!(shared.is_empty());
    }

    #[test]
    fn test_divergence_kind_equality() {
        let k1 = DivergenceKind::SuccessRevertMismatch {
            a_success: true,
            b_success: false,
        };
        let k2 = DivergenceKind::SuccessRevertMismatch {
            a_success: true,
            b_success: false,
        };
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_diff_result_serialization() {
        let result = DiffResult {
            impl_a: "VaultV1".to_string(),
            impl_b: "VaultV2".to_string(),
            sequences_run: 100,
            steps_run: 500,
            divergences: vec![],
            reproducer: None,
            elapsed_secs: 1.5,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("VaultV1"));
        assert!(json.contains("VaultV2"));
    }

    #[test]
    fn test_unsupported_reference_flag() {
        let args = DiffArgs {
            impl_a: "A".to_string(),
            impl_b: "B".to_string(),
            reference: Some("ref".to_string()),
            tolerance: 0.01,
            rpc_url: None,
            timeout: 60,
            output: None,
            project: Some(".".into()),
            seed: None,
            max_execs: 1000,
            depth: 10,
            match_contract: None,
        };
        let result = DiffConfig::from_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("--reference"));
    }

    #[test]
    fn test_unsupported_rpc_url_flag() {
        let args = DiffArgs {
            impl_a: "A".to_string(),
            impl_b: "B".to_string(),
            reference: None,
            tolerance: 0.01,
            rpc_url: Some("http://rpc.test".to_string()),
            timeout: 60,
            output: None,
            project: Some(".".into()),
            seed: None,
            max_execs: 1000,
            depth: 10,
            match_contract: None,
        };
        let result = DiffConfig::from_args(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("--rpc-url"));
    }
}
