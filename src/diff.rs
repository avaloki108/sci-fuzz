//! Differential execution between two local Foundry contract implementations.
//!
//! [`DiffRunner`] deploys both contracts into isolated revm executors, drives
//! identical generated call sequences against them, and reports any
//! reproducible divergence in success/revert status, return data, or emitted
//! event signatures.
//!
//! What this does NOT do:
//! - On-chain / RPC-backed comparison (`--rpc-url` is unsupported).
//! - Prove which implementation is correct.
//! - ABI-decode return values (raw bytes are reported when they differ).
//! - Handle constructors that require arguments (zero-arg constructors only).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::evm::EvmExecutor;
use crate::mutator::TxMutator;
use crate::project::Project;
use crate::shrinker::SequenceShrinker;
use crate::types::{Address, Bytes, ContractInfo, Log, Transaction, B256};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Classification of the observed divergence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DivergenceKind {
    /// Impl A succeeded; impl B reverted.
    SuccessVsRevert,
    /// Impl A reverted; impl B succeeded.
    RevertVsSuccess,
    /// Both succeeded but returned different data.
    /// Raw bytes are reported; ABI decoding is not attempted.
    OutputMismatch,
    /// Both succeeded with identical return data but emitted different
    /// event signatures (topic\[0\] sets differ).
    LogSignatureDifference,
}

impl std::fmt::Display for DivergenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DivergenceKind::SuccessVsRevert => write!(f, "success-vs-revert"),
            DivergenceKind::RevertVsSuccess => write!(f, "revert-vs-success"),
            DivergenceKind::OutputMismatch => write!(f, "output-mismatch"),
            DivergenceKind::LogSignatureDifference => write!(f, "log-signature-difference"),
        }
    }
}

/// Execution outcome of one call step.
#[derive(Debug, Clone)]
pub struct StepOutcome {
    /// `true` if the call did not revert.
    pub success: bool,
    /// Raw return data (ABI-encoded return value on success, revert reason bytes on failure).
    pub output: Bytes,
    /// topic\[0\] from each emitted log (the keccak256 event signature hash).
    pub log_sigs: Vec<B256>,
}

/// A confirmed, reproducible divergence between the two implementations.
#[derive(Debug, Clone)]
pub struct DivergenceRecord {
    /// What kind of divergence was observed.
    pub kind: DivergenceKind,
    /// Calldata of the transaction that triggered the divergence.
    pub calldata: Bytes,
    /// Outcome from impl A.
    pub outcome_a: StepOutcome,
    /// Outcome from impl B.
    pub outcome_b: StepOutcome,
    /// Shrunk transaction sequence (prefix steps + diverging tx) that
    /// reproduces the divergence deterministically.
    pub minimal_sequence: Vec<Transaction>,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a [`DiffRunner`] campaign.
pub struct DiffConfig {
    /// Path to the Foundry project root.
    pub project: PathBuf,
    /// Forge artifact name of the first implementation.
    pub impl_a_name: String,
    /// Forge artifact name of the second implementation.
    pub impl_b_name: String,
    /// Deterministic RNG seed (0 = no specific seed, still deterministic).
    pub seed: u64,
    /// Wall-clock timeout for the entire campaign.
    pub timeout: Duration,
    /// Maximum number of individual EVM call executions before stopping.
    pub max_execs: u64,
    /// Maximum transaction sequence depth per iteration.
    pub depth: u32,
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Runs the differential fuzzing campaign.
pub struct DiffRunner {
    pub config: DiffConfig,
}

impl DiffRunner {
    pub fn new(config: DiffConfig) -> Self {
        Self { config }
    }

    /// Run the campaign and return found divergences.
    ///
    /// Stops after the first divergence. Re-run with a different seed to
    /// search further. Returns an empty vec if no divergence was found within
    /// the budget.
    pub fn run(&mut self) -> Result<Vec<DivergenceRecord>> {
        let project_root = self
            .config
            .project
            .canonicalize()
            .unwrap_or_else(|_| self.config.project.clone());

        println!("running forge build...");
        let (project, _, artifact_count) = Project::build_and_select_targets(&project_root)?;
        println!("loaded {} artifact(s)", artifact_count);

        let contract_a = find_contract_by_name(&project, &self.config.impl_a_name)?.clone();
        let contract_b = find_contract_by_name(&project, &self.config.impl_b_name)?.clone();

        let bytecode_a = contract_a
            .creation_bytecode
            .clone()
            .filter(|b| !b.is_empty())
            .with_context(|| {
                format!(
                    "'{}' has no deployable creation bytecode (unlinked library or requires constructor args?)",
                    self.config.impl_a_name
                )
            })?;
        let bytecode_b = contract_b
            .creation_bytecode
            .clone()
            .filter(|b| !b.is_empty())
            .with_context(|| {
                format!(
                    "'{}' has no deployable creation bytecode (unlinked library or requires constructor args?)",
                    self.config.impl_b_name
                )
            })?;

        // Two isolated executors — A and B never share state.
        let mut exec_a = EvmExecutor::new();
        let mut exec_b = EvmExecutor::new();

        let deployer = Address::repeat_byte(0x42);

        let addr_a = exec_a
            .deploy(deployer, bytecode_a)
            .with_context(|| format!("deploy of '{}' reverted", self.config.impl_a_name))?;
        let addr_b = exec_b
            .deploy(deployer, bytecode_b)
            .with_context(|| format!("deploy of '{}' reverted", self.config.impl_b_name))?;

        println!("  {} => {addr_a}", self.config.impl_a_name);
        println!("  {} => {addr_b}", self.config.impl_b_name);

        // Snapshot post-deployment state for sequence resets.
        let exec_a_init = exec_a.clone();
        let exec_b_init = exec_b.clone();

        // Build the call generator from contract A's ABI. Both implementations
        // are expected to share the same interface; A is the ABI source.
        let mut mutator_target = contract_a.clone();
        mutator_target.address = addr_a;
        let mutator = TxMutator::new(vec![mutator_target]);
        let shrinker = SequenceShrinker::new();

        let mut rng = StdRng::seed_from_u64(self.config.seed);
        let start = Instant::now();
        let mut total_execs = 0u64;
        let mut divergences: Vec<DivergenceRecord> = Vec::new();
        let max_depth = (self.config.depth as usize).max(1);

        while total_execs < self.config.max_execs && start.elapsed() < self.config.timeout {
            // Reset both executors to the post-deployment baseline.
            exec_a = exec_a_init.clone();
            exec_b = exec_b_init.clone();

            let depth = rng.gen_range(1..=max_depth);
            let mut sequence: Vec<Transaction> = Vec::with_capacity(depth);
            let mut prev_sender = None;

            for _ in 0..depth {
                let tx = mutator.generate_in_sequence(prev_sender, &mut rng);
                prev_sender = Some(tx.sender);
                sequence.push(tx);
            }

            total_execs += sequence.len() as u64;

            if let Some(record) = find_divergence_in_sequence(
                &mut exec_a,
                addr_a,
                &mut exec_b,
                addr_b,
                &sequence,
                &exec_a_init,
                &exec_b_init,
                &shrinker,
            ) {
                divergences.push(record);
                break; // one confirmed divergence is enough for one run
            }
        }

        println!(
            "diff complete: {} execs in {:.1}s — {} divergence(s) found",
            total_execs,
            start.elapsed().as_secs_f64(),
            divergences.len()
        );

        Ok(divergences)
    }
}

// ---------------------------------------------------------------------------
// Divergence detection
// ---------------------------------------------------------------------------

fn find_divergence_in_sequence(
    exec_a: &mut EvmExecutor,
    addr_a: Address,
    exec_b: &mut EvmExecutor,
    addr_b: Address,
    sequence: &[Transaction],
    exec_a_init: &EvmExecutor,
    exec_b_init: &EvmExecutor,
    shrinker: &SequenceShrinker,
) -> Option<DivergenceRecord> {
    for (i, tx) in sequence.iter().enumerate() {
        let res_a = exec_a.execute(&redirect_tx(tx, addr_a)).ok()?;
        let res_b = exec_b.execute(&redirect_tx(tx, addr_b)).ok()?;

        if let Some(kind) = classify_divergence(&res_a, &res_b) {
            let outcome_a = make_step_outcome(&res_a);
            let outcome_b = make_step_outcome(&res_b);
            let diverging = &sequence[..=i];

            let minimal =
                shrink_for_diff(diverging, addr_a, addr_b, exec_a_init, exec_b_init, shrinker);

            return Some(DivergenceRecord {
                kind,
                calldata: tx.data.clone(),
                outcome_a,
                outcome_b,
                minimal_sequence: minimal,
            });
        }
    }
    None
}

/// Returns the divergence kind if `a` and `b` differ in a meaningful way.
///
/// Two reverts with different revert data are NOT reported as a divergence —
/// only success-vs-revert asymmetry and successful-but-different results are.
fn classify_divergence(
    a: &crate::types::ExecutionResult,
    b: &crate::types::ExecutionResult,
) -> Option<DivergenceKind> {
    match (a.success, b.success) {
        (true, false) => return Some(DivergenceKind::SuccessVsRevert),
        (false, true) => return Some(DivergenceKind::RevertVsSuccess),
        (false, false) => return None, // both reverted — not a divergence
        (true, true) => {}
    }
    if a.output != b.output {
        return Some(DivergenceKind::OutputMismatch);
    }
    let sigs_a = extract_log_sigs(&a.logs);
    let sigs_b = extract_log_sigs(&b.logs);
    if sigs_a != sigs_b {
        return Some(DivergenceKind::LogSignatureDifference);
    }
    None
}

fn make_step_outcome(result: &crate::types::ExecutionResult) -> StepOutcome {
    StepOutcome {
        success: result.success,
        output: result.output.clone(),
        log_sigs: extract_log_sigs(&result.logs),
    }
}

fn extract_log_sigs(logs: &[Log]) -> Vec<B256> {
    logs.iter()
        .filter_map(|log| log.topics.first().copied())
        .collect()
}

// ---------------------------------------------------------------------------
// Shrinking
// ---------------------------------------------------------------------------

/// Shrink `sequence` while the divergence is still reproducible.
///
/// Each candidate is replayed from scratch on fresh copies of both executors.
fn shrink_for_diff(
    sequence: &[Transaction],
    addr_a: Address,
    addr_b: Address,
    exec_a_init: &EvmExecutor,
    exec_b_init: &EvmExecutor,
    shrinker: &SequenceShrinker,
) -> Vec<Transaction> {
    // Move clones into the closure so each shrink attempt starts from the
    // same post-deployment baseline without any shared mutable state.
    let ea = exec_a_init.clone();
    let eb = exec_b_init.clone();

    shrinker.shrink(sequence, move |candidate| {
        let mut a = ea.clone();
        let mut b = eb.clone();
        sequence_has_divergence(&mut a, addr_a, &mut b, addr_b, candidate)
    })
}

fn sequence_has_divergence(
    exec_a: &mut EvmExecutor,
    addr_a: Address,
    exec_b: &mut EvmExecutor,
    addr_b: Address,
    sequence: &[Transaction],
) -> bool {
    for tx in sequence {
        let res_a = match exec_a.execute(&redirect_tx(tx, addr_a)) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let res_b = match exec_b.execute(&redirect_tx(tx, addr_b)) {
            Ok(r) => r,
            Err(_) => return false,
        };
        if classify_divergence(&res_a, &res_b).is_some() {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Clone `tx` with `to` overridden to `addr`.
fn redirect_tx(tx: &Transaction, addr: Address) -> Transaction {
    Transaction {
        to: Some(addr),
        ..tx.clone()
    }
}

/// Find a contract in `project.contracts` by its `name` field.
fn find_contract_by_name<'a>(project: &'a Project, name: &str) -> Result<&'a ContractInfo> {
    project
        .contracts
        .values()
        .find(|c| c.name.as_deref() == Some(name))
        .ok_or_else(|| {
            let mut available: Vec<&str> = project
                .contracts
                .values()
                .filter_map(|c| c.name.as_deref())
                .collect();
            available.sort_unstable();
            anyhow::anyhow!(
                "contract '{}' not found in project artifacts.\nAvailable: {}",
                name,
                if available.is_empty() {
                    "(none — did `forge build` succeed?)".to_string()
                } else {
                    available.join(", ")
                }
            )
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExecutionResult, Log};

    fn make_result(success: bool, output: &[u8], log_sigs: &[B256]) -> ExecutionResult {
        let logs = log_sigs
            .iter()
            .map(|sig| Log {
                address: Address::ZERO,
                topics: vec![*sig],
                data: Default::default(),
            })
            .collect();
        ExecutionResult {
            success,
            output: Bytes::copy_from_slice(output),
            logs,
            ..Default::default()
        }
    }

    // ── classify_divergence unit tests ──────────────────────────────────────

    #[test]
    fn no_divergence_identical_results() {
        let r = make_result(true, &[1, 2, 3, 4], &[]);
        assert!(classify_divergence(&r, &r.clone()).is_none());
    }

    #[test]
    fn success_vs_revert_detected() {
        let ok = make_result(true, &[1], &[]);
        let rev = make_result(false, &[0xab, 0xcd], &[]);
        assert_eq!(
            classify_divergence(&ok, &rev),
            Some(DivergenceKind::SuccessVsRevert)
        );
    }

    #[test]
    fn revert_vs_success_detected() {
        let ok = make_result(true, &[1], &[]);
        let rev = make_result(false, &[0xab, 0xcd], &[]);
        assert_eq!(
            classify_divergence(&rev, &ok),
            Some(DivergenceKind::RevertVsSuccess)
        );
    }

    #[test]
    fn different_return_value_detected() {
        let a = make_result(true, &[0, 0, 0, 1], &[]);
        let b = make_result(true, &[0, 0, 0, 2], &[]);
        assert_eq!(
            classify_divergence(&a, &b),
            Some(DivergenceKind::OutputMismatch)
        );
    }

    #[test]
    fn raw_output_fallback_no_abi_decode() {
        // Non-ABI-decodeable garbage bytes still trigger OutputMismatch.
        let a = make_result(true, &[0xde, 0xad, 0xbe, 0xef], &[]);
        let b = make_result(true, &[0xca, 0xfe, 0xba, 0xbe], &[]);
        assert_eq!(
            classify_divergence(&a, &b),
            Some(DivergenceKind::OutputMismatch)
        );
    }

    #[test]
    fn log_signature_difference_detected() {
        let sig_a = B256::from([0xaa; 32]);
        let sig_b = B256::from([0xbb; 32]);
        let a = make_result(true, &[], &[sig_a]);
        let b = make_result(true, &[], &[sig_b]);
        assert_eq!(
            classify_divergence(&a, &b),
            Some(DivergenceKind::LogSignatureDifference)
        );
    }

    #[test]
    fn both_revert_not_a_divergence() {
        // Two reverts with different data are not a divergence — only
        // success-vs-revert asymmetry counts.
        let a = make_result(false, &[1, 2], &[]);
        let b = make_result(false, &[3, 4], &[]);
        assert!(classify_divergence(&a, &b).is_none());
    }

    // ── DiffArgs struct fields (compile-time check) ─────────────────────────

    #[test]
    fn diff_args_has_required_fields() {
        // Verifies that cli.rs DiffArgs is no longer the old stub shape.
        // This is a compile test: if DiffArgs is missing any of these fields,
        // the test will fail to compile.
        #[cfg(feature = "cli")]
        {
            use crate::cli::DiffArgs;
            // We can't easily construct DiffArgs without clap, but we can
            // reference the fields to ensure they exist.
            fn _check_fields(a: &DiffArgs) {
                let _ = &a.impl_a;
                let _ = &a.impl_b;
                let _ = &a.project;
                let _ = &a.seed;
                let _ = &a.max_execs;
                let _ = &a.depth;
                let _ = &a.timeout;
                let _ = &a.match_contract;
                let _ = &a.reference;
                let _ = &a.rpc_url;
            }
        }
    }

    // ── Shrinking preserves divergence ──────────────────────────────────────

    #[test]
    fn shrinking_preserves_divergence() {
        use crate::types::U256;

        let shrinker = SequenceShrinker::new();

        // Build a sequence of 5 transactions. Only the transaction with
        // data[0] == 4 causes a divergence (mocked by the closure).
        let sequence: Vec<Transaction> = (0u8..5)
            .map(|i| Transaction {
                data: Bytes::from(vec![i, 0, 0, 0]),
                to: Some(Address::ZERO),
                sender: Address::ZERO,
                value: U256::ZERO,
                gas_limit: 30_000_000,
            })
            .collect();

        // "fails" = at least one tx in the candidate has data[0] == 4.
        let minimal = shrinker.shrink(&sequence, |candidate| {
            candidate.iter().any(|tx| tx.data.first() == Some(&4))
        });

        // After shrinking, the sequence should be non-empty and still contain
        // the diverging transaction.
        assert!(
            !minimal.is_empty(),
            "shrinker must not eliminate all transactions"
        );
        assert!(
            minimal.iter().any(|tx| tx.data.first() == Some(&4)),
            "shrinker must preserve the diverging transaction"
        );
        // Ideally it reduces to exactly 1 transaction.
        assert_eq!(
            minimal.len(),
            1,
            "shrinker should reduce to the single diverging tx"
        );
    }
}
