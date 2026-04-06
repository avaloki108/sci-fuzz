//! Fuzzing campaign orchestration.
//!
//! A [`Campaign`] ties together the EVM executor, snapshot corpus, mutator,
//! feedback, and oracle engine into a single fuzzing loop.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use alloy_json_abi::JsonAbi;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::evm::EvmExecutor;
use crate::feedback::{CoverageFeedback, PathFeedback};
use crate::path_id::fold_sequence;
use crate::rpc::FuzzerDatabase;
use revm::db::CacheDB;

use crate::economic::ProtocolProfileMap;
use crate::invariant::EchidnaPropertyCaller;
use crate::mutator::TxMutator;
use crate::oracle::{capture_eth_baseline, OracleEngine};
use crate::shrinker::SequenceShrinker;
use crate::snapshot::SnapshotCorpus;
use crate::types::{
    contract_info_for_mutator, Address, CampaignConfig, ContractInfo, CoverageMap, Finding,
    StateSnapshot, TestMode, Transaction, B256, U256,
};

/// ABI function names excluded from fuzzing (harness lifecycle; setup runs once at bootstrap).
const STRIP_HARNESS_LIFECYCLE: &[&str] = &["setUp", "beforeTest", "afterTest"];

/// deposit() selector: keccak256("deposit()")[..4] = 0xd0e30db0
const DEPOSIT_SEL: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];
/// withdraw() selector: keccak256("withdraw()")[..4] = 0x3ccfd60b
const WITHDRAW_SEL: [u8; 4] = [0x3c, 0xcf, 0xd6, 0x0b];

/// Deterministic per-worker RNG seed derived from the campaign root seed.
fn worker_rng_seed(root_seed: u64, worker_id: usize) -> u64 {
    root_seed ^ ((worker_id as u64).wrapping_mul(0xD6E8_FEB8_6659_FDB5_u64))
}

/// Parallel fuzzing uses multiple threads only when local DB mode is active.
fn effective_worker_count(workers: usize, rpc_url: &Option<String>) -> usize {
    if rpc_url.is_some() && workers > 1 {
        1
    } else {
        workers.max(1)
    }
}

fn executor_block_meta(executor: &EvmExecutor) -> (u64, u64) {
    let n = executor.block_env().number;
    let t = executor.block_env().timestamp;
    (n.saturating_to::<u64>(), t.saturating_to::<u64>())
}

/// Shared fuzzing state for multi-worker campaigns (mutex-protected).
struct SharedCampaignInner {
    feedback: CoverageFeedback,
    path_feedback: PathFeedback,
    snapshots: SnapshotCorpus,
    saved_dbs: HashMap<u64, CacheDB<FuzzerDatabase>>,
    mutator: TxMutator,
    findings: Vec<CampaignFindingRecord>,
    seen_finding_hashes: HashSet<u64>,
    finding_count: usize,
    first_hit_execs: Option<u64>,
    first_hit_time_ms: Option<u64>,
    seq_corpus: Vec<CorpusEntry>,
}

// ---------------------------------------------------------------------------
// Campaign
// ---------------------------------------------------------------------------

/// Top-level fuzzing campaign.
///
/// Call [`Campaign::run`] to start the loop.  It returns the list of
/// [`Finding`]s discovered during the campaign.
pub struct Campaign {
    config: CampaignConfig,
}

/// One unique finding captured during a campaign run, along with benchmark-
/// relevant metadata recorded before and after shrinking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignFindingRecord {
    /// The final stored finding. Its reproducer is the current shrunk sequence.
    pub finding: Finding,
    /// Reproducer length before deterministic shrinking.
    pub raw_reproducer_len: usize,
    /// Execution count when this unique finding was first observed.
    pub first_observed_execs: u64,
    /// Milliseconds elapsed when this unique finding was first observed.
    pub first_observed_time_ms: u64,
}

/// Structured outcome of one campaign run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
    /// Testing mode used for this campaign.
    pub test_mode: TestMode,
    /// Unique stored findings and their benchmark metadata.
    pub findings: Vec<CampaignFindingRecord>,
    /// Total EVM executions completed during the run.
    pub total_execs: u64,
    /// Aggregated coverage map from the entire campaign.
    #[serde(default, skip_serializing_if = "crate::types::CoverageMap::is_empty")]
    pub aggregate_coverage: crate::types::CoverageMap,
    /// Total wall-clock runtime in milliseconds.
    pub elapsed_ms: u64,
    /// Execution count for the first observed finding, if any.
    pub first_hit_execs: Option<u64>,
    /// Milliseconds to the first observed finding, if any.
    pub first_hit_time_ms: Option<u64>,
    /// Total number of finding events observed before deduplication.
    pub finding_count: usize,
    /// Total number of unique findings retained after deduplication.
    pub deduped_finding_count: usize,
    /// Post-run telemetry (selectors, reverts, invariants, coverage samples).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<crate::types::CampaignTelemetry>,
}

impl CampaignReport {
    /// Discard benchmark metadata and return just the stored findings.
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
            .into_iter()
            .map(|record| record.finding)
            .collect()
    }
}

impl Campaign {
    /// Create a campaign from the given configuration.
    pub fn new(config: CampaignConfig) -> Self {
        Self { config }
    }

    /// Run the fuzzing loop until timeout or the transaction budget is
    /// exhausted.  Returns all findings discovered.
    pub fn run(&mut self) -> anyhow::Result<Vec<Finding>> {
        Ok(self.run_with_report()?.into_findings())
    }

    /// Replay a fixed transaction sequence and return any findings.
    ///
    /// Sets up the EVM executor and deploys target contracts (same as the
    /// normal campaign path) then executes each transaction in `sequence`
    /// in order, running the oracle after every step.  Returns any
    /// invariant violations detected.
    ///
    /// This is used by the `replay` CLI subcommand to confirm that a
    /// previously serialized finding still triggers.
    pub fn replay_sequence(&mut self, sequence: &[Transaction]) -> anyhow::Result<Vec<Finding>> {
        // --- Executor setup (mirrors run_with_report) ----------------------
        let mut executor = if let Some(ref url) = self.config.rpc_url {
            let url = url.trim();
            let rpc_db = crate::rpc::RpcCacheDB::new(url, self.config.rpc_block_number)?;
            EvmExecutor::new_with_db(FuzzerDatabase::Rpc(rpc_db))
        } else {
            EvmExecutor::new()
        };
        executor.set_mode(self.config.mode);

        let attacker = self.config.resolved_attacker();
        if self.config.rpc_url.is_some() {
            executor.set_balance(attacker, self.config.fork_attacker_balance_wei);
        } else {
            executor.set_balance(attacker, U256::from(100_000_000_000_000_000_000_u128));
        }

        // --- Deploy targets -----------------------------------------------
        let mut deployed_targets: Vec<ContractInfo> = Vec::new();
        for target in &self.config.targets {
            let deployment_bytecode = target
                .creation_bytecode
                .clone()
                .filter(|c| !c.is_empty())
                .unwrap_or_else(|| target.deployed_bytecode.clone());

            if !deployment_bytecode.is_empty() {
                match executor.deploy(attacker, deployment_bytecode) {
                    Ok(addr) => deployed_targets.push(ContractInfo {
                        address: addr,
                        deployed_bytecode: target.deployed_bytecode.clone(),
                        creation_bytecode: target.creation_bytecode.clone(),
                        name: target.name.clone(),
                        source_path: target.source_path.clone(),
                        deployed_source_map: target.deployed_source_map.clone(),
                        source_file_list: target.source_file_list.clone(),
                        abi: target.abi.clone(),
                        link_references: Default::default(),
                    }),
                    Err(e) => eprintln!("[replay] skipping target — deploy failed: {e}"),
                }
            } else {
                deployed_targets.push(target.clone());
            }
        }

        // --- Oracle setup -------------------------------------------------
        let protocol_profiles =
            crate::protocol_semantics::build_protocol_profiles(&deployed_targets);
        let oracle = match self.config.test_mode {
            TestMode::Exploration => OracleEngine::empty(attacker),
            TestMode::Assertion => OracleEngine::new_assertion_mode(attacker),
            _ => OracleEngine::new_with_protocol_profiles(
                attacker,
                Some(Arc::clone(&protocol_profiles)),
            ),
        };

        // --- Execute sequence and collect violations ----------------------
        let mut findings: Vec<Finding> = Vec::new();
        let target_abis: HashMap<Address, JsonAbi> = deployed_targets
            .iter()
            .filter_map(|t| {
                t.abi
                    .clone()
                    .and_then(|v| serde_json::from_value(v).ok())
                    .map(|abi| (t.address, abi))
            })
            .collect();
        let pre_probes = crate::protocol_probes::capture_pre_sequence_probes(
            &executor,
            attacker,
            &protocol_profiles,
            &target_abis,
            sequence,
        );
        let pre_balances = capture_eth_baseline(&executor, attacker);
        let mut cumulative_sequence: Vec<Transaction> = Vec::new();

        for tx in sequence {
            let mut result = match executor.execute(tx) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[replay] tx execution error: {e}");
                    continue;
                }
            };
            cumulative_sequence.push(tx.clone());
            result.sequence_cumulative_logs = result.logs.clone();

            let new_findings = oracle.check(
                &pre_balances,
                &pre_probes,
                &result,
                &cumulative_sequence,
            );
            findings.extend(new_findings);
        }

        Ok(findings)
    }

    /// Run the fuzzing loop and return both findings and execution metrics.
    pub fn run_with_report(&mut self) -> anyhow::Result<CampaignReport> {
        // NOTE: replay_sequence() is defined above if you need a no-fuzz reproducer path.
        let effective_workers = effective_worker_count(self.config.workers, &self.config.rpc_url);
        if self.config.rpc_url.is_some() && self.config.workers > 1 {
            eprintln!(
                "[campaign] RPC mode: forcing workers=1 (fork DB is not shared across threads)"
            );
        }

        let mut rng = StdRng::seed_from_u64(self.config.seed);
        // --- 1. Set up the Executor ----------------------------------------
        let mut executor = if let Some(ref url) = self.config.rpc_url {
            let url = url.trim();
            if url.is_empty() {
                anyhow::bail!("fork campaign requires a non-empty rpc_url");
            }
            let rpc_db = crate::rpc::RpcCacheDB::new(url, self.config.rpc_block_number)?;
            EvmExecutor::new_with_db(FuzzerDatabase::Rpc(rpc_db))
        } else {
            EvmExecutor::new()
        };
        executor.set_mode(self.config.mode);

        if let Some(ref url) = self.config.rpc_url {
            let url = url.trim();
            crate::rpc::rpc_probe_url(url)?;
            match crate::rpc::fetch_eth_chain_id(url) {
                Ok(cid) => {
                    eprintln!("[campaign] fork: chain_id={cid} (eth_chainId)");
                    if let Some(expected) = self.config.fork_expected_chain_id {
                        if expected != cid {
                            eprintln!(
                                "[campaign] warning: fork_expected_chain_id={expected} but RPC reports chain_id={cid} — wrong RPC network?"
                            );
                        }
                    }
                }
                Err(e) => eprintln!("[campaign] warning: eth_chainId failed: {e:#}"),
            }
            let header =
                crate::rpc::fetch_fork_block_header_full(url, self.config.rpc_block_number)?;
            {
                let be = executor.block_env_mut();
                crate::rpc::merge_fork_header_into_block_env(&header, be);
            }
            eprintln!(
                "[campaign] fork: block_number={} timestamp={} gas_limit={:?} basefee={:?} (rpc_block tag: {:?})",
                header.number,
                header.timestamp,
                header.gas_limit,
                header.basefee,
                self.config.rpc_block_number
            );
        }

        let mut feedback = CoverageFeedback::new();
        let mut path_feedback = PathFeedback::new();
        let mut snapshots = SnapshotCorpus::new(self.config.max_snapshots);

        // --- Set up attacker address with some ETH -------------------------
        let attacker = self.config.resolved_attacker();
        if attacker.is_zero() {
            anyhow::bail!("attacker_address must not be zero; leave unset for default 0x42…42");
        }
        if self.config.rpc_url.is_some() {
            if self.config.fork_preserve_attacker_balance {
                eprintln!(
                    "[campaign] fork: preserving attacker balance from chain (no balance overlay)"
                );
            } else {
                executor.set_balance(attacker, self.config.fork_attacker_balance_wei);
                eprintln!(
                    "[campaign] fork: attacker balance set to {} wei",
                    self.config.fork_attacker_balance_wei
                );
            }
        } else {
            executor.set_balance(attacker, U256::from(100_000_000_000_000_000_000_u128));
            // 100 ETH local
        }

        crate::bootstrap::fund_fork_addresses(&mut executor, &self.config);

        let bootstrap = crate::bootstrap::bootstrap_targets(&mut executor, &self.config, attacker)?;
        eprintln!(
            "[campaign] bootstrap mode: {:?} ({} target(s) after deploy/attach)",
            bootstrap.mode,
            bootstrap.deployed_targets.len()
        );
        if let Some(ref setup) = bootstrap.setup_report {
            if !setup.deploy_failures.is_empty() {
                eprintln!(
                    "[campaign] setup: {} deploy failure(s) recorded (see logs)",
                    setup.deploy_failures.len()
                );
            }
            if setup.set_up_called && !setup.set_up_success {
                if let Some(ref err) = setup.set_up_error {
                    eprintln!("[campaign] setUp() did not complete: {err}");
                }
            }
        }
        let deployed_targets = bootstrap.deployed_targets;
        if deployed_targets.is_empty() && !self.config.targets.is_empty() {
            anyhow::bail!(
                "bootstrap produced zero targets — all deploys failed or attach-only misconfigured. \
                 For fork audits use predeployed addresses without bytecode in config; for local Foundry, check constructor args / cheatcodes."
            );
        }

        // --- JSON ABIs at deployed addresses (shrinker / oracles) ------------
        let target_abis: HashMap<Address, JsonAbi> = deployed_targets
            .iter()
            .filter_map(|t| {
                t.abi
                    .clone()
                    .and_then(|v| serde_json::from_value(v).ok())
                    .map(|abi| (t.address, abi))
            })
            .collect();

        // --- Build sub-systems using DEPLOYED addresses --------------------
        // Add the attacker to each target's address pool so the mutator
        // generates transactions FROM the funded attacker, not just from
        // the contract address (which would send ETH to itself).
        let mutator_targets: Vec<ContractInfo> = deployed_targets
            .iter()
            .map(|c| contract_info_for_mutator(c, STRIP_HARNESS_LIFECYCLE))
            .collect();
        let mut merged_target_weights = self.config.target_weights.clone();
        if self.config.auto_rank_targets {
            let ranked = crate::target_rank::rank_targets(&deployed_targets);
            eprintln!("[campaign] target ranking (auto, top 8 by score):");
            for e in ranked.iter().take(8) {
                eprintln!(
                    "  {:?} {:?} score={} signals={:?}",
                    e.name, e.address, e.score, e.signals
                );
            }
            for (addr, w) in crate::target_rank::weights_from_rankings(&ranked, 1, 10) {
                merged_target_weights.entry(addr).or_insert(w);
            }
        }
        let use_weights = self.config.system_mode
            || !merged_target_weights.is_empty()
            || !self.config.selector_weights.is_empty()
            || self.config.auto_rank_targets;
        let mut mutator = if use_weights {
            TxMutator::new_with_weights(
                mutator_targets,
                &merged_target_weights,
                &self.config.selector_weights,
            )
        } else {
            TxMutator::new(mutator_targets)
        };
        mutator.add_to_address_pool(attacker);

        // Fund and register extra senders (multi-actor system-level fuzzing).
        for &extra in &self.config.extra_senders {
            executor.set_balance(extra, self.config.sender_balance_wei);
            mutator.add_to_address_pool(extra);
            eprintln!(
                "[campaign] extra sender {extra:#x} funded with {} wei",
                self.config.sender_balance_wei
            );
        }
        let protocol_profiles =
            crate::protocol_semantics::build_protocol_profiles(&deployed_targets);
        let mut oracle = match self.config.test_mode {
            TestMode::Exploration => OracleEngine::empty(attacker),
            TestMode::Assertion => OracleEngine::new_assertion_mode(attacker),
            TestMode::Property | TestMode::FoundryInvariant | TestMode::Optimization => {
                OracleEngine::new_with_protocol_profiles(
                    attacker,
                    Some(Arc::clone(&protocol_profiles)),
                )
            }
        };

        // --- ABI-inferred invariants (Phase 6) ------------------------------
        if self.config.infer_invariants {
            let deployer = self
                .config
                .attacker_address
                .unwrap_or_else(|| attacker);
            let synth = crate::inferred_invariants::SynthesizedInvariants::synthesize(
                &deployed_targets,
                attacker,
                deployer,
            );
            let count = synth.invariants.len();
            if count > 0 {
                oracle.extend_invariants(synth.invariants);
                eprintln!(
                    "[campaign] synthesized {} ABI-inferred invariant(s):",
                    count
                );
                for desc in &synth.descriptions {
                    eprintln!("  ↳ {desc}");
                }
            }
        }

        // --- Build Echidna property callers at deployed addresses -----------
        let mut property_callers: Vec<EchidnaPropertyCaller> = Vec::new();
        for target in &deployed_targets {
            eprintln!(
                "[campaign] target {} bytecode={} abi={}",
                target.address,
                target.deployed_bytecode.len(),
                target.abi.is_some(),
            );
            if let Some(abi) = &target.abi {
                if let Some(caller) = EchidnaPropertyCaller::from_abi(target.address, abi) {
                    let n_props = caller.properties.len();
                    for (sel, name) in &caller.properties {
                        eprintln!(
                            "[campaign]   property: {} (selector 0x{})",
                            name,
                            hex::encode(sel),
                        );
                    }
                    property_callers.push(caller);
                    eprintln!(
                        "[campaign] registered {n_props} echidna properties at {}",
                        target.address
                    );
                } else {
                    eprintln!(
                        "[campaign] no echidna_* properties found in ABI for {}",
                        target.address
                    );
                }
            }
        }

        eprintln!(
            "[campaign] {} property callers built, {} deployed targets",
            property_callers.len(),
            deployed_targets.len()
        );

        let missing_abi: Vec<Address> = deployed_targets
            .iter()
            .filter(|t| t.abi.is_none())
            .map(|t| t.address)
            .collect();
        if !missing_abi.is_empty() {
            eprintln!(
                "[campaign] warning: {} target(s) have no ABI — mutation and echidna property discovery may be shallow: {:?}",
                missing_abi.len(),
                missing_abi
            );
        }

        // --- Seed the snapshot corpus with the initial state ----------------
        let (root_bn, root_ts) = executor_block_meta(&executor);
        let initial_snapshot = StateSnapshot {
            id: 0, // will be reassigned by corpus
            parent_id: None,
            storage: Default::default(),
            balances: Default::default(),
            block_number: root_bn,
            timestamp: root_ts,
            coverage: CoverageMap::new(),
            dataflow: Default::default(),
        };
        snapshots.add(initial_snapshot);

        // --- Persistent DB snapshots for stateful exploration ---------------
        let mut saved_dbs: HashMap<u64, CacheDB<FuzzerDatabase>> = HashMap::new();
        saved_dbs.insert(0, executor.snapshot());

        // --- Calibration phase: run each target's functions once to
        //     establish baselines -------------------------------------------
        tracing::info!("calibration phase started");
        let calibration_start = Instant::now();

        // Generate N seed transactions (one per known selector if we have
        // them, otherwise 8 random ones) and execute them to:
        // 1. Populate the coverage map with initial baseline
        // 2. Seed the value dictionary with return values
        // 3. Create initial snapshots from interesting results
        let seed_count = mutator.selector_count().clamp(8, 64);
        for _i in 0..seed_count {
            let tx = mutator.generate(&mut rng);
            if let Ok(result) = executor.execute(&tx) {
                mutator.feed_execution(&result);
                let cov = result.coverage.clone();
                let df = result.dataflow.clone();

                let novel_cov = feedback.record_from_coverage_map(&cov);
                let novel_df = feedback.record_dataflow(&df);
                let seq_path = fold_sequence(B256::ZERO, result.tx_path_id, 0);
                let novel_tx_path = path_feedback.record_tx_path(&result.tx_path_id);
                let novel_seq_path = path_feedback.record_sequence_path(&seq_path);
                let path_only = (novel_tx_path || novel_seq_path) && !novel_cov && !novel_df;

                if novel_cov || novel_df || novel_tx_path || novel_seq_path {
                    let (bn, ts) = executor_block_meta(&executor);
                    let snap = StateSnapshot {
                        id: 0,
                        parent_id: None,
                        storage: Default::default(),
                        balances: Default::default(),
                        block_number: bn,
                        timestamp: ts,
                        coverage: cov.clone(),
                        dataflow: df.clone(),
                    };
                    let snap_id = snapshots.add(snap);
                    snapshots.update_metadata(snap_id, |m| {
                        m.calibrated = true;
                        m.new_bits = cov.len() as u32;
                        if path_only {
                            m.path_bits = m.path_bits.saturating_add(1);
                        }
                    });
                }
            }
        }

        tracing::info!(
            elapsed_ms = calibration_start.elapsed().as_millis() as u64,
            seeds = seed_count,
            "calibration complete",
        );

        // Corpus of interesting sequences for splice-based crossover.
        // Load persisted entries before choosing sequential vs parallel path.
        let mut seq_corpus: Vec<CorpusEntry> = Vec::with_capacity(SEQ_CORPUS_CAP);
        if let Some(ref dir) = self.config.corpus_dir {
            if !self.config.fork_skip_corpus_load {
                let prior = load_corpus_from_dir(dir);
                seq_corpus.extend(prior.into_iter().take(SEQ_CORPUS_CAP));
            } else {
                eprintln!("[campaign] fork_skip_corpus_load: starting without persisted seq corpus");
            }
        }

        if effective_workers > 1 {
            let inner = SharedCampaignInner {
                feedback,
                path_feedback,
                snapshots,
                saved_dbs,
                mutator,
                findings: Vec::new(),
                seen_finding_hashes: HashSet::new(),
                finding_count: 0,
                first_hit_execs: None,
                first_hit_time_ms: None,
                seq_corpus,
            };
            return run_parallel_campaign(
                self.config.clone(),
                inner,
                oracle,
                property_callers,
                target_abis,
                protocol_profiles,
                attacker,
                effective_workers,
                deployed_targets,
            );
        }

        // --- Main fuzzing loop ---------------------------------------------
        let start = Instant::now();
        let mut total_execs: u64 = 0;
        let mut total_reverts: u64 = 0;
        let mut findings: Vec<CampaignFindingRecord> = Vec::new();
        let mut seen_finding_hashes: HashSet<u64> = HashSet::new();
        let mut finding_count: usize = 0;
        let mut first_hit_execs: Option<u64> = None;
        let mut first_hit_time_ms: Option<u64> = None;
        let mut successful_state_changes: u64 = 0;
        let mut snapshots_saved: u64 = 0;
        // Diagnostic counters for stateful property debugging.
        let mut diag_funded_deposits: u64 = 0;
        let mut diag_withdraws_ok: u64 = 0;
        let mut diag_deposit_then_withdraw: u64 = 0;
        // Time-based progress tracking (every 5 seconds to stderr).
        let progress_interval = std::time::Duration::from_secs(5);
        let mut last_progress = start;
        let timeout_s = self.config.timeout.as_secs();

        // Print initial "started" banner so the user knows the campaign is live.
        eprintln!(
            "[fuzz] started | targets={} | timeout={}s | depth={} | mode={:?}",
            deployed_targets.len(),
            timeout_s,
            self.config.max_depth,
            self.config.test_mode,
        );

        tracing::info!(
            timeout_s = self.config.timeout.as_secs(),
            max_depth = self.config.max_depth,
            targets = self.config.targets.len(),
            "campaign started",
        );

        loop {
            // Check timeout.
            if start.elapsed() >= self.config.timeout {
                tracing::info!(total_execs, "timeout reached");
                break;
            }
            if let Some(max_execs) = self.config.max_execs {
                if total_execs >= max_execs {
                    tracing::info!(total_execs, max_execs, "execution budget reached");
                    break;
                }
            }

            // Pick a snapshot to fuzz from.  30% of the time we force the
            // root state (snapshot 0) so the fuzzer can discover full
            // sequences from a clean slate — critical for properties like
            // "balance goes to zero" that require starting from zero.
            let use_root = rng.gen_bool(0.3);
            let base_snap_id = if use_root {
                Some(0u64)
            } else {
                snapshots.select_weighted(&mut rng).map(|s| s.id)
            };

            if let Some(sid) = base_snap_id {
                if !use_root {
                    snapshots.update_metadata(sid, |m| {
                        m.n_fuzz = m.n_fuzz.saturating_add(1);
                    });
                }
                // Restore to the selected snapshot's DB state so we build on
                // previously-discovered state (e.g. post-deposit).
                if let Some(db) = saved_dbs.get(&sid) {
                    executor.restore(db.clone());
                }
            }

            // Generate a transaction sequence.
            // 10% of the time splice two corpus sequences for crossover coverage.
            let do_splice = !seq_corpus.is_empty() && rng.gen_bool(0.10);
            let seq_len: u32 = rng.gen_range(1..=self.config.max_depth);
            let raw_sequence: Vec<Transaction> = if do_splice {
                // Coverage-weighted parent selection: bias toward
                // entries with fewer edges (rarer paths more valuable to mix).
                let (a_idx, b_idx) = coverage_weighted_pair(&seq_corpus, &mut rng);
                TxMutator::splice(
                    &seq_corpus[a_idx].sequence,
                    &seq_corpus[b_idx].sequence,
                    &mut rng,
                )
            } else if rng.gen_bool(self.config.sequence_template_mix) {
                let tmpl = crate::sequence_templates::pick_template(
                    &mut rng,
                    &self.config.sequence_template_weights,
                );
                crate::sequence_templates::build_sequence(
                    tmpl,
                    &mutator,
                    self.config.max_depth,
                    &mut rng,
                )
            } else {
                let mut seq: Vec<Transaction> = Vec::with_capacity(seq_len as usize);
                for _ in 0..seq_len {
                    let tx = if seq.is_empty() || rng.gen_bool(0.3) {
                        let prev_sender = seq.last().map(|t: &Transaction| t.sender);
                        mutator.generate_in_sequence(prev_sender, &mut rng)
                    } else {
                        mutator.mutate(seq.last().unwrap(), &mut rng)
                    };
                    seq.push(tx);
                }
                seq
            };

            // Wrap a small percentage (e.g. 5%) of sequences in a flashloan to enable
            // the Global Economic Oracle to catch logic flaws.
            let wrap_flashloan = rng.gen_bool(0.05);
            let final_sequence = if wrap_flashloan {
                let flashloan_mutator =
                    crate::flashloan::FlashloanMutator::new(&mutator, &mutator.dict);
                flashloan_mutator.wrap_sequence(raw_sequence, &mut rng)
            } else {
                raw_sequence
            };

            // Save the executor state so we can roll back after the sequence.
            let db_snapshot = executor.snapshot();
            // Balance/profit invariants must use balances at this snapshot, not
            // a one-time campaign-root baseline (fuzzing often resumes from
            // non-root corpus snapshots).
            let pre_seq_balances = capture_eth_baseline(&executor, attacker);
            let pre_sequence_probes = crate::protocol_probes::capture_pre_sequence_probes(
                &executor,
                attacker,
                &protocol_profiles,
                &target_abis,
                &final_sequence
            );
            let mut reached_exec_budget = false;
            let mut sequence: Vec<Transaction> = Vec::with_capacity(final_sequence.len());
            let mut cumulative_logs: Vec<crate::types::Log> = Vec::new();
            let mut sequence_path_id = B256::ZERO;

            for (step_idx, tx) in final_sequence.into_iter().enumerate() {
                let mut result = match executor.execute(&tx) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                cumulative_logs.extend(result.logs.iter().cloned());
                result.sequence_cumulative_logs = cumulative_logs.clone();

                total_execs += 1;
                if !result.success {
                    total_reverts += 1;
                }
                sequence.push(tx.clone());

                // vm.assume(false) → treat as precondition rejection, skip
                // invariant checks and snapshot saving for this sequence.

                // Diagnostic: track deposit/withdraw patterns.
                if result.success && tx.data.len() >= 4 {
                    // Skip invariant checks on expected reverts — they are intentional.
                    if result.revert_was_expected {
                        continue;
                    }

                    let sel: [u8; 4] = [tx.data[0], tx.data[1], tx.data[2], tx.data[3]];
                    if sel == DEPOSIT_SEL && tx.value > U256::ZERO {
                        diag_funded_deposits += 1;
                    }
                    if sel == WITHDRAW_SEL {
                        diag_withdraws_ok += 1;
                        // Check if this sequence already has a funded deposit.
                        let has_prior_deposit = sequence.iter().any(|prev| {
                            prev.data.len() >= 4
                                && prev.data[..4] == DEPOSIT_SEL
                                && prev.value > U256::ZERO
                                && prev.sender == tx.sender
                        });
                        if has_prior_deposit {
                            diag_deposit_then_withdraw += 1;
                        }
                    }
                }

                // --- Protocol probes (post-state static_call) --------------
                crate::protocol_probes::fill_protocol_probes(
                    &executor,
                    attacker,
                    &protocol_profiles,
                    &target_abis,
                    &sequence,
                    &mut result,
                );

                // --- Oracle / invariant checks -----------------------------
                let new_findings = oracle.check(&pre_seq_balances, &pre_sequence_probes, &result, &sequence);
                if !new_findings.is_empty() {
                    for mut f in new_findings {
                        finding_count += 1;
                        if first_hit_execs.is_none() {
                            first_hit_execs = Some(total_execs);
                            first_hit_time_ms = Some(start.elapsed().as_millis() as u64);
                        }
                        // Attach the reproducer sequence.
                        let mut repro = sequence.clone();
                        repro.push(tx.clone());
                        let raw_reproducer_len = repro.len();
                        f.reproducer = shrink_reproducer(
                            &mut executor,
                            &db_snapshot,
                            &oracle,
                            &property_callers,
                            &target_abis,
                            &protocol_profiles,
                            attacker,
                            &f,
                            &repro,
                        );
                        tracing::warn!(
                            severity = %f.severity,
                            title = %f.title,
                            "finding discovered",
                        );
                        let hash = f.dedup_hash();
                        if seen_finding_hashes.insert(hash) {
                            findings.push(CampaignFindingRecord {
                                finding: f,
                                raw_reproducer_len,
                                first_observed_execs: total_execs,
                                first_observed_time_ms: start.elapsed().as_millis() as u64,
                            });
                        }
                    }
                }

                // --- Feedback: is the result interesting? ------------------
                let cov = result.coverage.clone();
                let df = result.dataflow.clone();

                // Seed the mutator's value dictionary with storage values observed
                // during this execution — these are potential pool reserve amounts
                // that the flashloan mutator can propose as borrow sizes.
                if !result.state_diff.storage_writes.is_empty() {
                    let reserve_candidates: Vec<crate::types::U256> = result
                        .state_diff
                        .storage_writes
                        .values()
                        .flat_map(|slots| slots.values().copied())
                        .collect();
                    mutator.dict.seed_from_storage_reserves(&reserve_candidates);
                }

                // Keep the mutator's block-timestamp hint in sync so time-aware
                // argument generation produces plausible deadline/expiry values.
                {
                    let (_, ts) = executor_block_meta(&executor);
                    mutator.update_block_timestamp(ts);
                }

                // Track successful state-changing transactions.
                if result.success && !result.state_diff.storage_writes.is_empty() {
                    successful_state_changes += 1;
                }

                sequence_path_id =
                    fold_sequence(sequence_path_id, result.tx_path_id, step_idx as u32);

                let novel_cov = feedback.record_from_coverage_map(&cov);
                let novel_df = feedback.record_dataflow(&df);
                let novel_tx_path = path_feedback.record_tx_path(&result.tx_path_id);
                let novel_seq_path = path_feedback.record_sequence_path(&sequence_path_id);
                let path_only = (novel_tx_path || novel_seq_path) && !novel_cov && !novel_df;
                let is_novel = novel_cov || novel_df || novel_tx_path || novel_seq_path;
                if is_novel {
                    // Store a snapshot of this state for future exploration.
                    let (bn, ts) = executor_block_meta(&executor);
                    let snap = StateSnapshot {
                        id: 0,
                        parent_id: None,
                        storage: Default::default(),
                        balances: Default::default(),
                        block_number: bn,
                        timestamp: ts,
                        coverage: cov,
                        dataflow: df,
                    };
                    let snap_id = snapshots.add(snap);
                    if path_only {
                        snapshots.update_metadata(snap_id, |m| {
                            m.path_bits = m.path_bits.saturating_add(1);
                        });
                    }

                    // If this tx changed state, persist the DB so future
                    // iterations can start from this post-tx state.
                    // Cap at 64 saved DBs to avoid memory/perf blowup.
                    if result.success
                        && !result.state_diff.storage_writes.is_empty()
                        && saved_dbs.len() < 64
                    {
                        saved_dbs.insert(snap_id, executor.snapshot());
                        snapshots_saved += 1;
                    }

                    // Add this sequence to the splice corpus so future
                    // iterations can crossover from this coverage path.
                    if !sequence.is_empty() && (novel_cov || novel_df) {
                        let entry = CorpusEntry {
                            sequence: sequence.clone(),
                            novel_edge_count: feedback.global_coverage().len(),
                        };
                        insert_seq_corpus_entry(&mut seq_corpus, entry, &mut rng);
                    }
                }

                if let Some(max_execs) = self.config.max_execs {
                    if total_execs >= max_execs {
                        reached_exec_budget = true;
                        break;
                    }
                }
            }

            // DIAGNOSTIC: log first tx of every 100th sequence
            if total_execs % 500 < 10 && !sequence.is_empty() {
                let tx = &sequence[0];
                let has_deposit = sequence
                    .iter()
                    .any(|t| t.data.len() >= 4 && t.data[..4] == [0xd0, 0xe3, 0x0d, 0xb0]);
                let has_withdraw = sequence
                    .iter()
                    .any(|t| t.data.len() >= 4 && t.data[..4] == [0x3c, 0xcf, 0xd6, 0x0b]);
                let has_value = sequence.iter().any(|t| t.value > U256::ZERO);
                if has_deposit || has_withdraw {
                    eprintln!(
                        "[diag] seq len={} deposit={} withdraw={} value={} sender={}",
                        sequence.len(),
                        has_deposit,
                        has_withdraw,
                        has_value,
                        tx.sender
                    );
                }
            }
            // --- Check Echidna properties after the full sequence -----------
            // Diagnostic: if we had a deposit+withdraw in this sequence, log
            // the contract balance before property check.
            if diag_deposit_then_withdraw > 0 && total_execs % 500 < 50 {
                for target in &deployed_targets {
                    let bal = executor.get_balance(target.address);
                    if bal == U256::ZERO {
                        eprintln!(
                            "[diag] contract {} balance=0 after seq of {} txs — property SHOULD fail",
                            target.address,
                            sequence.len(),
                        );
                    }
                }
            }

            for caller_entry in &property_callers {
                let prop_findings = caller_entry.check_properties(&executor, attacker, &sequence);
                if !prop_findings.is_empty() {
                    eprintln!(
                        "[campaign] property violation! {} finding(s) after {} tx sequence",
                        prop_findings.len(),
                        sequence.len(),
                    );
                }
                for mut f in prop_findings {
                    finding_count += 1;
                    if first_hit_execs.is_none() {
                        first_hit_execs = Some(total_execs);
                        first_hit_time_ms = Some(start.elapsed().as_millis() as u64);
                    }
                    let raw_reproducer_len = sequence.len();
                    f.reproducer = shrink_reproducer(
                        &mut executor,
                        &db_snapshot,
                        &oracle,
                        &property_callers,
                        &target_abis,
                        &protocol_profiles,
                        attacker,
                        &f,
                        &sequence,
                    );
                    tracing::warn!(
                        severity = %f.severity,
                        title = %f.title,
                        "finding discovered",
                    );
                    let hash = f.dedup_hash();
                    if seen_finding_hashes.insert(hash) {
                        findings.push(CampaignFindingRecord {
                            finding: f,
                            raw_reproducer_len,
                            first_observed_execs: total_execs,
                            first_observed_time_ms: start.elapsed().as_millis() as u64,
                        });
                    }
                }
            }

            // Restore the executor to the pre-sequence state so the next
            // iteration starts fresh (or from a chosen snapshot).
            executor.restore(db_snapshot);

            // Periodic stats logging — time-based (every 5 s) so it's
            // visible regardless of exec speed.
            if last_progress.elapsed() >= progress_interval {
                last_progress = Instant::now();
                let elapsed = start.elapsed().as_secs_f64();
                let eps = total_execs as f64 / elapsed.max(0.001);
                let rev_pct = if total_execs > 0 {
                    total_reverts as f64 / total_execs as f64 * 100.0
                } else {
                    0.0
                };
                let remaining = timeout_s.saturating_sub(elapsed as u64);
                eprintln!(
                    "[fuzz] {elapsed:.0}s/{timeout_s}s | {eps:.0} exec/s | {total_execs} total | cov: {} edges | snaps: {} | findings: {} | rev: {rev_pct:.0}% | {remaining}s left",
                    feedback.total_coverage(),
                    snapshots.len(),
                    findings.len(),
                );
                tracing::info!(
                    total_execs,
                    execs_per_sec = format_args!("{eps:.0}"),
                    state_changes = successful_state_changes,
                    snapshots_saved,
                    coverage = feedback.total_coverage(),
                    snapshots = snapshots.len(),
                    findings = findings.len(),
                    revert_pct = format_args!("{rev_pct:.1}"),
                    "progress",
                );
            }

            if reached_exec_budget {
                tracing::info!(total_execs, "sequence stopped at execution budget");
                break;
            }
        }

        // Final summary.
        let elapsed = start.elapsed();
        tracing::info!(
            total_execs,
            elapsed_s = format_args!("{:.1}", elapsed.as_secs_f64()),
            coverage = feedback.total_coverage(),
            findings = findings.len(),
            "campaign finished",
        );

        let aggregate_coverage = coverage_map_from_global(feedback.global_coverage());

        // Persist the sequence corpus and findings for the next run.
        if let Some(ref dir) = self.config.corpus_dir {
            save_corpus_to_dir(&seq_corpus, dir);
            save_findings_to_dir(&findings, dir);
        }

        let report = CampaignReport {
            test_mode: self.config.test_mode,
            deduped_finding_count: findings.len(),
            elapsed_ms: elapsed.as_millis() as u64,
            finding_count,
            findings: findings.clone(),
            first_hit_execs,
            first_hit_time_ms,
            total_execs,
            aggregate_coverage: aggregate_coverage.clone(),
            telemetry: None,
        };

        // Persist campaign report and source coverage.
        if let Some(ref dir) = self.config.corpus_dir {
            save_campaign_report_to_dir(&report, dir);
            save_source_coverage_to_dir(&aggregate_coverage, &deployed_targets, dir);
        }

        Ok(report)
    }
}

/// Multi-worker fuzz loop: shared corpus, feedback, mutator, and deduped findings.
fn run_parallel_campaign(
    config: CampaignConfig,
    inner: SharedCampaignInner,
    oracle: OracleEngine,
    property_callers: Vec<EchidnaPropertyCaller>,
    target_abis: HashMap<Address, JsonAbi>,
    protocol_profiles: ProtocolProfileMap,
    attacker: Address,
    worker_count: usize,
    deployed_targets: Vec<ContractInfo>,
) -> anyhow::Result<CampaignReport> {
    let shared = Arc::new(Mutex::new(inner));
    let total_execs = Arc::new(AtomicU64::new(0));
    let oracle = Arc::new(oracle);
    let property_callers = Arc::new(property_callers);
    let target_abis = Arc::new(target_abis);
    let config = Arc::new(config);

    let start = Instant::now();
    let timeout_s = config.timeout.as_secs();
    tracing::info!(
        timeout_s,
        max_depth = config.max_depth,
        workers = worker_count,
        targets = config.targets.len(),
        "parallel campaign started",
    );

    eprintln!(
        "[fuzz] started | targets={} | timeout={}s | depth={} | workers={}",
        deployed_targets.len(),
        timeout_s,
        config.timeout.as_secs(),
        worker_count,
    );

    std::thread::scope(|s| {
        // Progress reporter thread — prints every 5s to stderr.
        {
            let shared = Arc::clone(&shared);
            let total_execs = Arc::clone(&total_execs);
            let config = Arc::clone(&config);
            s.spawn(move || {
                let progress_interval = std::time::Duration::from_secs(5);
                let mut last_report_execs: u64 = 0;
                let mut last_report_time = start;
                loop {
                    std::thread::sleep(progress_interval);
                    let elapsed = start.elapsed();
                    if elapsed >= config.timeout {
                        break;
                    }
                    let execs = total_execs.load(Ordering::Relaxed);
                    let dt = last_report_time.elapsed().as_secs_f64().max(0.001);
                    let eps = (execs - last_report_execs) as f64 / dt;
                    last_report_execs = execs;
                    last_report_time = Instant::now();

                    let (cov_edges, snap_count, finding_count, revert_count) = {
                        if let Ok(g) = shared.lock() {
                            let cov = g.feedback.total_coverage();
                            let snaps = g.snapshots.len();
                            let finds = g.findings.len();
                            (cov, snaps, finds, 0u64)
                        } else {
                            (0, 0, 0, 0)
                        }
                    };
                    let _ = revert_count; // parallel path doesn't track reverts yet
                    let remaining = config.timeout.saturating_sub(elapsed).as_secs();
                    eprintln!(
                        "[fuzz] {:.0}s/{}s | {:.0} exec/s | {} total | cov: {} edges | snaps: {} | findings: {} | {}s left",
                        elapsed.as_secs_f64(),
                        timeout_s,
                        eps,
                        execs,
                        cov_edges,
                        snap_count,
                        finding_count,
                        remaining,
                    );
                }
            });
        }

        for worker_id in 0..worker_count {
            let shared = Arc::clone(&shared);
            let total_execs = Arc::clone(&total_execs);
            let oracle = Arc::clone(&oracle);
            let property_callers = Arc::clone(&property_callers);
            let target_abis = Arc::clone(&target_abis);
            let protocol_profiles = protocol_profiles.clone();
            let config = Arc::clone(&config);
            s.spawn(move || {
                parallel_worker_loop(
                    worker_id,
                    &config,
                    shared,
                    total_execs,
                    oracle,
                    property_callers,
                    target_abis,
                    protocol_profiles,
                    attacker,
                    start,
                );
            });
        }
    });

    let elapsed = start.elapsed();
    let total_execs_u64 = total_execs.load(Ordering::Relaxed);
    tracing::info!(
        total_execs = total_execs_u64,
        elapsed_s = format_args!("{:.1}", elapsed.as_secs_f64()),
        "parallel campaign finished",
    );

    let inner = Arc::try_unwrap(shared)
        .map_err(|_| anyhow::anyhow!("parallel campaign: shared state still referenced"))?
        .into_inner()
        .map_err(|e| anyhow::anyhow!("parallel campaign mutex poisoned: {e}"))?;

    if let Some(ref dir) = config.corpus_dir {
        save_corpus_to_dir(&inner.seq_corpus, dir);
        save_findings_to_dir(&inner.findings, dir);
    }

    let aggregate_coverage = coverage_map_from_global(inner.feedback.global_coverage());

    let report = CampaignReport {
        test_mode: config.test_mode,
        deduped_finding_count: inner.findings.len(),
        elapsed_ms: elapsed.as_millis() as u64,
        finding_count: inner.finding_count,
        findings: inner.findings.clone(),
        first_hit_execs: inner.first_hit_execs,
        first_hit_time_ms: inner.first_hit_time_ms,
        total_execs: total_execs_u64,
        aggregate_coverage: aggregate_coverage.clone(),
        telemetry: None,
    };

    if let Some(ref dir) = config.corpus_dir {
        save_campaign_report_to_dir(&report, dir);
        save_source_coverage_to_dir(&aggregate_coverage, &deployed_targets, dir);
    }

    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn parallel_worker_loop(
    worker_id: usize,
    config: &CampaignConfig,
    shared: Arc<Mutex<SharedCampaignInner>>,
    total_execs: Arc<AtomicU64>,
    oracle: Arc<OracleEngine>,
    property_callers: Arc<Vec<EchidnaPropertyCaller>>,
    target_abis: Arc<HashMap<Address, JsonAbi>>,
    protocol_profiles: ProtocolProfileMap,
    attacker: Address,
    campaign_start: Instant,
) {
    let mut rng = StdRng::seed_from_u64(worker_rng_seed(config.seed, worker_id));
    let mut executor = EvmExecutor::new();
    executor.set_mode(config.mode);

    loop {
        if campaign_start.elapsed() >= config.timeout {
            break;
        }
        if let Some(max_execs) = config.max_execs {
            if total_execs.load(Ordering::Relaxed) >= max_execs {
                break;
            }
        }

        let base_snap_id = {
            let mut g = shared.lock().expect("shared mutex poisoned");
            let use_root = rng.gen_bool(0.3);
            let sid = if use_root {
                Some(0u64)
            } else {
                g.snapshots.select_weighted(&mut rng).map(|s| s.id)
            };
            if let Some(id) = sid {
                if !use_root {
                    g.snapshots.update_metadata(id, |m| {
                        m.n_fuzz = m.n_fuzz.saturating_add(1);
                    });
                }
            }
            sid
        };

        if let Some(sid) = base_snap_id {
            let db = {
                let g = shared.lock().expect("shared mutex poisoned");
                g.saved_dbs.get(&sid).cloned()
            };
            if let Some(db) = db {
                executor.restore(db);
            }
        }

        let final_sequence: Vec<Transaction> = {
            let g = shared.lock().expect("shared mutex poisoned");
            let do_splice = !g.seq_corpus.is_empty() && rng.gen_bool(0.10);
            let seq_len: u32 = rng.gen_range(1..=config.max_depth);
            let raw_sequence: Vec<Transaction> = if do_splice {
                let (a_idx, b_idx) = coverage_weighted_pair(&g.seq_corpus, &mut rng);
                TxMutator::splice(
                    &g.seq_corpus[a_idx].sequence,
                    &g.seq_corpus[b_idx].sequence,
                    &mut rng,
                )
            } else {
                let mut seq: Vec<Transaction> = Vec::with_capacity(seq_len as usize);
                for _ in 0..seq_len {
                    let tx = if seq.is_empty() || rng.gen_bool(0.3) {
                        let prev_sender = seq.last().map(|t: &Transaction| t.sender);
                        g.mutator.generate_in_sequence(prev_sender, &mut rng)
                    } else {
                        g.mutator.mutate(seq.last().unwrap(), &mut rng)
                    };
                    seq.push(tx);
                }
                seq
            };
            let wrap_flashloan = rng.gen_bool(0.05);
            if wrap_flashloan {
                let flashloan_mutator =
                    crate::flashloan::FlashloanMutator::new(&g.mutator, &g.mutator.dict);
                flashloan_mutator.wrap_sequence(raw_sequence, &mut rng)
            } else {
                raw_sequence
            }
        };

        let db_snapshot = executor.snapshot();
        let pre_seq_balances = capture_eth_baseline(&executor, attacker);
            let pre_sequence_probes = crate::protocol_probes::capture_pre_sequence_probes(
                &executor,
                attacker,
                &protocol_profiles,
                &target_abis,
                &final_sequence
            );
            let mut reached_exec_budget = false;
        let mut sequence: Vec<Transaction> = Vec::with_capacity(final_sequence.len());
        let mut cumulative_logs: Vec<crate::types::Log> = Vec::new();
        let mut sequence_path_id = B256::ZERO;

        for (step_idx, tx) in final_sequence.into_iter().enumerate() {
            if campaign_start.elapsed() >= config.timeout {
                reached_exec_budget = true;
                break;
            }
            if let Some(max_execs) = config.max_execs {
                if total_execs.load(Ordering::Relaxed) >= max_execs {
                    reached_exec_budget = true;
                    break;
                }
            }

            let mut result = match executor.execute(&tx) {
                Ok(r) => r,
                Err(_) => continue,
            };

            cumulative_logs.extend(result.logs.iter().cloned());
            result.sequence_cumulative_logs = cumulative_logs.clone();

            sequence.push(tx.clone());
            total_execs.fetch_add(1, Ordering::Relaxed);
            let exec_count = total_execs.load(Ordering::Relaxed);

            if result.success && tx.data.len() >= 4 {
                let sel: [u8; 4] = [tx.data[0], tx.data[1], tx.data[2], tx.data[3]];
                if sel == DEPOSIT_SEL && tx.value > U256::ZERO {
                    // diagnostic: keep parity with sequential path (no global counter in v1)
                }
            }

            crate::protocol_probes::fill_protocol_probes(
                &executor,
                attacker,
                &protocol_profiles,
                target_abis.as_ref(),
                &sequence,
                &mut result,
            );

            let new_findings = oracle.check(&pre_seq_balances, &pre_sequence_probes, &result, &sequence);
            if !new_findings.is_empty() {
                for mut f in new_findings {
                    let mut repro = sequence.clone();
                    repro.push(tx.clone());
                    let raw_reproducer_len = repro.len();
                    f.reproducer = shrink_reproducer(
                        &mut executor,
                        &db_snapshot,
                        oracle.as_ref(),
                        property_callers.as_slice(),
                        target_abis.as_ref(),
                        &protocol_profiles,
                        attacker,
                        &f,
                        &repro,
                    );
                    let hash = f.dedup_hash();
                    let mut g = shared.lock().expect("shared mutex poisoned");
                    g.finding_count += 1;
                    if g.first_hit_execs.is_none() {
                        g.first_hit_execs = Some(exec_count);
                        g.first_hit_time_ms = Some(campaign_start.elapsed().as_millis() as u64);
                    }
                    if g.seen_finding_hashes.insert(hash) {
                        g.findings.push(CampaignFindingRecord {
                            finding: f,
                            raw_reproducer_len,
                            first_observed_execs: exec_count,
                            first_observed_time_ms: campaign_start.elapsed().as_millis() as u64,
                        });
                    }
                }
            }

            let cov = result.coverage.clone();
            let df = result.dataflow.clone();

            sequence_path_id = fold_sequence(sequence_path_id, result.tx_path_id, step_idx as u32);

            {
                let mut g = shared.lock().expect("shared mutex poisoned");
                if !result.state_diff.storage_writes.is_empty() {
                    let reserve_candidates: Vec<crate::types::U256> = result
                        .state_diff
                        .storage_writes
                        .values()
                        .flat_map(|slots| slots.values().copied())
                        .collect();
                    g.mutator
                        .dict
                        .seed_from_storage_reserves(&reserve_candidates);
                }

                let novel_cov = g.feedback.record_from_coverage_map(&cov);
                let novel_df = g.feedback.record_dataflow(&df);
                let novel_tx_path = g.path_feedback.record_tx_path(&result.tx_path_id);
                let novel_seq_path = g.path_feedback.record_sequence_path(&sequence_path_id);
                let path_only = (novel_tx_path || novel_seq_path) && !novel_cov && !novel_df;
                if novel_cov || novel_df || novel_tx_path || novel_seq_path {
                    let (bn, ts) = executor_block_meta(&executor);
                    let snap = StateSnapshot {
                        id: 0,
                        parent_id: None,
                        storage: Default::default(),
                        balances: Default::default(),
                        block_number: bn,
                        timestamp: ts,
                        coverage: cov,
                        dataflow: df,
                    };
                    let snap_id = g.snapshots.add(snap);
                    if path_only {
                        g.snapshots.update_metadata(snap_id, |m| {
                            m.path_bits = m.path_bits.saturating_add(1);
                        });
                    }
                    if result.success
                        && !result.state_diff.storage_writes.is_empty()
                        && g.saved_dbs.len() < 64
                    {
                        g.saved_dbs.insert(snap_id, executor.snapshot());
                    }
                    if !sequence.is_empty() && (novel_cov || novel_df) {
                        let entry = CorpusEntry {
                            sequence: sequence.clone(),
                            novel_edge_count: g.feedback.global_coverage().len(),
                        };
                        insert_seq_corpus_entry(&mut g.seq_corpus, entry, &mut rng);
                    }
                }
            }

            if let Some(max_execs) = config.max_execs {
                if total_execs.load(Ordering::Relaxed) >= max_execs {
                    reached_exec_budget = true;
                    break;
                }
            }
        }

        if diag_parallel_should_log(worker_id, total_execs.load(Ordering::Relaxed)) {
            let g = shared.lock().expect("shared mutex poisoned");
            eprintln!(
                "[campaign] (parallel w{}) execs={} cov={} snaps={} findings={}",
                worker_id,
                total_execs.load(Ordering::Relaxed),
                g.feedback.total_coverage(),
                g.snapshots.len(),
                g.findings.len(),
            );
        }

        for caller_entry in property_callers.iter() {
            let prop_findings = caller_entry.check_properties(&executor, attacker, &sequence);
            for mut f in prop_findings {
                let raw_reproducer_len = sequence.len();
                f.reproducer = shrink_reproducer(
                    &mut executor,
                    &db_snapshot,
                    oracle.as_ref(),
                    property_callers.as_slice(),
                    target_abis.as_ref(),
                    &protocol_profiles,
                    attacker,
                    &f,
                    &sequence,
                );
                let hash = f.dedup_hash();
                let exec_count = total_execs.load(Ordering::Relaxed);
                let mut g = shared.lock().expect("shared mutex poisoned");
                g.finding_count += 1;
                if g.first_hit_execs.is_none() {
                    g.first_hit_execs = Some(exec_count);
                    g.first_hit_time_ms = Some(campaign_start.elapsed().as_millis() as u64);
                }
                if g.seen_finding_hashes.insert(hash) {
                    g.findings.push(CampaignFindingRecord {
                        finding: f,
                        raw_reproducer_len,
                        first_observed_execs: exec_count,
                        first_observed_time_ms: campaign_start.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        executor.restore(db_snapshot);

        if reached_exec_budget {
            break;
        }
    }
}

fn diag_parallel_should_log(worker_id: usize, total_execs: u64) -> bool {
    worker_id == 0 && total_execs > 0 && total_execs % 500 == 0
}

fn shrink_reproducer(
    executor: &mut EvmExecutor,
    base_db: &CacheDB<FuzzerDatabase>,
    oracle: &OracleEngine,
    property_callers: &[EchidnaPropertyCaller],
    target_abis: &HashMap<Address, JsonAbi>,
    protocol_profiles: &ProtocolProfileMap,
    attacker: Address,
    finding: &Finding,
    sequence: &[Transaction],
) -> Vec<Transaction> {
    let shrinker = SequenceShrinker::new().with_abis(target_abis.clone());
    let original_state = executor.snapshot();
    let target_failure = finding.failure_id();

    let shrunk = shrinker.shrink(sequence, |candidate| {
        reproduces_failure(
            executor,
            base_db,
            oracle,
            property_callers,
            target_abis,
            protocol_profiles,
            attacker,
            &target_failure,
            candidate,
        )
    });

    executor.restore(original_state);
    shrunk
}

fn reproduces_failure(
    executor: &mut EvmExecutor,
    base_snapshot: &CacheDB<FuzzerDatabase>,
    oracle: &OracleEngine,
    property_callers: &[EchidnaPropertyCaller],
    target_abis: &HashMap<Address, JsonAbi>,
    protocol_profiles: &ProtocolProfileMap,
    attacker: Address,
    target_failure: &str,
    sequence: &[Transaction],
) -> bool {
    executor.restore(base_snapshot.clone());
    let pre_seq_balances = capture_eth_baseline(executor, attacker);
    let pre_sequence_probes = crate::protocol_probes::capture_pre_sequence_probes(
        executor,
        attacker,
        protocol_profiles,
        target_abis,
        sequence,     // sequence is passed to `execute_seq_with_feedback`
    );

    let mut executed: Vec<Transaction> = Vec::with_capacity(sequence.len());
    let mut cumulative_logs: Vec<crate::types::Log> = Vec::new();
    for tx in sequence {
        let mut result = match executor.execute(tx) {
            Ok(result) => result,
            Err(_) => return false,
        };

        cumulative_logs.extend(result.logs.iter().cloned());
        result.sequence_cumulative_logs = cumulative_logs.clone();

        executed.push(tx.clone());

        crate::protocol_probes::fill_protocol_probes(
            executor,
            attacker,
            protocol_profiles,
            target_abis,
            &executed,
            &mut result,
        );

        if oracle
            .check(&pre_seq_balances, &pre_sequence_probes, &result, &executed)
            .iter()
            .any(|candidate| candidate.failure_id() == target_failure)
        {
            return true;
        }
    }

    property_callers.iter().any(|caller| {
        caller
            .check_properties(executor, attacker, &executed)
            .iter()
            .any(|candidate| candidate.failure_id() == target_failure)
    })
}

// ---------------------------------------------------------------------------
// Corpus persistence
// ---------------------------------------------------------------------------

/// Persist a sequence corpus to `{dir}/seq_corpus.json`.
///
/// Failures are logged as warnings but never propagate — losing corpus data
/// between runs is graceful degradation, not a fatal error.
fn save_corpus_to_dir(corpus: &[CorpusEntry], dir: &std::path::Path) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!(
            "[corpus] could not create corpus dir {}: {e}",
            dir.display()
        );
        return;
    }
    let path = dir.join("seq_corpus.json");
    match serde_json::to_vec(corpus) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&path, bytes) {
                tracing::warn!("[corpus] write failed {}: {e}", path.display());
            } else {
                tracing::info!(
                    "[corpus] saved {} entries to {}",
                    corpus.len(),
                    path.display()
                );
            }
        }
        Err(e) => tracing::warn!("[corpus] serialization failed: {e}"),
    }
}

/// Load a corpus from `{dir}/seq_corpus.json` if it exists.
///
/// Returns an empty `Vec` if the file is absent or fails to parse — the
/// campaign simply starts without prior corpus data.
fn load_corpus_from_dir(dir: &std::path::Path) -> Vec<CorpusEntry> {
    let path = dir.join("seq_corpus.json");
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read(&path) {
        Err(e) => {
            tracing::warn!("[corpus] read failed {}: {e}", path.display());
            Vec::new()
        }
        Ok(bytes) => match serde_json::from_slice::<Vec<CorpusEntry>>(&bytes) {
            Ok(entries) => {
                tracing::info!(
                    "[corpus] loaded {} entries from {}",
                    entries.len(),
                    path.display()
                );
                entries
            }
            Err(e) => {
                tracing::warn!(
                    "[corpus] parse failed (file may be from an older version) {}: {e}",
                    path.display()
                );
                Vec::new()
            }
        },
    }
}

/// Build a `CoverageMap` from the feedback's flat global hitcount table.
fn coverage_map_from_global(
    global: &std::collections::HashMap<(Address, (usize, usize)), u32>,
) -> crate::types::CoverageMap {
    let mut map = crate::types::CoverageMap::new();
    for (&(addr, (prev, cur)), &count) in global {
        map.record_hitcount(addr, prev, cur, count);
    }
    map
}

/// Save source-level coverage to `{dir}/source_coverage.json` if any
/// deployed targets carry a source map.
fn save_source_coverage_to_dir(
    coverage: &crate::types::CoverageMap,
    deployed_targets: &[ContractInfo],
    dir: &std::path::Path,
) {
    use crate::source_map::SourceCoverageReport;
    use std::collections::HashMap;

    // Build per-contract source-map metadata.
    // (bytecode, source_map_str, file_list, name)
    let mut contract_source_maps: HashMap<
        Address,
        (Vec<u8>, String, Vec<String>, Option<String>),
    > = HashMap::new();

    for target in deployed_targets {
        if let Some(ref sm) = target.deployed_source_map {
            if !sm.is_empty() && !target.deployed_bytecode.is_empty() {
                contract_source_maps.insert(
                    target.address,
                    (
                        target.deployed_bytecode.to_vec(),
                        sm.clone(),
                        target.source_file_list.clone(),
                        target.name.clone(),
                    ),
                );
            }
        }
    }

    if contract_source_maps.is_empty() {
        tracing::debug!("[coverage] no source maps available — skipping source coverage report");
        return;
    }

    // Load source file contents for offset→line mapping.
    let mut source_file_contents: HashMap<String, String> = HashMap::new();
    for (_, _, file_list, _) in contract_source_maps.values() {
        for path in file_list {
            if !source_file_contents.contains_key(path) {
                if let Ok(content) = std::fs::read_to_string(path) {
                    source_file_contents.insert(path.clone(), content);
                }
            }
        }
    }

    let report =
        SourceCoverageReport::build(coverage, &contract_source_maps, &source_file_contents);

    if let Err(e) = report.save_to_dir(dir) {
        tracing::warn!("[coverage] failed to save source coverage: {e}");
    } else {
        report.print_summary();
    }
}

/// Persist individual finding JSON files to `{dir}/findings/`.
fn save_findings_to_dir(findings: &[CampaignFindingRecord], dir: &std::path::Path) {
    let findings_dir = dir.join("findings");
    if let Err(e) = std::fs::create_dir_all(&findings_dir) {
        tracing::warn!("[corpus] could not create findings dir: {e}");
        return;
    }
    for (i, record) in findings.iter().enumerate() {
        let filename = format!("finding_{:04}_{}.json", i, record.finding.severity);
        let path = findings_dir.join(&filename);
        match serde_json::to_string_pretty(record) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!("[corpus] failed to write {}: {e}", path.display());
                }
            }
            Err(e) => tracing::warn!("[corpus] failed to serialize finding {i}: {e}"),
        }
    }
    tracing::info!("[corpus] saved {} finding(s) to {}", findings.len(), findings_dir.display());
}

/// Persist a `CampaignReport` to `{dir}/campaign_report.json`.
fn save_campaign_report_to_dir(report: &CampaignReport, dir: &std::path::Path) {
    let path = dir.join("campaign_report.json");
    match serde_json::to_string_pretty(report) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::warn!("[corpus] failed to write report: {e}");
            } else {
                tracing::info!("[corpus] saved campaign report to {}", path.display());
            }
        }
        Err(e) => tracing::warn!("[corpus] failed to serialize report: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Corpus entry for splice crossover
// ---------------------------------------------------------------------------

/// A corpus entry tracking a sequence and its coverage contribution.
#[derive(Serialize, Deserialize)]
struct CorpusEntry {
    sequence: Vec<Transaction>,
    /// Number of unique coverage edges at time of insertion.
    novel_edge_count: usize,
}

const SEQ_CORPUS_CAP: usize = 64;

fn insert_seq_corpus_entry(corpus: &mut Vec<CorpusEntry>, entry: CorpusEntry, rng: &mut impl Rng) {
    if corpus.len() >= SEQ_CORPUS_CAP {
        let evict = rng.gen_range(0..corpus.len());
        corpus[evict] = entry;
    } else {
        corpus.push(entry);
    }
}

/// Select two corpus indices weighted inversely by novel_edge_count.
fn coverage_weighted_pair(corpus: &[CorpusEntry], rng: &mut impl Rng) -> (usize, usize) {
    if corpus.len() == 1 {
        return (0, 0);
    }
    let weights: Vec<f64> = corpus
        .iter()
        .map(|e| 1.0 / (e.novel_edge_count.max(1) as f64))
        .collect();
    let total: f64 = weights.iter().sum();

    let pick = |r: f64| -> usize {
        let mut r = r;
        for (i, w) in weights.iter().enumerate() {
            r -= w;
            if r <= 0.0 {
                return i;
            }
        }
        corpus.len() - 1
    };

    (
        pick(rng.gen::<f64>() * total),
        pick(rng.gen::<f64>() * total),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Bytes, CampaignConfig, ContractInfo, ExecutorMode, Severity};
    use std::path::Path;
    use std::time::Duration;

    #[test]
    fn effective_worker_count_rpc_forces_single_thread() {
        assert_eq!(
            effective_worker_count(8, &Some("http://127.0.0.1:8545".to_string())),
            1
        );
        assert_eq!(effective_worker_count(8, &None), 8);
        assert_eq!(effective_worker_count(0, &None), 1);
    }

    #[test]
    fn parallel_empty_campaign_runs_and_aggregates_execs() {
        let config = CampaignConfig {
            timeout: Duration::from_millis(500),
            max_execs: None,
            max_depth: 4,
            max_snapshots: 64,
            workers: 4,
            seed: 99,
            targets: Vec::new(),
            harness: None,
            mode: ExecutorMode::Realistic,
            rpc_url: None,
            rpc_block_number: None,
            attacker_address: None,
            ..Default::default()
        };
        let report = Campaign::new(config)
            .run_with_report()
            .expect("parallel campaign should complete");
        assert!(
            report.total_execs > 0,
            "expected shared atomic exec counter to advance"
        );
        assert!(report.deduped_finding_count <= report.finding_count);
    }

    #[test]
    fn empty_campaign_completes() {
        let config = CampaignConfig {
            timeout: Duration::from_millis(200),
            max_execs: None,
            max_depth: 4,
            max_snapshots: 64,
            workers: 1,
            seed: 42,
            targets: Vec::new(),
            harness: None,
            mode: ExecutorMode::Realistic,
            rpc_url: None,
            rpc_block_number: None,
            attacker_address: None,
            ..Default::default()
        };
        let mut campaign = Campaign::new(config);
        let findings = campaign.run().expect("campaign should not error");
        // With no targets the mutator generates random txs that mostly
        // call Address::ZERO — we don't expect findings but we must not
        // panic either.
        // With no targets every tx calls Address::ZERO which reverts.
        // UnexpectedRevert fires once per execution, so we just check it
        // doesn't crash and doesn't produce *critical* findings.
        let critical = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        // Print findings for diagnosis
        for f in &findings {
            if f.severity == Severity::Critical {
                eprintln!("CRITICAL FINDING: {} — {}", f.title, f.description);
            }
        }
        assert_eq!(
            critical,
            0,
            "no critical findings expected on empty campaign (found {} critical out of {} total)",
            critical,
            findings.len(),
        );
    }

    #[test]
    fn campaign_rejects_zero_address_deployed_only_target() {
        let config = CampaignConfig {
            timeout: Duration::from_millis(50),
            max_execs: Some(5),
            max_depth: 2,
            max_snapshots: 8,
            workers: 1,
            seed: 1,
            targets: vec![ContractInfo {
                address: Address::ZERO,
                deployed_bytecode: Default::default(),
                creation_bytecode: None,
                name: Some("x".into()),
                source_path: None,
                deployed_source_map: None,
                source_file_list: vec![],
                abi: None,
                link_references: Default::default(),
            }],
            harness: None,
            mode: ExecutorMode::Fast,
            rpc_url: None,
            rpc_block_number: None,
            attacker_address: None,
            ..Default::default()
        };
        let err = Campaign::new(config)
            .run()
            .expect_err("expected validation error");
        assert!(
            err.to_string().contains("address is zero"),
            "unexpected err: {err:#}"
        );
    }

    #[test]
    fn campaign_runs_with_two_runtime_bytecode_targets() {
        let bin = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/contracts/control/compiled/PropFalse.bin");
        let abi_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/contracts/control/compiled/PropFalse.abi");
        if !bin.exists() || !abi_path.exists() {
            eprintln!("SKIP: compiled PropFalse fixtures missing");
            return;
        }
        let hex_str = std::fs::read_to_string(&bin).expect("read bin");
        let bytecode = hex::decode(hex_str.trim()).expect("hex");
        let abi: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&abi_path).expect("read abi"))
                .expect("abi json");
        let mk = |label: &str| ContractInfo {
            address: Address::ZERO,
            deployed_bytecode: Bytes::new(),
            creation_bytecode: Some(Bytes::from(bytecode.clone())),
            name: Some(label.into()),
            source_path: None,
            deployed_source_map: None,
            source_file_list: vec![],
            abi: Some(abi.clone()),
            link_references: Default::default(),
        };
        let config = CampaignConfig {
            timeout: Duration::from_millis(400),
            max_execs: Some(24),
            max_depth: 2,
            max_snapshots: 16,
            workers: 1,
            seed: 7,
            targets: vec![mk("T0"), mk("T1")],
            harness: None,
            mode: ExecutorMode::Fast,
            rpc_url: None,
            rpc_block_number: None,
            attacker_address: None,
            ..Default::default()
        };
        Campaign::new(config)
            .run()
            .expect("two deploy targets should complete");
    }

    // ── Corpus persistence tests ────────────────────────────────────────────

    #[test]
    fn save_and_load_corpus_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let entries = vec![
            CorpusEntry {
                sequence: vec![Transaction {
                    sender: Address::repeat_byte(0x01),
                    to: Some(Address::repeat_byte(0x42)),
                    data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
                    value: crate::types::U256::ZERO,
                    gas_limit: 1_000_000,
                }],
                novel_edge_count: 7,
            },
            CorpusEntry {
                sequence: vec![],
                novel_edge_count: 0,
            },
        ];

        save_corpus_to_dir(&entries, dir.path());

        // File must exist.
        assert!(dir.path().join("seq_corpus.json").exists());

        let loaded = load_corpus_from_dir(dir.path());
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].novel_edge_count, 7);
        assert_eq!(loaded[0].sequence.len(), 1);
        assert_eq!(loaded[1].sequence.len(), 0);
    }

    #[test]
    fn load_corpus_returns_empty_when_dir_absent() {
        let loaded = load_corpus_from_dir(std::path::Path::new("/nonexistent/path/xyz"));
        assert!(loaded.is_empty());
    }

    #[test]
    fn load_corpus_returns_empty_on_corrupt_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("seq_corpus.json");
        std::fs::write(&path, b"not valid json!!!").expect("write");

        let loaded = load_corpus_from_dir(dir.path());
        assert!(loaded.is_empty(), "should tolerate parse errors gracefully");
    }

    #[test]
    fn campaign_persists_corpus_when_corpus_dir_set() {
        let corpus_dir = tempfile::tempdir().expect("tempdir");

        let config = CampaignConfig {
            timeout: Duration::from_millis(300),
            max_execs: Some(200),
            max_depth: 4,
            max_snapshots: 32,
            workers: 1,
            seed: 123,
            targets: Vec::new(),
            harness: None,
            mode: ExecutorMode::Fast,
            rpc_url: None,
            rpc_block_number: None,
            attacker_address: None,
            corpus_dir: Some(corpus_dir.path().to_path_buf()),
            ..Default::default()
        };

        Campaign::new(config)
            .run()
            .expect("campaign should complete");

        // The corpus file must be written (even if the campaign found nothing).
        let corpus_file = corpus_dir.path().join("seq_corpus.json");
        assert!(
            corpus_file.exists(),
            "corpus file should have been written at {}",
            corpus_file.display()
        );

        // The file must be valid JSON (even if the array is empty).
        let bytes = std::fs::read(&corpus_file).expect("read corpus file");
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("corpus must be valid JSON");
        assert!(
            parsed.is_array(),
            "corpus JSON must be an array, got: {parsed}"
        );
    }

    #[test]
    fn parallel_campaign_persists_corpus_when_corpus_dir_set() {
        let corpus_dir = tempfile::tempdir().expect("tempdir");
        let config = CampaignConfig {
            timeout: Duration::from_millis(300),
            max_execs: Some(250),
            max_depth: 4,
            max_snapshots: 32,
            workers: 4,
            seed: 777,
            targets: Vec::new(),
            harness: None,
            mode: ExecutorMode::Fast,
            rpc_url: None,
            rpc_block_number: None,
            attacker_address: None,
            corpus_dir: Some(corpus_dir.path().to_path_buf()),
            ..Default::default()
        };
        Campaign::new(config)
            .run()
            .expect("parallel campaign should complete");
        assert!(corpus_dir.path().join("seq_corpus.json").exists());
    }

    #[test]
    fn parallel_campaign_loads_prior_corpus_file() {
        let corpus_dir = tempfile::tempdir().expect("tempdir");
        let entries = vec![CorpusEntry {
            sequence: vec![Transaction {
                sender: Address::repeat_byte(0x01),
                to: Some(Address::repeat_byte(0x42)),
                data: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
                value: crate::types::U256::ZERO,
                gas_limit: 1_000_000,
            }],
            novel_edge_count: 1,
        }];
        save_corpus_to_dir(&entries, corpus_dir.path());

        let config = CampaignConfig {
            timeout: Duration::from_millis(200),
            max_execs: Some(120),
            max_depth: 4,
            max_snapshots: 16,
            workers: 2,
            seed: 42,
            targets: Vec::new(),
            harness: None,
            mode: ExecutorMode::Fast,
            rpc_url: None,
            rpc_block_number: None,
            attacker_address: None,
            corpus_dir: Some(corpus_dir.path().to_path_buf()),
            ..Default::default()
        };
        Campaign::new(config)
            .run()
            .expect("parallel campaign should tolerate loading existing corpus");
    }

    #[test]
    fn parallel_campaign_tolerates_corrupt_corpus_file() {
        let corpus_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(corpus_dir.path().join("seq_corpus.json"), b"{not-json")
            .expect("write corrupt corpus");

        let config = CampaignConfig {
            timeout: Duration::from_millis(200),
            max_execs: Some(120),
            max_depth: 4,
            max_snapshots: 16,
            workers: 2,
            seed: 101,
            targets: Vec::new(),
            harness: None,
            mode: ExecutorMode::Fast,
            rpc_url: None,
            rpc_block_number: None,
            attacker_address: None,
            corpus_dir: Some(corpus_dir.path().to_path_buf()),
            ..Default::default()
        };
        Campaign::new(config)
            .run()
            .expect("parallel campaign should tolerate corrupt corpus");
    }
}
