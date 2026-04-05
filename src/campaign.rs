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
use crate::feedback::CoverageFeedback;
use crate::rpc::FuzzerDatabase;
use revm::db::CacheDB;

use crate::invariant::EchidnaPropertyCaller;
use crate::mutator::TxMutator;
use crate::oracle::OracleEngine;
use crate::shrinker::SequenceShrinker;
use crate::snapshot::SnapshotCorpus;
use crate::types::{
    contract_info_for_mutator, Address, CampaignConfig, ContractInfo, CoverageMap, Finding,
    StateSnapshot, Transaction, U256,
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

/// Shared fuzzing state for multi-worker campaigns (mutex-protected).
struct SharedCampaignInner {
    feedback: CoverageFeedback,
    snapshots: SnapshotCorpus,
    saved_dbs: HashMap<u64, CacheDB<FuzzerDatabase>>,
    mutator: TxMutator,
    findings: Vec<CampaignFindingRecord>,
    seen_finding_hashes: HashSet<u64>,
    finding_count: usize,
    first_hit_execs: Option<u64>,
    first_hit_time_ms: Option<u64>,
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
    /// Unique stored findings and their benchmark metadata.
    pub findings: Vec<CampaignFindingRecord>,
    /// Total EVM executions completed during the run.
    pub total_execs: u64,
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

    /// Run the fuzzing loop and return both findings and execution metrics.
    pub fn run_with_report(&mut self) -> anyhow::Result<CampaignReport> {
        let effective_workers = effective_worker_count(self.config.workers, &self.config.rpc_url);
        if self.config.rpc_url.is_some() && self.config.workers > 1 {
            eprintln!(
                "[campaign] RPC mode: forcing workers=1 (fork DB is not shared across threads)"
            );
        }

        let mut rng = StdRng::seed_from_u64(self.config.seed);
        // --- 1. Set up the Executor ----------------------------------------
        let mut executor = if let Some(ref url) = self.config.rpc_url {
            let rpc_db = crate::rpc::RpcCacheDB::new(url, self.config.rpc_block_number)?;
            EvmExecutor::new_with_db(FuzzerDatabase::Rpc(rpc_db))
        } else {
            EvmExecutor::new()
        };
        executor.set_mode(self.config.mode);

        let mut feedback = CoverageFeedback::new();
        let mut snapshots = SnapshotCorpus::new(self.config.max_snapshots);

        // --- Set up attacker address with some ETH -------------------------
        let attacker = Address::repeat_byte(0x42);
        executor.set_balance(attacker, U256::from(100_000_000_000_000_000_000_u128)); // 100 ETH

        // --- Deploy target contracts ---------------------------------------
        // We must track the ACTUAL deployed addresses (returned by CREATE)
        // because they differ from the config addresses.  The mutator and
        // property callers need to target the real on-chain addresses.
        let mut deployed_targets: Vec<ContractInfo> = Vec::new();
        for target in &self.config.targets {
            let deployment_bytecode = target
                .creation_bytecode
                .clone()
                .filter(|code| !code.is_empty())
                .unwrap_or_else(|| target.deployed_bytecode.clone());

            if !deployment_bytecode.is_empty() {
                let deployed_addr = executor.deploy(attacker, deployment_bytecode)?;
                deployed_targets.push(ContractInfo {
                    address: deployed_addr,
                    deployed_bytecode: target.deployed_bytecode.clone(),
                    creation_bytecode: target.creation_bytecode.clone(),
                    name: target.name.clone(),
                    source_path: target.source_path.clone(),
                    abi: target.abi.clone(),
                });
            } else {
                // No bytecode — use the config address as-is (pre-deployed).
                deployed_targets.push(target.clone());
            }
        }

        // --- Optional Foundry harness: deploy, then setUp() -----------------
        if let Some(ref harness) = self.config.harness {
            let deployment_bytecode = harness
                .creation_bytecode
                .clone()
                .filter(|code| !code.is_empty())
                .unwrap_or_else(|| harness.deployed_bytecode.clone());

            if deployment_bytecode.is_empty() {
                anyhow::bail!("harness contract has no bytecode to deploy");
            }

            let deployed_addr = executor.deploy(attacker, deployment_bytecode)?;
            deployed_targets.push(ContractInfo {
                address: deployed_addr,
                deployed_bytecode: harness.deployed_bytecode.clone(),
                creation_bytecode: harness.creation_bytecode.clone(),
                name: harness.name.clone(),
                source_path: harness.source_path.clone(),
                abi: harness.abi.clone(),
            });

            crate::harness::run_setup(&mut executor, attacker, deployed_addr)
                .map_err(|e| anyhow::anyhow!("harness setUp failed: {e}"))?;
            eprintln!(
                "[campaign] ran setUp() on harness {} ({})",
                harness.name.as_deref().unwrap_or("?"),
                deployed_addr
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
        let mut mutator = TxMutator::new(mutator_targets);
        mutator.add_to_address_pool(attacker);
        let mut oracle = OracleEngine::new(attacker);

        // Seed the oracle with the attacker's ACTUAL initial balance so
        // BalanceIncrease doesn't fire spuriously just because the attacker
        // was pre-funded.  Without this, old=0 and any nonzero balance looks
        // like profit.
        {
            let mut initial_balances = std::collections::HashMap::new();
            initial_balances.insert(attacker, executor.get_balance(attacker));
            oracle.set_initial_balances(initial_balances);
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
        // --- Seed the snapshot corpus with the initial state ----------------
        let initial_snapshot = StateSnapshot {
            id: 0, // will be reassigned by corpus
            parent_id: None,
            storage: Default::default(),
            balances: Default::default(),
            block_number: 1,
            timestamp: 1,
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

                if novel_cov || novel_df {
                    let snap = StateSnapshot {
                        id: 0,
                        parent_id: None,
                        storage: Default::default(),
                        balances: Default::default(),
                        block_number: 1,
                        timestamp: 1,
                        coverage: cov.clone(),
                        dataflow: df.clone(),
                    };
                    let snap_id = snapshots.add(snap);
                    snapshots.update_metadata(snap_id, |m| {
                        m.calibrated = true;
                        m.new_bits = cov.len() as u32;
                    });
                }
            }
        }

        tracing::info!(
            elapsed_ms = calibration_start.elapsed().as_millis() as u64,
            seeds = seed_count,
            "calibration complete",
        );

        if effective_workers > 1 {
            let inner = SharedCampaignInner {
                feedback,
                snapshots,
                saved_dbs,
                mutator,
                findings: Vec::new(),
                seen_finding_hashes: HashSet::new(),
                finding_count: 0,
                first_hit_execs: None,
                first_hit_time_ms: None,
            };
            return run_parallel_campaign(
                self.config.clone(),
                inner,
                oracle,
                property_callers,
                target_abis,
                attacker,
                effective_workers,
            );
        }

        // --- Main fuzzing loop ---------------------------------------------
        let start = Instant::now();
        let mut total_execs: u64 = 0;
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
            let seq_len: u32 = rng.gen_range(1..=self.config.max_depth);
            let mut raw_sequence: Vec<Transaction> = Vec::with_capacity(seq_len as usize);

            for _ in 0..seq_len {
                let tx = if raw_sequence.is_empty() || rng.gen_bool(0.3) {
                    let prev_sender = raw_sequence.last().map(|t: &Transaction| t.sender);
                    mutator.generate_in_sequence(prev_sender, &mut rng)
                } else {
                    mutator.mutate(raw_sequence.last().unwrap(), &mut rng)
                };
                raw_sequence.push(tx);
            }

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
            let mut reached_exec_budget = false;
            let mut sequence: Vec<Transaction> = Vec::with_capacity(final_sequence.len());
            let mut cumulative_logs: Vec<crate::types::Log> = Vec::new();

            for tx in final_sequence {
                let mut result = match executor.execute(&tx) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                cumulative_logs.extend(result.logs.iter().cloned());
                result.sequence_cumulative_logs = cumulative_logs.clone();

                total_execs += 1;
                sequence.push(tx.clone());

                // Diagnostic: track deposit/withdraw patterns.
                if result.success && tx.data.len() >= 4 {
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

                // --- Oracle / invariant checks -----------------------------
                let new_findings = oracle.check(&result, &sequence);
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

                // Track successful state-changing transactions.
                if result.success && !result.state_diff.storage_writes.is_empty() {
                    successful_state_changes += 1;
                }

                let novel_cov = feedback.record_from_coverage_map(&cov);
                let novel_df = feedback.record_dataflow(&df);
                let is_novel = novel_cov || novel_df;
                if is_novel {
                    // Store a snapshot of this state for future exploration.
                    let snap = StateSnapshot {
                        id: 0,
                        parent_id: None,
                        storage: Default::default(),
                        balances: Default::default(),
                        block_number: 1,
                        timestamp: 1,
                        coverage: cov,
                        dataflow: df,
                    };
                    let snap_id = snapshots.add(snap);

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

            // Periodic stats logging.
            if total_execs % 500 == 0 && total_execs > 0 {
                let elapsed = start.elapsed().as_secs_f64();
                let prop_count: usize = findings
                    .iter()
                    .filter(|record| record.finding.title.contains("echidna"))
                    .count();
                eprintln!(
                    "[campaign] execs={total_execs} speed={:.0}/s state_chg={successful_state_changes} snaps_saved={snapshots_saved} cov={} snaps={} findings={} prop_findings={prop_count} deposits={diag_funded_deposits} withdraws={diag_withdraws_ok} dep+wdr={diag_deposit_then_withdraw}",
                    total_execs as f64 / elapsed,
                    feedback.total_coverage(),
                    snapshots.len(),
                    findings.len(),
                );
                tracing::info!(
                    total_execs,
                    execs_per_sec = format_args!("{:.0}", total_execs as f64 / elapsed),
                    state_changes = successful_state_changes,
                    snapshots_saved,
                    coverage = feedback.total_coverage(),
                    snapshots = snapshots.len(),
                    findings = findings.len(),
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

        Ok(CampaignReport {
            deduped_finding_count: findings.len(),
            elapsed_ms: elapsed.as_millis() as u64,
            finding_count,
            findings,
            first_hit_execs,
            first_hit_time_ms,
            total_execs,
        })
    }
}

/// Multi-worker fuzz loop: shared corpus, feedback, mutator, and deduped findings.
fn run_parallel_campaign(
    config: CampaignConfig,
    inner: SharedCampaignInner,
    oracle: OracleEngine,
    property_callers: Vec<EchidnaPropertyCaller>,
    target_abis: HashMap<Address, JsonAbi>,
    attacker: Address,
    worker_count: usize,
) -> anyhow::Result<CampaignReport> {
    let shared = Arc::new(Mutex::new(inner));
    let total_execs = Arc::new(AtomicU64::new(0));
    let oracle = Arc::new(oracle);
    let property_callers = Arc::new(property_callers);
    let target_abis = Arc::new(target_abis);
    let config = Arc::new(config);

    let start = Instant::now();
    tracing::info!(
        timeout_s = config.timeout.as_secs(),
        max_depth = config.max_depth,
        workers = worker_count,
        targets = config.targets.len(),
        "parallel campaign started",
    );

    std::thread::scope(|s| {
        for worker_id in 0..worker_count {
            let shared = Arc::clone(&shared);
            let total_execs = Arc::clone(&total_execs);
            let oracle = Arc::clone(&oracle);
            let property_callers = Arc::clone(&property_callers);
            let target_abis = Arc::clone(&target_abis);
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

    Ok(CampaignReport {
        deduped_finding_count: inner.findings.len(),
        elapsed_ms: elapsed.as_millis() as u64,
        finding_count: inner.finding_count,
        findings: inner.findings,
        first_hit_execs: inner.first_hit_execs,
        first_hit_time_ms: inner.first_hit_time_ms,
        total_execs: total_execs_u64,
    })
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
            let seq_len: u32 = rng.gen_range(1..=config.max_depth);
            let mut raw_sequence: Vec<Transaction> = Vec::with_capacity(seq_len as usize);
            for _ in 0..seq_len {
                let tx = if raw_sequence.is_empty() || rng.gen_bool(0.3) {
                    let prev_sender = raw_sequence.last().map(|t: &Transaction| t.sender);
                    g.mutator.generate_in_sequence(prev_sender, &mut rng)
                } else {
                    g.mutator.mutate(raw_sequence.last().unwrap(), &mut rng)
                };
                raw_sequence.push(tx);
            }
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
        let mut reached_exec_budget = false;
        let mut sequence: Vec<Transaction> = Vec::with_capacity(final_sequence.len());
        let mut cumulative_logs: Vec<crate::types::Log> = Vec::new();

        for tx in final_sequence {
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

            let new_findings = oracle.check(&result, &sequence);
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
                if novel_cov || novel_df {
                    let snap = StateSnapshot {
                        id: 0,
                        parent_id: None,
                        storage: Default::default(),
                        balances: Default::default(),
                        block_number: 1,
                        timestamp: 1,
                        coverage: cov,
                        dataflow: df,
                    };
                    let snap_id = g.snapshots.add(snap);
                    if result.success
                        && !result.state_diff.storage_writes.is_empty()
                        && g.saved_dbs.len() < 64
                    {
                        g.saved_dbs.insert(snap_id, executor.snapshot());
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
    attacker: Address,
    target_failure: &str,
    sequence: &[Transaction],
) -> bool {
    executor.restore(base_snapshot.clone());

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

        if oracle
            .check(&result, &executed)
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CampaignConfig, ExecutorMode, Severity};
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
}
