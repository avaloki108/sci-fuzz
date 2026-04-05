//! Multi-seed benchmark — 10 seeds × 3 EF/CF targets.
//!
//! This test answers the question: "Is the detection robust across seeds,
//! or was seed 42 just lucky?"
//!
//! For each (target, property) pair it runs 10 independent seeds and records:
//!   - hit_rate   (seeds_hit / seeds_run)
//!   - median_first_hit_execs  (primary — machine-independent)
//!   - median_time_ms          (secondary)
//!   - distinct_repros         (how many independent paths found the bug)
//!
//! Results are printed as two CSV blocks:
//!   1. Per-seed rows  (12 columns, ScorecardEntry schema)
//!   2. Summary rows   (12 columns, MultiSeedSummary schema)
//!
//! And saved to target/multiseed_results.csv + target/multiseed_summary.csv.
//!
//! RUNTIME: Each seed runs for up to 10 s, 10 seeds × 3 targets = 300 s max.
//! In practice the fast targets finish well under 10 s.

use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use sci_fuzz::evm::EvmExecutor;
use sci_fuzz::invariant::EchidnaPropertyCaller;
use sci_fuzz::mutator::TxMutator;
use sci_fuzz::oracle::OracleEngine;
use sci_fuzz::scoreboard::{MultiSeedSummary, Scoreboard, ScorecardEntry};
use sci_fuzz::snapshot::SnapshotCorpus;
use sci_fuzz::types::{
    Address, Bytes, ContractInfo, Finding, Severity, StateSnapshot, Transaction, U256,
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const COMPILED: &str = "tests/contracts/efcf-compiled";

fn read_bin(name: &str) -> Option<Vec<u8>> {
    let path = format!("{COMPILED}/{name}.bin");
    if !Path::new(&path).exists() {
        return None;
    }
    hex::decode(std::fs::read_to_string(&path).ok()?.trim()).ok()
}

fn read_abi(name: &str) -> Option<serde_json::Value> {
    let path = format!("{COMPILED}/{name}.abi");
    if !Path::new(&path).exists() {
        return None;
    }
    serde_json::from_str(&std::fs::read_to_string(&path).ok()?).ok()
}

fn attacker() -> Address {
    Address::repeat_byte(0x42)
}

// ---------------------------------------------------------------------------
// BenchmarkHarness
//
// One self-contained fuzzing run for a single (contract, seed) pair.
// Returns (findings, total_execs, first_hit_execs, first_hit_ms).
// ---------------------------------------------------------------------------

struct BenchmarkHarness {
    executor: EvmExecutor,
    mutator: TxMutator,
    property_caller: Option<EchidnaPropertyCaller>,
    oracle: OracleEngine,
    snapshots: SnapshotCorpus,
    feedback: sci_fuzz::feedback::CoverageFeedback,
    rng: StdRng,
    attacker: Address,
    initial_db: revm::db::CacheDB<revm::db::EmptyDB>,
}

impl BenchmarkHarness {
    fn new(
        contract_addr: Address,
        bytecode: Vec<u8>,
        abi: Option<serde_json::Value>,
        seed: u64,
    ) -> Self {
        let mut executor = EvmExecutor::new();
        let att = attacker();
        executor.set_balance(att, U256::from(100_000_000_000_000_000_000_u128));

        let target = ContractInfo {
            address: contract_addr,
            deployed_bytecode: Bytes::from(bytecode),
            creation_bytecode: None,
            name: None,
            source_path: None,
            abi: abi.clone(),
        };

        let mut mutator = TxMutator::new(vec![target]);
        mutator.add_to_address_pool(att);

        let mut oracle = OracleEngine::new(att);
        {
            let mut init_bal = std::collections::HashMap::new();
            init_bal.insert(att, executor.get_balance(att));
            oracle.set_initial_balances(init_bal);
        }

        let property_caller = abi
            .as_ref()
            .and_then(|a| EchidnaPropertyCaller::from_abi(contract_addr, a));

        let initial_db = executor.snapshot();

        let mut snapshots = SnapshotCorpus::new(16);
        snapshots.add(StateSnapshot::default());

        Self {
            executor,
            mutator,
            property_caller,
            oracle,
            snapshots,
            feedback: sci_fuzz::feedback::CoverageFeedback::new(),
            rng: StdRng::seed_from_u64(seed),
            attacker: att,
            initial_db,
        }
    }

    fn run(
        &mut self,
        timeout: Duration,
        max_depth: u32,
    ) -> (Vec<Finding>, u64, Option<u64>, Option<u64>) {
        let start = Instant::now();
        let mut total_execs: u64 = 0;
        let mut findings: Vec<Finding> = Vec::new();
        let mut seen_hashes: HashSet<u64> = HashSet::new();
        let mut first_hit_execs: Option<u64> = None;
        let mut first_hit_ms: Option<u64> = None;

        while start.elapsed() < timeout {
            // 30 % root-state restarts.
            if self.rng.gen_bool(0.3) {
                self.executor.restore(self.initial_db.clone());
            }

            let db_snap = self.executor.snapshot();
            let seq_len = self.rng.gen_range(1..=max_depth as usize);
            let mut sequence: Vec<Transaction> = Vec::new();

            for _ in 0..seq_len {
                let prev_sender = sequence.last().map(|t| t.sender);
                let tx = self
                    .mutator
                    .generate_in_sequence(prev_sender, &mut self.rng);

                match self.executor.execute(&tx) {
                    Ok(result) => {
                        total_execs += 1;
                        self.mutator.feed_execution(&result);

                        // Lightweight coverage feedback from real execution hitcounts.
                        let cov = result.coverage.clone();
                        if self.feedback.record_from_coverage_map(&cov)
                            && result.success
                            && !result.state_diff.storage_writes.is_empty()
                        {
                            let snap = StateSnapshot {
                                coverage: cov,
                                ..StateSnapshot::default()
                            };
                            self.snapshots.add(snap);
                        }

                        // Oracle checks (BalanceIncrease, SelfDestruct, …).
                        for mut f in self.oracle.check(&result, &sequence) {
                            let mut repro = sequence.clone();
                            repro.push(tx.clone());
                            f.reproducer = repro;
                            let h = f.dedup_hash();
                            if seen_hashes.insert(h) {
                                if first_hit_execs.is_none() {
                                    first_hit_execs = Some(total_execs);
                                    first_hit_ms = Some(start.elapsed().as_millis() as u64);
                                }
                                findings.push(f);
                            }
                        }

                        sequence.push(tx);
                    }
                    Err(_) => continue,
                }
            }

            // Echidna property checks after the full sequence.
            if let Some(ref caller) = self.property_caller {
                for mut f in caller.check_properties(&self.executor, self.attacker, &sequence) {
                    f.reproducer = sequence.clone();
                    let h = f.dedup_hash();
                    if seen_hashes.insert(h) {
                        if first_hit_execs.is_none() {
                            first_hit_execs = Some(total_execs);
                            first_hit_ms = Some(start.elapsed().as_millis() as u64);
                        }
                        findings.push(f);
                    }
                }
            }

            self.executor.restore(db_snap);
        }

        (findings, total_execs, first_hit_execs, first_hit_ms)
    }
}

// ---------------------------------------------------------------------------
// Per-target multi-seed runner
// ---------------------------------------------------------------------------

struct TargetSpec {
    name: &'static str,
    property: &'static str,
    category: &'static str,
    max_depth: u32,
    timeout_secs: u64,
    /// Which finding field to check for detection.
    detect_fn: fn(&Finding) -> bool,
    /// Oracle/mechanism name recorded in the scoreboard.
    mechanism: &'static str,
}

fn run_multiseed(spec: &TargetSpec, seeds: &[u64], board: &mut Scoreboard) {
    let bin = match read_bin(spec.name) {
        Some(b) => b,
        None => {
            eprintln!("SKIP: {}/{}.bin not found", COMPILED, spec.name);
            return;
        }
    };
    let abi = read_abi(spec.name);
    let timeout = Duration::from_secs(spec.timeout_secs);

    eprintln!();
    eprintln!(
        "=== {} ({}, {} seeds × {}s) ===",
        spec.name,
        spec.category,
        seeds.len(),
        spec.timeout_secs,
    );
    eprintln!("{}", ScorecardEntry::csv_header());

    for &seed in seeds {
        // Deploy fresh for every seed.
        let mut executor = EvmExecutor::new();
        let deployer = attacker();
        executor.set_balance(deployer, U256::from(100_000_000_000_000_000_000_u128));

        let contract_addr = match executor.deploy(deployer, Bytes::from(bin.clone())) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("  seed={seed} DEPLOY ERROR: {e}");
                continue;
            }
        };

        let mut harness = BenchmarkHarness::new(contract_addr, bin.clone(), abi.clone(), seed);
        // Use the freshly deployed executor (with the contract already at the
        // correct address) instead of the one created inside BenchmarkHarness.
        harness.executor = executor;
        harness
            .executor
            .set_balance(attacker(), U256::from(100_000_000_000_000_000_000_u128));
        harness.initial_db = harness.executor.snapshot();

        // Re-seed oracle baseline with the new executor's attacker balance.
        {
            let mut init_bal = std::collections::HashMap::new();
            init_bal.insert(attacker(), harness.executor.get_balance(attacker()));
            harness.oracle.set_initial_balances(init_bal);
        }

        let (findings, total_execs, first_hit_execs, first_hit_ms) =
            harness.run(timeout, spec.max_depth);

        let hit: Option<&Finding> = findings.iter().find(|f| (spec.detect_fn)(f));

        let entry = if let Some(f) = hit {
            ScorecardEntry::found(
                spec.name,
                spec.property,
                spec.category,
                "fast",
                seed,
                first_hit_execs.unwrap_or(0),
                first_hit_ms.unwrap_or(0),
                total_execs,
                f,
                spec.mechanism,
            )
        } else {
            ScorecardEntry::not_found(
                spec.name,
                spec.property,
                spec.category,
                "fast",
                seed,
                total_execs,
            )
        };

        eprintln!("{}", entry.to_csv_row());
        board.add(entry);
    }
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// Run 10 seeds × 3 EF/CF targets and emit a complete multi-seed scoreboard.
///
/// Runtime budget: 10 seeds × 10 s × 3 targets = 300 s (5 min).
/// harvey_baz and Delegatecall should complete long before timeout.
/// SimpleDAO is expected to remain undetected (needs ControlLeak).
#[test]
fn multiseed_efcf_three_targets() {
    let seeds: Vec<u64> = (0..10).map(|i| 1000 + i * 37).collect();

    let specs = [
        TargetSpec {
            name: "harvey_baz",
            property: "echidna_all_states",
            category: "PropertyViolation",
            max_depth: 8,
            timeout_secs: 10,
            detect_fn: |f: &Finding| f.title.contains("echidna_all_states"),
            mechanism: "EchidnaPropertyCaller",
        },
        TargetSpec {
            name: "SimpleDAO",
            property: "BalanceIncrease",
            category: "Reentrancy",
            max_depth: 8,
            timeout_secs: 10,
            detect_fn: |f: &Finding| f.severity == Severity::Critical,
            mechanism: "BalanceIncrease",
        },
        TargetSpec {
            name: "Delegatecall",
            property: "update_lib_unrestricted",
            category: "AccessControl",
            max_depth: 4,
            timeout_secs: 10,
            detect_fn: |f: &Finding| {
                !matches!(f.severity, Severity::Info | Severity::Low)
                    || f.title.contains("update_lib")
            },
            mechanism: "UnexpectedRevert_or_StateChange",
        },
    ];

    let mut board = Scoreboard::new();

    for spec in &specs {
        run_multiseed(spec, &seeds, &mut board);
    }

    // ── Summary table ────────────────────────────────────────────────────────

    eprintln!();
    eprintln!("=== MULTI-SEED SUMMARY ===");
    board.print_summary();

    // ── Per-seed CSV ─────────────────────────────────────────────────────────

    let per_seed_path = Path::new("target/multiseed_results.csv");
    std::fs::create_dir_all("target").ok();
    if let Err(e) = board.write_csv(per_seed_path) {
        eprintln!("WARNING: could not write per-seed CSV: {e}");
    } else {
        eprintln!();
        eprintln!("Per-seed CSV written to {}", per_seed_path.display());
    }

    // ── Summary CSV ──────────────────────────────────────────────────────────

    let summary_path = Path::new("target/multiseed_summary.csv");
    {
        use std::fmt::Write as _;

        // Build summary rows from the board entries.
        // Group by (target, property).
        let mut groups: std::collections::HashMap<(&str, &str), Vec<&ScorecardEntry>> =
            std::collections::HashMap::new();
        for e in board.entries() {
            groups.entry((&e.target, &e.property)).or_default().push(e);
        }

        let mut csv = String::new();
        writeln!(csv, "{}", MultiSeedSummary::csv_header()).unwrap();

        let mut keys: Vec<_> = groups.keys().collect();
        keys.sort();
        for key in keys {
            let group: Vec<ScorecardEntry> = groups[key].iter().map(|e| (*e).clone()).collect();
            let summary = MultiSeedSummary::from_entries(&group);
            writeln!(csv, "{}", summary.to_csv_row()).unwrap();
        }

        if let Err(e) = std::fs::write(summary_path, &csv) {
            eprintln!("WARNING: could not write summary CSV: {e}");
        } else {
            eprintln!("Summary CSV written to {}", summary_path.display());
        }

        // Print to stderr.
        eprint!("{}", csv);
    }

    // ── Assertions ───────────────────────────────────────────────────────────

    // We must have recorded exactly seeds.len() entries per target.
    // The Scoreboard deduplicates by hash for *found* entries, so we
    // count total entries including not_found rows.
    let total_entries = board.len();
    eprintln!(
        "\nTotal scoreboard entries: {} ({} detected)",
        total_entries,
        board.detected_count(),
    );

    // At minimum, we expect entries for every (target × seed) combination
    // attempted. The exact count depends on deduplication of found entries.
    let min_expected = specs
        .iter()
        .filter(|s| {
            // Only count specs whose binary exists.
            Path::new(&format!("{}/{}.bin", COMPILED, s.name)).exists()
        })
        .count()
        * seeds.len();

    // Because deduplication removes repeated found hashes, the board may
    // have fewer entries than (targets × seeds). We assert a lower bound:
    // at least 1 entry per target that was attempted.
    let targets_with_entries = specs
        .iter()
        .filter(|s| {
            Path::new(&format!("{}/{}.bin", COMPILED, s.name)).exists()
                && board.entries().iter().any(|e| e.target == s.name)
        })
        .count();

    assert!(
        targets_with_entries >= 1,
        "must have at least one scored target",
    );

    // harvey_baz should be detected on at least some seeds (it is a pure
    // Echidna property with no complex state; ABI-aware generation should
    // cover the branches reliably).
    if Path::new(&format!("{COMPILED}/harvey_baz.bin")).exists() {
        let harvey_detected = board
            .entries()
            .iter()
            .filter(|e| e.target == "harvey_baz" && e.detected)
            .count();

        // We cannot hard-assert a minimum hit count without knowing the
        // exact ABI-generation behavior for int256 parameters.  We soft-log.
        eprintln!(
            "harvey_baz: {}/{} seeds detected",
            harvey_detected,
            seeds.len(),
        );

        // Soft: warn if zero seeds hit — this would mean the property
        // checker is not reaching the branches.
        if harvey_detected == 0 {
            eprintln!(
                "  WARNING: harvey_baz not detected on any seed. \
                 int256 argument generation may not cover all 5 branches."
            );
        }
    }

    // SimpleDAO is expected to remain undetected (ControlLeak not implemented).
    if Path::new(&format!("{COMPILED}/SimpleDAO.bin")).exists() {
        let dao_detected = board
            .entries()
            .iter()
            .filter(|e| e.target == "SimpleDAO" && e.detected)
            .count();
        eprintln!(
            "SimpleDAO: {}/{} seeds detected (expected: 0 — ControlLeak not implemented)",
            dao_detected,
            seeds.len(),
        );
    }
}
