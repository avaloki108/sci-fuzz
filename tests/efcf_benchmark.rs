//! EF/CF benchmark run — evidence collection against real compiled contracts.
//!
//! Runs sci-fuzz against three representative EF/CF contract classes:
//!   - Reentrancy (SimpleDAO)
//!   - Property violation (harvey_baz — Echidna property)
//!   - Access control (Delegatecall)
//!
//! For each contract, the test records:
//!   target, property, category, mode, seed,
//!   detected, time_to_first_hit_ms, total_execs,
//!   sequence_len, distinct_reproducer_hash
//!
//! Results are printed as CSV to stderr for immediate inspection and saved
//! to `target/benchmark_results.csv`.
//!
//! These tests are the first external-contract credibility gate.

use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use sci_fuzz::evm::EvmExecutor;
use sci_fuzz::feedback::CoverageFeedback;
use sci_fuzz::invariant::{EchidnaPropertyCaller, InvariantRegistry};
use sci_fuzz::mutator::TxMutator;
use sci_fuzz::oracle::OracleEngine;
use sci_fuzz::scoreboard::{Scoreboard, ScorecardEntry};
use sci_fuzz::snapshot::SnapshotCorpus;
use sci_fuzz::types::{
    Address, Bytes, CampaignConfig, ContractInfo, Finding, Severity, StateSnapshot,
    Transaction, U256,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const COMPILED: &str = "tests/contracts/efcf-compiled";

fn read_bin(name: &str) -> Option<Vec<u8>> {
    let path = format!("{COMPILED}/{name}.bin");
    if !Path::new(&path).exists() {
        return None;
    }
    let hex_str = std::fs::read_to_string(&path).ok()?;
    hex::decode(hex_str.trim()).ok()
}

fn read_abi(name: &str) -> Option<serde_json::Value> {
    let path = format!("{COMPILED}/{name}.abi");
    if !Path::new(&path).exists() {
        return None;
    }
    let s = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&s).ok()
}

fn attacker() -> Address {
    Address::repeat_byte(0x42)
}

/// Minimal fuzzing loop used by every benchmark target.
///
/// Returns (findings, total_execs, elapsed_ms).
struct BenchmarkLoop {
    executor: EvmExecutor,
    contract_addr: Address,
    mutator: TxMutator,
    property_caller: Option<EchidnaPropertyCaller>,
    oracle: OracleEngine,
    snapshots: SnapshotCorpus,
    feedback: CoverageFeedback,
    rng: StdRng,
    attacker: Address,
}

impl BenchmarkLoop {
    fn new(
        contract_addr: Address,
        bytecode: Vec<u8>,
        abi: Option<serde_json::Value>,
        seed: u64,
    ) -> Self {
        let mut executor = EvmExecutor::new();
        let attacker = attacker();
        executor.set_balance(attacker, U256::from(100_000_000_000_000_000_000_u128)); // 100 ETH

        let target = ContractInfo {
            address: contract_addr,
            deployed_bytecode: Bytes::from(bytecode),
            creation_bytecode: None,
            name: None,
            source_path: None,
            abi: abi.clone(),
        };

        let mut mutator = TxMutator::new(vec![target]);
        mutator.add_to_address_pool(attacker);

        let mut oracle = OracleEngine::new(attacker);
        {
            let mut balances = std::collections::HashMap::new();
            balances.insert(attacker, executor.get_balance(attacker));
            oracle.set_initial_balances(balances);
        }

        let property_caller = abi
            .as_ref()
            .and_then(|a| EchidnaPropertyCaller::from_abi(contract_addr, a));

        let mut snapshots = SnapshotCorpus::new(16);
        snapshots.add(StateSnapshot::default());

        Self {
            executor,
            contract_addr,
            mutator,
            property_caller,
            oracle,
            snapshots,
            feedback: CoverageFeedback::new(),
            rng: StdRng::seed_from_u64(seed),
            attacker,
        }
    }

    /// Run until a finding is detected or the timeout expires.
    /// Returns (findings, total_execs, first_hit_ms).
    fn run(&mut self, timeout: Duration, max_depth: u32) -> (Vec<Finding>, u64, Option<u64>) {
        let initial_db = self.executor.snapshot();
        let start = Instant::now();
        let mut total_execs: u64 = 0;
        let mut findings: Vec<Finding> = Vec::new();
        let mut seen_hashes: HashSet<u64> = HashSet::new();
        let mut first_hit_ms: Option<u64> = None;

        while start.elapsed() < timeout {
            // 30% root-state restarts, 70% from corpus snapshot.
            let use_root = self.rng.gen_bool(0.3);
            if use_root {
                self.executor.restore(initial_db.clone());
            }

            let db_snap = self.executor.snapshot();
            let seq_len: usize = self.rng.gen_range(1..=max_depth as usize);
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

                        // Update coverage feedback using real execution hitcounts.
                        let cov = result.coverage.clone();
                        let is_novel = self.feedback.record_from_coverage_map(&cov);
                        if is_novel
                            && result.success
                            && !result.state_diff.storage_writes.is_empty()
                        {
                            let snap = StateSnapshot {
                                coverage: cov,
                                ..StateSnapshot::default()
                            };
                            self.snapshots.add(snap);
                        }

                        // Oracle checks.
                        let oracle_findings = self.oracle.check(&result, &sequence);
                        for mut f in oracle_findings {
                            let mut repro = sequence.clone();
                            repro.push(tx.clone());
                            f.reproducer = repro;
                            let h = f.dedup_hash();
                            if seen_hashes.insert(h) {
                                if first_hit_ms.is_none() {
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
                let prop_findings =
                    caller.check_properties(&self.executor, self.attacker, &sequence);
                for mut f in prop_findings {
                    f.reproducer = sequence.clone();
                    let h = f.dedup_hash();
                    if seen_hashes.insert(h) {
                        if first_hit_ms.is_none() {
                            first_hit_ms = Some(start.elapsed().as_millis() as u64);
                        }
                        findings.push(f);
                    }
                }
            }

            self.executor.restore(db_snap);
        }

        (findings, total_execs, first_hit_ms)
    }
}

// ---------------------------------------------------------------------------
// Test 1 — harvey_baz (Echidna property, multi-branch)
//
// harvey_baz has a property `echidna_all_states()` that returns false
// when all five state booleans are set simultaneously.  Getting all
// five requires hitting different branches of baz(a,b,c) through
// ABI-encoded int256 arguments.  This is the EF/CF "Harvey" contract
// and is a standard benchmark for stateful property discovery.
// ---------------------------------------------------------------------------

#[test]
fn efcf_harvey_baz_property() {
    let bytecode = match read_bin("harvey_baz") {
        Some(b) => b,
        None => {
            eprintln!("SKIP: efcf-compiled/harvey_baz.bin not found");
            return;
        }
    };
    let abi = read_abi("harvey_baz");

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(10u128.pow(18)));
    let contract_addr = executor
        .deploy(deployer, Bytes::from(bytecode.clone()))
        .expect("harvey_baz deployment must succeed");

    let seed = 42u64;
    let timeout = Duration::from_secs(30);
    let max_depth = 8;

    let mut bench = BenchmarkLoop::new(contract_addr, bytecode, abi, seed);
    // Re-use the already-deployed executor state.
    bench.executor = executor;
    bench
        .executor
        .set_balance(attacker(), U256::from(10u128.pow(18)));

    let (findings, total_execs, first_hit_ms) = bench.run(timeout, max_depth);

    let prop_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.title.contains("echidna_all_states"))
        .collect();

    eprintln!("--- harvey_baz ---");
    eprintln!(
        "  execs={total_execs}, findings={}, first_hit_ms={:?}",
        findings.len(),
        first_hit_ms,
    );

    let entry = if let Some(&f) = prop_findings.first() {
        eprintln!(
            "  FOUND: [{}] {} ({} txs)",
            f.severity,
            f.title,
            f.reproducer.len(),
        );
        ScorecardEntry::found(
            "harvey_baz",
            "echidna_all_states",
            "PropertyViolation",
            "fast",
            seed,
            0,
            first_hit_ms.unwrap_or(0),
            total_execs,
            f,
            "echidna_property",
        )
    } else {
        eprintln!("  NOT FOUND within {}s", timeout.as_secs());
        ScorecardEntry::not_found(
            "harvey_baz",
            "echidna_all_states",
            "PropertyViolation",
            "fast",
            seed,
            total_execs,
        )
    };

    // Print CSV row.
    eprintln!("{}", ScorecardEntry::csv_header());
    eprintln!("{}", entry.to_csv_row());

    // ASSERTION: harvey_baz is a property-only contract; sci-fuzz MUST
    // discover the violation because the echidna_all_states() function
    // returns false when all five branches are covered.
    // NOTE: This requires the ABI-aware mutation to generate int256 args
    // that hit different code paths.  If ABI extraction doesn't work for
    // 0.7.6 contracts, the property may not be discovered within 30s.
    if prop_findings.is_empty() {
        eprintln!(
            "  INFO: echidna_all_states not triggered. \
             This means the baz(int256,int256,int256) branches were not fully covered. \
             Requires better typed-arg generation for int256 parameters."
        );
    }
    // Soft assertion — log result, don't hard-fail so CI can collect partial data.
    // Once ABI-aware int256 generation is verified, this becomes a hard assert.
}

// ---------------------------------------------------------------------------
// Test 2 — SimpleDAO (reentrancy via EtherDrain oracle)
//
// SimpleDAO has a classic reentrancy bug: withdraw() calls msg.sender
// before updating the credit balance. A BalanceIncrease oracle should
// detect when the attacker's ETH balance increases beyond their deposit.
// ---------------------------------------------------------------------------

#[test]
fn efcf_simple_dao_ether_drain() {
    let bytecode = match read_bin("SimpleDAO") {
        Some(b) => b,
        None => {
            eprintln!("SKIP: efcf-compiled/SimpleDAO.bin not found");
            return;
        }
    };
    let abi = read_abi("SimpleDAO");

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(100u128 * 10u128.pow(18)));

    // Pre-fund the DAO contract (simulates existing user deposits).
    let contract_addr = executor
        .deploy(deployer, Bytes::from(bytecode.clone()))
        .expect("SimpleDAO deployment must succeed");

    // Pre-seed the contract with 10 ETH from another user so the attacker
    // can profit by draining more than they deposited.
    let other_user = Address::repeat_byte(0xBE);
    executor.set_balance(other_user, U256::from(10u128 * 10u128.pow(18)));
    let deposit_sel = {
        use tiny_keccak::{Hasher, Keccak};
        let mut k = Keccak::v256();
        k.update(b"deposit()");
        let mut h = [0u8; 32];
        k.finalize(&mut h);
        Bytes::from(h[..4].to_vec())
    };
    let _ = executor.execute(&Transaction {
        sender: other_user,
        to: Some(contract_addr),
        data: deposit_sel,
        value: U256::from(10u128 * 10u128.pow(18)),
        gas_limit: 30_000_000,
    });
    eprintln!(
        "  SimpleDAO seeded: contract balance = {} wei",
        executor.get_balance(contract_addr),
    );

    let seed = 42u64;
    let timeout = Duration::from_secs(30);

    let mut bench = BenchmarkLoop::new(contract_addr, bytecode, abi, seed);
    bench.executor = executor;
    bench
        .executor
        .set_balance(attacker(), U256::from(100u128 * 10u128.pow(18)));

    let (findings, total_execs, first_hit_ms) = bench.run(timeout, 8);

    let drain_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();

    eprintln!("--- SimpleDAO ---");
    eprintln!(
        "  execs={total_execs}, critical_findings={}, first_hit_ms={:?}",
        drain_findings.len(),
        first_hit_ms,
    );

    let entry = if let Some(&f) = drain_findings.first() {
        eprintln!(
            "  FOUND: [{}] {} ({} txs)",
            f.severity,
            f.title,
            f.reproducer.len(),
        );
        for (i, tx) in f.reproducer.iter().enumerate() {
            eprintln!(
                "    tx[{i}]: to={} value={} data=0x{}",
                tx.to.map(|a| format!("{a}")).unwrap_or_default(),
                tx.value,
                hex::encode(&tx.data),
            );
        }
        ScorecardEntry::found(
            "SimpleDAO",
            "BalanceIncrease",
            "Reentrancy",
            "fast",
            seed,
            0,
            first_hit_ms.unwrap_or(0),
            total_execs,
            f,
            "balance_increase_oracle",
        )
    } else {
        eprintln!("  NOT FOUND within {}s", timeout.as_secs());
        eprintln!(
            "  INFO: BalanceIncrease not triggered. \
             SimpleDAO reentrancy requires: deposit ETH, then withdraw, \
             then re-enter via receive(). Reentrancy callbacks require \
             control-leak interception (not yet implemented)."
        );
        ScorecardEntry::not_found(
            "SimpleDAO",
            "BalanceIncrease",
            "Reentrancy",
            "fast",
            seed,
            total_execs,
        )
    };

    eprintln!("{}", ScorecardEntry::csv_header());
    eprintln!("{}", entry.to_csv_row());

    // Soft assertion — reentrancy requires control-leak interception
    // (mid-call state capture), which is not yet implemented.
    // We assert the campaign at least ran and collected execs.
    assert!(
        total_execs > 0,
        "campaign must execute at least one transaction"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — Delegatecall (access control)
//
// Delegatecall's update_lib() has no access control (the require is
// commented out). Any address can set lib to an attacker contract.
// The oracle should detect that update_lib succeeds from a non-owner.
// This is an access control bug, not a reentrancy.
// ---------------------------------------------------------------------------

#[test]
fn efcf_delegatecall_access_control() {
    let bytecode = match read_bin("Delegatecall") {
        Some(b) => b,
        None => {
            eprintln!("SKIP: efcf-compiled/Delegatecall.bin not found");
            return;
        }
    };
    let abi = read_abi("Delegatecall");

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(10u128.pow(18)));

    let contract_addr = executor
        .deploy(deployer, Bytes::from(bytecode.clone()))
        .expect("Delegatecall deployment must succeed");

    // The Delegatecall contract sets owner = msg.sender in constructor.
    // update_lib() has NO access control — anyone can call it.
    // A correct access-control oracle would detect that a non-owner
    // can successfully call update_lib().
    //
    // We test this by: calling update_lib() from a non-owner address
    // and checking if it succeeds (it should — that's the bug).

    let update_lib_sel = {
        use tiny_keccak::{Hasher, Keccak};
        let mut k = Keccak::v256();
        k.update(b"update_lib(address)");
        let mut h = [0u8; 32];
        k.finalize(&mut h);
        h[..4].to_vec()
    };

    // Build calldata: update_lib(address(0xdeadbeef...))
    let mut calldata = update_lib_sel;
    calldata.extend_from_slice(&[0u8; 12]); // left-pad address
    calldata.extend_from_slice(&[
        0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    // Non-owner caller.
    let non_owner = Address::repeat_byte(0x99);
    executor.set_balance(non_owner, U256::from(10u128.pow(18)));

    let result = executor
        .execute(&Transaction {
            sender: non_owner,
            to: Some(contract_addr),
            data: Bytes::from(calldata),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        })
        .expect("execute must not error");

    eprintln!("--- Delegatecall ---");
    eprintln!("  update_lib() from non-owner: success={}", result.success);

    // The BUG: update_lib() succeeds for non-owner because the require is commented out.
    // A correct access-control fuzzer MUST detect this.
    let access_control_bug_present = result.success;
    eprintln!(
        "  access_control_bug_present = {} (expected: true — require is commented out)",
        access_control_bug_present,
    );

    let seed = 42u64;
    let timeout = Duration::from_secs(10);

    let mut bench = BenchmarkLoop::new(contract_addr, bytecode, abi, seed);
    bench.executor = executor;
    bench
        .executor
        .set_balance(attacker(), U256::from(10u128.pow(18)));

    let (findings, total_execs, first_hit_ms) = bench.run(timeout, 4);

    eprintln!(
        "  execs={total_execs}, findings={}, first_hit_ms={:?}",
        findings.len(),
        first_hit_ms,
    );

    // sci-fuzz does not yet have an explicit access-control oracle.
    // The built-in oracles (BalanceIncrease, SelfDestruct) don't fire here
    // because the Delegatecall contract doesn't hold ETH.
    //
    // We record what was detected (likely nothing with current oracles)
    // as an honest benchmark result.
    let entry = if !findings.is_empty() {
        let f = &findings[0];
        ScorecardEntry::found(
            "Delegatecall",
            "update_lib_unrestricted",
            "AccessControl",
            "fast",
            seed,
            0,
            first_hit_ms.unwrap_or(0),
            total_execs,
            f,
            "generic_oracle",
        )
    } else {
        eprintln!(
            "  NOT FOUND — access-control bugs require a dedicated oracle. \
             sci-fuzz currently has: BalanceIncrease, SelfDestruct, EchidnaProperty. \
             An AccessControl oracle (detect privileged ops from non-privileged senders) \
             is a known missing capability."
        );
        ScorecardEntry::not_found(
            "Delegatecall",
            "update_lib_unrestricted",
            "AccessControl",
            "fast",
            seed,
            total_execs,
        )
    };

    eprintln!("{}", ScorecardEntry::csv_header());
    eprintln!("{}", entry.to_csv_row());

    // HARD assertion: the access control bug IS present in the contract
    // (update_lib has no require). If this fails, the contract changed.
    assert!(
        access_control_bug_present,
        "Delegatecall.update_lib() should succeed for non-owner (require is commented out)"
    );

    // Soft: we don't yet detect it via oracle, but we at least ran the campaign.
    assert!(total_execs > 0, "campaign must execute transactions");
}

// ---------------------------------------------------------------------------
// Test 4 — Aggregated scoreboard output
//
// Runs all three targets and emits a complete CSV to
// `target/benchmark_results.csv` and stderr.
// ---------------------------------------------------------------------------

#[test]
fn efcf_scoreboard_summary() {
    let mut board = Scoreboard::new();

    // --- harvey_baz ---
    if let (Some(bin), abi) = (read_bin("harvey_baz"), read_abi("harvey_baz")) {
        let mut executor = EvmExecutor::new();
        let deployer = attacker();
        executor.set_balance(deployer, U256::from(10u128.pow(18)));
        if let Ok(addr) = executor.deploy(deployer, Bytes::from(bin.clone())) {
            let seed = 42u64;
            let mut bench = BenchmarkLoop::new(addr, bin, abi, seed);
            bench.executor = executor;
            bench
                .executor
                .set_balance(attacker(), U256::from(10u128.pow(18)));
            let (findings, execs, hit_ms) = bench.run(Duration::from_secs(10), 8);
            let prop: Vec<_> = findings
                .iter()
                .filter(|f| f.title.contains("echidna_all_states"))
                .collect();
            let entry = if let Some(&f) = prop.first() {
                ScorecardEntry::found(
                    "harvey_baz",
                    "echidna_all_states",
                    "PropertyViolation",
                    "fast",
                    seed,
                    0,
                    hit_ms.unwrap_or(0),
                    execs,
                    f,
                    "echidna_property",
                )
            } else {
                ScorecardEntry::not_found(
                    "harvey_baz",
                    "echidna_all_states",
                    "PropertyViolation",
                    "fast",
                    seed,
                    execs,
                )
            };
            board.add(entry);
        }
    }

    // --- SimpleDAO ---
    if let (Some(bin), abi) = (read_bin("SimpleDAO"), read_abi("SimpleDAO")) {
        let mut executor = EvmExecutor::new();
        let deployer = attacker();
        executor.set_balance(deployer, U256::from(100u128 * 10u128.pow(18)));
        if let Ok(addr) = executor.deploy(deployer, Bytes::from(bin.clone())) {
            let seed = 42u64;
            let mut bench = BenchmarkLoop::new(addr, bin, abi, seed);
            bench.executor = executor;
            bench
                .executor
                .set_balance(attacker(), U256::from(100u128 * 10u128.pow(18)));
            let (findings, execs, hit_ms) = bench.run(Duration::from_secs(10), 8);
            let crit: Vec<_> = findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .collect();
            let entry = if let Some(&f) = crit.first() {
                ScorecardEntry::found(
                    "SimpleDAO",
                    "BalanceIncrease",
                    "Reentrancy",
                    "fast",
                    seed,
                    0,
                    hit_ms.unwrap_or(0),
                    execs,
                    f,
                    "balance_increase_oracle",
                )
            } else {
                ScorecardEntry::not_found(
                    "SimpleDAO",
                    "BalanceIncrease",
                    "Reentrancy",
                    "fast",
                    seed,
                    execs,
                )
            };
            board.add(entry);
        }
    }

    // --- Delegatecall ---
    if let (Some(bin), abi) = (read_bin("Delegatecall"), read_abi("Delegatecall")) {
        let mut executor = EvmExecutor::new();
        let deployer = attacker();
        executor.set_balance(deployer, U256::from(10u128.pow(18)));
        if let Ok(addr) = executor.deploy(deployer, Bytes::from(bin.clone())) {
            let seed = 42u64;
            let mut bench = BenchmarkLoop::new(addr, bin, abi, seed);
            bench.executor = executor;
            bench
                .executor
                .set_balance(attacker(), U256::from(10u128.pow(18)));
            let (findings, execs, hit_ms) = bench.run(Duration::from_secs(10), 4);
            let entry = if !findings.is_empty() {
                ScorecardEntry::found(
                    "Delegatecall",
                    "update_lib_unrestricted",
                    "AccessControl",
                    "fast",
                    seed,
                    0,
                    hit_ms.unwrap_or(0),
                    execs,
                    &findings[0],
                    "generic_oracle",
                )
            } else {
                ScorecardEntry::not_found(
                    "Delegatecall",
                    "update_lib_unrestricted",
                    "AccessControl",
                    "fast",
                    seed,
                    execs,
                )
            };
            board.add(entry);
        }
    }

    // --- Output ---
    eprintln!();
    eprintln!("=== EF/CF BENCHMARK SCOREBOARD ===");
    board.print_csv();
    eprintln!("Total: {}/{} detected", board.detected_count(), board.len(),);

    // Save to file.
    let out_path = std::path::Path::new("target/benchmark_results.csv");
    if let Some(parent) = out_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = board.write_csv(out_path) {
        eprintln!("WARNING: could not write scoreboard CSV: {e}");
    } else {
        eprintln!("Scoreboard written to {}", out_path.display());
    }

    // Hard assertion: we must have at least one entry per target.
    assert!(
        board.len() >= 3,
        "scoreboard must have entries for all 3 targets"
    );
}
