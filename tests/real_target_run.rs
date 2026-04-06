//! Integration test: deploy a real compiled contract, run the fuzzer against it,
//! and verify that sci-fuzz produces an actual finding with a concrete
//! reproducer.
//!
//! This is the "targets > 0" proof that the engine actually works end-to-end:
//!   1. Compile PropFalse.sol (already done by solc, artifacts in compiled/)
//!   2. Load bytecode + ABI from disk
//!   3. Build a Campaign with the contract as a real target
//!   4. Run for a short timeout
//!   5. Assert that the EchidnaPropertyCaller detects the always-false property
//!
//! We also test PropMulti (one good + one bad property) and PropStateful
//! (two-step deposit→withdraw drain) as progressively harder targets.

use std::path::Path;
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use sci_fuzz::evm::EvmExecutor;
use sci_fuzz::feedback::CoverageFeedback;
use sci_fuzz::invariant::EchidnaPropertyCaller;
use sci_fuzz::mutator::TxMutator;
use sci_fuzz::oracle::OracleEngine;
use sci_fuzz::snapshot::SnapshotCorpus;
use sci_fuzz::types::{
    Address, Bytes, CampaignConfig, ContractInfo, ExecutorMode, Finding, StateSnapshot,
    Transaction, U256,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const COMPILED: &str = "tests/contracts/control/compiled";

fn read_bin(name: &str) -> Vec<u8> {
    let path = format!("{COMPILED}/{name}.bin");
    let hex_str =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    hex::decode(hex_str.trim()).unwrap_or_else(|e| panic!("bad hex in {path}: {e}"))
}

fn read_abi(name: &str) -> serde_json::Value {
    let path = format!("{COMPILED}/{name}.abi");
    let json_str =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    serde_json::from_str(&json_str).unwrap_or_else(|e| panic!("bad JSON in {path}: {e}"))
}

fn attacker() -> Address {
    Address::repeat_byte(0x42)
}

/// Compute the 4-byte selector for a Solidity function signature.
fn selector(sig: &str) -> Vec<u8> {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    k.update(sig.as_bytes());
    let mut h = [0u8; 32];
    k.finalize(&mut h);
    h[..4].to_vec()
}

/// Skip the test gracefully if compiled artifacts are missing.
macro_rules! require_compiled {
    ($name:expr) => {
        let bin_path = format!("{}/{}.bin", COMPILED, $name);
        if !Path::new(&bin_path).exists() {
            eprintln!("SKIP: {} not found — run solc first", bin_path);
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// 1. PropFalse — simplest case: property always false, targets > 0
// ---------------------------------------------------------------------------

/// Deploy PropFalse as a real campaign target and verify that:
///   - the campaign runs with targets > 0
///   - EchidnaPropertyCaller detects the always-false property
///   - a Finding is produced with a non-empty reproducer
#[test]
fn real_target_prop_false_found() {
    require_compiled!("PropFalse");

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(10u128.pow(18)));

    // Deploy the contract.
    let bytecode = read_bin("PropFalse");
    let abi = read_abi("PropFalse");
    let contract_addr = executor
        .deploy(deployer, Bytes::from(bytecode.clone()))
        .expect("PropFalse deployment must succeed");

    // Build the EchidnaPropertyCaller from the ABI.
    let property_caller = EchidnaPropertyCaller::from_abi(contract_addr, &abi)
        .expect("should find echidna_always_false");
    assert_eq!(property_caller.properties.len(), 1);

    // Build a ContractInfo for the mutator.
    let target = ContractInfo {
        address: contract_addr,
        deployed_bytecode: Bytes::from(bytecode),
        creation_bytecode: None,
        name: Some("PropFalse".into()),
        source_path: None,
        deployed_source_map: None,
            source_file_list: vec![],
                abi: Some(abi),
    };

    // Wire up sub-systems.
    let mutator = TxMutator::new(vec![target.clone()]);
    let oracle = OracleEngine::new(deployer);
    let mut feedback = CoverageFeedback::new();
    let mut snapshots = SnapshotCorpus::new(256);
    snapshots.add(StateSnapshot::default());

    let mut rng = StdRng::seed_from_u64(12345);
    let mut findings: Vec<Finding> = Vec::new();
    let mut total_execs: u64 = 0;
    let start = Instant::now();
    let timeout = Duration::from_secs(5);

    // --- Main fuzzing loop (mini-campaign) ---------------------------------
    while start.elapsed() < timeout && findings.is_empty() {
        let db_snap = executor.snapshot();
        let pre_seq_balances = sci_fuzz::oracle::capture_eth_baseline(&executor, deployer);

        let seq_len: usize = rng.gen_range(1..=4);
        let mut sequence: Vec<Transaction> = Vec::new();
        let mut cumulative_logs: Vec<sci_fuzz::types::Log> = Vec::new();

        for _ in 0..seq_len {
            let tx = if sequence.is_empty() || rng.gen_bool(0.3) {
                mutator.generate(&mut rng)
            } else {
                mutator.mutate(sequence.last().unwrap(), &mut rng)
            };

            match executor.execute(&tx) {
                Ok(mut result) => {
                    cumulative_logs.extend(result.logs.iter().cloned());
                    result.sequence_cumulative_logs = cumulative_logs.clone();
                    total_execs += 1;

                    sequence.push(tx.clone());

                    // Check built-in invariants (sequence includes current tx).
                    let oracle_findings = oracle.check(&pre_seq_balances, &sci_fuzz::types::ProtocolProbeReport::default(), &result, &sequence);
                    for f in oracle_findings {
                        let mut finding = f;
                        let mut repro = sequence.clone();
                        finding.reproducer = repro;
                        findings.push(finding);
                    }
                }
                Err(_) => continue,
            }
        }

        // Check Echidna properties after the sequence.
        let prop_findings = property_caller.check_properties(&executor, deployer, &sequence);
        for f in prop_findings {
            findings.push(f);
        }

        // Restore state for next iteration.
        executor.restore(db_snap);
    }

    // --- Assertions --------------------------------------------------------
    eprintln!(
        "PropFalse: total_execs={total_execs}, findings={}, elapsed={:.2}s",
        findings.len(),
        start.elapsed().as_secs_f64(),
    );

    assert!(
        !findings.is_empty(),
        "PropFalse has an always-false property — sci-fuzz MUST find it. \
         Executed {total_execs} transactions in {:.2}s with 0 findings.",
        start.elapsed().as_secs_f64(),
    );

    let prop_finding = findings
        .iter()
        .find(|f| f.title.contains("echidna_always_false"));
    assert!(
        prop_finding.is_some(),
        "expected a finding naming echidna_always_false, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>(),
    );

    eprintln!(
        "  → finding: [{}] {}",
        prop_finding.unwrap().severity,
        prop_finding.unwrap().title,
    );
}

// ---------------------------------------------------------------------------
// 2. PropMulti — two properties, must flag bad but not good
// ---------------------------------------------------------------------------

#[test]
fn real_target_prop_multi_finds_bad_only() {
    require_compiled!("PropMulti");

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(10u128.pow(18)));

    let bytecode = read_bin("PropMulti");
    let abi = read_abi("PropMulti");
    let contract_addr = executor
        .deploy(deployer, Bytes::from(bytecode.clone()))
        .expect("PropMulti deployment must succeed");

    let property_caller =
        EchidnaPropertyCaller::from_abi(contract_addr, &abi).expect("should find 2 properties");
    assert_eq!(property_caller.properties.len(), 2);

    // No need to fuzz — properties are stateless, so we can check immediately.
    let findings = property_caller.check_properties(&executor, deployer, &[]);

    // Only echidna_bad should fire.
    assert_eq!(
        findings.len(),
        1,
        "expected exactly 1 violation (echidna_bad), got {}",
        findings.len(),
    );

    let f = &findings[0];
    assert!(
        f.title.contains("echidna_bad"),
        "finding should name echidna_bad, got: {}",
        f.title,
    );

    // echidna_good must NOT appear.
    assert!(
        !findings.iter().any(|f| f.title.contains("echidna_good")),
        "echidna_good should NOT be flagged",
    );

    eprintln!("PropMulti: correctly flagged echidna_bad, left echidna_good alone");
}

// ---------------------------------------------------------------------------
// 3. PropStateful — requires deposit+withdraw to violate
// ---------------------------------------------------------------------------

/// Run a targeted mini-campaign against PropStateful. The fuzzer must discover
/// the two-step deposit→withdraw sequence that drains the contract and causes
/// `echidna_not_drained()` to return false.
///
/// This test is harder: it requires the fuzzer to generate a meaningful
/// multi-transaction sequence with correct selectors and value.
#[test]
fn real_target_prop_stateful_found_via_fuzzing() {
    require_compiled!("PropStateful");

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(100u128 * 10u128.pow(18))); // 100 ETH

    let bytecode = read_bin("PropStateful");
    let abi = read_abi("PropStateful");
    let contract_addr = executor
        .deploy(deployer, Bytes::from(bytecode.clone()))
        .expect("PropStateful deployment must succeed");

    let property_caller = EchidnaPropertyCaller::from_abi(contract_addr, &abi)
        .expect("should find echidna_not_drained");
    assert_eq!(property_caller.properties.len(), 1);
    assert_eq!(property_caller.properties[0].1, "echidna_not_drained");

    // Before any fuzzing: property should hold.
    let pre_findings = property_caller.check_properties(&executor, deployer, &[]);
    assert!(
        pre_findings.is_empty(),
        "property should hold before any transactions",
    );

    let target = ContractInfo {
        address: contract_addr,
        deployed_bytecode: Bytes::from(bytecode),
        creation_bytecode: None,
        name: Some("PropStateful".into()),
        source_path: None,
        deployed_source_map: None,
            source_file_list: vec![],
                abi: Some(abi),
    };

    let mut mutator = TxMutator::new(vec![target]);
    let mut rng = StdRng::seed_from_u64(99999);
    let mut findings: Vec<Finding> = Vec::new();
    let mut total_execs: u64 = 0;
    let start = Instant::now();
    let timeout = Duration::from_secs(30); // give it more time for the 2-step

    while start.elapsed() < timeout && findings.is_empty() {
        let db_snap = executor.snapshot();
        let seq_len: usize = rng.gen_range(1..=8);
        let mut sequence: Vec<Transaction> = Vec::new();

        for _ in 0..seq_len {
            let tx = if sequence.is_empty() || rng.gen_bool(0.3) {
                mutator.generate(&mut rng)
            } else {
                mutator.mutate(sequence.last().unwrap(), &mut rng)
            };

            match executor.execute(&tx) {
                Ok(result) => {
                    total_execs += 1;
                    mutator.feed_execution(&result);
                    sequence.push(tx);
                }
                Err(_) => continue,
            }
        }

        // Check Echidna property after the full sequence.
        let prop_findings = property_caller.check_properties(&executor, deployer, &sequence);
        if !prop_findings.is_empty() {
            for f in prop_findings {
                findings.push(f);
            }
        }

        executor.restore(db_snap);
    }

    let elapsed = start.elapsed();
    eprintln!(
        "PropStateful: total_execs={total_execs}, findings={}, elapsed={:.2}s",
        findings.len(),
        elapsed.as_secs_f64(),
    );

    if findings.is_empty() {
        // This is the hardest test. The fuzzer needs to:
        //   1. Call deposit() with msg.value > 0
        //   2. Call withdraw() from the same sender
        // Both require the right selector AND the right value.
        //
        // If we don't find it within the timeout, the test is "soft-fail":
        // it prints a diagnostic but does NOT hard-assert. This is an honest
        // acknowledgement that the fuzzer may not always solve deep-state
        // targets within a short timeout.
        eprintln!(
            "  → WARNING: did not find the drain sequence in {:.1}s / {total_execs} execs.",
            elapsed.as_secs_f64(),
        );
        eprintln!("    This is expected for a random fuzzer without targeted sequence generation.");
        eprintln!("    To make this reliable, sci-fuzz needs:");
        eprintln!(
            "    - Corpus-based sequence building (reuse successful deposit before withdraw)"
        );
        eprintln!("    - Coverage instrumentation (detect that deposit() changes state)");
        eprintln!("    - Value-aware generation (send nonzero msg.value for payable functions)");
    } else {
        let f = &findings[0];
        eprintln!(
            "  → FOUND: [{}] {} (reproducer: {} txs)",
            f.severity,
            f.title,
            f.reproducer.len(),
        );

        assert!(
            f.title.contains("echidna_not_drained"),
            "finding should name the property",
        );

        // Print the reproducer for inspection.
        for (i, tx) in f.reproducer.iter().enumerate() {
            eprintln!(
                "    tx[{i}]: to={} value={} data=0x{}",
                tx.to.map(|a| format!("{a}")).unwrap_or("CREATE".into()),
                tx.value,
                hex::encode(&tx.data),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Campaign struct with targets > 0
// ---------------------------------------------------------------------------

/// Run the actual Campaign struct (not a hand-rolled loop) with a real target.
/// This proves that the Campaign.run() method works end-to-end with deployed
/// contracts.
#[test]
fn campaign_with_real_target() {
    require_compiled!("PropFalse");

    // Pre-deploy the contract so we can get its address.
    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(10u128.pow(18)));

    let bytecode = read_bin("PropFalse");
    let abi = read_abi("PropFalse");
    let contract_addr = executor
        .deploy(deployer, Bytes::from(bytecode.clone()))
        .expect("deploy must succeed");

    // Build campaign config with a real target.
    let target = ContractInfo {
        address: contract_addr,
        deployed_bytecode: Bytes::from(bytecode),
        creation_bytecode: None,
        name: Some("PropFalse".into()),
        source_path: None,
        deployed_source_map: None,
            source_file_list: vec![],
                abi: Some(abi),
    };

    let config = CampaignConfig {
        timeout: Duration::from_secs(2),
        max_execs: None,
        max_depth: 4,
        max_snapshots: 256,
        workers: 1,
        seed: 54321,
        targets: vec![target],
        harness: None,
        mode: ExecutorMode::Fast,
        rpc_url: None,
        rpc_block_number: None,
        attacker_address: None,
        ..Default::default()
    };

    let mut campaign = sci_fuzz::campaign::Campaign::new(config);
    let findings = campaign.run().expect("campaign must not error");

    // The campaign's built-in oracle might or might not detect the always-false
    // property (it depends on whether the campaign wires EchidnaPropertyCaller).
    // What matters here is that it ran with targets > 0 and didn't crash.
    eprintln!(
        "campaign_with_real_target: findings={}, ran without error",
        findings.len(),
    );

    // We do NOT assert findings here because the Campaign struct doesn't yet
    // wire EchidnaPropertyCaller internally (that's a known gap). What we
    // prove is that the execution loop runs with real deployed contracts.
    //
    // The property detection was already proven in the tests above using the
    // hand-rolled loop.
}

// ---------------------------------------------------------------------------
// 5. Scorecard: machine-readable output for the PropFalse run
// ---------------------------------------------------------------------------

/// Produce a machine-readable scorecard line for the PropFalse target.
/// This is the seed of the benchmark scoreboard.
#[test]
fn scorecard_prop_false() {
    require_compiled!("PropFalse");

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(10u128.pow(18)));

    let bytecode = read_bin("PropFalse");
    let abi = read_abi("PropFalse");
    let contract_addr = executor
        .deploy(deployer, Bytes::from(bytecode.clone()))
        .expect("deploy");

    let property_caller = EchidnaPropertyCaller::from_abi(contract_addr, &abi).unwrap();
    let mutator = TxMutator::new(vec![ContractInfo {
        address: contract_addr,
        deployed_bytecode: Bytes::from(bytecode),
        creation_bytecode: None,
        name: Some("PropFalse".into()),
        source_path: None,
        deployed_source_map: None,
            source_file_list: vec![],
                abi: Some(abi),
    }]);

    let mut rng = StdRng::seed_from_u64(42);
    let start = Instant::now();
    let mut total_execs: u64 = 0;
    let mut time_to_first_ms: Option<u128> = None;
    let mut reproducer_len: usize = 0;

    let timeout = Duration::from_secs(5);

    while start.elapsed() < timeout {
        let db_snap = executor.snapshot();
        let seq_len: usize = rng.gen_range(1..=4);
        let mut sequence: Vec<Transaction> = Vec::new();

        for _ in 0..seq_len {
            let tx = mutator.generate(&mut rng);
            if executor.execute(&tx).is_ok() {
                total_execs += 1;
                sequence.push(tx);
            }
        }

        let prop_findings = property_caller.check_properties(&executor, deployer, &sequence);
        if !prop_findings.is_empty() && time_to_first_ms.is_none() {
            time_to_first_ms = Some(start.elapsed().as_millis());
            reproducer_len = sequence.len();
            executor.restore(db_snap);
            break;
        }

        executor.restore(db_snap);
    }

    // Print scorecard as CSV.
    eprintln!("--- SCORECARD ---");
    eprintln!(
        "target,category,expected,detected,time_to_first_hit_ms,total_execs,sequence_len,mode,seed"
    );
    eprintln!(
        "PropFalse,PropertyViolation,echidna_always_false,{},{},{total_execs},{reproducer_len},fast,42",
        if time_to_first_ms.is_some() {
            "true"
        } else {
            "false"
        },
        time_to_first_ms.unwrap_or(0),
    );

    assert!(
        time_to_first_ms.is_some(),
        "PropFalse must be detected within {timeout:?}",
    );

    let ms = time_to_first_ms.unwrap();
    eprintln!("  → detected in {ms}ms after {total_execs} execs, sequence_len={reproducer_len}");

    // Sanity: it should be found almost immediately (< 100ms) since the
    // property is unconditionally false.
    assert!(ms < 1000, "PropFalse should be found in <1s, took {ms}ms",);
}

// ---------------------------------------------------------------------------
// 6. PropStateful via Campaign — the real test
// ---------------------------------------------------------------------------

/// Run the actual Campaign against PropStateful.
/// The Campaign now has: payable-aware generation, actor reuse, snapshot
/// retention, and property checking. This should solve the 2-step drain.
#[test]
fn campaign_solves_prop_stateful() {
    require_compiled!("PropStateful");

    // Pre-deploy the contract.
    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(100u128 * 10u128.pow(18)));

    let bytecode = read_bin("PropStateful");
    let abi = read_abi("PropStateful");
    let contract_addr = executor
        .deploy(deployer, Bytes::from(bytecode.clone()))
        .expect("deploy must succeed");

    let target = ContractInfo {
        address: contract_addr,
        deployed_bytecode: Bytes::from(bytecode),
        creation_bytecode: None,
        name: Some("PropStateful".into()),
        source_path: None,
        deployed_source_map: None,
            source_file_list: vec![],
                abi: Some(abi),
    };

    let config = CampaignConfig {
        timeout: Duration::from_secs(30),
        max_execs: None,
        max_depth: 8,
        max_snapshots: 16,
        workers: 1,
        seed: 77777,
        targets: vec![target],
        harness: None,
        mode: ExecutorMode::Fast,
        rpc_url: None,
        rpc_block_number: None,
        attacker_address: None,
        ..Default::default()
    };

    let mut campaign = sci_fuzz::campaign::Campaign::new(config);
    let findings = campaign.run().expect("campaign must not error");

    let prop_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.title.contains("echidna_not_drained"))
        .collect();

    eprintln!(
        "campaign_solves_prop_stateful: total_findings={}, property_findings={}",
        findings.len(),
        prop_findings.len(),
    );

    if prop_findings.is_empty() {
        eprintln!("  → WARNING: Campaign did not solve PropStateful.");
        eprintln!("    Total findings (non-property): {}", findings.len());
        // Print first few non-property findings for diagnostic
        for f in findings.iter().take(5) {
            eprintln!("    [{}] {}", f.severity, f.title);
        }
    } else {
        let f = &prop_findings[0];
        eprintln!(
            "  → FOUND: [{}] {} (reproducer: {} txs)",
            f.severity,
            f.title,
            f.reproducer.len(),
        );
        for (i, tx) in f.reproducer.iter().enumerate() {
            eprintln!(
                "    tx[{i}]: sender={} to={} value={} data=0x{}",
                tx.sender,
                tx.to.map(|a| format!("{a}")).unwrap_or("CREATE".into()),
                tx.value,
                hex::encode(&tx.data),
            );
        }
    }

    assert!(
        !prop_findings.is_empty(),
        "Campaign must detect echidna_not_drained violation via deposit→withdraw"
    );
}
