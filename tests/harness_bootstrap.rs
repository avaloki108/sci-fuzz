//! Offline tests for Foundry harness discovery, `setUp()` execution, and
//! `echidna_*` behavior relative to setup state.

use std::path::Path;
use std::time::Duration;

use sci_fuzz::evm::EvmExecutor;
use sci_fuzz::harness;
use sci_fuzz::invariant::EchidnaPropertyCaller;
use sci_fuzz::project::{abi_has_echidna_property, abi_has_set_up, Project};
use sci_fuzz::types::{Address, CampaignConfig, ContractInfo, ExecutorMode, U256};

const FIXTURE_ROOT: &str = "tests/fixtures/harness_project";

fn load_fixture_bootstrap() -> sci_fuzz::FuzzBootstrap {
    let root = Path::new(FIXTURE_ROOT);
    let mut project = Project::load(root).expect("fixture project");
    project
        .load_artifacts_from_out()
        .expect("load fixture artifacts");
    project
        .prepare_fuzz_bootstrap()
        .expect("prepare_fuzz_bootstrap")
}

#[test]
fn abi_detects_setup_and_echidna() {
    let raw: serde_json::Value = serde_json::from_str(
        r#"[
        {"type":"function","name":"setUp","inputs":[],"outputs":[],"stateMutability":"nonpayable"},
        {"type":"function","name":"echidna_x","inputs":[],"outputs":[{"type":"bool"}],"stateMutability":"view"}
    ]"#,
    )
    .unwrap();
    assert!(abi_has_set_up(&raw));
    assert!(abi_has_echidna_property(&raw));

    let no_setup: serde_json::Value = serde_json::from_str(
        r#"[{"type":"function","name":"foo","inputs":[],"outputs":[],"stateMutability":"nonpayable"}]"#,
    )
    .unwrap();
    assert!(!abi_has_set_up(&no_setup));
}

#[test]
fn fixture_classifies_runtime_vs_harness() {
    let b = load_fixture_bootstrap();
    assert_eq!(b.runtime_targets.len(), 1);
    assert_eq!(b.runtime_targets[0].name.as_deref(), Some("RuntimeStub"));
    let sp = b.runtime_targets[0].source_path.as_deref();
    assert!(
        sp.unwrap().contains("src/"),
        "runtime should be under src/: {sp:?}"
    );

    let h = b.harness.as_ref().expect("harness");
    assert_eq!(h.name.as_deref(), Some("HarnessWithSetup"));
    assert!(h.source_path.as_deref().unwrap().contains("test/"));
    assert!(abi_has_set_up(h.abi.as_ref().unwrap()));
    assert!(abi_has_echidna_property(h.abi.as_ref().unwrap()));
}

#[test]
fn setup_changes_echidna_outcome() {
    let b = load_fixture_bootstrap();
    let harness = b.harness.expect("harness");

    let attacker = Address::repeat_byte(0x42);
    let mut executor = EvmExecutor::new();
    executor.set_balance(attacker, U256::from(10u128.pow(18)));

    let init_code = harness
        .creation_bytecode
        .clone()
        .expect("creation bytecode");
    let deployed = executor
        .deploy(attacker, init_code)
        .expect("deploy harness");

    let abi = harness.abi.expect("abi");
    let caller = EchidnaPropertyCaller::from_abi(deployed, &abi).expect("echidna_*");

    let violations_before = caller.check_properties(&executor, attacker, &[]);
    assert!(
        !violations_before.is_empty(),
        "echidna_initialized should fail before setUp"
    );

    harness::run_setup(&mut executor, attacker, deployed).expect("setUp");

    let violations_after = caller.check_properties(&executor, attacker, &[]);
    assert!(
        violations_after.is_empty(),
        "echidna_initialized should hold after setUp: {:?}",
        violations_after
    );
}

#[test]
fn campaign_runs_harness_setup_before_fuzzing() {
    let b = load_fixture_bootstrap();
    let config = CampaignConfig {
        timeout: Duration::from_millis(500),
        max_execs: Some(80),
        max_depth: 4,
        max_snapshots: 32,
        workers: 1,
        seed: 999,
        targets: b.runtime_targets,
        harness: b.harness,
        mode: ExecutorMode::Fast,
        rpc_url: None,
        rpc_block_number: None,
    };

    let mut campaign = sci_fuzz::campaign::Campaign::new(config);
    let findings = campaign.run().expect("campaign completes");
    let bad: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("echidna_initialized"))
        .collect();
    assert!(
        bad.is_empty(),
        "property should hold after setUp; unexpected: {bad:?}"
    );
}

#[test]
fn mutator_does_not_include_set_up_selector() {
    use sci_fuzz::mutator::TxMutator;
    use sci_fuzz::types::contract_info_for_mutator;

    let b = load_fixture_bootstrap();
    let h = b.harness.expect("harness");
    let addr = Address::repeat_byte(0x99);
    let c = ContractInfo {
        address: addr,
        deployed_bytecode: h.deployed_bytecode.clone(),
        creation_bytecode: h.creation_bytecode.clone(),
        name: h.name.clone(),
        source_path: h.source_path.clone(),
        abi: h.abi.clone(),
    };
    let stripped = contract_info_for_mutator(&c, &["setUp", "beforeTest", "afterTest"]);
    let m = TxMutator::new(vec![stripped]);
    let sel = harness::setup_selector();
    assert!(
        !m.has_abi_selector(sel),
        "setUp selector should not be fuzzed"
    );
}
