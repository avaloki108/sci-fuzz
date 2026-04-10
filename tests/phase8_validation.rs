//! Phase 8 validation: LibAFL campaign vs baseline on EF/CF benchmark.

use std::path::Path;
use std::time::Instant;

use chimera_fuzz::{
    evm::EvmExecutor,
    libafl_adapter::campaign::LibAflCampaign,
    types::{Address, Bytes, ContractInfo, TestMode, U256},
};

const COMPILED: &str = "tests/contracts/efcf-compiled";
const ATTACKER: Address = Address::repeat_byte(0x42);
const SEED: u64 = 42;
const MAX_ITERS: u64 = 500;

fn read_bin(name: &str) -> Option<Vec<u8>> {
    let path = format!("{COMPILED}/{name}.bin");
    if !Path::new(&path).exists() { return None; }
    hex::decode(std::fs::read_to_string(&path).ok()?.trim()).ok()
}

fn read_abi(name: &str) -> Option<serde_json::Value> {
    let path = format!("{COMPILED}/{name}.abi");
    if !Path::new(&path).exists() { return None; }
    serde_json::from_str(&std::fs::read_to_string(&path).ok()?).ok()
}

fn deploy(evm: &mut EvmExecutor, bytecode: Vec<u8>, deployer: Address) -> Option<Address> {
    evm.deploy(deployer, Bytes::from(bytecode)).ok()
}

fn make_target(evm: &EvmExecutor, addr: Address, name: &str, abi: Option<serde_json::Value>) -> ContractInfo {
    let code = evm.get_code(addr).map(|b| b.to_vec()).unwrap_or_default();
    ContractInfo {
        address: addr,
        deployed_bytecode: code.into(),
        creation_bytecode: None,
        name: Some(name.to_string()),
        source_path: None,
        deployed_source_map: None,
        source_file_list: vec![],
        abi,
        link_references: Default::default(),
    }
}

/// Simple single-contract campaign.
fn make_campaign(name: &str, max_iters: u64) -> Option<LibAflCampaign> {
    let bytecode = read_bin(name)?;
    let abi = read_abi(name);
    let mut evm = EvmExecutor::new();
    evm.set_balance(ATTACKER, U256::from(100_000_000_000_000_000_000_u128));
    let addr = deploy(&mut evm, bytecode, Address::repeat_byte(0xde))?;
    let target = make_target(&evm, addr, name, abi);
    LibAflCampaign::builder()
        .evm(evm).targets(vec![target])
        .attacker(ATTACKER).seed(SEED).max_iters(max_iters)
        .build().ok()
}

/// SimpleDAO + attacker contract both deployed — proper reentrancy setup.
fn make_simpledao_campaign(max_iters: u64) -> Option<LibAflCampaign> {
    let dao_bin = read_bin("SimpleDAO")?;
    let dao_abi = read_abi("SimpleDAO");
    let atk_bin = read_bin("SimpleDAOAttacker")?;
    let atk_abi = read_abi("SimpleDAOAttacker");

    let mut evm = EvmExecutor::new();
    evm.set_balance(ATTACKER, U256::from(100_000_000_000_000_000_000_u128));

    let dao_addr = deploy(&mut evm, dao_bin, Address::repeat_byte(0xd0))?;
    evm.set_balance(dao_addr, U256::from(10_000_000_000_000_000_000_u128));

    let mut atk_init = atk_bin;
    let mut arg = [0u8; 32];
    arg[12..].copy_from_slice(dao_addr.as_slice());
    atk_init.extend_from_slice(&arg);
    let atk_addr = deploy(&mut evm, atk_init, Address::repeat_byte(0xa0))?;
    evm.set_balance(atk_addr, U256::from(5_000_000_000_000_000_000_u128));

    let dao_target = make_target(&evm, dao_addr, "SimpleDAO", dao_abi);
    let atk_target = make_target(&evm, atk_addr, "SimpleDAOAttacker", atk_abi);

    LibAflCampaign::builder()
        .evm(evm)
        .targets(vec![dao_target, atk_target])
        .attacker(ATTACKER)
        .seed(SEED).max_iters(max_iters)
        .build().ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn phase8_simpledao_with_attacker() {
    let campaign = match make_simpledao_campaign(MAX_ITERS) {
        Some(c) => c,
        None => { eprintln!("SKIP: SimpleDAO/Attacker not compiled"); return; }
    };
    let t0 = Instant::now();
    let result = campaign.run().expect("campaign failed");
    eprintln!(
        "\n[Phase 8] SimpleDAO+Attacker: {} execs, {} corpus, {} findings, {}ms",
        result.executions, result.corpus_size, result.findings.len(), t0.elapsed().as_millis()
    );
    assert!(result.executions > 0);
}

#[test]
fn phase8_harvey_baz() {
    let name = "harvey_baz";
    let bytecode = match read_bin(name) {
        Some(b) => b,
        None => { eprintln!("SKIP"); return; }
    };
    let abi = read_abi(name);
    let mut evm = EvmExecutor::new();
    evm.set_balance(ATTACKER, U256::from(100_000_000_000_000_000_000_u128));
    let addr = deploy(&mut evm, bytecode, Address::repeat_byte(0xde)).unwrap();
    let target = make_target(&evm, addr, name, abi);
    let campaign = LibAflCampaign::builder()
        .evm(evm).targets(vec![target])
        .attacker(ATTACKER).seed(SEED).max_iters(MAX_ITERS)
        .test_mode(TestMode::Assertion)  // Echidna property mode for echidna_all_states
        .build().expect("build");
    let result = campaign.run().expect("campaign failed");
    eprintln!(
        "\n[Phase 8] harvey_baz (Assertion mode): {} execs, {} corpus, {} findings",
        result.executions, result.corpus_size, result.findings.len()
    );
    assert!(result.executions > 0);
}

#[test]
fn phase8_delegatecall() {
    let name = "Delegatecall";
    let bytecode = match read_bin(name) {
        Some(b) => b,
        None => { eprintln!("SKIP"); return; }
    };
    let abi = read_abi(name);
    let deployer = Address::repeat_byte(0xde);
    let mut evm = EvmExecutor::new();
    evm.set_balance(ATTACKER, U256::from(100_000_000_000_000_000_000_u128));
    let addr = deploy(&mut evm, bytecode, deployer).unwrap();
    let target = make_target(&evm, addr, name, abi);
    let campaign = LibAflCampaign::builder()
        .evm(evm).targets(vec![target])
        .attacker(ATTACKER).deployer(deployer)  // deployer != attacker for AC oracle
        .seed(SEED).max_iters(MAX_ITERS)
        .build().expect("build");
    let result = campaign.run().expect("campaign failed");
    eprintln!(
        "\n[Phase 8] Delegatecall (access-control): {} execs, {} corpus, {} findings",
        result.executions, result.corpus_size, result.findings.len()
    );
    assert!(result.executions > 0);
}

#[test]
fn phase8_summary() {
    let targets: &[(&str, bool)] = &[
        ("SimpleDAO+Attacker", true),
        ("harvey_baz",         false),
        ("Delegatecall",       false),
    ];

    let mut rows: Vec<(&str, u64, usize, usize)> = vec![];

    for (name, use_dao) in targets {
        let campaign = if *use_dao {
            make_simpledao_campaign(MAX_ITERS)
        } else if *name == "harvey_baz" {
            // Assertion mode for echidna property
            let bytecode = match read_bin(name) {
                Some(b) => b,
                None => continue,
            };
            let abi = read_abi(name);
            let mut evm = EvmExecutor::new();
            evm.set_balance(ATTACKER, U256::from(100_000_000_000_000_000_000_u128));
            let addr = match deploy(&mut evm, bytecode, Address::repeat_byte(0xde)) {
                Some(a) => a,
                None => continue,
            };
            let target = make_target(&evm, addr, name, abi);
            LibAflCampaign::builder()
                .evm(evm).targets(vec![target])
                .attacker(ATTACKER).seed(SEED).max_iters(MAX_ITERS)
                .test_mode(TestMode::Assertion)
                .build().ok()
        } else if *name == "Delegatecall" {
            // Access control mode — deployer != attacker
            let bytecode = match read_bin(name) {
                Some(b) => b,
                None => continue,
            };
            let abi = read_abi(name);
            let deployer = Address::repeat_byte(0xde);
            let mut evm = EvmExecutor::new();
            evm.set_balance(ATTACKER, U256::from(100_000_000_000_000_000_000_u128));
            let addr = match deploy(&mut evm, bytecode, deployer) {
                Some(a) => a,
                None => continue,
            };
            let target = make_target(&evm, addr, name, abi);
            LibAflCampaign::builder()
                .evm(evm).targets(vec![target])
                .attacker(ATTACKER).deployer(deployer)
                .seed(SEED).max_iters(MAX_ITERS)
                .build().ok()
        } else {
            make_campaign(name, MAX_ITERS)
        };
        match campaign {
            None => { rows.push((name, 0, 0, 0)); }
            Some(c) => match c.run() {
                Ok(r) => rows.push((name, r.executions, r.corpus_size, r.findings.len())),
                Err(e) => { eprintln!("WARN {name}: {e}"); rows.push((name, 0, 0, 0)); }
            }
        }
    }

    eprintln!("\n╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║          Phase 8 Validation — LibAFL vs Baseline            ║");
    eprintln!("╠══════════════════════╦══════════╦══════════╦════════╦═══════╣");
    eprintln!("║ Target               ║ Baseline ║  Execs   ║ Corpus ║ Finds ║");
    eprintln!("╠══════════════════════╬══════════╬══════════╬════════╬═══════╣");
    for (name, execs, corpus, finds) in &rows {
        eprintln!("║ {:20} ║ 0 found  ║ {:8} ║ {:6} ║ {:5} ║", name, execs, corpus, finds);
    }
    eprintln!("╚══════════════════════╩══════════╩══════════╩════════╩═══════╝");

    let total_finds: usize = rows.iter().map(|(_, _, _, f)| f).sum();
    let total_execs: u64   = rows.iter().map(|(_, e, _, _)| e).sum();
    let improved = rows.iter().filter(|(_, _, _, f)| *f > 0).count();
    eprintln!("\nOLD:  0/{} found anything", targets.len());
    eprintln!("NEW:  {}/{} found ({} total findings, {} execs)", improved, targets.len(), total_finds, total_execs);

    assert!(total_execs > 0);
}
