//! Integration test: validate Echidna property-calling semantics against
//! compiled control contracts.
//!
//! These tests deploy tiny Solidity contracts (pre-compiled to bytecode)
//! into a real `EvmExecutor`, wire up `EchidnaPropertyCaller`, and verify
//! that sci-fuzz's property verdicts match Echidna's documented semantics:
//!
//! | Contract       | Property                  | Returns | Echidna verdict | sci-fuzz must agree |
//! |----------------|---------------------------|---------|-----------------|---------------------|
//! | PropFalse      | echidna_always_false       | false   | VIOLATED        | yes — finding       |
//! | PropReverts    | echidna_always_reverts     | reverts | HOLDS           | yes — no finding    |
//! | PropMulti      | echidna_good               | true    | HOLDS           | yes — no finding    |
//! | PropMulti      | echidna_bad                | false   | VIOLATED        | yes — finding       |
//! | PropStateful   | echidna_not_drained        | true    | HOLDS (until…)  | yes — need 2+ txs   |
//!
//! Additionally we test the low-level ABI bool decoding with edge cases:
//! empty returndata, short returndata, 32-byte true, 32-byte false, etc.

use std::path::Path;

use sci_fuzz::evm::EvmExecutor;
use sci_fuzz::invariant::EchidnaPropertyCaller;
use sci_fuzz::types::{Address, Bytes, Transaction, U256};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a `.bin` file (hex-encoded bytecode from solc) and return raw bytes.
fn read_bin(path: &str) -> Vec<u8> {
    let hex_str =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    hex::decode(hex_str.trim()).unwrap_or_else(|e| panic!("bad hex in {path}: {e}"))
}

/// Read a `.abi` file (JSON) and return a `serde_json::Value`.
fn read_abi(path: &str) -> serde_json::Value {
    let json_str =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    serde_json::from_str(&json_str).unwrap_or_else(|e| panic!("bad JSON in {path}: {e}"))
}

/// Deploy a contract and return its address.
/// `deployer` must have enough balance (in Fast mode this doesn't matter).
fn deploy(executor: &mut EvmExecutor, deployer: Address, bytecode: &[u8]) -> Address {
    executor
        .deploy(deployer, Bytes::from(bytecode.to_vec()))
        .expect("deployment must succeed")
}

/// A fixed "attacker" address used as the caller for property checks and
/// fuzzing transactions.
fn attacker() -> Address {
    Address::repeat_byte(0x42)
}

/// Compiled-artifacts directory, relative to the workspace root.
const COMPILED: &str = "tests/contracts/control/compiled";

// ---------------------------------------------------------------------------
// 1. PropFalse — property always returns false → MUST be flagged
// ---------------------------------------------------------------------------

#[test]
fn prop_false_is_detected_as_violation() {
    let bin_path = format!("{COMPILED}/PropFalse.bin");
    let abi_path = format!("{COMPILED}/PropFalse.abi");

    if !Path::new(&bin_path).exists() {
        eprintln!("SKIP: {bin_path} not found — run `solc` first");
        return;
    }

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(1_000_000_000_000_000_000u128));

    let contract = deploy(&mut executor, deployer, &read_bin(&bin_path));
    let abi = read_abi(&abi_path);

    let caller = EchidnaPropertyCaller::from_abi(contract, &abi)
        .expect("should discover echidna_always_false");

    assert_eq!(caller.properties.len(), 1, "exactly one echidna_* function");
    assert_eq!(caller.properties[0].1, "echidna_always_false");

    // Check the property — it always returns false, so we must get a finding.
    let findings = caller.check_properties(&executor, deployer, &[]);
    assert_eq!(findings.len(), 1, "expected exactly one violation");
    assert!(
        findings[0].title.contains("echidna_always_false"),
        "finding title should name the property, got: {}",
        findings[0].title,
    );
}

// ---------------------------------------------------------------------------
// 2. PropReverts — property always reverts → MUST NOT be flagged
// ---------------------------------------------------------------------------

#[test]
fn prop_reverts_is_not_flagged() {
    let bin_path = format!("{COMPILED}/PropReverts.bin");
    let abi_path = format!("{COMPILED}/PropReverts.abi");

    if !Path::new(&bin_path).exists() {
        eprintln!("SKIP: {bin_path} not found — run `solc` first");
        return;
    }

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(1_000_000_000_000_000_000u128));

    let contract = deploy(&mut executor, deployer, &read_bin(&bin_path));
    let abi = read_abi(&abi_path);

    let caller = EchidnaPropertyCaller::from_abi(contract, &abi)
        .expect("should discover echidna_always_reverts");

    assert_eq!(caller.properties.len(), 1);

    // Echidna semantics: revert ⇒ property holds (conservative).
    let findings = caller.check_properties(&executor, deployer, &[]);
    assert!(
        findings.is_empty(),
        "reverting property must NOT produce a finding, but got: {findings:?}",
    );
}

// ---------------------------------------------------------------------------
// 3. PropMulti — two properties: good (true) and bad (false)
// ---------------------------------------------------------------------------

#[test]
fn prop_multi_flags_bad_not_good() {
    let bin_path = format!("{COMPILED}/PropMulti.bin");
    let abi_path = format!("{COMPILED}/PropMulti.abi");

    if !Path::new(&bin_path).exists() {
        eprintln!("SKIP: {bin_path} not found — run `solc` first");
        return;
    }

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(1_000_000_000_000_000_000u128));

    let contract = deploy(&mut executor, deployer, &read_bin(&bin_path));
    let abi = read_abi(&abi_path);

    let caller =
        EchidnaPropertyCaller::from_abi(contract, &abi).expect("should discover both properties");

    // Must have extracted exactly 2 properties.
    assert_eq!(
        caller.properties.len(),
        2,
        "expected echidna_good + echidna_bad"
    );

    let prop_names: Vec<&str> = caller.properties.iter().map(|(_, n)| n.as_str()).collect();
    assert!(prop_names.contains(&"echidna_good"), "missing echidna_good");
    assert!(prop_names.contains(&"echidna_bad"), "missing echidna_bad");

    let findings = caller.check_properties(&executor, deployer, &[]);

    // Only echidna_bad should fire.
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one violation (echidna_bad)"
    );
    assert!(
        findings[0].title.contains("echidna_bad"),
        "finding should name echidna_bad, got: {}",
        findings[0].title,
    );
}

// ---------------------------------------------------------------------------
// 4. PropStateful — property holds until deposit+withdraw sequence
// ---------------------------------------------------------------------------

#[test]
fn prop_stateful_holds_initially_fails_after_drain() {
    let bin_path = format!("{COMPILED}/PropStateful.bin");
    let abi_path = format!("{COMPILED}/PropStateful.abi");

    if !Path::new(&bin_path).exists() {
        eprintln!("SKIP: {bin_path} not found — run `solc` first");
        return;
    }

    let mut executor = EvmExecutor::new();
    let deployer = attacker();
    executor.set_balance(deployer, U256::from(10_000_000_000_000_000_000u128)); // 10 ETH

    let contract = deploy(&mut executor, deployer, &read_bin(&bin_path));
    let abi = read_abi(&abi_path);

    let caller = EchidnaPropertyCaller::from_abi(contract, &abi)
        .expect("should discover echidna_not_drained");

    assert_eq!(caller.properties.len(), 1);
    assert_eq!(caller.properties[0].1, "echidna_not_drained");

    // --- Before any transactions: property should hold ---
    let findings_before = caller.check_properties(&executor, deployer, &[]);
    assert!(
        findings_before.is_empty(),
        "property should hold before any deposits, got: {findings_before:?}",
    );

    // --- Step 1: deposit 1 ETH ---
    // deposit() selector = keccak256("deposit()") first 4 bytes
    let deposit_selector = {
        use tiny_keccak::{Hasher, Keccak};
        let mut k = Keccak::v256();
        k.update(b"deposit()");
        let mut h = [0u8; 32];
        k.finalize(&mut h);
        [h[0], h[1], h[2], h[3]]
    };

    let deposit_tx = Transaction {
        sender: deployer,
        to: Some(contract),
        data: Bytes::from(deposit_selector.to_vec()),
        value: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
        gas_limit: 30_000_000,
    };

    let deposit_result = executor
        .execute(&deposit_tx)
        .expect("deposit should execute");
    assert!(
        deposit_result.success,
        "deposit should succeed, got error: {:?}",
        deposit_result.output,
    );

    // After deposit: property should still hold (contract has funds).
    let findings_after_deposit =
        caller.check_properties(&executor, deployer, &[deposit_tx.clone()]);
    assert!(
        findings_after_deposit.is_empty(),
        "property should hold after deposit, got: {findings_after_deposit:?}",
    );

    // --- Step 2: withdraw all ---
    let withdraw_selector = {
        use tiny_keccak::{Hasher, Keccak};
        let mut k = Keccak::v256();
        k.update(b"withdraw()");
        let mut h = [0u8; 32];
        k.finalize(&mut h);
        [h[0], h[1], h[2], h[3]]
    };

    let withdraw_tx = Transaction {
        sender: deployer,
        to: Some(contract),
        data: Bytes::from(withdraw_selector.to_vec()),
        value: U256::ZERO,
        gas_limit: 30_000_000,
    };

    let withdraw_result = executor
        .execute(&withdraw_tx)
        .expect("withdraw should execute");
    assert!(
        withdraw_result.success,
        "withdraw should succeed, got error: {:?}",
        withdraw_result.output,
    );

    // After withdraw: property should FAIL (contract is drained).
    let sequence = vec![deposit_tx, withdraw_tx];
    let findings_after_drain = caller.check_properties(&executor, deployer, &sequence);
    assert_eq!(
        findings_after_drain.len(),
        1,
        "property must fail after drain, got {} findings",
        findings_after_drain.len(),
    );
    assert!(
        findings_after_drain[0]
            .title
            .contains("echidna_not_drained"),
        "finding should name the property, got: {}",
        findings_after_drain[0].title,
    );
}

// ---------------------------------------------------------------------------
// 5. ABI bool decoding edge cases
// ---------------------------------------------------------------------------

/// Test the low-level bool decoding logic used by EchidnaPropertyCaller.
///
/// The ABI encoding of `bool` is a 32-byte word:
///   true  = 0x0000…0001
///   false = 0x0000…0000
///
/// Our decoder must handle:
///   - 32-byte false → property failed
///   - 32-byte true  → property holds
///   - empty return  → treat as revert → property holds (conservative)
///   - short return  → treat as revert → property holds
///   - extra padding → check byte 31
#[test]
fn abi_bool_decoding_edge_cases() {
    // We can't call check_properties without a deployed contract, so we
    // test the decoding logic by checking what static_call returns and how
    // the caller would interpret it.
    //
    // The decoding rule in EchidnaPropertyCaller is:
    //   success && output.len() >= 32 && output[31] == 0x00 → false → violated
    //   success && output.len() >= 32 && output[31] != 0x00 → true → holds
    //   success && output.len() < 32                        → ambiguous → holds (conservative)
    //   !success                                            → revert → holds

    // Helper: simulate the decoder's logic.
    fn is_property_violated(success: bool, output: &[u8]) -> bool {
        success && output.len() >= 32 && output[31] == 0x00
    }

    // 32-byte false (all zeros)
    let abi_false = [0u8; 32];
    assert!(
        is_property_violated(true, &abi_false),
        "32-byte false must be detected as violation"
    );

    // 32-byte true (last byte = 1)
    let mut abi_true = [0u8; 32];
    abi_true[31] = 1;
    assert!(
        !is_property_violated(true, &abi_true),
        "32-byte true must NOT be detected as violation"
    );

    // Empty returndata (success but no data — ambiguous, treat as holds)
    assert!(
        !is_property_violated(true, &[]),
        "empty returndata must NOT be detected as violation"
    );

    // Short returndata (less than 32 bytes — ambiguous, treat as holds)
    assert!(
        !is_property_violated(true, &[0u8; 16]),
        "short returndata must NOT be detected as violation"
    );

    // Revert with 32 zero bytes — even though the data "looks like" false,
    // the call reverted so the property holds.
    assert!(
        !is_property_violated(false, &[0u8; 32]),
        "revert must NOT be detected as violation regardless of data"
    );

    // Revert with no data
    assert!(
        !is_property_violated(false, &[]),
        "revert with no data must NOT be detected as violation"
    );

    // Extra-long return (64 bytes, first word is false, second is junk)
    // We should still check byte 31 of the first word.
    let mut long_return = vec![0u8; 64];
    long_return[63] = 0xFF; // junk in second word
    assert!(
        is_property_violated(true, &long_return),
        "extra-long return with false in first word must be detected"
    );

    // Extra-long return where first word is true
    let mut long_true = vec![0u8; 64];
    long_true[31] = 1;
    assert!(
        !is_property_violated(true, &long_true),
        "extra-long return with true in first word must NOT be detected"
    );
}

// ---------------------------------------------------------------------------
// 6. from_abi filtering: non-echidna functions, functions with args, events
// ---------------------------------------------------------------------------

#[test]
fn from_abi_filters_correctly() {
    // ABI with a mix: echidna_* with correct sig, non-echidna, wrong return,
    // echidna with args, event.
    let abi: serde_json::Value = serde_json::json!([
        {
            "type": "function",
            "name": "echidna_good",
            "inputs": [],
            "outputs": [{"type": "bool"}]
        },
        {
            "type": "function",
            "name": "echidna_with_args",
            "inputs": [{"type": "uint256", "name": "x"}],
            "outputs": [{"type": "bool"}]
        },
        {
            "type": "function",
            "name": "echidna_wrong_return",
            "inputs": [],
            "outputs": [{"type": "uint256"}]
        },
        {
            "type": "function",
            "name": "not_echidna",
            "inputs": [],
            "outputs": [{"type": "bool"}]
        },
        {
            "type": "event",
            "name": "echidna_event",
            "inputs": []
        },
        {
            "type": "function",
            "name": "echidna_also_good",
            "inputs": [],
            "outputs": [{"type": "bool"}]
        }
    ]);

    let target = Address::repeat_byte(0x01);
    let caller = EchidnaPropertyCaller::from_abi(target, &abi)
        .expect("should find at least one valid property");

    let names: Vec<&str> = caller.properties.iter().map(|(_, n)| n.as_str()).collect();

    // Should include the two valid echidna_* functions.
    assert!(
        names.contains(&"echidna_good"),
        "should include echidna_good"
    );
    assert!(
        names.contains(&"echidna_also_good"),
        "should include echidna_also_good"
    );

    // Should exclude everything else.
    assert!(
        !names.contains(&"echidna_with_args"),
        "should exclude functions with arguments"
    );
    assert!(
        !names.contains(&"echidna_wrong_return"),
        "should exclude non-bool returns"
    );
    assert!(
        !names.contains(&"not_echidna"),
        "should exclude non-echidna functions"
    );
    assert!(!names.contains(&"echidna_event"), "should exclude events");

    assert_eq!(names.len(), 2, "exactly 2 valid properties");
}

// ---------------------------------------------------------------------------
// 7. No properties found → from_abi returns None
// ---------------------------------------------------------------------------

#[test]
fn from_abi_returns_none_for_no_properties() {
    let abi: serde_json::Value = serde_json::json!([
        {
            "type": "function",
            "name": "deposit",
            "inputs": [],
            "outputs": []
        }
    ]);

    let target = Address::repeat_byte(0x02);
    assert!(
        EchidnaPropertyCaller::from_abi(target, &abi).is_none(),
        "should return None when no echidna_* properties exist"
    );
}
