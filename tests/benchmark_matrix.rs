//! Benchmark matrix — expected vulnerabilities for EF/CF test contracts.
//!
//! Each entry maps a contract file to its expected vulnerability type.
//! This lets us track: which bugs sci-fuzz finds, which it misses, and how
//! long each takes.

/// Expected vulnerability type for a benchmark contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedBug {
    EtherDrain,
    Selfdestruct,
    Reentrancy,
    IntegerOverflow,
    PropertyViolation,
    AccessControl,
    None,
}

/// A benchmark entry.
pub struct BenchmarkEntry {
    pub contract_file: &'static str,
    pub expected_bug: ExpectedBug,
    pub description: &'static str,
}

/// The full benchmark matrix.
pub fn benchmark_matrix() -> Vec<BenchmarkEntry> {
    vec![
        // -----------------------------------------------------------------
        // Reentrancy
        // -----------------------------------------------------------------
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/SimpleDAO.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Classic reentrancy via withdraw",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/SimpleDAONoBranch.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "SimpleDAO variant without branching guard",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/SimpleDAORequire.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "SimpleDAO variant with require guard",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ReentrancyVulnBankBuggyLock.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Reentrancy in bank with buggy lock",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ReentrancyVulnBankBuggyLockHard.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Harder variant of buggy lock reentrancy",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ReentrancyBuggyLock2.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Another buggy lock reentrancy variant",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ReentrancyDeepCrossFunction.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Deep cross-function reentrancy",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ReentrancyDeepCrossFunctionMultiAttacker.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Cross-function reentrancy with multiple attackers",
        },
        BenchmarkEntry {
            contract_file:
                "tests/contracts/efcf-core/ReentrancyDeepCrossFunctionMultiAttackerLevels.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Cross-function reentrancy with multiple attacker levels",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ReentrancyDeepCrossFunctionSelfdestruct.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Cross-function reentrancy leading to selfdestruct",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ReentrancyRegisterCallback.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Reentrancy via registered callback",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ReentrancyReturnDataCheck.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Reentrancy with return data check",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/UnconditionalReentrancyVulnBank.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Unconditional reentrancy in bank contract",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/reentrancy_etherstore.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Reentrancy in ether store pattern",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/reentrancy_splits.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Reentrancy via split withdraw pattern",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/modifier_reentrancy.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Reentrancy exploiting modifier ordering",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/modifier_reentrancy_mod.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Modified modifier reentrancy variant",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/modifier_reentrancy_mod2.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Second modifier reentrancy variant",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/modifier_reentrancy_mod3.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Third modifier reentrancy variant",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/baby_bank.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Baby bank reentrancy pattern",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/baby_bank_mod.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Modified baby bank reentrancy",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/BuggyToken.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Token exchange reentrancy",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/SpankchainLedgerChannel.sol",
            expected_bug: ExpectedBug::Reentrancy,
            description: "Spankchain ledger channel reentrancy",
        },
        // -----------------------------------------------------------------
        // Selfdestruct
        // -----------------------------------------------------------------
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/Suicidal.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "Unconditional selfdestruct",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/SuicidalDoSOnly.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "Selfdestruct causing DoS",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/SuicidalWithCondition.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "Selfdestruct gated by condition",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/SuicidalWithMagicValueCondition.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "Selfdestruct gated by magic value check",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ParityWalletBugSuicide.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "Parity wallet selfdestruct bug",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ParityWalletBugSuicideWithRequire.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "Parity wallet selfdestruct with require guard",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/boom_suicidal.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "Boom suicidal contract",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/boom_suicidal_hard.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "Harder boom suicidal variant",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/suicide_multitx_feasible.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "Multi-tx selfdestruct from SWC-106",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/cstate.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "State-dependent selfdestruct (Smartian example)",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/cstate_req.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "State-dependent selfdestruct with require",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/keccak2.sol",
            expected_bug: ExpectedBug::Selfdestruct,
            description: "Selfdestruct gated by keccak preimage",
        },
        // -----------------------------------------------------------------
        // Integer overflow
        // -----------------------------------------------------------------
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/integer_overflow.sol",
            expected_bug: ExpectedBug::IntegerOverflow,
            description: "Integer overflow leading to selfdestruct",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/TokenWhaleChallenge.sol",
            expected_bug: ExpectedBug::IntegerOverflow,
            description: "Token whale underflow in _transfer",
        },
        // -----------------------------------------------------------------
        // Ether drain
        // -----------------------------------------------------------------
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/simpleetherdrain.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Simple unrestricted ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/simpleetherdrainother.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Ether drain to arbitrary address",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/CrossFunctionToken.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Cross-function ether drain in token",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/callvalue.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Ether drain via callvalue check bypass",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/callvalue2.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Ether drain via callvalue variant 2",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/callvalue3.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Ether drain via callvalue variant 3",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/initbalance.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Drain via initial balance transfer",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/initbalance2.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Drain via initial balance variant 2",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/dispenser.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Ether drain via dispenser logic",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/number_constraints.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Ether drain gated by number constraints",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/teether_test1_simple.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Teether: simple XOR key ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/teether_test2_singlesha.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Teether: single SHA ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/teether_test2_singleshamod.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Teether: modified single SHA ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/teether_test3_doublesha.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Teether: double SHA ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/teether_test14_multiowned.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Teether: multi-owned ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/teether_test22.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Teether: test 22 ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/teether_test_approve.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Teether: approve-based ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/DonationChallenge.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "CTE donation challenge — storage collision drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/RetirementFundChallenge.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "CTE retirement fund challenge drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/FiftyYearsChallenge.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "CTE fifty years challenge drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/crowdsale_mod.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Modified crowdsale ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/crypto_roulette_exploitable.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Crypto roulette storage collision exploit",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/timestamp.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Timestamp-dependent ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/tokensalechallenge.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "CTE token sale challenge drain",
        },
        // -----------------------------------------------------------------
        // Property violation (Echidna-style)
        // -----------------------------------------------------------------
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/single.sol",
            expected_bug: ExpectedBug::PropertyViolation,
            description: "Single echidna_state property violation",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/multi.sol",
            expected_bug: ExpectedBug::PropertyViolation,
            description: "Multi-step echidna_state3 property violation",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/multi_hard.sol",
            expected_bug: ExpectedBug::PropertyViolation,
            description: "Harder multi-step property with decoy functions",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/harvey_baz.sol",
            expected_bug: ExpectedBug::PropertyViolation,
            description: "Harvey baz — all_states property violation",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/harvey_foo.sol",
            expected_bug: ExpectedBug::PropertyViolation,
            description: "Harvey foo — echidna_assert property violation",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/boolean_selector.sol",
            expected_bug: ExpectedBug::PropertyViolation,
            description: "Boolean selector echidna_oracle property",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/crytic_complex_example.sol",
            expected_bug: ExpectedBug::PropertyViolation,
            description: "Crytic complex multi-state property violation",
        },
        // -----------------------------------------------------------------
        // Access control
        // -----------------------------------------------------------------
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/Delegatecall.sol",
            expected_bug: ExpectedBug::AccessControl,
            description: "Delegatecall without access control",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ParityWalletBugCall.sol",
            expected_bug: ExpectedBug::AccessControl,
            description: "Parity wallet unprotected call",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/ParityWalletBugCallArg.sol",
            expected_bug: ExpectedBug::AccessControl,
            description: "Parity wallet unprotected call with argument",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/arbitrary_location_write_simple.sol",
            expected_bug: ExpectedBug::AccessControl,
            description: "SWC-124 arbitrary storage write via array overflow",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/NoCodeCallReturns.sol",
            expected_bug: ExpectedBug::AccessControl,
            description: "No-code call returns exploitable initialization",
        },
        // -----------------------------------------------------------------
        // Ether drain (challenge / puzzle contracts)
        // -----------------------------------------------------------------
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/GuessTheNumberChallenge.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "CTE guess the number challenge",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/GuessTheNumberChallengeMod1.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Modified guess the number challenge",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/GuessTheSecretNumberChallenge.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "CTE guess the secret number (hash preimage)",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/GuessTheSecretNumberChallengeMod.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Modified guess the secret number",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/GuessTheRandomNumberChallenge.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "CTE guess the random number (blockhash)",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/GuessTheRandomNumberChallengeMod.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Modified guess the random number",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/PredictTheBlockHashChallenge.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "CTE predict the blockhash challenge",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/PredictTheFutureChallenge.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "CTE predict the future challenge",
        },
        // -----------------------------------------------------------------
        // Ether drain (EF/CF basic + data-flow puzzles)
        // -----------------------------------------------------------------
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/basic.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Basic multi-step ether drain with constraints",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/basic_hard.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Harder basic ether drain with interfaces",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/mutual_data_dep.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Mutual data dependency ether drain",
        },
        BenchmarkEntry {
            contract_file: "tests/contracts/efcf-core/testHardcoded.sol",
            expected_bug: ExpectedBug::EtherDrain,
            description: "Hardcoded value ether drain",
        },
    ]
}

#[test]
fn benchmark_matrix_has_entries() {
    let matrix = benchmark_matrix();
    assert!(
        matrix.len() >= 30,
        "benchmark matrix should have at least 30 entries, got {}",
        matrix.len(),
    );
}

#[test]
fn all_contract_files_exist() {
    let matrix = benchmark_matrix();
    for entry in &matrix {
        assert!(
            std::path::Path::new(entry.contract_file).exists(),
            "Contract file missing: {} ({})",
            entry.contract_file,
            entry.description,
        );
    }
}

#[test]
fn no_duplicate_contract_files() {
    let matrix = benchmark_matrix();
    let mut seen = std::collections::HashSet::new();
    for entry in &matrix {
        assert!(
            seen.insert(entry.contract_file),
            "Duplicate contract file in benchmark matrix: {}",
            entry.contract_file,
        );
    }
}

#[test]
fn all_bug_categories_represented() {
    let matrix = benchmark_matrix();

    let has = |bug: ExpectedBug| matrix.iter().any(|e| e.expected_bug == bug);

    assert!(has(ExpectedBug::EtherDrain), "missing EtherDrain entries");
    assert!(
        has(ExpectedBug::Selfdestruct),
        "missing Selfdestruct entries"
    );
    assert!(has(ExpectedBug::Reentrancy), "missing Reentrancy entries");
    assert!(
        has(ExpectedBug::IntegerOverflow),
        "missing IntegerOverflow entries"
    );
    assert!(
        has(ExpectedBug::PropertyViolation),
        "missing PropertyViolation entries"
    );
    assert!(
        has(ExpectedBug::AccessControl),
        "missing AccessControl entries"
    );
}
