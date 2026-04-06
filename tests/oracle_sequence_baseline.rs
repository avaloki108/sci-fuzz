//! Per-sequence oracle baselines: balance/profit checks must use pre-sequence
//! balances (after restoring the base snapshot), not a stale campaign-root map.

use std::collections::HashMap;

use sci_fuzz::oracle::{capture_eth_baseline, OracleEngine};
use sci_fuzz::types::{Address, ExecutionResult, Transaction, U256};

fn empty_tx(sender: Address) -> Transaction {
    Transaction {
        sender,
        to: Some(Address::ZERO),
        data: Default::default(),
        value: U256::ZERO,
        gas_limit: 30_000_000,
    }
}

fn wei_eth(n: u128) -> U256 {
    U256::from(n) * U256::from(10u128.pow(18))
}

#[test]
fn balance_increase_fires_with_root_state_baseline() {
    let attacker = Address::repeat_byte(0x42);
    let mut executor = sci_fuzz::EvmExecutor::new();
    let ten_eth = wei_eth(10);
    executor.set_balance(attacker, ten_eth);

    let pre = capture_eth_baseline(&executor, attacker);
    let oracle = OracleEngine::new(attacker);

    let mut result = ExecutionResult::default();
    let new_bal = ten_eth + U256::from(10_000u64);
    result
        .state_diff
        .balance_changes
        .insert(attacker, (ten_eth, new_bal));

    let seq = vec![empty_tx(attacker)];
    let findings = oracle.check(&pre, &sci_fuzz::types::ProtocolProbeReport::default(), &result, &seq);
    assert!(
        findings
            .iter()
            .any(|f| f.title.contains("balance increase")),
        "expected BalanceIncrease finding; got {:?}",
        findings
    );
}

#[test]
fn stale_campaign_root_baseline_does_not_false_positive_on_snapshot_state() {
    let attacker = Address::repeat_byte(0x42);
    let oracle = OracleEngine::new(attacker);

    // Simulate "post-snapshot" state: attacker already holds 10 ETH (e.g. after
    // deposit), matching what the EVM would report after restore.
    let mut result = ExecutionResult::default();
    let ten_eth = wei_eth(10);
    let tiny_gain = U256::from(500u64);
    let new_bal = ten_eth + tiny_gain;
    result
        .state_diff
        .balance_changes
        .insert(attacker, (ten_eth, new_bal));

    let seq = vec![empty_tx(attacker)];

    let correct_pre = HashMap::from([(attacker, ten_eth)]);
    let stale_high = HashMap::from([(attacker, wei_eth(100))]);

    let correct_findings = oracle.check(&correct_pre, &sci_fuzz::types::ProtocolProbeReport::default(), &result, &seq);
    assert!(
        !correct_findings.is_empty(),
        "expected gain vs correct baseline to be reported"
    );

    // Stale baseline (100 ETH) while actual sequence start was 10 ETH: post-tx
    // balance is still below 100 ETH → no spurious "profit" vs stale root.
    let stale_findings = oracle.check(&stale_high, &sci_fuzz::types::ProtocolProbeReport::default(), &result, &seq);
    assert!(
        stale_findings.is_empty(),
        "stale high baseline must not fire BalanceIncrease when new < old baseline"
    );
}
