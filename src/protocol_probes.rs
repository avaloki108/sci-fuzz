//! Executor-backed `static_call` protocol probes for classified contracts.
//!
//! Populates [`crate::types::ProtocolProbeReport`] on [`crate::types::ExecutionResult`]
//! at **post-transaction** state (same pattern as `sequence_cumulative_logs`).

use std::collections::{HashMap, HashSet};

use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::JsonAbi;

use crate::economic::ProtocolProfileMap;
use crate::evm::EvmExecutor;
use crate::protocol_semantics::{topic_erc4626_deposit, topic_erc4626_withdraw};
use crate::types::{
    Address, AmmProbeSnapshot, Bytes, ContractProbeSnapshot, Erc20ProbeSnapshot,
    Erc4626DepositProbeRow, Erc4626ProbeSnapshot, Erc4626WithdrawProbeRow, ExecutionResult,
    ProbeScalar, ProbeStatus, ProtocolProbeReport, Transaction, U256,
};

/// Hard cap on `static_call` invocations per transaction step.
const MAX_STATIC_CALLS_PER_STEP: usize = 32;

fn has_function(abi: &JsonAbi, name: &str) -> bool {
    abi.functions.contains_key(name)
}

fn decode_u256_word(out: &[u8]) -> Option<U256> {
    if out.len() < 32 {
        return None;
    }
    Some(U256::from_be_slice(&out[..32]))
}

fn decode_address_word(out: &[u8]) -> Option<Address> {
    if out.len() < 32 {
        return None;
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&out[12..32]);
    Some(Address::from(a))
}

fn decode_u256_pair_abi(out: &[u8]) -> Option<(U256, U256)> {
    if out.len() < 64 {
        return None;
    }
    Some((
        U256::from_be_slice(&out[..32]),
        U256::from_be_slice(&out[32..64]),
    ))
}

/// Decode `getReserves()` → (reserve0, reserve1, _blockTimestampLast).
fn decode_get_reserves(out: &[u8]) -> Option<(U256, U256)> {
    let (r0, r1) = decode_u256_pair_abi(out)?;
    Some((r0, r1))
}

fn encode_call(abi: &JsonAbi, name: &str, args: &[DynSolValue]) -> Option<Bytes> {
    let funcs = abi.functions.get(name)?;
    let f = funcs.first()?;
    let data = f.abi_encode_input(args).ok()?;
    Some(Bytes::from(data))
}

fn run_probe(
    executor: &EvmExecutor,
    caller: Address,
    contract: Address,
    data: Bytes,
    calls_left: &mut usize,
) -> Option<(bool, Bytes)> {
    if *calls_left == 0 {
        return None;
    }
    *calls_left -= 1;
    executor.static_call(caller, contract, data).ok()
}

fn status_u256(ok: bool, out: &Bytes) -> ProbeStatus {
    if !ok {
        return ProbeStatus::Reverted;
    }
    match decode_u256_word(out.as_ref()) {
        Some(v) => ProbeStatus::Ok(ProbeScalar::U256(v)),
        None => ProbeStatus::DecodeFailed,
    }
}

fn status_address(ok: bool, out: &Bytes) -> ProbeStatus {
    if !ok {
        return ProbeStatus::Reverted;
    }
    match decode_address_word(out.as_ref()) {
        Some(a) => ProbeStatus::Ok(ProbeScalar::Address(a)),
        None => ProbeStatus::DecodeFailed,
    }
}

fn status_reserves(ok: bool, out: &Bytes) -> (Option<ProbeStatus>, Option<ProbeStatus>) {
    if !ok {
        return (Some(ProbeStatus::Reverted), Some(ProbeStatus::Reverted));
    }
    match decode_get_reserves(out.as_ref()) {
        Some((r0, r1)) => (
            Some(ProbeStatus::Ok(ProbeScalar::U256(r0))),
            Some(ProbeStatus::Ok(ProbeScalar::U256(r1))),
        ),
        None => (
            Some(ProbeStatus::DecodeFailed),
            Some(ProbeStatus::DecodeFailed),
        ),
    }
}

fn candidate_addresses(sequence: &[Transaction], result: &ExecutionResult) -> Vec<Address> {
    let mut set: HashSet<Address> = HashSet::new();
    for tx in sequence {
        if let Some(to) = tx.to {
            set.insert(to);
        }
    }
    for log in &result.logs {
        set.insert(log.address);
    }
    set.into_iter().collect()
}

/// Populate `result.protocol_probes` using post-state `static_call` probes.
pub fn fill_protocol_probes(
    executor: &EvmExecutor,
    caller: Address,
    profiles: &ProtocolProfileMap,
    abis: &HashMap<Address, JsonAbi>,
    sequence: &[Transaction],
    result: &mut ExecutionResult,
) {
    result.protocol_probes = ProtocolProbeReport::default();
    if !result.success {
        return;
    }

    let mut calls_left = MAX_STATIC_CALLS_PER_STEP;
    let mut report = ProtocolProbeReport::default();

    for addr in candidate_addresses(sequence, result) {
        let Some(prof) = profiles.get(&addr) else {
            continue;
        };
        let Some(abi) = abis.get(&addr) else {
            continue;
        };

        let mut snap = ContractProbeSnapshot::default();

        if prof.is_erc4626_like() {
            let mut e = Erc4626ProbeSnapshot::default();

            if has_function(abi, "asset") {
                if let Some(data) = encode_call(abi, "asset", &[]) {
                    if let Some((ok, out)) =
                        run_probe(executor, caller, addr, data, &mut calls_left)
                    {
                        e.asset = Some(status_address(ok, &out));
                    }
                }
            }
            if has_function(abi, "totalAssets") {
                if let Some(data) = encode_call(abi, "totalAssets", &[]) {
                    if let Some((ok, out)) =
                        run_probe(executor, caller, addr, data, &mut calls_left)
                    {
                        e.total_assets = Some(status_u256(ok, &out));
                    }
                }
            }

            let dep_t = topic_erc4626_deposit();
            let wit_t = topic_erc4626_withdraw();
            for log in &result.logs {
                if log.address != addr {
                    continue;
                }
                if log.topics.first().copied() == Some(dep_t) && log.data.len() >= 64 {
                    let assets = U256::from_be_slice(&log.data[..32]);
                    let shares = U256::from_be_slice(&log.data[32..64]);
                    let mut row = Erc4626DepositProbeRow {
                        assets,
                        shares_emitted: shares,
                        preview_deposit_shares: None,
                        convert_to_shares: None,
                    };

                    if has_function(abi, "previewDeposit") {
                        if let Some(data) = encode_call(
                            abi,
                            "previewDeposit",
                            &[DynSolValue::Uint(assets, 256)],
                        ) {
                            if let Some((ok, out)) =
                                run_probe(executor, caller, addr, data, &mut calls_left)
                            {
                                row.preview_deposit_shares = Some(status_u256(ok, &out));
                            }
                        }
                    }
                    if has_function(abi, "convertToShares") {
                        if let Some(data) = encode_call(
                            abi,
                            "convertToShares",
                            &[DynSolValue::Uint(assets, 256)],
                        ) {
                            if let Some((ok, out)) =
                                run_probe(executor, caller, addr, data, &mut calls_left)
                            {
                                row.convert_to_shares = Some(status_u256(ok, &out));
                            }
                        }
                    }
                    e.deposit_rows.push(row);
                }

                if log.topics.first().copied() == Some(wit_t) && log.data.len() >= 64 {
                    let assets = U256::from_be_slice(&log.data[..32]);
                    let shares = U256::from_be_slice(&log.data[32..64]);
                    let mut row = Erc4626WithdrawProbeRow {
                        assets,
                        shares_burned: shares,
                        preview_withdraw_shares: None,
                        preview_redeem_assets: None,
                    };
                    if has_function(abi, "previewWithdraw") {
                        if let Some(data) = encode_call(
                            abi,
                            "previewWithdraw",
                            &[DynSolValue::Uint(assets, 256)],
                        ) {
                            if let Some((ok, out)) =
                                run_probe(executor, caller, addr, data, &mut calls_left)
                            {
                                row.preview_withdraw_shares = Some(status_u256(ok, &out));
                            }
                        }
                    }
                    if has_function(abi, "previewRedeem") {
                        if let Some(data) = encode_call(
                            abi,
                            "previewRedeem",
                            &[DynSolValue::Uint(shares, 256)],
                        ) {
                            if let Some((ok, out)) =
                                run_probe(executor, caller, addr, data, &mut calls_left)
                            {
                                row.preview_redeem_assets = Some(status_u256(ok, &out));
                            }
                        }
                    }
                    e.withdraw_rows.push(row);
                }
            }

            if e.asset.is_some()
                || e.total_assets.is_some()
                || !e.deposit_rows.is_empty()
                || !e.withdraw_rows.is_empty()
            {
                snap.erc4626 = Some(e);
            }
        }

        if prof.is_erc20_like() {
            let mut t = Erc20ProbeSnapshot::default();
            if has_function(abi, "totalSupply") {
                if let Some(data) = encode_call(abi, "totalSupply", &[]) {
                    if let Some((ok, out)) =
                        run_probe(executor, caller, addr, data, &mut calls_left)
                    {
                        t.total_supply = Some(status_u256(ok, &out));
                    }
                }
            }
            if has_function(abi, "balanceOf") {
                if let Some(data) =
                    encode_call(abi, "balanceOf", &[DynSolValue::Address(caller)])
                {
                    if let Some((ok, out)) =
                        run_probe(executor, caller, addr, data, &mut calls_left)
                    {
                        t.balance_of_caller = Some(status_u256(ok, &out));
                    }
                }
            }
            if t.total_supply.is_some() || t.balance_of_caller.is_some() {
                snap.erc20 = Some(t);
            }
        }

        if prof.is_amm_pair_like() && has_function(abi, "getReserves") {
            if let Some(data) = encode_call(abi, "getReserves", &[]) {
                if let Some((ok, out)) = run_probe(executor, caller, addr, data, &mut calls_left)
                {
                    let (r0, r1) = status_reserves(ok, &out);
                    snap.amm = Some(AmmProbeSnapshot {
                        reserve0: r0,
                        reserve1: r1,
                    });
                }
            }
        }

        if snap.erc4626.is_some() || snap.erc20.is_some() || snap.amm.is_some() {
            report.per_contract.insert(addr, snap);
        }
    }

    result.protocol_probes = report;
}

/// Helper for tests / oracles: resolve `ProbeStatus::Ok` to `U256`.
pub fn probe_u256(status: &ProbeStatus) -> Option<U256> {
    match status {
        ProbeStatus::Ok(ProbeScalar::U256(v)) => Some(*v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_json_abi::JsonAbi;
    use serde_json::json;

    fn sample_erc4626_abi() -> JsonAbi {
        serde_json::from_value(json!([
            {"type":"function","name":"asset","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view"},
            {"type":"function","name":"totalAssets","inputs":[],"outputs":[{"type":"uint256"}],"stateMutability":"view"},
            {"type":"function","name":"previewDeposit","inputs":[{"name":"a","type":"uint256"}],"outputs":[{"type":"uint256"}],"stateMutability":"view"},
            {"type":"function","name":"convertToShares","inputs":[{"name":"a","type":"uint256"}],"outputs":[{"type":"uint256"}],"stateMutability":"view"}
        ]))
        .expect("abi")
    }

    #[test]
    fn encode_preview_deposit_has_selector_and_args() {
        let abi = sample_erc4626_abi();
        let assets = U256::from(1000u64);
        let data = encode_call(
            &abi,
            "previewDeposit",
            &[DynSolValue::Uint(assets, 256)],
        )
        .expect("encode");
        assert!(data.len() >= 4 + 32);
        let word = &data[4..36];
        assert_eq!(U256::from_be_slice(word), assets);
    }

    #[test]
    fn decode_get_reserves_three_words() {
        let mut buf = [0u8; 96];
        buf[31] = 7;
        buf[63] = 9;
        let (r0, r1) = decode_get_reserves(&buf).expect("decode");
        assert_eq!(r0, U256::from(7u64));
        assert_eq!(r1, U256::from(9u64));
    }
}
