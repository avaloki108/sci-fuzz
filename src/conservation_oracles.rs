//! Conservation-oriented economic oracles (multi-asset flows, vault custody vs events).

use std::collections::HashMap;

use crate::conservation::{effective_logs, first_pair_sync_change_missing_explanation};
use crate::economic::{address_to_b256, materially_divergent_probe_u256, ProtocolProfileMap};
use crate::invariant::Invariant;
use crate::protocol_probes::probe_u256;
use crate::protocol_semantics::{
    append_triage_simple, topic_erc20_transfer, topic_erc4626_deposit, ContractProtocolProfile,
};
use crate::types::{
    Address, ExecutionResult, Finding, ProbeScalar, ProbeStatus, Severity, Transaction, U256,
};

fn lookup_profile<'a>(
    profiles: &'a Option<ProtocolProfileMap>,
    addr: Address,
) -> Option<&'a ContractProtocolProfile> {
    profiles.as_ref().and_then(|m| m.get(&addr))
}

fn suppress_erc4626_rate_gated(p: Option<&ContractProtocolProfile>) -> bool {
    matches!(p, Some(pr) if pr.abi_present && pr.erc4626_score == 0)
}

// ---------------------------------------------------------------------------
// AMM: consecutive Sync reserve change must be explained by Swap/Mint/Burn
// ---------------------------------------------------------------------------

/// Flags when two `Sync` events for the same pair show changed reserves with no
/// intervening Uniswap V2–shaped Swap/Mint/Burn on that pair in log order.
pub struct AmmSyncExplainedOracle {
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for AmmSyncExplainedOracle {
    fn default() -> Self {
        Self { profiles: None }
    }
}

impl Invariant for AmmSyncExplainedOracle {
    fn name(&self) -> &str {
        "economic-amm-sync-explained"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let logs = effective_logs(result);
        let anomaly = first_pair_sync_change_missing_explanation(logs)?;
        let pair = anomaly.pair;
        if matches!(
            lookup_profile(&self.profiles, pair),
            Some(pr) if pr.abi_present && !pr.is_amm_pair_like()
        ) {
            return None;
        }
        let base = format!(
            "Pair {pair}: consecutive `Sync` logs (indices {} → {}) show reserves changing from reserve0={} reserve1={} to reserve0={} reserve1={} with **no** intervening `Swap`/`Mint`/`Burn` on this pair in log order — structurally unexplained for canonical Uniswap V2–style pools.",
            anomaly.prev_log_index,
            anomaly.cur_log_index,
            anomaly.prev.reserve0,
            anomaly.prev.reserve1,
            anomaly.cur.reserve0,
            anomaly.cur.reserve1,
        );
        let desc = append_triage_simple(
            base,
            pair,
            lookup_profile(&self.profiles, pair),
            "AMM conservation: reserve-changing Sync pairs should bracket at least one Swap/Mint/Burn on the same pair address.",
            "sequence_cumulative_logs or result.logs: Sync/Swap/Mint/Burn topic scan (heuristic log-order structural check).",
            "Donations + sync(), non-V2 forks, or missing events in the trace can confuse this; not a full constant-product proof.",
        );
        Some(Finding {
            severity: Severity::High,
            title: format!("Economic: AMM Sync reserve change without Swap/Mint/Burn ({pair})"),
            description: desc,
            contract: pair,
            reproducer: sequence.to_vec(),
            exploit_profit: None,
        })
    }
}

// ---------------------------------------------------------------------------
// ERC-4626: Deposit assets vs ERC-20 Transfer to vault (same tx)
// ---------------------------------------------------------------------------

/// Compares `Deposit` event `assets` to the sum of underlying `Transfer` deliveries to the vault.
pub struct Erc4626DepositVsUnderlyingTransferOracle {
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc4626DepositVsUnderlyingTransferOracle {
    fn default() -> Self {
        Self { profiles: None }
    }
}

fn transfer_topic() -> crate::types::B256 {
    topic_erc20_transfer()
}

/// Sum `Transfer` amounts to `vault` from logs where `log.address == asset_token`.
fn sum_transfers_to_vault(
    logs: &[crate::types::Log],
    asset_token: Address,
    vault: Address,
) -> U256 {
    let t = transfer_topic();
    let vault_t = address_to_b256(vault);
    let mut sum = U256::ZERO;
    for log in logs {
        if log.address != asset_token {
            continue;
        }
        if log.topics.get(0).copied() != Some(t) || log.topics.len() < 3 {
            continue;
        }
        if log.topics[2] != vault_t {
            continue;
        }
        if log.data.len() >= 32 {
            sum = sum.saturating_add(U256::from_be_slice(&log.data[..32]));
        }
    }
    sum
}

impl Invariant for Erc4626DepositVsUnderlyingTransferOracle {
    fn name(&self) -> &str {
        "economic-erc4626-deposit-vs-transfer"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }
        let dep_t = topic_erc4626_deposit();
        for log in &result.logs {
            if log.topics.get(0).copied() != Some(dep_t) || log.data.len() < 64 {
                continue;
            }
            let vault = log.address;
            if suppress_erc4626_rate_gated(lookup_profile(&self.profiles, vault)) {
                continue;
            }
            let deposit_assets = U256::from_be_slice(&log.data[..32]);
            if deposit_assets.is_zero() {
                continue;
            }

            let Some(snap) = result.protocol_probes.per_contract.get(&vault) else {
                continue;
            };
            let Some(e) = snap.erc4626.as_ref() else {
                continue;
            };
            let asset_token = match e.asset.as_ref() {
                Some(ProbeStatus::Ok(ProbeScalar::Address(a))) => *a,
                _ => continue,
            };

            let transferred = sum_transfers_to_vault(&result.logs, asset_token, vault);
            if !materially_divergent_probe_u256(transferred, deposit_assets) {
                continue;
            }

            let probe_note = match e.asset_balance_of_vault.as_ref().and_then(probe_u256) {
                Some(b) => format!(
                    " Post-state probe `balanceOf` on underlying asset {asset_token} for vault={vault} returned {b} (post-tx; not a delta from Deposit alone)."
                ),
                None => String::new(),
            };

            let base = format!(
                "Vault {vault}: `Deposit` event reports assets={deposit_assets} but ERC-20 `Transfer` on underlying asset {asset_token} **to** this vault in the **same transaction** sums to {transferred} — materially mismatched (possible missing underlying delivery, fee-on-transfer asymmetry, or broken accounting).{probe_note}",
            );
            let desc = append_triage_simple(
                base,
                vault,
                lookup_profile(&self.profiles, vault),
                "ERC-4626 conservation: recorded deposits should align with visible underlying token delivery in the same tx when the asset is a standard ERC-20.",
                "result.logs: Deposit event assets vs sum of Transfer(to=vault) on probed `asset()` address; optional asset_balance_of_vault probe.",
                "Native ETH, ERC-777, fee-on-transfer, or internal credit paths may not show as standard Transfer; triage with vault code.",
            );
            return Some(Finding {
                severity: Severity::High,
                title: format!(
                    "Economic: ERC-4626 Deposit assets vs underlying Transfer ({vault})"
                ),
                description: desc,
                contract: vault,
                reproducer: sequence.to_vec(),
                exploit_profit: None,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Bytes, ContractProbeSnapshot, Erc4626ProbeSnapshot, Log};

    fn deposit_log(vault: Address, assets: u64) -> Log {
        let mut data = [0u8; 64];
        data[24..32].copy_from_slice(&assets.to_be_bytes());
        Log {
            address: vault,
            topics: vec![
                topic_erc4626_deposit(),
                crate::types::B256::ZERO,
                crate::types::B256::ZERO,
            ],
            data: Bytes::copy_from_slice(&data),
        }
    }

    fn transfer_to_vault(token: Address, vault: Address, amount: u64) -> Log {
        Log {
            address: token,
            topics: vec![
                topic_erc20_transfer(),
                crate::types::B256::ZERO,
                address_to_b256(vault),
            ],
            data: Bytes::copy_from_slice(&U256::from(amount).to_be_bytes::<32>()),
        }
    }

    #[test]
    fn deposit_vs_transfer_fires_when_under_delivered() {
        let vault = Address::repeat_byte(0x11);
        let asset = Address::repeat_byte(0x22);
        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs.push(deposit_log(vault, 1000));
        r.logs.push(transfer_to_vault(asset, vault, 1));

        let mut e = Erc4626ProbeSnapshot::default();
        e.asset = Some(ProbeStatus::Ok(ProbeScalar::Address(asset)));
        r.protocol_probes.per_contract.insert(
            vault,
            ContractProbeSnapshot {
                erc4626: Some(e),
                ..Default::default()
            },
        );

        let inv = Erc4626DepositVsUnderlyingTransferOracle::default();
        let f = inv.check(&HashMap::new(), &r, &[]).expect("finding");
        assert!(f.title.contains("Deposit"));
        assert!(f.description.contains("1000"));
        assert!(f.description.contains("underlying asset"));
    }

    #[test]
    fn deposit_vs_transfer_includes_balance_probe_in_text() {
        let vault = Address::repeat_byte(0x33);
        let asset = Address::repeat_byte(0x44);
        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs.push(deposit_log(vault, 10_000));
        r.logs.push(transfer_to_vault(asset, vault, 1));

        let mut e = Erc4626ProbeSnapshot::default();
        e.asset = Some(ProbeStatus::Ok(ProbeScalar::Address(asset)));
        e.asset_balance_of_vault = Some(ProbeStatus::Ok(ProbeScalar::U256(U256::from(9999u64))));
        r.protocol_probes.per_contract.insert(
            vault,
            ContractProbeSnapshot {
                erc4626: Some(e),
                ..Default::default()
            },
        );

        let inv = Erc4626DepositVsUnderlyingTransferOracle::default();
        let f = inv.check(&HashMap::new(), &r, &[]).expect("finding");
        assert!(f.description.contains("balanceOf"));
        assert!(f.description.contains("9999"));
    }

    #[test]
    fn amm_sync_explained_fires_on_unexplained_double_sync() {
        use crate::protocol_semantics::topic_uni_v2_sync;
        let pair = Address::repeat_byte(0xDD);
        let mut data = [0u8; 64];
        data[31] = 10;
        data[63] = 10;
        let s1 = Log {
            address: pair,
            topics: vec![topic_uni_v2_sync()],
            data: Bytes::copy_from_slice(&data),
        };
        data[31] = 20;
        data[63] = 20;
        let s2 = Log {
            address: pair,
            topics: vec![topic_uni_v2_sync()],
            data: Bytes::copy_from_slice(&data),
        };
        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs = vec![s1, s2];

        let inv = AmmSyncExplainedOracle::default();
        let f = inv.check(&HashMap::new(), &r, &[]).expect("finding");
        assert!(f.title.contains("Sync"));
        assert!(f.description.contains("Swap"));
    }

    #[test]
    fn amm_sync_explained_quiet_when_swap_between_syncs() {
        use crate::protocol_semantics::topic_uni_v2_sync;
        let pair = Address::repeat_byte(0xEE);
        let mut data = [0u8; 64];
        data[31] = 10;
        data[63] = 10;
        let s1 = Log {
            address: pair,
            topics: vec![topic_uni_v2_sync()],
            data: Bytes::copy_from_slice(&data),
        };
        let sw = Log {
            address: pair,
            topics: vec![
                crate::protocol_semantics::topic_uni_v2_swap(),
                crate::types::B256::ZERO,
                crate::types::B256::ZERO,
            ],
            data: Bytes::copy_from_slice(&[0u8; 128]),
        };
        data[31] = 20;
        data[63] = 20;
        let s2 = Log {
            address: pair,
            topics: vec![topic_uni_v2_sync()],
            data: Bytes::copy_from_slice(&data),
        };
        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs = vec![s1, sw, s2];
        let inv = AmmSyncExplainedOracle::default();
        assert!(inv.check(&HashMap::new(), &r, &[]).is_none());
    }

    #[test]
    fn deposit_vs_transfer_skips_without_asset_probe() {
        let vault = Address::repeat_byte(0x55);
        let mut r = ExecutionResult::default();
        r.success = true;
        r.logs.push(deposit_log(vault, 1000));
        r.protocol_probes.per_contract.insert(
            vault,
            ContractProbeSnapshot {
                erc4626: Some(Erc4626ProbeSnapshot::default()),
                ..Default::default()
            },
        );
        let inv = Erc4626DepositVsUnderlyingTransferOracle::default();
        assert!(inv.check(&HashMap::new(), &r, &[]).is_none());
    }
}
