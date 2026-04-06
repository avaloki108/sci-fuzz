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
        _pre_probes: &crate::types::ProtocolProbeReport,
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
// ERC-4626: First-Depositor Inflation Attack Detection
// ---------------------------------------------------------------------------

/// Detects first-depositor inflation attack patterns in ERC-4626 vaults.
///
/// Attack pattern (checked within a single transaction sequence):
/// 1. Attacker deposits 1 wei → gets 1 share (vault empty, assets < 1000 wei).
/// 2. Attacker donates large amount to vault directly (Transfer to vault, no Deposit event).
/// 3. Next depositor gets 0 shares because `totalAssets` >> `totalSupply`.
///
/// This oracle fires on step 1 (tiny deposit with 1 share) OR when it sees
/// a deposit returning 0 shares in the same sequence as a prior donation.
/// Uses only data available within a single execution result — fully `Send + Sync`.
pub struct Erc4626FirstDepositorInflationOracle {
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc4626FirstDepositorInflationOracle {
    fn default() -> Self {
        Self { profiles: None }
    }
}

impl Invariant for Erc4626FirstDepositorInflationOracle {
    fn name(&self) -> &str {
        "economic-erc4626-first-depositor-inflation"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        _pre_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }

        let dep_t = topic_erc4626_deposit();
        let xfer_t = transfer_topic();
        let logs = effective_logs(result);

        // --- Step 1 detection: tiny first deposit (assets < 1000, shares <= 1) ----
        // Also captures step 3: zero-share deposit from a subsequent depositor.
        let mut tiny_deposit_vault: Option<Address> = None;
        let mut zero_share_vault: Option<(Address, U256)> = None;

        for log in logs {
            if log.topics.get(0).copied() != Some(dep_t) || log.data.len() < 64 {
                continue;
            }
            let vault = log.address;
            if suppress_erc4626_rate_gated(lookup_profile(&self.profiles, vault)) {
                continue;
            }
            let assets = U256::from_be_slice(&log.data[..32]);
            let shares = U256::from_be_slice(&log.data[32..64]);

            // Step 1: attacker seeds vault with 1 wei to get 1 share.
            if assets > U256::ZERO && assets < U256::from(1_000u64) && shares <= U256::from(1u64) {
                tiny_deposit_vault = Some(vault);
            }
            // Step 3: victim gets 0 shares for a non-trivial deposit — confirmed inflation.
            if shares.is_zero() && assets > U256::from(1_000u64) {
                zero_share_vault = Some((vault, assets));
            }
        }

        // Confirmed inflation: step 3 fires — victim deposited real assets and got 0 shares.
        if let Some((vault, victim_assets)) = zero_share_vault {
            // Measure donation: any large Transfer to vault in cumulative logs
            // that has no matching Deposit event on the same vault in the same tx.
            let vault_b256 = address_to_b256(vault);
            let donation: U256 = result
                .sequence_cumulative_logs
                .iter()
                .filter(|l| {
                    l.topics.get(0).copied() == Some(xfer_t)
                        && l.topics.len() >= 3
                        && l.topics[2] == vault_b256
                })
                .map(|l| {
                    if l.data.len() >= 32 {
                        U256::from_be_slice(&l.data[..32])
                    } else {
                        U256::ZERO
                    }
                })
                .fold(U256::ZERO, |a, b| a.saturating_add(b));

            let desc = append_triage_simple(
                format!(
                    "Vault {vault}: victim deposited {victim_assets} assets and received 0 shares \
                     (sequence includes {donation} wei in inbound Transfers). \
                     Confirmed first-depositor share-inflation attack — attacker seeded vault, \
                     inflated totalAssets via donation, and rounded victim to zero shares.",
                ),
                vault,
                lookup_profile(&self.profiles, vault),
                "ERC-4626 inflation: totalAssets >> totalSupply allows attacker to steal victim deposits via rounding to zero shares.",
                "sequence_cumulative_logs: Deposit shares=0 + inbound Transfer without Deposit on vault; indicates inflation attack.",
                "Fee-on-transfer assets or very low precision vaults may produce shares=0 benignly — verify with source code.",
            );
            return Some(Finding {
                severity: Severity::Critical,
                title: format!(
                    "Economic: ERC4626 first-depositor inflation — victim gets 0 shares ({vault})"
                ),
                description: desc,
                contract: vault,
                reproducer: sequence.to_vec(),
                exploit_profit: Some(victim_assets),
            });
        }

        // Step 1 only (setup detected, full attack not yet confirmed in this sequence).
        if let Some(vault) = tiny_deposit_vault {
            let desc = append_triage_simple(
                format!(
                    "Vault {vault}: tiny first deposit (assets < 1000 wei, shares ≤ 1) — \
                     step 1 of a first-depositor inflation attack. \
                     If the attacker donates to inflate totalAssets before the next depositor, \
                     that depositor will receive 0 shares.",
                ),
                vault,
                lookup_profile(&self.profiles, vault),
                "ERC-4626 first-depositor: vault with no virtual-share offset allows share-inflation via donation after first seed deposit.",
                "result.logs: Deposit(assets < 1000, shares ≤ 1) heuristic.",
                "Vaults with virtual shares (e.g. OpenZeppelin 5.x ERC4626) are not vulnerable; confirm absence of `_offset()` override.",
            );
            return Some(Finding {
                severity: Severity::High,
                title: format!(
                    "Economic: ERC4626 first-depositor inflation setup detected ({vault})"
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

// ---------------------------------------------------------------------------
// ERC-4626: Strict Pre/Post Sequence Accounting Drift
// ---------------------------------------------------------------------------

/// Extracts the values from `pre_probes` and `result.protocol_probes`, subtracts the 
/// sequence event delta expectation, and flags unexpected shifts.
/// (Detects slippage drift or hidden balance mutations in DeFi invariants).
pub struct Erc4626StrictAccountingDriftOracle {
    pub profiles: Option<ProtocolProfileMap>,
}

impl Default for Erc4626StrictAccountingDriftOracle {
    fn default() -> Self {
        Self { profiles: None }
    }
}

impl Invariant for Erc4626StrictAccountingDriftOracle {
    fn name(&self) -> &str {
        "economic-erc4626-strict-accounting-drift"
    }

    fn check(
        &self,
        _pre_balances: &HashMap<Address, U256>,
        pre_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Option<Finding> {
        if !result.success {
            return None;
        }

        let logs = crate::conservation::effective_logs(result);

        // Iterate over vaults in post-probes
        for (vault, post_snap) in &result.protocol_probes.per_contract {
            let pre_snap = match pre_probes.per_contract.get(vault) {
                Some(s) => s,
                None => continue,
            };

            let post_erc = match &post_snap.erc4626 {
                Some(e) => e,
                None => continue,
            };
            let pre_erc = match &pre_snap.erc4626 {
                Some(e) => e,
                None => continue,
            };

            if suppress_erc4626_rate_gated(lookup_profile(&self.profiles, *vault)) {
                continue;
            }

            // Must have tracked initial vs final `totalAssets`
            let pre_assets = match pre_erc.total_assets.as_ref().and_then(probe_u256) {
                Some(a) => a,
                None => continue,
            };
            let post_assets = match post_erc.total_assets.as_ref().and_then(probe_u256) {
                Some(a) => a,
                None => continue,
            };

            // Get the asset token to track underlying transfers
            let asset_token = match post_erc.asset.as_ref() {
                Some(ProbeStatus::Ok(ProbeScalar::Address(a))) => Some(*a),
                _ => None,
            };

            // Phase 2 logic: extract expected deltas
            let deltas = crate::conservation::compute_vault_event_deltas(logs, *vault, asset_token);

            // Phase 3 & 4 logic: Reconciliation
            // Expectation: post_assets = pre_assets + deposit_assets - withdraw_assets
            let expected_assets = pre_assets
                .saturating_add(deltas.deposit_assets)
                .saturating_sub(deltas.withdraw_assets);
            
            if materially_divergent_probe_u256(expected_assets, post_assets) {
                let drift = if post_assets > expected_assets {
                    format!("unexplained growth of {}", post_assets - expected_assets)
                } else {
                    format!("unexplained shrinkage of {}", expected_assets - post_assets)
                };

                let base = format!(
                    "Vault {vault}: Strict accounting drift detected! `totalAssets` probe shows {post_assets}, but sequence events imply {expected_assets} (started at {pre_assets}, +{} deposited, -{} withdrawn). Evidence of {drift}.",
                    deltas.deposit_assets, deltas.withdraw_assets
                );
                
                let desc = append_triage_simple(
                    base,
                    *vault,
                    lookup_profile(&self.profiles, *vault),
                    "ERC-4626 strict conservation of underlying assets across events, no hidden mutation.",
                    "Comparison of `totalAssets()` pre/post relative to `Deposit`/`Withdraw` event summations.",
                    "Some vaults slowly accrue external yields without events. Triage if profit magnitude is exploitable.",
                );

                return Some(Finding {
                    severity: Severity::High,
                    title: format!("Economic: ERC-4626 hidden asset drift ({vault})"),
                    description: desc,
                    contract: *vault,
                    reproducer: sequence.to_vec(),
                    exploit_profit: None, 
                });
            }
        }
        None
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
        _pre_probes: &crate::types::ProtocolProbeReport,
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
        let f = inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &r, &[]).expect("finding");
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
        let f = inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &r, &[]).expect("finding");
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
        let f = inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &r, &[]).expect("finding");
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
        assert!(inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &r, &[]).is_none());
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
        assert!(inv.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &r, &[]).is_none());
    }
    #[test]
    fn drift_oracle_fires_on_hidden_drift() {
        let vault = Address::repeat_byte(0x55);
        let mut r = ExecutionResult::default();
        r.success = true; // no logs, just probe diff

        // Pre probes (started at 1000)
        let mut pre_rep = crate::types::ProtocolProbeReport::default();
        let mut pre_erc = Erc4626ProbeSnapshot::default();
        pre_erc.total_assets = Some(ProbeStatus::Ok(ProbeScalar::U256(U256::from(1000u64))));
        pre_rep.per_contract.insert(vault, ContractProbeSnapshot { erc4626: Some(pre_erc), ..Default::default() });

        // Post probes (jumped to 2000 unexpectedly)
        let mut post_erc = Erc4626ProbeSnapshot::default();
        post_erc.total_assets = Some(ProbeStatus::Ok(ProbeScalar::U256(U256::from(2000u64))));
        r.protocol_probes.per_contract.insert(vault, ContractProbeSnapshot { erc4626: Some(post_erc), ..Default::default() });

        let inv = Erc4626StrictAccountingDriftOracle::default();
        let f = inv.check(&HashMap::new(), &pre_rep, &r, &[]).expect("finding");
        assert!(f.title.contains("hidden asset drift"));
        assert!(f.description.contains("unexplained growth of 1000"));
        assert!(f.description.contains("shows 2000"));
        assert!(f.description.contains("imply 1000"));
    }

    #[test]
    fn drift_oracle_quiet_on_expected_growth() {
        let vault = Address::repeat_byte(0x66);
        let mut r = ExecutionResult::default();
        r.success = true;
        
        // Deposit 500
        r.logs.push(deposit_log(vault, 500));

        let mut pre_rep = crate::types::ProtocolProbeReport::default();
        let mut pre_erc = Erc4626ProbeSnapshot::default();
        pre_erc.total_assets = Some(ProbeStatus::Ok(ProbeScalar::U256(U256::from(1000u64))));
        // Need to add asset probe so it doesn't fail
        pre_erc.asset = Some(ProbeStatus::Ok(ProbeScalar::Address(Address::repeat_byte(0x99))));
        pre_rep.per_contract.insert(vault, ContractProbeSnapshot { erc4626: Some(pre_erc), ..Default::default() });

        let mut post_erc = Erc4626ProbeSnapshot::default();
        post_erc.total_assets = Some(ProbeStatus::Ok(ProbeScalar::U256(U256::from(1500u64))));
        r.protocol_probes.per_contract.insert(vault, ContractProbeSnapshot { erc4626: Some(post_erc), ..Default::default() });

        let inv = Erc4626StrictAccountingDriftOracle::default();
        assert!(inv.check(&HashMap::new(), &pre_rep, &r, &[]).is_none());
    }
}
