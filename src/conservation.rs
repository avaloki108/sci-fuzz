//! Observable reserve and flow helpers for conservation-style oracles.
//!
//! These are **heuristic** reconciliations over execution logs (and optional probes),
//! not formal verification of constant-product invariants or full DeFi economics.

use crate::protocol_semantics::{
    topic_uni_v2_burn, topic_uni_v2_mint, topic_uni_v2_swap, topic_uni_v2_sync, u112_from_word,
};
use crate::types::{ExecutionResult, Log, U256};

/// Choose logs for multi-step vs single-tx reasoning (matches economic oracles).
///
/// When the campaign fills [`ExecutionResult::sequence_cumulative_logs`], use it so
/// checks see the full sequence; otherwise use this transaction’s [`ExecutionResult::logs`].
pub fn effective_logs(result: &ExecutionResult) -> &[Log] {
    if !result.sequence_cumulative_logs.is_empty() {
        result.sequence_cumulative_logs.as_slice()
    } else {
        result.logs.as_slice()
    }
}

/// Parsed Uniswap V2–style `Sync` reserves for a pair log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReserves {
    pub reserve0: U256,
    pub reserve1: U256,
}

/// Parse `Sync(uint112,uint112)` data payload (first two words).
pub fn parse_sync_reserves(log: &Log) -> Option<SyncReserves> {
    let sync_t = topic_uni_v2_sync();
    if log.topics.first().copied() != Some(sync_t) || log.data.len() < 64 {
        return None;
    }
    Some(SyncReserves {
        reserve0: u112_from_word(&log.data[..32]),
        reserve1: u112_from_word(&log.data[32..64]),
    })
}

/// Whether `log` looks like a V2–shaped Swap, Mint, or Burn on `pair`.
pub fn is_v2_swap_mint_or_burn(pair: &crate::types::Address, log: &Log) -> bool {
    if log.address != *pair {
        return false;
    }
    let t0 = log.topics.first().copied();
    matches!(
        t0,
        Some(t)
            if t == topic_uni_v2_swap()
                || t == topic_uni_v2_mint()
                || t == topic_uni_v2_burn()
    )
}

/// Unexplained reserve change between two `Sync` events for the same pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairSyncUnexplainedChange {
    pub pair: crate::types::Address,
    pub prev_log_index: usize,
    pub cur_log_index: usize,
    pub prev: SyncReserves,
    pub cur: SyncReserves,
}

/// If reserves change between consecutive `Sync` logs for the same pair address,
/// require at least one intervening Swap/Mint/Burn on that pair in **strict log order**.
///
/// Returns the first anomaly in traversal order, if any.
pub fn first_pair_sync_change_missing_explanation(
    logs: &[Log],
) -> Option<PairSyncUnexplainedChange> {
    let sync_t = topic_uni_v2_sync();
    let mut last_sync: std::collections::HashMap<crate::types::Address, (usize, SyncReserves)> =
        std::collections::HashMap::new();

    for (i, log) in logs.iter().enumerate() {
        if log.topics.first().copied() != Some(sync_t) {
            continue;
        }
        let Some(cur) = parse_sync_reserves(log) else {
            continue;
        };
        let pair = log.address;

        if let Some((prev_i, prev)) = last_sync.get(&pair).copied() {
            if prev != cur {
                let mut explained = false;
                for log_b in logs.iter().take(i).skip(prev_i + 1) {
                    if is_v2_swap_mint_or_burn(&pair, log_b) {
                        explained = true;
                        break;
                    }
                }
                if !explained {
                    return Some(PairSyncUnexplainedChange {
                        pair,
                        prev_log_index: prev_i,
                        cur_log_index: i,
                        prev,
                        cur,
                    });
                }
            }
        }
        last_sync.insert(pair, (i, cur));
    }
    None
}

/// Summed values from `Deposit`, `Withdraw`, and `Transfer` logs targeting a specific vault
/// over a sequence of execution logs. This "expectation" forms the event-implied intent
/// for later comparison against probe-deltas (Phase 2).
#[derive(Debug, Clone, Default)]
pub struct VaultEventDeltas {
    pub deposit_assets: U256,
    pub deposit_shares: U256,
    pub withdraw_assets: U256,
    pub withdraw_shares: U256,
    /// Sum of all `Transfer(from, vault, amount)` observed in the logs on the tracked asset.
    pub asset_transfers_in: U256,
    /// Sum of all `Transfer(vault, to, amount)` observed in the logs on the tracked asset.
    pub asset_transfers_out: U256,
}

/// Parses cumulative logs to form a strict event-sum expectation of asset/share movements for a vault.
pub fn compute_vault_event_deltas(
    logs: &[Log],
    vault: crate::types::Address,
    asset_token: Option<crate::types::Address>,
) -> VaultEventDeltas {
    use crate::economic::address_to_b256;
    use crate::protocol_semantics::{
        topic_erc20_transfer, topic_erc4626_deposit, topic_erc4626_withdraw,
    };

    let dep_t = topic_erc4626_deposit();
    let wit_t = topic_erc4626_withdraw();
    let xfer_t = topic_erc20_transfer();
    let vault_b256 = address_to_b256(vault);

    let mut deltas = VaultEventDeltas::default();

    for log in logs {
        let topic0 = match log.topics.first().copied() {
            Some(t) => t,
            None => continue,
        };

        if log.address == vault {
            if topic0 == dep_t && log.data.len() >= 64 {
                let assets = U256::from_be_slice(&log.data[..32]);
                let shares = U256::from_be_slice(&log.data[32..64]);
                deltas.deposit_assets = deltas.deposit_assets.saturating_add(assets);
                deltas.deposit_shares = deltas.deposit_shares.saturating_add(shares);
            } else if topic0 == wit_t && log.data.len() >= 64 {
                let assets = U256::from_be_slice(&log.data[..32]);
                let shares = U256::from_be_slice(&log.data[32..64]);
                deltas.withdraw_assets = deltas.withdraw_assets.saturating_add(assets);
                deltas.withdraw_shares = deltas.withdraw_shares.saturating_add(shares);
            }
        }

        if let Some(asset) = asset_token {
            if log.address == asset && topic0 == xfer_t && log.topics.len() >= 3 && log.data.len() >= 32 {
                let from = log.topics[1];
                let to = log.topics[2];
                let amount = U256::from_be_slice(&log.data[..32]);

                if to == vault_b256 {
                    deltas.asset_transfers_in = deltas.asset_transfers_in.saturating_add(amount);
                }
                if from == vault_b256 {
                    deltas.asset_transfers_out = deltas.asset_transfers_out.saturating_add(amount);
                }
            }
        }
    }

    deltas
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Bytes, B256};

    fn sync_log(pair: Address, r0: u64, r1: u64) -> Log {
        let sync_t = topic_uni_v2_sync();
        let mut data = [0u8; 64];
        // u112 lives in the last 14 bytes of each 32-byte word (`u112_from_word`).
        data[31] = r0 as u8;
        data[63] = r1 as u8;
        Log {
            address: pair,
            topics: vec![sync_t],
            data: Bytes::copy_from_slice(&data),
        }
    }

    fn swap_log(pair: Address) -> Log {
        Log {
            address: pair,
            topics: vec![topic_uni_v2_swap(), B256::ZERO, B256::ZERO],
            data: Bytes::copy_from_slice(&[0u8; 128]),
        }
    }

    #[test]
    fn effective_logs_prefers_cumulative_when_present() {
        let mut r = ExecutionResult::default();
        let a = Log {
            address: Address::ZERO,
            topics: vec![topic_uni_v2_sync()],
            data: Bytes::copy_from_slice(&[0u8; 64]),
        };
        r.logs.push(a.clone());
        assert_eq!(effective_logs(&r).len(), 1);

        let mut b = a.clone();
        b.address = Address::repeat_byte(1);
        r.sequence_cumulative_logs = vec![a, b];
        assert_eq!(effective_logs(&r).len(), 2);
    }

    #[test]
    fn two_syncs_reserve_change_without_swap_fires() {
        let pair = Address::repeat_byte(0xAA);
        let logs = vec![sync_log(pair, 10, 10), sync_log(pair, 20, 20)];
        let a = first_pair_sync_change_missing_explanation(&logs);
        assert!(a.is_some());
        let a = a.unwrap();
        assert_eq!(a.pair, pair);
        assert_eq!(a.prev.reserve0, U256::from(10u64));
        assert_eq!(a.cur.reserve1, U256::from(20u64));
    }

    #[test]
    fn sync_swap_sync_no_fire() {
        let pair = Address::repeat_byte(0xBB);
        let logs = vec![
            sync_log(pair, 10, 10),
            swap_log(pair),
            sync_log(pair, 20, 20),
        ];
        assert!(first_pair_sync_change_missing_explanation(&logs).is_none());
    }

    #[test]
    fn identical_sync_twice_no_fire() {
        let pair = Address::repeat_byte(0xCC);
        let logs = vec![sync_log(pair, 5, 5), sync_log(pair, 5, 5)];
        assert!(first_pair_sync_change_missing_explanation(&logs).is_none());
    }

    #[test]
    fn compute_vault_event_deltas_correctness() {
        use crate::protocol_semantics::{topic_erc20_transfer, topic_erc4626_deposit, topic_erc4626_withdraw};
        use crate::economic::address_to_b256;
        
        let vault = Address::repeat_byte(0x11);
        let asset = Address::repeat_byte(0x22);

        let mut dr = [0u8; 64];
        dr[24..32].copy_from_slice(&1000u64.to_be_bytes()); // assets
        dr[56..64].copy_from_slice(&900u64.to_be_bytes());  // shares
        let deposit_log = Log {
            address: vault,
            topics: vec![topic_erc4626_deposit(), B256::ZERO, B256::ZERO],
            data: Bytes::copy_from_slice(&dr),
        };

        let mut wr = [0u8; 64];
        wr[24..32].copy_from_slice(&500u64.to_be_bytes()); // assets
        wr[56..64].copy_from_slice(&450u64.to_be_bytes()); // shares
        let withdraw_log = Log {
            address: vault,
            topics: vec![topic_erc4626_withdraw(), B256::ZERO, B256::ZERO, B256::ZERO],
            data: Bytes::copy_from_slice(&wr),
        };

        let transfer_in = Log {
            address: asset,
            topics: vec![topic_erc20_transfer(), B256::ZERO, address_to_b256(vault)],
            data: Bytes::copy_from_slice(&U256::from(1000u64).to_be_bytes::<32>()),
        };

        let transfer_out = Log {
            address: asset,
            topics: vec![topic_erc20_transfer(), address_to_b256(vault), B256::ZERO],
            data: Bytes::copy_from_slice(&U256::from(500u64).to_be_bytes::<32>()),
        };

        // Some unrelated log
        let unrelated = sync_log(Address::repeat_byte(0x99), 10, 10);

        let logs = vec![deposit_log, transfer_in, withdraw_log, transfer_out, unrelated];
        let deltas = compute_vault_event_deltas(&logs, vault, Some(asset));

        assert_eq!(deltas.deposit_assets, U256::from(1000u64));
        assert_eq!(deltas.deposit_shares, U256::from(900u64));
        assert_eq!(deltas.withdraw_assets, U256::from(500u64));
        assert_eq!(deltas.withdraw_shares, U256::from(450u64));
        assert_eq!(deltas.asset_transfers_in, U256::from(1000u64));
        assert_eq!(deltas.asset_transfers_out, U256::from(500u64));
    }
}
