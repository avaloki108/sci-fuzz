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
}
