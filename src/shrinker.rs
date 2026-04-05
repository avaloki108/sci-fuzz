//! Deterministic transaction-sequence shrinking.
//!
//! The shrinker is deliberately simple and practical:
//! - remove prefix / suffix chunks
//! - remove interior transaction chunks
//! - reduce sender churn
//! - reduce `msg.value`
//! - reduce calldata words while preserving selectors when present

use alloy_dyn_abi::{DynSolValue, JsonAbiExt};
use alloy_json_abi::JsonAbi;
use std::collections::HashMap;

use crate::types::{Address, Bytes, Transaction, U256};

/// Deterministic reducer for transaction sequences.
#[derive(Debug, Default, Clone)]
pub struct SequenceShrinker {
    /// Optional ABIs for target contracts, enabling semantic parameter shrinking.
    pub target_abis: HashMap<Address, JsonAbi>,
}

impl SequenceShrinker {
    /// Create a new sequence shrinker.
    pub fn new() -> Self {
        Self {
            target_abis: HashMap::new(),
        }
    }

    /// Set ABIs for semantic shrinking.
    pub fn with_abis(mut self, abis: HashMap<Address, JsonAbi>) -> Self {
        self.target_abis = abis;
        self
    }

    /// Shrink `sequence` while `fails(candidate)` remains true.
    ///
    /// Applies passes in priority order and restarts whenever a pass makes
    /// progress. The first applicable pass wins; order matters because
    /// sequence-length reduction is cheaper than value shrinking.
    ///
    /// New passes vs the original:
    /// - **single-tx delta**: try each tx in isolation first (catches easy 1-tx repros)
    /// - **sender unification**: replace all distinct senders with the first sender
    /// - **per-arg zero sweep**: zero each 32-byte calldata word individually
    /// - **boundary-aware value**: try ETH boundary amounts not just binary halving
    pub fn shrink<F>(&self, sequence: &[Transaction], mut fails: F) -> Vec<Transaction>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        let mut current = sequence.to_vec();
        if !fails(&current) {
            return current;
        }

        // Fast path: try single-tx isolation first.
        if let Some(next) = self.try_single_tx_isolation(&current, &mut fails) {
            current = next;
        }

        loop {
            // Priority 1: remove as much of the sequence as possible.
            if let Some(next) = self.try_remove_prefix(&current, &mut fails) {
                current = next;
                continue;
            }
            if let Some(next) = self.try_remove_suffix(&current, &mut fails) {
                current = next;
                continue;
            }
            if let Some(next) = self.try_remove_chunks(&current, &mut fails) {
                current = next;
                continue;
            }

            // Priority 2: simplify individual transactions.
            if let Some(next) = self.try_simplify_transactions(&current, &mut fails) {
                current = next;
                continue;
            }

            // Priority 3: bulk sender unification (collapses all callers to one).
            if let Some(next) = self.try_unify_senders(&current, &mut fails) {
                current = next;
                continue;
            }

            // Priority 4: per-argument zeroing sweep (one word at a time).
            if let Some(next) = self.try_zero_calldata_args(&current, &mut fails) {
                current = next;
                continue;
            }

            // Priority 5: reorder to expose removable prefix/suffix in next round.
            if let Some(next) = self.try_reorder_transactions(&current, &mut fails) {
                current = next;
                continue;
            }

            break;
        }

        current
    }

    fn try_remove_prefix<F>(
        &self,
        current: &[Transaction],
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        for remove in (1..=current.len()).rev() {
            let candidate = current[remove..].to_vec();
            if fails(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn try_remove_suffix<F>(
        &self,
        current: &[Transaction],
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        for keep in 0..current.len() {
            let candidate = current[..keep].to_vec();
            if fails(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn try_remove_chunks<F>(
        &self,
        current: &[Transaction],
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        if current.len() < 2 {
            return None;
        }

        let mut chunk_len = current.len() / 2;
        while chunk_len >= 1 {
            for start in 0..=current.len().saturating_sub(chunk_len) {
                let mut candidate = Vec::with_capacity(current.len() - chunk_len);
                candidate.extend_from_slice(&current[..start]);
                candidate.extend_from_slice(&current[start + chunk_len..]);
                if fails(&candidate) {
                    return Some(candidate);
                }
            }
            if chunk_len == 1 {
                break;
            }
            chunk_len /= 2;
        }
        None
    }

    fn try_simplify_transactions<F>(
        &self,
        current: &[Transaction],
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        for idx in 0..current.len() {
            if let Some(candidate) = self.try_simplify_sender(current, idx, fails) {
                return Some(candidate);
            }
            if let Some(candidate) = self.try_simplify_value(current, idx, fails) {
                return Some(candidate);
            }
            // Try semantic simplification first if ABI is available
            if let Some(candidate) = self.try_simplify_calldata_semantic(current, idx, fails) {
                return Some(candidate);
            }
            // Fall back to byte-level word shrinking
            if let Some(candidate) = self.try_simplify_calldata(current, idx, fails) {
                return Some(candidate);
            }
        }
        None
    }

    fn try_reorder_transactions<F>(
        &self,
        current: &[Transaction],
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        if current.len() < 2 {
            return None;
        }

        // Try swapping adjacent transactions.
        for i in 0..current.len() - 1 {
            let mut candidate = current.to_vec();
            candidate.swap(i, i + 1);
            if fails(&candidate) {
                return Some(candidate);
            }
        }

        None
    }

    // ---------------------------------------------------------------------------
    // New shrinking passes
    // ---------------------------------------------------------------------------

    /// Try each transaction in isolation — the cheapest possible reproducer.
    ///
    /// If the bug is triggered by a single transaction we can stop immediately
    /// instead of doing expensive chunk bisection.
    fn try_single_tx_isolation<F>(
        &self,
        current: &[Transaction],
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        for i in 0..current.len() {
            let candidate = vec![current[i].clone()];
            if fails(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Replace every distinct sender in the sequence with the sender of the
    /// first transaction — collapses multi-actor sequences to a single actor.
    ///
    /// This dramatically reduces reproducer noise for bugs that don't depend
    /// on caller identity.
    fn try_unify_senders<F>(
        &self,
        current: &[Transaction],
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        if current.is_empty() {
            return None;
        }
        let canonical = current[0].sender;
        let has_variance = current.iter().any(|tx| tx.sender != canonical);
        if !has_variance {
            return None;
        }
        let candidate: Vec<Transaction> = current
            .iter()
            .map(|tx| {
                if tx.sender != canonical {
                    let mut t = tx.clone();
                    t.sender = canonical;
                    t
                } else {
                    tx.clone()
                }
            })
            .collect();
        if fails(&candidate) {
            Some(candidate)
        } else {
            None
        }
    }

    /// Zero each 32-byte calldata argument word individually.
    ///
    /// Works in the raw byte domain (not ABI-decoded) so it applies to all
    /// contracts, not just those with ABIs. Preserves the 4-byte selector.
    /// When a word can be zeroed while the bug still reproduces, we take it.
    fn try_zero_calldata_args<F>(
        &self,
        current: &[Transaction],
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        for tx_idx in 0..current.len() {
            let bytes = current[tx_idx].data.to_vec();
            if bytes.len() <= 4 {
                continue;
            }
            let selector_len = 4usize;
            let arg_bytes = &bytes[selector_len..];
            let n_words = arg_bytes.len() / 32;
            for word_idx in 0..n_words {
                let start = selector_len + word_idx * 32;
                let end = start + 32;
                // Skip already-zero words.
                if bytes[start..end] == [0u8; 32] {
                    continue;
                }
                let mut new_data = bytes.clone();
                new_data[start..end].copy_from_slice(&[0u8; 32]);
                let mut candidate = current.to_vec();
                candidate[tx_idx].data = Bytes::from(new_data);
                if fails(&candidate) {
                    return Some(candidate);
                }
            }
        }
        None
    }

    fn try_simplify_calldata_semantic<F>(
        &self,
        current: &[Transaction],
        idx: usize,
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        let tx = &current[idx];
        let target = tx.to?;
        let abi = self.target_abis.get(&target)?;
        let data = &tx.data;

        if data.len() < 4 {
            return None;
        }

        let selector = &data[..4];
        let function = abi
            .functions()
            .find(|f| f.selector().as_slice() == selector)?;

        let decoded = function.abi_decode_input(&data[4..], true).ok()?;

        for p_idx in 0..decoded.len() {
            let mut params = decoded.clone();
            for simplified_param in self.shrink_dyn_sol_value(&decoded[p_idx]) {
                if simplified_param == decoded[p_idx] {
                    continue;
                }
                params[p_idx] = simplified_param;
                let mut candidate = current.to_vec();
                candidate[idx].data = Bytes::from(function.abi_encode_input(&params).ok()?);
                if fails(&candidate) {
                    return Some(candidate);
                }
            }
        }

        None
    }

    fn shrink_dyn_sol_value(&self, value: &DynSolValue) -> Vec<DynSolValue> {
        let mut out = Vec::new();
        match value {
            DynSolValue::Uint(v, bits) => {
                let shrunk_u256 = shrink_u256_candidates(*v);
                for cand in shrunk_u256 {
                    out.push(DynSolValue::Uint(cand, *bits));
                }
            }
            DynSolValue::Int(v, bits) => {
                use alloy_primitives::I256;
                out.push(DynSolValue::Int(I256::ZERO, *bits));
                if *v != I256::ZERO {
                    out.push(DynSolValue::Int(I256::from_raw(U256::from(1u64)), *bits));
                }
            }
            DynSolValue::Bool(b) => {
                if *b {
                    out.push(DynSolValue::Bool(false));
                }
            }
            DynSolValue::Address(a) => {
                if *a != Address::ZERO {
                    out.push(DynSolValue::Address(Address::ZERO));
                }
            }
            DynSolValue::Array(items) | DynSolValue::FixedArray(items) => {
                if !items.is_empty() {
                    out.push(DynSolValue::Array(Vec::new()));
                }
            }
            DynSolValue::Bytes(b) => {
                if !b.is_empty() {
                    out.push(DynSolValue::Bytes(Vec::new()));
                }
            }
            _ => {}
        }
        out
    }

    fn try_simplify_sender<F>(
        &self,
        current: &[Transaction],
        idx: usize,
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        let tx = &current[idx];
        let mut candidates = Vec::new();
        if idx > 0 {
            if tx.sender != current[idx - 1].sender {
                candidates.push(current[idx - 1].sender);
            }
            if tx.sender != current[0].sender {
                candidates.push(current[0].sender);
            }
        } else if tx.sender != Address::ZERO {
            candidates.push(Address::ZERO);
        }
        dedup_addresses(&mut candidates);

        for sender in candidates {
            if sender == tx.sender {
                continue;
            }
            let mut candidate = current.to_vec();
            candidate[idx].sender = sender;
            if fails(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn try_simplify_value<F>(
        &self,
        current: &[Transaction],
        idx: usize,
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        let tx = &current[idx];
        for value in shrink_u256_candidates(tx.value) {
            if value == tx.value {
                continue;
            }
            let mut candidate = current.to_vec();
            candidate[idx].value = value;
            if fails(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn try_simplify_calldata<F>(
        &self,
        current: &[Transaction],
        idx: usize,
        fails: &mut F,
    ) -> Option<Vec<Transaction>>
    where
        F: FnMut(&[Transaction]) -> bool,
    {
        let tx = &current[idx];
        let bytes = tx.data.to_vec();
        if bytes.is_empty() {
            return None;
        }

        let selector_len = bytes.len().min(4);
        if bytes.len() > selector_len {
            let mut selector_only = bytes[..selector_len].to_vec();
            let mut candidate = current.to_vec();
            candidate[idx].data = Bytes::from(std::mem::take(&mut selector_only));
            if fails(&candidate) {
                return Some(candidate);
            }
        }

        for start in (selector_len..bytes.len()).step_by(32) {
            let end = (start + 32).min(bytes.len());
            let word = &bytes[start..end];
            for replacement in shrink_word_candidates(word) {
                if replacement == word {
                    continue;
                }
                let mut data = bytes.clone();
                data[start..end].copy_from_slice(&replacement);
                let mut candidate = current.to_vec();
                candidate[idx].data = Bytes::from(data);
                if fails(&candidate) {
                    return Some(candidate);
                }
            }
        }

        None
    }
}

fn dedup_addresses(values: &mut Vec<Address>) {
    let mut out = Vec::with_capacity(values.len());
    for value in values.drain(..) {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    *values = out;
}

/// Produce a ranked list of smaller candidates for a U256 value.
///
/// Candidates are ordered cheapest-first so the shrink loop tries the smallest
/// values before falling back to binary bisection.
///
/// - 0 and 1 always come first
/// - Common ETH/token boundary amounts (1 wei, 1 gwei, 0.01 ether … 1000 ether)
/// - Power-of-2 bisection down to 2
fn shrink_u256_candidates(value: U256) -> Vec<U256> {
    let mut out = Vec::new();

    // Always try zero first — if bug fires with 0, that's the cleanest repro.
    out.push(U256::ZERO);

    if value == U256::ZERO {
        return out;
    }

    out.push(U256::from(1u64));

    // ETH / token boundary amounts — common in DeFi bugs (flash loans, inflation, rounding).
    const BOUNDARIES: &[u128] = &[
        1,                            // 1 wei
        1_000,                        // 1 kwei
        1_000_000,                    // 1 mwei
        1_000_000_000,                // 1 gwei
        1_000_000_000_000,            // 1 microether
        1_000_000_000_000_000,        // 0.001 ether / 1 finney
        10_000_000_000_000_000,       // 0.01 ether
        100_000_000_000_000_000,      // 0.1 ether
        1_000_000_000_000_000_000,    // 1 ether
        10_000_000_000_000_000_000,   // 10 ether
        100_000_000_000_000_000_000,  // 100 ether
        // Common ERC20 base-unit amounts (18 decimals)
        1_000_000_000_000_000_000_000,         // 1000 tokens
        1_000_000_000_000_000_000_000_000,     // 1e6 tokens
    ];
    for &b in BOUNDARIES {
        let v = U256::from(b);
        if v < value {
            out.push(v);
        }
    }

    // Binary bisection from value/2 down to 2.
    let two = U256::from(2u64);
    let mut cur = value / two;
    while cur > U256::from(1u64) {
        out.push(cur);
        cur /= two;
    }

    dedup_u256(&mut out);
    out
}

fn dedup_u256(values: &mut Vec<U256>) {
    let mut out = Vec::with_capacity(values.len());
    for value in values.drain(..) {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    *values = out;
}

fn shrink_word_candidates(word: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let value = U256::from_be_slice(word);
    out.push(vec![0u8; word.len()]);

    if !word.is_empty() && value > U256::ZERO {
        let mut one = vec![0u8; word.len()];
        one[word.len() - 1] = 1;
        out.push(one);
    }

    if !word.is_empty() {
        for candidate in shrink_u256_candidates(value) {
            let bytes = candidate.to_be_bytes::<32>();
            out.push(bytes[32 - word.len()..].to_vec());
        }
    }

    dedup_vecs(&mut out);
    out
}

fn dedup_vecs(values: &mut Vec<Vec<u8>>) {
    let mut out = Vec::with_capacity(values.len());
    for value in values.drain(..) {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    *values = out;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(sender: u8, to: u8, selector: [u8; 4], word: u64, value: u64) -> Transaction {
        let mut data = selector.to_vec();
        let mut word_bytes = [0u8; 32];
        word_bytes[24..].copy_from_slice(&word.to_be_bytes());
        data.extend_from_slice(&word_bytes);

        Transaction {
            sender: Address::with_last_byte(sender),
            to: Some(Address::with_last_byte(to)),
            data: Bytes::from(data),
            value: U256::from(value),
            gas_limit: 30_000_000,
        }
    }

    #[test]
    fn shrinker_reduces_longer_failing_sequence() {
        let shrinker = SequenceShrinker::new();
        let selector = [0xde, 0xad, 0xbe, 0xef];
        let target = Address::with_last_byte(0xAA);
        let initial = vec![
            tx(0x01, 0x10, selector, 0x9999, 7),
            tx(0x02, 0xAA, selector, 0x80, 100),
            tx(0x03, 0x20, selector, 0x9999, 9),
            tx(0x04, 0x30, selector, 0x9999, 11),
        ];

        let shrunk = shrinker.shrink(&initial, |seq| {
            seq.iter().any(|tx| {
                tx.to == Some(target)
                    && tx.data.len() >= 36
                    && tx.data[..4] == selector
                    && U256::from_be_slice(&tx.data[4..36]) <= U256::from(0x80u64)
                    && tx.value <= U256::from(100u64)
            })
        });

        assert!(shrunk.len() < initial.len(), "sequence should get shorter");
        assert_eq!(shrunk.len(), 1, "only the interesting tx should remain");
        assert_eq!(shrunk[0].to, Some(target));
        assert_eq!(shrunk[0].data[..4], selector);
        assert_eq!(U256::from_be_slice(&shrunk[0].data[4..36]), U256::ZERO);
        assert_eq!(shrunk[0].value, U256::ZERO);
    }

    #[test]
    fn shrinker_reduces_sender_changes_when_length_must_stay() {
        let shrinker = SequenceShrinker::new();
        let selector = [0xca, 0xfe, 0xba, 0xbe];
        let initial = vec![
            tx(0x11, 0x10, selector, 0, 0),
            tx(0x22, 0xAA, selector, 5, 0),
        ];

        let shrunk = shrinker.shrink(&initial, |seq| {
            seq.len() == 2
                && seq[0].sender == Address::with_last_byte(0x11)
                && seq[1].to == Some(Address::with_last_byte(0xAA))
        });

        assert_eq!(shrunk.len(), 2);
        assert_eq!(shrunk[1].sender, shrunk[0].sender);
    }

    #[test]
    fn single_tx_isolation_finds_repro_immediately() {
        let shrinker = SequenceShrinker::new();
        let sel = [0xde, 0xad, 0xbe, 0xef];
        let bad_target = Address::with_last_byte(0xBB);
        let initial = vec![
            tx(0x01, 0xAA, sel, 0, 0),
            tx(0x02, 0xBB, sel, 1, 0), // the interesting one
            tx(0x03, 0xCC, sel, 0, 0),
            tx(0x04, 0xDD, sel, 0, 0),
        ];

        let shrunk = shrinker.shrink(&initial, |seq| {
            seq.iter().any(|t| t.to == Some(bad_target))
        });

        assert_eq!(shrunk.len(), 1, "should isolate to 1 tx");
        assert_eq!(shrunk[0].to, Some(bad_target));
    }

    #[test]
    fn sender_unification_collapses_to_single_actor() {
        let shrinker = SequenceShrinker::new();
        let sel = [0x11, 0x22, 0x33, 0x44];
        // Bug fires whenever both txs have same target and sequence length = 2.
        // It doesn't care about senders, so they should be unified.
        let target = Address::with_last_byte(0xAA);
        let initial = vec![
            tx(0x11, 0xAA, sel, 0, 0),
            tx(0x22, 0xAA, sel, 0, 0),
        ];

        let shrunk = shrinker.shrink(&initial, |seq| {
            seq.len() == 2 && seq.iter().all(|t| t.to == Some(target))
        });

        assert_eq!(shrunk.len(), 2);
        assert_eq!(shrunk[0].sender, shrunk[1].sender, "senders should be unified");
    }

    #[test]
    fn zero_calldata_args_zeroes_irrelevant_words() {
        let shrinker = SequenceShrinker::new();
        let sel = [0xAB, 0xCD, 0xEF, 0x01];
        // Bug: selector matches + word[0] == 999 (word[1] value irrelevant).
        let mut data = sel.to_vec();
        let mut word0 = [0u8; 32];
        word0[31] = 231; // 999 = 0x03E7 → [0]*30 + [0x03, 0xE7]
        word0[30] = 3;
        let word1 = [0xFFu8; 32]; // noisy word that should get zeroed
        data.extend_from_slice(&word0);
        data.extend_from_slice(&word1);

        let initial = vec![Transaction {
            sender: Address::ZERO,
            to: Some(Address::with_last_byte(0xAA)),
            data: Bytes::from(data),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        }];

        let shrunk = shrinker.shrink(&initial, |seq| {
            if seq.is_empty() || seq[0].data.len() < 68 {
                return false;
            }
            let word = U256::from_be_slice(&seq[0].data[4..36]);
            // Bug depends only on word0 >= 999 — word1 is irrelevant.
            seq[0].data[..4] == sel && word >= U256::from(999u64)
        });

        assert_eq!(shrunk.len(), 1);
        // word1 (bytes 36..68) should be zeroed
        assert_eq!(&shrunk[0].data[36..68], &[0u8; 32]);
    }

    #[test]
    fn value_shrinks_to_eth_boundary() {
        // 3 ether should shrink toward 1 ether boundary, not just halve blindly.
        let shrinker = SequenceShrinker::new();
        let sel = [0xd0, 0xe3, 0x0d, 0xb0]; // deposit()
        let one_ether: u64 = 1_000_000_000_000_000_000;
        let initial = vec![Transaction {
            sender: Address::ZERO,
            to: Some(Address::with_last_byte(0xAA)),
            data: Bytes::from(sel.to_vec()),
            value: U256::from(3u64) * U256::from(one_ether),
            gas_limit: 30_000_000,
        }];

        // Bug fires when value >= 1 ether.
        let shrunk = shrinker.shrink(&initial, |seq| {
            !seq.is_empty() && seq[0].value >= U256::from(one_ether)
        });

        assert_eq!(shrunk.len(), 1);
        assert_eq!(shrunk[0].value, U256::from(one_ether), "should shrink to 1 ether boundary");
    }
}
