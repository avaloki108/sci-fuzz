//! CmpLog-guided mutation (Redqueen-style).
//!
//! Reads `ComparisonEvent`s from recent execution results and substitutes
//! comparison operands directly into calldata — breaking through
//! `require(x == specificValue)` barriers without brute force.
//!
//! ## How it works
//!
//! During EVM execution, the `CoverageInspector` in `evm.rs` intercepts
//! every `EQ`, `LT`, `GT`, `SLT`, `SGT`, and `ISZERO` opcode and records
//! the two operand values as a `ComparisonEvent`.
//!
//! The CmpLogMutator takes those events and:
//! 1. Extracts the `rhs` operand (the "target" value being compared against)
//! 2. Encodes it as a 32-byte big-endian word
//! 3. Finds that word (or a prefix of it) in the transaction calldata
//! 4. Replaces it with the `lhs` (or `rhs`) to try to satisfy the comparison
//!
//! Even without precise dataflow tracking, substituting comparison operands
//! into calldata significantly increases the chance of passing `require`
//! checks that guard interesting code paths.

use std::borrow::Cow;

use rand::{Rng, SeedableRng, rngs::StdRng};

use libafl::{
    Error,
    corpus::CorpusId,
    mutators::{MutationResult, Mutator},
};
use libafl_bolts::Named;

use crate::{
    types::{Bytes, ComparisonEvent, CmpOpcodeKind, Transaction, U256},
    libafl_adapter::input::EvmInput,
};

// ── CmpLogMutator ─────────────────────────────────────────────────────────────

/// CmpLog-guided mutator: substitutes comparison operands into calldata.
///
/// Feed it `ComparisonEvent`s from recent executions and it will try to
/// satisfy comparisons by rewriting calldata words.
pub struct CmpLogMutator {
    /// Ring buffer of comparison events from recent executions.
    events: Vec<ComparisonEvent>,
    /// Max events to retain (bounded to avoid context explosion).
    max_events: usize,
    rng: StdRng,
}

impl CmpLogMutator {
    /// Create a new CmpLogMutator with the given event capacity.
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Vec::with_capacity(max_events),
            max_events: max_events.max(1),
            rng: StdRng::from_entropy(),
        }
    }

    /// Feed new comparison events from an execution result.
    ///
    /// Call this after each execution so the mutator has fresh data.
    pub fn feed(&mut self, new_events: &[ComparisonEvent]) {
        for ev in new_events {
            if self.events.len() >= self.max_events {
                // Ring-buffer: drop oldest.
                self.events.remove(0);
            }
            self.events.push(ev.clone());
        }
    }

    /// Clear all stored events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Number of stored events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True if no events are stored.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl Named for CmpLogMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CmpLogMutator");
        &NAME
    }
}

impl<S> Mutator<EvmInput, S> for CmpLogMutator {
    fn mutate(&mut self, _state: &mut S, input: &mut EvmInput) -> Result<MutationResult, Error> {
        if self.events.is_empty() || input.transactions.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // Pick a random comparison event.
        let ev = &self.events[self.rng.gen_range(0..self.events.len())].clone();

        // Pick a random transaction to mutate.
        let tx_idx = self.rng.gen_range(0..input.transactions.len());
        let tx = &mut input.transactions[tx_idx];

        // Try to substitute the comparison operand into calldata.
        let mutated = match ev.kind {
            // For EQ: try substituting rhs into calldata so lhs == rhs.
            CmpOpcodeKind::Eq => {
                try_substitute_word(tx, ev.rhs)
                    || try_substitute_word(tx, ev.lhs)
            }
            // For LT/SLT: try substituting rhs - 1 (boundary condition).
            CmpOpcodeKind::Lt | CmpOpcodeKind::Slt => {
                let target = ev.rhs.saturating_sub(U256::from(1u64));
                try_substitute_word(tx, target)
                    || try_substitute_word(tx, ev.rhs)
            }
            // For GT/SGT: try substituting rhs + 1 (boundary condition).
            CmpOpcodeKind::Gt | CmpOpcodeKind::Sgt => {
                let target = ev.rhs.saturating_add(U256::from(1u64));
                try_substitute_word(tx, target)
                    || try_substitute_word(tx, ev.rhs)
            }
            // For ISZERO: try substituting 0 to trigger the zero branch.
            CmpOpcodeKind::IsZero => {
                try_substitute_word(tx, U256::ZERO)
                    || try_substitute_word(tx, ev.lhs)
            }
        };

        if mutated {
            Ok(MutationResult::Mutated)
        } else {
            // Fallback: directly append the value to calldata.
            // This seeds the dictionary even if no exact match was found.
            let word = u256_to_be_bytes(ev.rhs);
            let mut data = tx.data.to_vec();
            // Replace the last 32 bytes if calldata is long enough,
            // otherwise append (skip 4-byte selector if present).
            if data.len() >= 36 {
                let insert_at = 4 + ((data.len() - 4) / 32).saturating_sub(1) * 32;
                let end = (insert_at + 32).min(data.len());
                data[insert_at..end].copy_from_slice(&word[..end - insert_at]);
            } else if data.len() >= 4 {
                data.extend_from_slice(&word);
            }
            tx.data = Bytes::from(data);
            Ok(MutationResult::Mutated)
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Try to find the 32-byte encoding of `value` (or a 4+ byte prefix) in
/// `tx.data` and replace it with the exact value.
///
/// Returns `true` if a substitution was made.
fn try_substitute_word(tx: &mut Transaction, value: U256) -> bool {
    let word = u256_to_be_bytes(value);
    let data = tx.data.to_vec();

    // Skip the 4-byte selector — ABI arguments start at byte 4.
    if data.len() < 8 {
        return false;
    }

    let args = &data[4..];

    // Scan for 32-byte aligned slots containing a prefix match (≥ 4 bytes).
    let slots = args.len() / 32;
    for i in 0..slots {
        let slot = &args[i * 32..(i + 1) * 32];
        // Check if at least 4 bytes match at some offset within the slot.
        if slot_prefix_matches(slot, &word) {
            // Replace entire 32-byte slot with the target value.
            let mut new_data = data.clone();
            let offset = 4 + i * 32;
            new_data[offset..offset + 32].copy_from_slice(&word);
            tx.data = Bytes::from(new_data);
            return true;
        }
    }

    false
}

/// Returns true if `slot` contains at least 4 consecutive bytes of `word`
/// anywhere within it. This is intentionally fuzzy — we want to match
/// even if the value is sign-extended or zero-padded differently.
fn slot_prefix_matches(slot: &[u8], word: &[u8; 32]) -> bool {
    // Try matching the last 4+ significant bytes of `word` within `slot`.
    // Find first non-zero byte in word.
    let first_nonzero = word.iter().position(|&b| b != 0).unwrap_or(28);
    let sig_len = (32 - first_nonzero).min(32);
    if sig_len < 4 {
        return false; // value too small to reliably match
    }
    let sig = &word[first_nonzero..];

    // Search for sig as a substring of slot.
    slot.windows(sig.len().min(slot.len()))
        .any(|w| w == &sig[..w.len()])
}

/// Encode a `U256` as 32 big-endian bytes.
fn u256_to_be_bytes(v: U256) -> [u8; 32] {
    v.to_be_bytes()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Address;

    fn mock_event(kind: CmpOpcodeKind, lhs: u64, rhs: u64) -> ComparisonEvent {
        ComparisonEvent {
            contract: Address::with_last_byte(0x01),
            call_depth: 0,
            pc: 42,
            kind,
            lhs: U256::from(lhs),
            rhs: U256::from(rhs),
        }
    }

    fn input_with_value(encoded_val: u64) -> EvmInput {
        // Build ABI-encoded calldata: selector (4 bytes) + uint256 arg (32 bytes)
        let mut data = vec![0xaa, 0xbb, 0xcc, 0xdd]; // selector
        let word = U256::from(encoded_val).to_be_bytes::<32>();
        data.extend_from_slice(&word);
        EvmInput::new(vec![Transaction {
            sender: Address::with_last_byte(0x10),
            to: Some(Address::with_last_byte(0x01)),
            data: Bytes::from(data),
            value: U256::ZERO,
            gas_limit: 100_000,
        }])
    }

    #[test]
    fn cmplog_mutator_feeds_events() {
        let mut m = CmpLogMutator::new(100);
        assert!(m.is_empty());
        m.feed(&[mock_event(CmpOpcodeKind::Eq, 1, 42)]);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn cmplog_mutator_skips_empty() {
        let mut m = CmpLogMutator::new(100);
        let mut inp = EvmInput::empty();
        assert_eq!(m.mutate(&mut (), &mut inp).unwrap(), MutationResult::Skipped);
    }

    #[test]
    fn cmplog_mutator_skips_no_events() {
        let mut m = CmpLogMutator::new(100);
        let mut inp = input_with_value(1);
        assert_eq!(m.mutate(&mut (), &mut inp).unwrap(), MutationResult::Skipped);
    }

    #[test]
    fn cmplog_mutator_substitutes_eq_value() {
        // Calldata encodes value=1. EQ comparison: lhs=1, rhs=0x539 (1337).
        // Mutator should substitute 0x539 into calldata.
        let mut m = CmpLogMutator::new(100);
        m.feed(&[mock_event(CmpOpcodeKind::Eq, 1, 1337)]);

        let original = input_with_value(1);
        let mut inp = original.clone();

        // Run up to 50 times — should substitute at least once.
        let mut found = false;
        for _ in 0..50 {
            let mut i = original.clone();
            m.mutate(&mut (), &mut i).unwrap();
            let data = &i.transactions[0].data;
            // Check if 1337 (0x0...0539) appears in calldata.
            if data.windows(4).any(|w| w == [0x00, 0x00, 0x05, 0x39]) {
                found = true;
                break;
            }
        }
        assert!(found, "CmpLogMutator should have substituted 1337 into calldata within 50 tries");
    }

    #[test]
    fn cmplog_ring_buffer_bounded() {
        let mut m = CmpLogMutator::new(3);
        for i in 0..10 {
            m.feed(&[mock_event(CmpOpcodeKind::Eq, i, i + 1)]);
        }
        assert_eq!(m.len(), 3, "ring buffer should be bounded at max_events");
    }

    #[test]
    fn u256_to_be_bytes_roundtrip() {
        let v = U256::from(0xdeadbeef_u64);
        let bytes = u256_to_be_bytes(v);
        let back = U256::from_be_bytes(bytes);
        assert_eq!(v, back);
    }
}
