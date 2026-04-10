//! LibAFL `Input` + `Observer` + `Executor` adapter for chimerafuzz.
//!
//! Phase 1 (this file): `EvmInput` — wraps `Vec<Transaction>` and implements
//! LibAFL's `Input` trait so LibAFL's corpus/scheduler/mutators can operate
//! on EVM transaction sequences.
//!
//! Phase 2 (observer.rs): `EvmCoverageObserver` — maps chimerafuzz coverage
//! feedback to LibAFL's `MapObserver` for `MaxMapFeedback`.
//!
//! Phase 2 (executor.rs): `LibAflEvmExecutor` — implements `Executor` and
//! wraps `EvmExecutor`, running sequences and collecting coverage + findings.

use std::vec::Vec;
use std::string::String;
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
};

use libafl::inputs::Input;
use libafl_bolts::HasLen;
use serde::{Deserialize, Serialize};

use crate::types::Transaction;

// ── EvmInput ─────────────────────────────────────────────────────────────────

/// A LibAFL `Input` wrapping an ordered sequence of EVM transactions.
///
/// This is the core unit that LibAFL's corpus, scheduler, and mutators
/// operate on. Each `EvmInput` represents one fuzzing test case: a series
/// of transactions executed sequentially in a snapshot-restored EVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmInput {
    /// Ordered list of transactions to execute.
    pub transactions: Vec<Transaction>,
}

impl EvmInput {
    /// Create a new `EvmInput` from a transaction sequence.
    pub fn new(transactions: Vec<Transaction>) -> Self {
        Self { transactions }
    }

    /// Create an empty input (zero transactions).
    pub fn empty() -> Self {
        Self {
            transactions: Vec::new(),
        }
    }

    /// Number of transactions in this input.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// True if the input has no transactions.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

/// `Hash` is required by LibAFL's `Input` trait bound.
///
/// We delegate to `std::hash::Hash` on each field of `Transaction`.
/// `Transaction` now derives `Hash`, so this is straightforward.
impl Hash for EvmInput {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.transactions.hash(state);
    }
}

/// LibAFL `HasLen` trait — used by the minimizer scheduler to prefer shorter inputs.
impl HasLen for EvmInput {
    fn len(&self) -> usize {
        self.transactions.len()
    }
}

/// LibAFL `Input` trait — enables corpus storage, file I/O, and naming.
///
/// Default `to_file`/`from_file` use `postcard` serialization (LibAFL default).
/// We override `generate_name` to include the sequence length for readability.
impl Input for EvmInput {
    fn generate_name(&self, id: Option<libafl::corpus::CorpusId>) -> String {
        use libafl_bolts::generic_hash_std;
        let h = generic_hash_std(self);
        match id {
            Some(cid) => format!("evm_{cid:08}_{h:016x}_len{}", self.transactions.len()),
            None => format!("evm_{h:016x}_len{}", self.transactions.len()),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Bytes, U256};

    fn sample_tx() -> Transaction {
        Transaction {
            sender: Address::with_last_byte(0x01),
            to: Some(Address::with_last_byte(0x02)),
            data: Bytes::from(vec![0xaa, 0xbb, 0xcc, 0xdd]),
            value: U256::ZERO,
            gas_limit: 100_000,
        }
    }

    #[test]
    fn evm_input_roundtrip_serde_json() {
        let input = EvmInput::new(vec![sample_tx(), sample_tx()]);
        let encoded = serde_json::to_vec(&input).expect("serialize");
        let decoded: EvmInput = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(input.len(), decoded.len());
        assert_eq!(input.transactions[0].sender, decoded.transactions[0].sender);
        assert_eq!(input.transactions[0].data, decoded.transactions[0].data);
    }

    #[test]
    fn evm_input_roundtrip_json() {
        let input = EvmInput::new(vec![sample_tx()]);
        let json = serde_json::to_string(&input).expect("json serialize");
        let decoded: EvmInput = serde_json::from_str(&json).expect("json deserialize");
        assert_eq!(input.len(), decoded.len());
        assert_eq!(input.transactions[0].gas_limit, decoded.transactions[0].gas_limit);
    }

    #[test]
    fn evm_input_hash_stable() {
        use std::collections::hash_map::DefaultHasher;
        let input = EvmInput::new(vec![sample_tx()]);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        input.hash(&mut h1);
        input.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish(), "hash must be deterministic");
    }

    #[test]
    fn evm_input_different_hash() {
        use std::collections::hash_map::DefaultHasher;
        let a = EvmInput::new(vec![sample_tx()]);
        let mut tx2 = sample_tx();
        tx2.value = U256::from(1_000u64);
        let b = EvmInput::new(vec![tx2]);
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_ne!(ha.finish(), hb.finish(), "different inputs must hash differently");
    }

    #[test]
    fn generate_name_contains_len() {
        let input = EvmInput::new(vec![sample_tx(), sample_tx(), sample_tx()]);
        let name = input.generate_name(None);
        assert!(name.contains("len3"), "name should contain sequence length: {name}");
    }

    #[test]
    fn empty_input() {
        let input = EvmInput::empty();
        assert!(input.is_empty());
        assert_eq!(input.len(), 0);
    }
}
