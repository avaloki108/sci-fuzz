//! LibAFL `Mutator` implementations for chimerafuzz.
//!
//! Each mutator wraps a specific strategy from `TxMutator` and exposes it
//! as a LibAFL `Mutator<EvmInput, S>`. They can be combined via LibAFL's
//! `StdScheduledMutator` for adaptive mutation scheduling.
//!
//! ## Mutators
//!
//! | Mutator | Strategy | Source |
//! |---------|----------|--------|
//! | `AbiCalldataMutator` | ABI-aware selector + arg mutation | `TxMutator::mutate` |
//! | `SenderValueMutator` | Address + ETH value mutation | `TxMutator::mutate` |
//! | `SequenceStructureMutator` | Insert / remove / swap transactions | `TxMutator::mutate_sequence` |
//! | `SpliceMutator` | Cross-corpus calldata splicing | `TxMutator::splice` |
//! | `HavocMutator` | Multi-step combined mutations | combined |

use std::borrow::Cow;
use rand::{Rng, SeedableRng, rngs::StdRng};

use libafl::{
    Error,
    corpus::CorpusId,
    mutators::{MutationResult, Mutator},
};
use libafl_bolts::Named;

use crate::{
    mutator::TxMutator,
    types::{Bytes, Transaction, U256},
    libafl_adapter::input::EvmInput,
};

// ── Shared RNG seed helper ────────────────────────────────────────────────────

/// Pull a u64 seed from LibAFL state's RNG if it has one, or use a fixed seed.
/// We use `StdRng` directly in each mutator to avoid requiring `HasRand` bound.
fn new_rng() -> StdRng {
    StdRng::from_entropy()
}

// ── AbiCalldataMutator ────────────────────────────────────────────────────────

/// Mutates calldata in an ABI-aware way.
///
/// - Swaps function selectors while keeping argument encoding intact
/// - Bit-flips within ABI argument slots (not the selector)
/// - Replaces argument words with interesting values from the dictionary
/// - Changes individual bytes in argument encoding
pub struct AbiCalldataMutator {
    inner: TxMutator,
    rng: StdRng,
}

impl AbiCalldataMutator {
    /// Create from an existing `TxMutator`.
    pub fn new(inner: TxMutator) -> Self {
        Self {
            inner,
            rng: new_rng(),
        }
    }
}

impl Named for AbiCalldataMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("AbiCalldataMutator");
        &NAME
    }
}

impl<S> Mutator<EvmInput, S> for AbiCalldataMutator {
    fn mutate(&mut self, _state: &mut S, input: &mut EvmInput) -> Result<MutationResult, Error> {
        if input.transactions.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        // Pick a random transaction and apply ABI-aware calldata mutation.
        let idx = self.rng.gen_range(0..input.transactions.len());
        let orig = input.transactions[idx].clone();
        let mutated = self.inner.mutate(&orig, &mut self.rng);
        input.transactions[idx] = mutated;
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

// ── SenderValueMutator ────────────────────────────────────────────────────────

/// Mutates `msg.sender` and `msg.value` on a random transaction.
///
/// - Changes sender to a different fuzzer-controlled address
/// - Changes value to a different interesting ETH amount (0, 1 gwei, 1 ETH, max)
pub struct SenderValueMutator {
    inner: TxMutator,
    rng: StdRng,
}

impl SenderValueMutator {
    pub fn new(inner: TxMutator) -> Self {
        Self {
            inner,
            rng: new_rng(),
        }
    }
}

impl Named for SenderValueMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("SenderValueMutator");
        &NAME
    }
}

const INTERESTING_VALUES: &[u128] = &[
    0,
    1,
    1_000_000_000,              // 1 gwei
    10_000_000_000_000_000,     // 0.01 ETH
    100_000_000_000_000_000,    // 0.1 ETH
    1_000_000_000_000_000_000,  // 1 ETH
    u128::MAX / 2,
    u128::MAX,
];

impl<S> Mutator<EvmInput, S> for SenderValueMutator {
    fn mutate(&mut self, _state: &mut S, input: &mut EvmInput) -> Result<MutationResult, Error> {
        if input.transactions.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let idx = self.rng.gen_range(0..input.transactions.len());
        // Alternate between sender change and value change.
        if self.rng.gen_bool(0.5) {
            input.transactions[idx].sender = self.inner.random_sender(&mut self.rng);
        } else {
            let val = INTERESTING_VALUES[self.rng.gen_range(0..INTERESTING_VALUES.len())];
            input.transactions[idx].value = U256::from(val);
        }
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

// ── SequenceStructureMutator ──────────────────────────────────────────────────

/// Mutates the structure of the transaction sequence.
///
/// Operations (chosen randomly):
/// - **Insert** a new random transaction at a random position
/// - **Remove** a transaction (if sequence length > 1)
/// - **Swap** two transactions
/// - **Duplicate** a transaction
pub struct SequenceStructureMutator {
    inner: TxMutator,
    rng: StdRng,
    max_len: usize,
}

impl SequenceStructureMutator {
    pub fn new(inner: TxMutator, max_len: usize) -> Self {
        Self {
            inner,
            rng: new_rng(),
            max_len,
        }
    }
}

impl Named for SequenceStructureMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("SequenceStructureMutator");
        &NAME
    }
}

impl<S> Mutator<EvmInput, S> for SequenceStructureMutator {
    fn mutate(&mut self, _state: &mut S, input: &mut EvmInput) -> Result<MutationResult, Error> {
        let len = input.transactions.len();

        match self.rng.gen_range(0u8..4) {
            // Insert
            0 if len < self.max_len => {
                let new_tx = self.inner.generate(&mut self.rng);
                let pos = if len == 0 { 0 } else { self.rng.gen_range(0..=len) };
                input.transactions.insert(pos, new_tx);
                Ok(MutationResult::Mutated)
            }
            // Remove
            1 if len > 1 => {
                let pos = self.rng.gen_range(0..len);
                input.transactions.remove(pos);
                Ok(MutationResult::Mutated)
            }
            // Swap
            2 if len >= 2 => {
                let a = self.rng.gen_range(0..len);
                let mut b = self.rng.gen_range(0..len);
                while b == a { b = self.rng.gen_range(0..len); }
                input.transactions.swap(a, b);
                Ok(MutationResult::Mutated)
            }
            // Duplicate
            3 if len >= 1 && len < self.max_len => {
                let pos = self.rng.gen_range(0..len);
                let dup = input.transactions[pos].clone();
                input.transactions.insert(pos + 1, dup);
                Ok(MutationResult::Mutated)
            }
            _ => Ok(MutationResult::Skipped),
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

// ── SpliceMutator ─────────────────────────────────────────────────────────────

/// Splices calldata from one transaction into another.
///
/// Takes a random transaction from the input and splices the calldata
/// of a randomly selected transaction within the same sequence.
/// This helps the fuzzer combine interesting call paths.
pub struct SpliceMutator {
    inner: TxMutator,
    rng: StdRng,
}

impl SpliceMutator {
    pub fn new(inner: TxMutator) -> Self {
        Self {
            inner,
            rng: new_rng(),
        }
    }
}

impl Named for SpliceMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("SpliceMutator");
        &NAME
    }
}

impl<S> Mutator<EvmInput, S> for SpliceMutator {
    fn mutate(&mut self, _state: &mut S, input: &mut EvmInput) -> Result<MutationResult, Error> {
        let len = input.transactions.len();
        if len < 2 {
            return Ok(MutationResult::Skipped);
        }
        // Splice: take prefix from first half, suffix from second half.
        // This combines interesting call sequences.
        let all = input.transactions.clone();
        let spliced = TxMutator::splice(&all[..len/2], &all[len/2..], &mut self.rng);
        if !spliced.is_empty() {
            input.transactions = spliced;
        }
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

// ── HavocMutator ─────────────────────────────────────────────────────────────

/// Multi-step havoc mutator: applies 2-8 random mutations in one go.
///
/// Havoc is AFL's most aggressive mutation strategy — it randomly combines
/// multiple low-level mutations to escape local optima. This is especially
/// useful after coverage plateaus.
pub struct HavocMutator {
    inner: TxMutator,
    rng: StdRng,
    max_steps: usize,
}

impl HavocMutator {
    pub fn new(inner: TxMutator, max_steps: usize) -> Self {
        Self {
            inner,
            rng: new_rng(),
            max_steps: max_steps.max(2),
        }
    }
}

impl Named for HavocMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("HavocMutator");
        &NAME
    }
}

impl<S> Mutator<EvmInput, S> for HavocMutator {
    fn mutate(&mut self, _state: &mut S, input: &mut EvmInput) -> Result<MutationResult, Error> {
        if input.transactions.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        let steps = self.rng.gen_range(2..=self.max_steps);
        for _ in 0..steps {
            let idx = self.rng.gen_range(0..input.transactions.len());
            let orig = input.transactions[idx].clone();
            input.transactions[idx] = self.inner.mutate(&orig, &mut self.rng);
        }
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, ContractInfo};

    fn make_mutator() -> TxMutator {
        let info = ContractInfo {
            address: Address::with_last_byte(0x01),
            deployed_bytecode: Bytes::from(vec![0x60, 0x80]),
            creation_bytecode: None,
            name: Some("Test".to_string()),
            source_path: None,
            deployed_source_map: None,
            source_file_list: vec![],
            abi: None,
            link_references: Default::default(),
        };
        TxMutator::new(vec![info])
    }

    fn sample_input() -> EvmInput {
        EvmInput::new(vec![
            Transaction {
                sender: Address::with_last_byte(0x10),
                to: Some(Address::with_last_byte(0x01)),
                data: Bytes::from(vec![0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x01]),
                value: U256::ZERO,
                gas_limit: 100_000,
            },
            Transaction {
                sender: Address::with_last_byte(0x10),
                to: Some(Address::with_last_byte(0x01)),
                data: Bytes::from(vec![0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x02]),
                value: U256::ZERO,
                gas_limit: 100_000,
            },
        ])
    }

    #[test]
    fn abi_calldata_mutator_produces_output() {
        let mut m = AbiCalldataMutator::new(make_mutator());
        let mut input = sample_input();
        let orig_data = input.transactions[0].data.clone();
        // Run several times — at least one should mutate.
        let mut mutated = false;
        for _ in 0..20 {
            let mut inp = input.clone();
            let r = m.mutate(&mut (), &mut inp).unwrap();
            if r == MutationResult::Mutated {
                mutated = true;
            }
        }
        assert!(mutated, "AbiCalldataMutator should mutate at least once in 20 tries");
    }

    #[test]
    fn sender_value_mutator_changes_something() {
        let mut m = SenderValueMutator::new(make_mutator());
        let mut changed = false;
        for _ in 0..20 {
            let mut inp = sample_input();
            m.mutate(&mut (), &mut inp).unwrap();
            if inp.transactions[0].sender != Address::with_last_byte(0x10)
                || inp.transactions[0].value != U256::ZERO
            {
                changed = true;
                break;
            }
        }
        assert!(changed);
    }

    #[test]
    fn sequence_structure_mutator_insert() {
        let mut m = SequenceStructureMutator::new(make_mutator(), 32);
        let mut input = sample_input();
        let orig_len = input.len();
        // Force an insert by running many times.
        for _ in 0..50 {
            let mut inp = sample_input();
            m.mutate(&mut (), &mut inp).unwrap();
            if inp.len() > orig_len {
                return; // success
            }
        }
        panic!("sequence structure mutator should insert at least once in 50 tries");
    }

    #[test]
    fn sequence_structure_mutator_remove() {
        let mut m = SequenceStructureMutator::new(make_mutator(), 32);
        let orig_len = sample_input().len();
        for _ in 0..50 {
            let mut inp = sample_input();
            m.mutate(&mut (), &mut inp).unwrap();
            if inp.len() < orig_len {
                return;
            }
        }
        panic!("should remove at least once in 50 tries");
    }

    #[test]
    fn splice_mutator_changes_sequence() {
        let mut m = SpliceMutator::new(make_mutator());
        let orig = sample_input();
        let mut inp = orig.clone();
        let r = m.mutate(&mut (), &mut inp).unwrap();
        // Splice on a 2-tx input should produce a non-empty result.
        assert_eq!(r, MutationResult::Mutated);
        assert!(!inp.transactions.is_empty());
    }

    #[test]
    fn havoc_mutator_runs_without_panic() {
        let mut m = HavocMutator::new(make_mutator(), 8);
        let mut inp = sample_input();
        let r = m.mutate(&mut (), &mut inp).unwrap();
        assert_eq!(r, MutationResult::Mutated);
    }

    #[test]
    fn empty_input_skipped() {
        let mut abi = AbiCalldataMutator::new(make_mutator());
        let mut inp = EvmInput::empty();
        assert_eq!(abi.mutate(&mut (), &mut inp).unwrap(), MutationResult::Skipped);

        let mut seq = SequenceStructureMutator::new(make_mutator(), 32);
        let mut inp = EvmInput::empty();
        // Empty seq: insert should still work (len=0 < max_len).
        // Remove/swap/dup should skip.
        seq.mutate(&mut (), &mut inp).unwrap(); // just shouldn't panic
    }
}
