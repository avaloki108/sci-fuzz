//! Flashloan mutations for global economic oracle.
//!
//! Provides a mutator that wraps sequences inside mock `borrow` and `repay` calls.

use rand::Rng;

use crate::mutator::{TxMutator, ValueDictionary};
use crate::types::{Address, Bytes, Transaction, U256};

/// Special address acting as the mock flashloan provider.
pub const MOCK_FLASHLOAN_POOL: Address = Address::repeat_byte(0xFE);

/// Four-byte selector for `mockBorrow(uint256)`
pub const BORROW_SELECTOR: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
/// Four-byte selector for `mockRepay(uint256)`
pub const REPAY_SELECTOR: [u8; 4] = [0x55, 0x66, 0x77, 0x88];

/// Wraps fuzzer-generated sequences in a mock flashloan lifecycle.
pub struct FlashloanMutator<'a> {
    pub base_mutator: &'a TxMutator,
    pub dict: &'a ValueDictionary,
}

impl<'a> FlashloanMutator<'a> {
    /// Create a new flashloan mutator.
    pub fn new(base_mutator: &'a TxMutator, dict: &'a ValueDictionary) -> Self {
        Self { base_mutator, dict }
    }

    /// Prepend a borrow and append a repay transaction to the given sequence.
    pub fn wrap_sequence(
        &self,
        sequence: Vec<Transaction>,
        rng: &mut impl Rng,
    ) -> Vec<Transaction> {
        let amount = self.dict.random_uint(rng);

        let sender = sequence
            .first()
            .map(|tx| tx.sender)
            .unwrap_or_else(|| self.dict.random_address(rng));

        let mut borrow_data = vec![];
        borrow_data.extend_from_slice(&BORROW_SELECTOR);
        borrow_data.extend_from_slice(&amount.to_be_bytes::<32>());

        let borrow_tx = Transaction {
            sender,
            to: Some(MOCK_FLASHLOAN_POOL),
            data: Bytes::from(borrow_data),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        };

        // Flat 0.09% fee approximation
        let fee = amount / U256::from(1000u64);
        let repay_amount = amount.saturating_add(fee);

        let mut repay_data = vec![];
        repay_data.extend_from_slice(&REPAY_SELECTOR);
        repay_data.extend_from_slice(&repay_amount.to_be_bytes::<32>());

        let repay_tx = Transaction {
            sender,
            to: Some(MOCK_FLASHLOAN_POOL),
            data: Bytes::from(repay_data),
            value: repay_amount, // Assume native ETH flashloan, so value goes to the pool
            gas_limit: 30_000_000,
        };

        let mut wrapped = vec![borrow_tx];
        wrapped.extend(sequence);
        wrapped.push(repay_tx);

        wrapped
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_sequence() {
        let mut dict = ValueDictionary::new();
        dict.uint_values.push(U256::from(1_000_000_000u64));
        let mut rng = rand::thread_rng();

        let base_mutator = TxMutator::new(vec![]);
        let flashloan_mutator = FlashloanMutator::new(&base_mutator, &dict);

        let sequence = vec![base_mutator.generate(&mut rng)];
        let wrapped = flashloan_mutator.wrap_sequence(sequence, &mut rng);

        assert_eq!(wrapped.len(), 3);
        assert_eq!(wrapped[0].to, Some(MOCK_FLASHLOAN_POOL));
        assert_eq!(&wrapped[0].data[..4], &BORROW_SELECTOR);

        assert_eq!(wrapped[2].to, Some(MOCK_FLASHLOAN_POOL));
        assert_eq!(&wrapped[2].data[..4], &REPAY_SELECTOR);
    }
}
