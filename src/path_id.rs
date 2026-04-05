//! Ordered control-flow path identity for a single transaction and for sequences.
//!
//! Path IDs are derived from the **ordered stream** of `(contract_address, prev_pc, current_pc)`
//! steps taken during execution — the same attribution as [`crate::types::CoverageMap`].
//! They complement multiset edge coverage: two runs can have identical per-edge hitcounts but
//! different path IDs when the dynamic order differs.

use alloy_primitives::{keccak256, Address, B256};

/// Path ID for native / synthetic executions that never run the bytecode inspector
/// (e.g. mock flashloan handler). Distinct from an empty trace (`finalize` on zero steps).
#[inline]
pub fn native_flashloan_path_id() -> B256 {
    keccak256(b"sci-fuzz/native-flashloan/v1")
}

/// Rolling hasher updated once per interpreter step, in execution order.
#[derive(Debug, Clone, Default)]
pub struct PathStreamHasher {
    state_lo: u64,
    state_hi: u64,
    step_count: u64,
}

const GOLDEN: u64 = 0x9E37_79B1_85EB_CA87;

impl PathStreamHasher {
    /// Mix one directed edge, matching [`crate::evm::CoverageInspector`] semantics.
    pub fn mix_edge(&mut self, address: Address, prev_pc: usize, current_pc: usize) {
        let (a0, a1) = split_address(address);
        let p = prev_pc as u64;
        let c = current_pc as u64;

        self.state_lo = self.state_lo.wrapping_mul(GOLDEN).wrapping_add(a0 ^ p);
        self.state_hi = self
            .state_hi
            .wrapping_mul(GOLDEN.wrapping_add(1))
            .wrapping_add(a1 ^ c);
        self.state_lo ^= self.state_hi.wrapping_shl(17) | self.state_hi.wrapping_shr(47);
        self.state_hi ^= self.state_lo;

        self.step_count = self.step_count.wrapping_add(1);
    }

    /// Finalize to a compact [`B256`] (single `keccak256` over fixed layout).
    pub fn finalize(&self) -> B256 {
        let mut packed = [0u8; 40];
        packed[0..8].copy_from_slice(&self.state_lo.to_be_bytes());
        packed[8..16].copy_from_slice(&self.state_hi.to_be_bytes());
        packed[16..24].copy_from_slice(&self.step_count.to_be_bytes());
        packed[24..40].copy_from_slice(b"sci-fuzz-txpath\x01");
        keccak256(packed)
    }
}

fn split_address(address: Address) -> (u64, u64) {
    let b = address.into_array();
    let mut lo = 0u64;
    let mut hi = 0u64;
    for i in 0..8 {
        lo |= (b[i] as u64) << (i * 8);
    }
    for i in 0..8 {
        hi |= (b[8 + i] as u64) << (i * 8);
    }
    hi ^= (b[16] as u64) | ((b[17] as u64) << 8) | ((b[18] as u64) << 16) | ((b[19] as u64) << 24);
    (lo, hi)
}

/// Compute the same [`B256`] as finishing a [`PathStreamHasher`] after mixing `edges` in order.
pub fn tx_path_id_from_stream(edges: &[(Address, usize, usize)]) -> B256 {
    let mut h = PathStreamHasher::default();
    for &(addr, prev, curr) in edges {
        h.mix_edge(addr, prev, curr);
    }
    h.finalize()
}

/// Order-sensitive rolling hash over per-transaction path IDs (sequence of txs).
pub fn fold_sequence(prev: B256, tx_path: B256, step_index: u32) -> B256 {
    let mut buf = [0u8; 72];
    buf[0..32].copy_from_slice(prev.as_slice());
    buf[32..64].copy_from_slice(tx_path.as_slice());
    buf[64..68].copy_from_slice(&step_index.to_be_bytes());
    buf[68..72].copy_from_slice(b"seq\x01");
    keccak256(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_multiset_different_order_different_tx_path_id() {
        let addr = Address::ZERO;
        // Same edges each taken twice: (0,1),(1,2) twice vs interleaved order — multiset identical.
        let order_a = vec![(addr, 0, 1), (addr, 1, 2), (addr, 0, 1), (addr, 1, 2)];
        let order_b = vec![(addr, 0, 1), (addr, 0, 1), (addr, 1, 2), (addr, 1, 2)];
        let id_a = tx_path_id_from_stream(&order_a);
        let id_b = tx_path_id_from_stream(&order_b);
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn identical_stream_stable_tx_path_id() {
        let addr = Address::repeat_byte(0xAB);
        let edges = vec![(addr, 0, 1), (addr, 1, 2), (addr, 2, 3)];
        let x = tx_path_id_from_stream(&edges);
        let y = tx_path_id_from_stream(&edges);
        assert_eq!(x, y);
    }

    #[test]
    fn same_tx_ids_different_sequence_order_different_seq_id() {
        let a = B256::repeat_byte(0x11);
        let b = B256::repeat_byte(0x22);
        let z = B256::ZERO;
        let seq_ab = fold_sequence(fold_sequence(z, a, 0), b, 1);
        let seq_ba = fold_sequence(fold_sequence(z, b, 0), a, 1);
        assert_ne!(seq_ab, seq_ba);
    }
}
