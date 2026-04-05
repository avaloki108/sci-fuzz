//! Coverage feedback with AFL-style hitcount bucketing and virgin bits.
//!
//! This module implements two key algorithms ported from AFL / LibAFL:
//!
//! 1. **Hitcount bucketing** — for each control-flow edge `(prev_pc, current_pc)`
//!    (per attributed contract address), we track how many times that edge
//!    was taken and classify the raw count into power-of-two buckets
//!    (1, 2, 4, 8, 16, 32, 64, 128). A transition between buckets (e.g. a loop
//!    executing 3 times vs 8 times) counts as new coverage.
//!
//! 2. **Virgin bits tracking** — a global map of `(address, edge, bucket)`
//!    triples that have *never* been observed. When an execution produces a
//!    triple absent from the virgin map the input is considered novel and
//!    should be retained in the corpus.
//!
//! Together these give a richer signal than simple “was this PC hit?” coverage,
//! especially for loops and divergent branches (different edges).
//!
//! # References
//!
//! * AFL `COUNT_CLASS_LOOKUP` — <https://github.com/google/AFL>
//! * LibAFL `HitcountsMapObserver` — `libafl/src/observers/map/hitcount_map.rs`

use std::collections::{HashMap, HashSet, VecDeque};

use crate::types::{Address, CoverageMap, B256};

// ---------------------------------------------------------------------------
// Hitcount bucketing
// ---------------------------------------------------------------------------

/// Full 256-entry lookup table matching AFL / LibAFL's `COUNT_CLASS_LOOKUP`.
///
/// Index by raw hitcount (clamped to 0–255) to obtain the bucket value.
/// Counts above 255 are treated as 128 (the highest bucket).
const COUNT_CLASS_LOOKUP: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i: usize = 0;
    while i < 256 {
        table[i] = match i as u32 {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            4..=7 => 8,
            8..=15 => 16,
            16..=31 => 32,
            32..=127 => 64,
            _ => 128,
        };
        i += 1;
    }
    table
};

/// Classify a raw hitcount into an AFL-style power-of-two bucket.
///
/// | Raw count | Bucket |
/// |-----------|--------|
/// | 0         | 0      |
/// | 1         | 1      |
/// | 2         | 2      |
/// | 3         | 4      |
/// | 4 – 7     | 8      |
/// | 8 – 15    | 16     |
/// | 16 – 31   | 32     |
/// | 32 – 127  | 64     |
/// | 128 +     | 128    |
#[inline]
pub fn bucket(count: u32) -> u8 {
    let idx = if count > 255 { 255 } else { count as usize };
    COUNT_CLASS_LOOKUP[idx]
}

// ---------------------------------------------------------------------------
// CoverageFeedback
// ---------------------------------------------------------------------------

/// Enhanced coverage feedback with hitcount bucketing and virgin bits.
///
/// Tracks the *bucketed hitcount* for each `(address, (prev_pc, current_pc))`
/// edge. A new bucket for a previously-seen edge is still novel — e.g.
/// “loop ran once” vs “loop ran 20 times” on the same back-edge.
///
/// # Virgin bits
///
/// The `seen_bits` map records every `(address, edge, bucket)` triple observed
/// across the campaign. An execution is *interesting* when it produces at least
/// one triple **not** present in `seen_bits`.
#[derive(Debug, Clone)]
pub struct CoverageFeedback {
    /// Every `(address, edge)` → set of buckets that **have** been seen.
    /// A new bucket value for a known key, or a brand-new key, both
    /// constitute novel coverage.
    seen_bits: HashMap<(Address, (usize, usize)), HashSet<u8>>,

    /// Accumulated raw hitcounts across the entire campaign (for stats /
    /// reporting). Values are the *maximum* hitcount observed for each
    /// `(address, edge)` pair.
    global_hitcounts: HashMap<(Address, (usize, usize)), u32>,

    /// Dataflow waypoints observed globally.
    seen_dataflow: HashMap<Address, HashSet<crate::types::U256>>,

    /// Total unique `(address, edge, bucket)` triples discovered so far.
    total_bits: usize,

    /// Whether the most recent call to [`record`](Self::record) or
    /// [`record_from_coverage_map`](Self::record_from_coverage_map)
    /// discovered new coverage.
    last_was_novel: bool,
}

impl CoverageFeedback {
    /// Create a feedback tracker with empty state.
    pub fn new() -> Self {
        Self {
            seen_bits: HashMap::new(),
            global_hitcounts: HashMap::new(),
            seen_dataflow: HashMap::new(),
            total_bits: 0,
            last_was_novel: false,
        }
    }

    /// Read-only check: would `hitcounts` produce at least one novel
    /// `(address, (prev_pc, current_pc), bucket)` triple?
    ///
    /// This does **not** mutate the feedback state — call
    /// [`record`](Self::record) afterwards to actually merge.
    pub fn is_interesting(&self, hitcounts: &HashMap<(Address, (usize, usize)), u32>) -> bool {
        for (&key, &count) in hitcounts {
            let b = bucket(count);
            if b == 0 {
                continue;
            }
            match self.seen_bits.get(&key) {
                None => return true,
                Some(buckets) => {
                    if !buckets.contains(&b) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Merge `hitcounts` into the global state.
    ///
    /// Returns `true` when at least one previously-unseen
    /// `(address, edge, bucket)` triple was discovered.
    pub fn record(&mut self, hitcounts: &HashMap<(Address, (usize, usize)), u32>) -> bool {
        let mut novel = false;

        for (&key, &count) in hitcounts {
            let b = bucket(count);
            if b == 0 {
                continue;
            }

            // Update seen_bits / virgin tracking.
            let buckets = self.seen_bits.entry(key).or_default();
            if buckets.insert(b) {
                // This bucket was never seen for this (address, edge).
                self.total_bits += 1;
                novel = true;
            }

            // Update raw hitcount high-water mark.
            let stored = self.global_hitcounts.entry(key).or_insert(0);
            if count > *stored {
                *stored = count;
            }
        }

        if novel {
            self.last_was_novel = true;
        }
        novel
    }

    /// Convenience wrapper: flatten a [`CoverageMap`] into raw hitcounts and
    /// record it.
    ///
    /// Returns `true` when new coverage was discovered.
    pub fn record_from_coverage_map(&mut self, cov: &CoverageMap) -> bool {
        let hitcounts = coverage_map_to_hitcounts(cov);
        let novel = self.record(&hitcounts);
        self.last_was_novel = novel;
        novel
    }

    /// Record dataflow waypoints and return true if any are novel.
    pub fn record_dataflow(&mut self, dataflow: &crate::types::DataflowWaypoints) -> bool {
        let mut novel = false;
        for (addr, slots) in &dataflow.map {
            let seen = self.seen_dataflow.entry(*addr).or_default();
            for slot in slots {
                if seen.insert(*slot) {
                    self.total_bits += 1; // Count dataflow accesses towards total bits
                    novel = true;
                }
            }
        }
        if novel {
            self.last_was_novel = true;
        }
        novel
    }

    /// Total number of unique `(address, edge, bucket)` triples discovered.
    pub fn total_coverage(&self) -> usize {
        self.total_bits
    }

    /// Whether any coverage has been recorded at all.
    pub fn is_empty(&self) -> bool {
        self.total_bits == 0
    }

    /// Borrow the accumulated raw hitcounts (high-water marks).
    pub fn global_coverage(&self) -> &HashMap<(Address, (usize, usize)), u32> {
        &self.global_hitcounts
    }
}

impl Default for CoverageFeedback {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Path feedback (bounded novelty for ordered path IDs)
// ---------------------------------------------------------------------------

/// Default max distinct tx- and sequence-path IDs retained per category.
pub const DEFAULT_PATH_FEEDBACK_CAP: usize = 50_000;

/// Tracks first-seen per-transaction and per-sequence path fingerprints with FIFO eviction.
///
/// Used alongside [`CoverageFeedback`]: edge multiset novelty can be false while path
/// order novelty is true.
#[derive(Debug, Clone)]
pub struct PathFeedback {
    seen_tx: HashSet<B256>,
    order_tx: VecDeque<B256>,
    seen_seq: HashSet<B256>,
    order_seq: VecDeque<B256>,
    cap_tx: usize,
    cap_seq: usize,
}

impl PathFeedback {
    pub fn new() -> Self {
        Self::with_caps(DEFAULT_PATH_FEEDBACK_CAP, DEFAULT_PATH_FEEDBACK_CAP)
    }

    pub fn with_caps(cap_tx: usize, cap_seq: usize) -> Self {
        Self {
            seen_tx: HashSet::new(),
            order_tx: VecDeque::new(),
            seen_seq: HashSet::new(),
            order_seq: VecDeque::new(),
            cap_tx: cap_tx.max(1),
            cap_seq: cap_seq.max(1),
        }
    }

    fn insert_bounded(
        set: &mut HashSet<B256>,
        order: &mut VecDeque<B256>,
        cap: usize,
        id: B256,
    ) -> bool {
        if set.contains(&id) {
            return false;
        }
        set.insert(id);
        order.push_back(id);
        while set.len() > cap {
            if let Some(old) = order.pop_front() {
                set.remove(&old);
            }
        }
        true
    }

    /// Returns `true` the first time this `tx_path_id` is seen (within the cap).
    pub fn record_tx_path(&mut self, id: &B256) -> bool {
        Self::insert_bounded(&mut self.seen_tx, &mut self.order_tx, self.cap_tx, *id)
    }

    /// Returns `true` the first time this sequence path id is seen (within the cap).
    pub fn record_sequence_path(&mut self, id: &B256) -> bool {
        Self::insert_bounded(&mut self.seen_seq, &mut self.order_seq, self.cap_seq, *id)
    }
}

impl Default for PathFeedback {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a [`CoverageMap`] into a flat hitcount map.
fn coverage_map_to_hitcounts(cov: &CoverageMap) -> HashMap<(Address, (usize, usize)), u32> {
    let mut hitcounts = HashMap::new();
    for (addr, edges) in &cov.map {
        for (&edge, &count) in edges {
            hitcounts.insert((*addr, edge), count);
        }
    }
    hitcounts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Address;

    // -- bucket function ---------------------------------------------------

    #[test]
    fn bucket_boundary_values() {
        assert_eq!(bucket(0), 0, "zero hits → bucket 0");
        assert_eq!(bucket(1), 1, "1 hit → bucket 1");
        assert_eq!(bucket(2), 2, "2 hits → bucket 2");
        assert_eq!(bucket(3), 4, "3 hits → bucket 4");
        assert_eq!(bucket(4), 8, "4 hits → bucket 8");
        assert_eq!(bucket(7), 8, "7 hits → bucket 8");
        assert_eq!(bucket(8), 16, "8 hits → bucket 16");
        assert_eq!(bucket(15), 16, "15 hits → bucket 16");
        assert_eq!(bucket(16), 32, "16 hits → bucket 32");
        assert_eq!(bucket(31), 32, "31 hits → bucket 32");
        assert_eq!(bucket(32), 64, "32 hits → bucket 64");
        assert_eq!(bucket(127), 64, "127 hits → bucket 64");
        assert_eq!(bucket(128), 128, "128 hits → bucket 128");
        assert_eq!(bucket(255), 128, "255 hits → bucket 128");
        assert_eq!(bucket(1000), 128, "1000 hits → bucket 128 (clamped)");
        assert_eq!(bucket(u32::MAX), 128, "u32::MAX hits → bucket 128");
    }

    #[test]
    fn bucket_matches_lookup_table() {
        for i in 0u32..=255 {
            assert_eq!(
                bucket(i),
                COUNT_CLASS_LOOKUP[i as usize],
                "bucket({i}) should equal COUNT_CLASS_LOOKUP[{i}]"
            );
        }
    }

    // -- virgin bits detection ---------------------------------------------

    #[test]
    fn first_hit_is_novel() {
        let mut fb = CoverageFeedback::new();
        assert!(fb.is_empty());

        let mut hc = HashMap::new();
        hc.insert((Address::ZERO, (42usize, 43usize)), 1u32);

        assert!(fb.is_interesting(&hc), "first hit should be interesting");
        assert!(fb.record(&hc), "first record should report novel coverage");
        assert_eq!(fb.total_coverage(), 1);
        assert!(!fb.is_empty());
    }

    #[test]
    fn repeated_same_coverage_is_not_novel() {
        let mut fb = CoverageFeedback::new();

        let mut hc = HashMap::new();
        hc.insert((Address::ZERO, (10, 11)), 1u32);
        hc.insert((Address::ZERO, (20, 21)), 5u32);

        assert!(fb.record(&hc), "first time → novel");
        assert_eq!(fb.total_coverage(), 2); // two distinct (address, edge, bucket) triples

        // Exact same hitcounts → same buckets → not novel.
        assert!(
            !fb.is_interesting(&hc),
            "identical hitcounts should not be interesting"
        );
        assert!(
            !fb.record(&hc),
            "duplicate record should not report novel coverage"
        );
        assert_eq!(fb.total_coverage(), 2, "total should not change");
    }

    #[test]
    fn new_bucket_for_existing_edge_is_novel() {
        let mut fb = CoverageFeedback::new();

        // First execution: edge 10->11 hit once → bucket 1.
        let mut hc1 = HashMap::new();
        hc1.insert((Address::ZERO, (0x10, 0x11)), 1u32);
        assert!(fb.record(&hc1));
        assert_eq!(fb.total_coverage(), 1);

        // Same hitcount → same bucket → not novel.
        assert!(!fb.record(&hc1));

        // Second execution: edge 10->11 hit 5 times → bucket 8.
        // Different bucket for the same edge → novel!
        let mut hc2 = HashMap::new();
        hc2.insert((Address::ZERO, (0x10, 0x11)), 5u32);
        assert!(
            fb.is_interesting(&hc2),
            "different bucket for same edge should be interesting"
        );
        assert!(fb.record(&hc2));
        assert_eq!(
            fb.total_coverage(),
            2,
            "should now have 2 bits: bucket 1 and bucket 8"
        );

        // Third execution: edge 10->11 hit 100 times → bucket 64.
        let mut hc3 = HashMap::new();
        hc3.insert((Address::ZERO, (0x10, 0x11)), 100u32);
        assert!(fb.record(&hc3));
        assert_eq!(fb.total_coverage(), 3);
    }

    #[test]
    fn record_from_coverage_map_works() {
        let mut fb = CoverageFeedback::new();

        let addr_a = Address::repeat_byte(0xAA);
        let addr_b = Address::repeat_byte(0xBB);

        let mut cov = CoverageMap::new();
        cov.record_hit(addr_a, 0, 1);
        cov.record_hit(addr_a, 42, 43);
        cov.record_hit(addr_b, 7, 8);

        assert!(
            fb.record_from_coverage_map(&cov),
            "first record_from_coverage_map should be novel"
        );
        // Each edge was hit once → bucket 1, so 3 unique triples.
        assert_eq!(fb.total_coverage(), 3);

        // Recording the same CoverageMap again should not be novel.
        assert!(
            !fb.record_from_coverage_map(&cov),
            "duplicate coverage map should not be novel"
        );
        assert_eq!(fb.total_coverage(), 3);
    }

    #[test]
    fn interesting_when_edge_set_differs_with_same_pc_endpoints() {
        let mut fb = CoverageFeedback::new();
        let mut first_path = HashMap::new();
        first_path.insert((Address::ZERO, (0, 1)), 1u32);
        first_path.insert((Address::ZERO, (1, 2)), 1u32);
        assert!(fb.record(&first_path));

        let mut other_path = HashMap::new();
        other_path.insert((Address::ZERO, (0, 2)), 1u32);
        other_path.insert((Address::ZERO, (2, 1)), 1u32);
        assert!(
            fb.is_interesting(&other_path),
            "disjoint edges should be novel even when PCs overlap"
        );
        assert!(fb.record(&other_path));
    }

    #[test]
    fn zero_hitcount_is_ignored() {
        let mut fb = CoverageFeedback::new();

        let mut hc = HashMap::new();
        hc.insert((Address::ZERO, (99, 100)), 0u32);

        assert!(
            !fb.is_interesting(&hc),
            "zero-count entries should not be interesting"
        );
        assert!(!fb.record(&hc));
        assert!(fb.is_empty());
    }

    #[test]
    fn global_coverage_tracks_high_water_mark() {
        let mut fb = CoverageFeedback::new();
        let key = (Address::ZERO, (5usize, 6usize));

        let mut hc1 = HashMap::new();
        hc1.insert(key, 3u32);
        fb.record(&hc1);
        assert_eq!(fb.global_coverage().get(&key), Some(&3));

        // Higher count updates the high-water mark.
        let mut hc2 = HashMap::new();
        hc2.insert(key, 50u32);
        fb.record(&hc2);
        assert_eq!(fb.global_coverage().get(&key), Some(&50));

        // Lower count does NOT decrease it.
        let mut hc3 = HashMap::new();
        hc3.insert(key, 2u32);
        fb.record(&hc3);
        assert_eq!(
            fb.global_coverage().get(&key),
            Some(&50),
            "high-water mark should not decrease"
        );
    }

    #[test]
    fn default_impl_matches_new() {
        let a = CoverageFeedback::new();
        let b = CoverageFeedback::default();
        assert_eq!(a.total_coverage(), b.total_coverage());
        assert!(a.is_empty());
        assert!(b.is_empty());
    }

    #[test]
    fn multiple_addresses_tracked_independently() {
        let mut fb = CoverageFeedback::new();

        let addr_a = Address::repeat_byte(0x01);
        let addr_b = Address::repeat_byte(0x02);

        // Same PC on different addresses → distinct entries.
        let mut hc = HashMap::new();
        hc.insert((addr_a, (0, 1)), 1u32);
        hc.insert((addr_b, (0, 1)), 1u32);

        assert!(fb.record(&hc));
        assert_eq!(fb.total_coverage(), 2);

        // A new bucket on only one address is still novel.
        let mut hc2 = HashMap::new();
        hc2.insert((addr_a, (0, 1)), 10u32); // bucket changes: 1 → 16
        hc2.insert((addr_b, (0, 1)), 1u32); // same bucket: 1
        assert!(fb.record(&hc2));
        assert_eq!(fb.total_coverage(), 3, "one new bit from addr_a");
    }

    #[test]
    fn record_from_coverage_map_uses_hitcounts() {
        let mut fb = CoverageFeedback::new();
        let addr = Address::ZERO;
        let mut cov = CoverageMap::new();

        cov.record_hit(addr, 7, 8);
        assert!(fb.record_from_coverage_map(&cov));
        assert_eq!(fb.global_coverage().get(&(addr, (7, 8))), Some(&1));

        cov.record_hit(addr, 7, 8);
        cov.record_hit(addr, 7, 8);
        assert!(
            fb.record_from_coverage_map(&cov),
            "1 hit then 3 hits should cross into a new bucket"
        );
        assert_eq!(fb.global_coverage().get(&(addr, (7, 8))), Some(&3));
    }

    #[test]
    fn path_novelty_without_edge_novelty() {
        use crate::path_id::tx_path_id_from_stream;
        let addr = Address::ZERO;
        let stream_a = vec![(addr, 0, 1), (addr, 1, 2), (addr, 0, 1), (addr, 1, 2)];
        let stream_b = vec![(addr, 0, 1), (addr, 0, 1), (addr, 1, 2), (addr, 1, 2)];
        let mut cov_a = CoverageMap::new();
        for &(a, p, c) in &stream_a {
            cov_a.record_hit(a, p, c);
        }
        let mut cov_b = CoverageMap::new();
        for &(a, p, c) in &stream_b {
            cov_b.record_hit(a, p, c);
        }

        let id_a = tx_path_id_from_stream(&stream_a);
        let id_b = tx_path_id_from_stream(&stream_b);
        assert_ne!(id_a, id_b);

        let mut hc_b = HashMap::new();
        for (a, edges) in &cov_b.map {
            for (&e, &c) in edges {
                hc_b.insert((*a, e), c);
            }
        }

        let mut fb = CoverageFeedback::new();
        assert!(fb.record_from_coverage_map(&cov_a));
        assert!(!fb.is_interesting(&hc_b));

        let mut pf = PathFeedback::new();
        assert!(pf.record_tx_path(&id_a));
        assert!(pf.record_tx_path(&id_b));
    }
}
