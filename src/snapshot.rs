//! Snapshot corpus for sci-fuzz.
//!
//! Manages a bounded collection of [`StateSnapshot`]s, each representing a
//! point-in-time EVM world state. Snapshots are weighted by coverage
//! *novelty* — `(address, (prev_pc, current_pc))` edges that appear in fewer
//! snapshots score higher — so the fuzzer gravitates toward under-explored
//! control-flow transitions.
//!
//! On top of pure novelty scoring, an AFL++-style **power schedule** adjusts
//! the energy (fuzzing budget) assigned to each snapshot based on how often it
//! has been selected, how much new coverage it contributed, its depth in the
//! snapshot tree, and whether it was discovered during calibration.

use std::collections::HashMap;

use rand::Rng;

// Required by the module interface — `EvmExecutor` will be consumed by
// snapshot-restore helpers; `CoverageMap` and `U256` are accessed through
// `StateSnapshot` fields rather than named directly in current method bodies.
#[allow(unused_imports)]
use crate::evm::EvmExecutor;
#[allow(unused_imports)]
use crate::types::{Address, CoverageMap, StateSnapshot, U256};

// ---------------------------------------------------------------------------
// PowerMetadata
// ---------------------------------------------------------------------------

/// Metadata for power scheduling (ported from AFL++/LibAFL).
///
/// Each snapshot in the corpus carries one of these structs, kept in a
/// parallel `Vec` inside [`SnapshotCorpus`].  The values are used by
/// [`SnapshotCorpus::compute_energy`] to decide how much fuzzing budget
/// a snapshot deserves.
#[derive(Debug, Clone, Default)]
pub struct PowerMetadata {
    /// How many times this snapshot has been selected for fuzzing.
    pub n_fuzz: u32,
    /// How many new coverage bits this snapshot contributed when first added.
    pub new_bits: u32,
    /// Depth in the snapshot tree (distance from root).
    pub depth: u32,
    /// Average execution time in microseconds for sequences from this snapshot.
    pub avg_exec_us: u64,
    /// Whether this snapshot was found via calibration (higher priority).
    pub calibrated: bool,
    /// Handicap: lower priority if this snapshot rarely produces new coverage.
    pub handicap: u32,
}

// ---------------------------------------------------------------------------
// SnapshotCorpus
// ---------------------------------------------------------------------------

/// A bounded corpus of EVM state snapshots with coverage-aware selection and
/// pruning.
///
/// Snapshots are stored in a flat [`Vec`] and identified by their
/// [`StateSnapshot::id`] field.  When the corpus exceeds `max_size`, the
/// least-novel entries are pruned automatically.
///
/// Selection uses AFL++-style power scheduling: the energy assigned to each
/// snapshot combines novelty scoring with metadata such as selection count,
/// new-bits contribution, tree depth, calibration status, and handicap.
#[derive(Debug)]
pub struct SnapshotCorpus {
    /// All retained snapshots, in insertion order.
    snapshots: Vec<StateSnapshot>,
    /// Power scheduling metadata, parallel to `snapshots`.
    metadata: Vec<PowerMetadata>,
    /// Upper bound on the number of retained snapshots.
    max_size: usize,
    /// Monotonically increasing counter used to assign IDs.
    next_id: u64,
}

impl SnapshotCorpus {
    /// Create an empty corpus that will retain at most `max_size` snapshots.
    ///
    /// # Panics
    ///
    /// Panics if `max_size` is zero.
    pub fn new(max_size: usize) -> Self {
        assert!(max_size > 0, "max_size must be at least 1");
        Self {
            snapshots: Vec::new(),
            metadata: Vec::new(),
            max_size,
            next_id: 0,
        }
    }

    /// Insert a snapshot into the corpus.
    ///
    /// The snapshot's `id` field is overwritten with a freshly assigned,
    /// monotonically increasing identifier which is also returned to the
    /// caller.  A default [`PowerMetadata`] entry is created for the new
    /// snapshot.  If the corpus exceeds `max_size` after insertion,
    /// [`prune`] is called automatically.
    ///
    /// [`prune`]: Self::prune
    pub fn add(&mut self, mut snapshot: StateSnapshot) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        snapshot.id = id;
        self.snapshots.push(snapshot);
        self.metadata.push(PowerMetadata::default());

        if self.snapshots.len() > self.max_size {
            self.prune();
        }

        id
    }

    /// Look up a snapshot by its `id`.
    ///
    /// Returns `None` when no snapshot with that ID exists (either it was
    /// never added or it has been pruned).
    pub fn get(&self, id: u64) -> Option<&StateSnapshot> {
        self.snapshots.iter().find(|s| s.id == id)
    }

    /// Select a random snapshot weighted by AFL++-style power-scheduled
    /// energy.
    ///
    /// Energy combines the novelty score (inverse frequency of each
    /// `(address, edge)` pair) with power-scheduling metadata — see
    /// [`compute_energy`](Self::compute_energy) for the full formula.
    ///
    /// Returns `None` only when the corpus is empty.
    pub fn select_weighted(&self, rng: &mut impl Rng) -> Option<&StateSnapshot> {
        if self.snapshots.is_empty() {
            return None;
        }

        let energies: Vec<f64> = (0..self.snapshots.len())
            .map(|i| self.compute_energy(i))
            .collect();
        let total: f64 = energies.iter().sum();
        debug_assert!(total > 0.0);

        let mut dart = rng.gen_range(0.0..total);
        for (i, &energy) in energies.iter().enumerate() {
            dart -= energy;
            if dart <= 0.0 {
                return Some(&self.snapshots[i]);
            }
        }

        // Floating-point residue — fall back to the last entry.
        self.snapshots.last()
    }

    /// Drop the least-novel snapshots until the corpus fits within
    /// `max_size`.
    ///
    /// Novelty is measured identically to [`select_weighted`]: snapshots
    /// whose coverage pairs are already well-represented elsewhere score
    /// lowest and are removed first.  The corresponding [`PowerMetadata`]
    /// entry is removed in lockstep.
    ///
    /// [`select_weighted`]: Self::select_weighted
    pub fn prune(&mut self) {
        while self.snapshots.len() > self.max_size {
            let scores = self.novelty_scores();

            // Find the index of the snapshot with the lowest score.
            let min_idx = scores
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(i, _)| i)
                .expect("corpus is non-empty");

            self.snapshots.swap_remove(min_idx);
            self.metadata.swap_remove(min_idx);
        }
    }

    /// Number of snapshots currently in the corpus.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Returns `true` when the corpus contains no snapshots.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Mutate the [`PowerMetadata`] for the snapshot with the given `id`.
    ///
    /// The closure `f` receives a mutable reference to the metadata entry.
    /// If no snapshot with `id` exists the call is silently ignored.
    pub fn update_metadata(&mut self, id: u64, f: impl FnOnce(&mut PowerMetadata)) {
        if let Some(idx) = self.snapshots.iter().position(|s| s.id == id) {
            f(&mut self.metadata[idx]);
        }
    }

    // -- internal helpers ---------------------------------------------------

    /// Compute the energy (fuzzing budget) for a snapshot using an
    /// AFL++-style power schedule.
    ///
    /// The base signal comes from the coverage novelty score (inverse
    /// frequency of `(address, edge)` pairs). On top of that several
    /// metadata-driven adjustments are applied:
    ///
    /// * **New-bits bonus** — snapshots that discovered many fresh coverage
    ///   bits receive proportionally more energy.
    /// * **Exploration penalty** — snapshots that have been selected many
    ///   times have their energy dampened via a square-root divisor.
    /// * **Depth bonus** — deeper snapshots (further from root) are harder
    ///   to reach and receive a small linear boost.
    /// * **Calibration bonus** — snapshots discovered during the
    ///   calibration phase get a 2× multiplier.
    /// * **Handicap penalty** — snapshots that rarely produce new coverage
    ///   are penalised linearly.
    ///
    /// The result is clamped to a minimum of `0.01` so every snapshot
    /// retains a non-zero chance of selection.
    fn compute_energy(&self, idx: usize) -> f64 {
        let meta = &self.metadata[idx];
        let scores = self.novelty_scores();
        let novelty = scores[idx];

        // Base energy from novelty.
        let mut energy = novelty;

        // Boost for high new_bits.
        energy *= 1.0 + (meta.new_bits as f64 * 0.5);

        // Penalty for over-exploration.
        if meta.n_fuzz > 0 {
            energy /= (meta.n_fuzz as f64).sqrt();
        }

        // Depth bonus (deeper states are harder to reach).
        energy *= 1.0 + (meta.depth as f64 * 0.1);

        // Calibration bonus.
        if meta.calibrated {
            energy *= 2.0;
        }

        // Handicap penalty.
        energy /= 1.0 + (meta.handicap as f64 * 0.2);

        energy.max(0.01) // minimum energy
    }

    /// Compute a novelty score for every snapshot in the corpus.
    ///
    /// For each `(address, edge)` pair across the entire corpus we count how
    /// many snapshots include it. A snapshot's score is the sum of
    /// `1.0 / count` over all its pairs, plus a baseline of `1.0`.
    fn novelty_scores(&self) -> Vec<f64> {
        // Step 1 — count how many snapshots cover each (address, edge) pair.
        let mut pair_counts: HashMap<(Address, (usize, usize)), usize> = HashMap::new();
        for snap in &self.snapshots {
            for (addr, edges) in &snap.coverage.map {
                for &edge in edges.keys() {
                    *pair_counts.entry((*addr, edge)).or_insert(0) += 1;
                }
            }
        }

        // Step 2 — score each snapshot.
        self.snapshots
            .iter()
            .map(|snap| {
                let mut score = 1.0_f64; // baseline so empty-coverage snapshots survive
                for (addr, edges) in &snap.coverage.map {
                    for &edge in edges.keys() {
                        let count = pair_counts.get(&(*addr, edge)).copied().unwrap_or(1);
                        score += 1.0 / count as f64;
                    }
                }
                score
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::StateSnapshot;

    /// Helper — build a minimal snapshot whose coverage hits the given edges
    /// at [`Address::ZERO`].
    fn snapshot_with_pcs(pcs: &[(usize, usize)]) -> StateSnapshot {
        let mut snap = StateSnapshot::default();
        let addr = Address::ZERO;
        for &(prev, current) in pcs {
            snap.coverage.record_hit(addr, prev, current);
        }
        snap
    }

    #[test]
    fn add_get_len_is_empty() {
        let mut corpus = SnapshotCorpus::new(16);
        assert!(corpus.is_empty());
        assert_eq!(corpus.len(), 0);

        let id0 = corpus.add(snapshot_with_pcs(&[(0, 1), (1, 2)]));
        assert_eq!(corpus.len(), 1);
        assert!(!corpus.is_empty());

        let id1 = corpus.add(snapshot_with_pcs(&[(2, 3), (3, 4)]));
        assert_eq!(corpus.len(), 2);
        assert_ne!(id0, id1);

        // Look-up by ID works.
        let s0 = corpus.get(id0).expect("id0 should exist");
        assert_eq!(s0.id, id0);
        assert_eq!(s0.coverage.len(), 2);

        // Non-existent ID returns None.
        assert!(corpus.get(9999).is_none());
    }

    #[test]
    fn prune_keeps_most_novel() {
        // Corpus can hold at most 2 snapshots.
        let mut corpus = SnapshotCorpus::new(2);

        // Snap A: covers PCs 0, 1 (shared with B).
        let _id_a = corpus.add(snapshot_with_pcs(&[(0, 1), (1, 2)]));
        // Snap B: covers PCs 0, 1 (identical to A — redundant).
        let _id_b = corpus.add(snapshot_with_pcs(&[(0, 1), (1, 2)]));
        assert_eq!(corpus.len(), 2);

        // Snap C: covers PCs 10, 20 — completely novel.
        let id_c = corpus.add(snapshot_with_pcs(&[(10, 11), (20, 21)]));

        // After auto-prune the corpus should be back to 2 entries, and the
        // novel snapshot C must have survived.
        assert_eq!(corpus.len(), 2);
        assert!(
            corpus.get(id_c).is_some(),
            "the most novel snapshot should survive pruning"
        );
    }

    #[test]
    fn prune_keeps_metadata_in_sync() {
        let mut corpus = SnapshotCorpus::new(2);

        let id_a = corpus.add(snapshot_with_pcs(&[(0, 1), (1, 2)]));
        corpus.update_metadata(id_a, |m| m.calibrated = true);

        let _id_b = corpus.add(snapshot_with_pcs(&[(0, 1), (1, 2)]));

        // Novel snapshot forces a prune.
        let id_c = corpus.add(snapshot_with_pcs(&[(10, 11), (20, 21)]));
        assert_eq!(corpus.len(), 2);

        // Metadata vec must stay in sync with snapshots vec.
        assert_eq!(corpus.metadata.len(), corpus.snapshots.len());

        // If id_a survived, its metadata should still be calibrated.
        if corpus.get(id_a).is_some() {
            let idx = corpus.snapshots.iter().position(|s| s.id == id_a).unwrap();
            assert!(corpus.metadata[idx].calibrated);
        }

        // id_c should definitely exist.
        assert!(corpus.get(id_c).is_some());
    }

    #[test]
    fn select_weighted_returns_valid_snapshot() {
        let mut corpus = SnapshotCorpus::new(8);
        corpus.add(snapshot_with_pcs(&[(0, 1), (1, 2), (2, 3)]));
        corpus.add(snapshot_with_pcs(&[(3, 4), (4, 5), (5, 6)]));
        corpus.add(snapshot_with_pcs(&[(6, 7)]));

        let mut rng = rand::thread_rng();
        for _ in 0..50 {
            let snap = corpus
                .select_weighted(&mut rng)
                .expect("corpus is non-empty");
            // The returned snapshot must actually be one we inserted.
            assert!(
                corpus.get(snap.id).is_some(),
                "selected snapshot must exist in corpus"
            );
        }
    }

    #[test]
    fn update_metadata_modifies_correct_entry() {
        let mut corpus = SnapshotCorpus::new(8);
        let id0 = corpus.add(snapshot_with_pcs(&[(0, 1)]));
        let id1 = corpus.add(snapshot_with_pcs(&[(1, 2)]));

        corpus.update_metadata(id0, |m| {
            m.n_fuzz = 10;
            m.new_bits = 5;
            m.depth = 3;
            m.calibrated = true;
        });

        corpus.update_metadata(id1, |m| {
            m.handicap = 7;
        });

        let idx0 = corpus.snapshots.iter().position(|s| s.id == id0).unwrap();
        let idx1 = corpus.snapshots.iter().position(|s| s.id == id1).unwrap();

        assert_eq!(corpus.metadata[idx0].n_fuzz, 10);
        assert_eq!(corpus.metadata[idx0].new_bits, 5);
        assert_eq!(corpus.metadata[idx0].depth, 3);
        assert!(corpus.metadata[idx0].calibrated);
        assert_eq!(corpus.metadata[idx0].handicap, 0);

        assert_eq!(corpus.metadata[idx1].n_fuzz, 0);
        assert_eq!(corpus.metadata[idx1].handicap, 7);
    }

    #[test]
    fn update_metadata_nonexistent_id_is_noop() {
        let mut corpus = SnapshotCorpus::new(8);
        corpus.add(snapshot_with_pcs(&[(0, 1)]));

        // Should not panic.
        corpus.update_metadata(9999, |m| {
            m.n_fuzz = 42;
        });
    }

    #[test]
    fn compute_energy_baseline() {
        let mut corpus = SnapshotCorpus::new(8);
        corpus.add(snapshot_with_pcs(&[(0, 1), (1, 2), (2, 3)]));

        // Default metadata: no n_fuzz, no new_bits, no depth, not
        // calibrated, no handicap.  Energy should equal pure novelty.
        let novelty = corpus.novelty_scores()[0];
        let energy = corpus.compute_energy(0);
        let expected = novelty * 1.0; // new_bits=0 → multiplier 1.0

        assert!(
            (energy - expected).abs() < 1e-9,
            "energy {energy} should match novelty {expected} for default metadata"
        );
    }

    #[test]
    fn compute_energy_calibration_bonus() {
        let mut corpus = SnapshotCorpus::new(8);
        let id = corpus.add(snapshot_with_pcs(&[(0, 1), (1, 2)]));

        let energy_before = corpus.compute_energy(0);

        corpus.update_metadata(id, |m| m.calibrated = true);
        let energy_after = corpus.compute_energy(0);

        assert!(
            (energy_after - energy_before * 2.0).abs() < 1e-9,
            "calibration should double the energy"
        );
    }

    #[test]
    fn compute_energy_n_fuzz_penalty() {
        let mut corpus = SnapshotCorpus::new(8);
        let id = corpus.add(snapshot_with_pcs(&[(0, 1), (1, 2)]));

        let energy_fresh = corpus.compute_energy(0);

        corpus.update_metadata(id, |m| m.n_fuzz = 100);
        let energy_explored = corpus.compute_energy(0);

        assert!(
            energy_explored < energy_fresh,
            "energy should decrease after many selections"
        );
        // With n_fuzz=100, divisor is sqrt(100)=10.
        let expected = energy_fresh / 10.0;
        assert!(
            (energy_explored - expected).abs() < 1e-9,
            "energy {energy_explored} should be ~{expected} with n_fuzz=100"
        );
    }

    #[test]
    fn compute_energy_depth_bonus() {
        let mut corpus = SnapshotCorpus::new(8);
        let id = corpus.add(snapshot_with_pcs(&[(0, 1)]));

        let energy_shallow = corpus.compute_energy(0);

        corpus.update_metadata(id, |m| m.depth = 10);
        let energy_deep = corpus.compute_energy(0);

        // depth=10 → multiplier = 1.0 + 10*0.1 = 2.0
        assert!(
            (energy_deep - energy_shallow * 2.0).abs() < 1e-9,
            "depth=10 should double the energy"
        );
    }

    #[test]
    fn compute_energy_handicap_penalty() {
        let mut corpus = SnapshotCorpus::new(8);
        let id = corpus.add(snapshot_with_pcs(&[(0, 1)]));

        let energy_base = corpus.compute_energy(0);

        corpus.update_metadata(id, |m| m.handicap = 5);
        let energy_handicapped = corpus.compute_energy(0);

        // handicap=5 → divisor = 1.0 + 5*0.2 = 2.0
        let expected = energy_base / 2.0;
        assert!(
            (energy_handicapped - expected).abs() < 1e-9,
            "handicap=5 should halve the energy"
        );
    }

    #[test]
    fn compute_energy_new_bits_boost() {
        let mut corpus = SnapshotCorpus::new(8);
        let id = corpus.add(snapshot_with_pcs(&[(0, 1)]));

        let energy_base = corpus.compute_energy(0);

        corpus.update_metadata(id, |m| m.new_bits = 4);
        let energy_boosted = corpus.compute_energy(0);

        // new_bits=4 → multiplier = 1.0 + 4*0.5 = 3.0
        let expected = energy_base * 3.0;
        assert!(
            (energy_boosted - expected).abs() < 1e-9,
            "new_bits=4 should triple the energy"
        );
    }

    #[test]
    fn compute_energy_never_below_minimum() {
        let mut corpus = SnapshotCorpus::new(8);
        let id = corpus.add(snapshot_with_pcs(&[])); // no coverage at all

        // Crank handicap and n_fuzz way up to try to push energy below min.
        corpus.update_metadata(id, |m| {
            m.n_fuzz = 1_000_000;
            m.handicap = 1_000;
        });

        let energy = corpus.compute_energy(0);
        assert!(
            energy >= 0.01,
            "energy {energy} must never drop below minimum 0.01"
        );
    }

    #[test]
    fn metadata_default_values() {
        let meta = PowerMetadata::default();
        assert_eq!(meta.n_fuzz, 0);
        assert_eq!(meta.new_bits, 0);
        assert_eq!(meta.depth, 0);
        assert_eq!(meta.avg_exec_us, 0);
        assert!(!meta.calibrated);
        assert_eq!(meta.handicap, 0);
    }

    #[test]
    fn add_always_pushes_default_metadata() {
        let mut corpus = SnapshotCorpus::new(16);
        corpus.add(snapshot_with_pcs(&[(0, 1)]));
        corpus.add(snapshot_with_pcs(&[(1, 2)]));
        corpus.add(snapshot_with_pcs(&[(2, 3)]));

        assert_eq!(corpus.metadata.len(), 3);
        for meta in &corpus.metadata {
            assert_eq!(meta.n_fuzz, 0);
            assert!(!meta.calibrated);
        }
    }

    #[test]
    fn select_weighted_favors_calibrated_snapshot() {
        let mut corpus = SnapshotCorpus::new(8);

        // Two snapshots with identical coverage.
        let id_a = corpus.add(snapshot_with_pcs(&[(0, 1), (1, 2)]));
        let id_b = corpus.add(snapshot_with_pcs(&[(2, 3), (3, 4)]));

        // Mark only B as calibrated (2× energy boost).
        corpus.update_metadata(id_b, |m| m.calibrated = true);

        // Run many selections and count how often each is picked.
        let mut rng = rand::thread_rng();
        let mut count_a = 0u64;
        let mut count_b = 0u64;
        let trials = 10_000;
        for _ in 0..trials {
            let snap = corpus.select_weighted(&mut rng).unwrap();
            if snap.id == id_a {
                count_a += 1;
            } else {
                count_b += 1;
            }
        }

        // B should be picked roughly 2× as often as A.
        assert!(
            count_b as f64 > count_a as f64 * 1.5,
            "calibrated snapshot B ({count_b}) should be picked much more \
             often than A ({count_a})"
        );
    }
}
