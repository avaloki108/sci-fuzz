//! LibAFL scheduler + state factory for chimerafuzz.
//!
//! Provides helpers for assembling LibAFL's coverage pipeline:
//!
//! ```text
//! SharedCoverageMap ([u8; 65536])
//!   └── StdMapObserver
//!         └── HitcountsMapObserver — AFL bucketing
//!               └── .track_indices() — required by MinimizerScheduler
//!                     └── MaxMapFeedback — novelty detection
//!                           └── IndexesLenTimeMinimizerScheduler
//!                                 └── QueueScheduler
//! ```
//!
//! In Phase 6 (`campaign.rs`), these are assembled inline where Rust can
//! infer all the concrete generic types without complex `impl Trait` bounds.

use std::sync::Arc;

use libafl_bolts::rands::StdRand;

use crate::libafl_adapter::observer::SharedCoverageMap;

// ── Corpus stats ──────────────────────────────────────────────────────────────

/// Corpus statistics for campaign telemetry.
#[derive(Debug, Clone)]
pub struct CorpusStats {
    pub total: usize,
    pub favored: usize,
    pub executions: u64,
}

// ── RNG helper ────────────────────────────────────────────────────────────────

/// Create a `StdRand` from `seed`, or from entropy if `seed == 0`.
pub fn make_rand(seed: u64) -> StdRand {
    if seed == 0 {
        StdRand::new()
    } else {
        StdRand::with_seed(seed)
    }
}

// ── Coverage pipeline macro ───────────────────────────────────────────────────

/// Build the LibAFL coverage pipeline from a `SharedCoverageMap`.
///
/// Expands to `(observer, feedback)` where:
/// - `observer` = `HitcountsMapObserver<StdMapObserver<u8>>.track_indices()`
/// - `feedback` = `MaxMapFeedback::new(&observer)`
///
/// ## Safety
/// `$shared` (an `Arc<SharedCoverageMap>`) must outlive `observer`.
///
/// ## Usage
/// ```ignore
/// let shared = SharedCoverageMap::new();
/// let (observer, feedback) = build_coverage_pipeline!(shared);
/// let scheduler = IndexesLenTimeMinimizerScheduler::new(&observer, QueueScheduler::new());
/// ```
#[macro_export]
macro_rules! build_coverage_pipeline {
    ($shared:expr) => {{
        use libafl::feedbacks::MaxMapFeedback;
        use libafl::observers::{CanTrack, HitcountsMapObserver, StdMapObserver};
        use libafl_bolts::ownedref::OwnedMutSlice;

        let map_slice = unsafe {
            OwnedMutSlice::from_raw_parts_mut(
                $shared.as_mut_ptr(),
                $crate::libafl_adapter::observer::MAP_SIZE,
            )
        };
        let base = StdMapObserver::from_ownedref("chimera_edges", map_slice);
        let observer = HitcountsMapObserver::new(base).track_indices();
        let feedback = MaxMapFeedback::new(&observer);
        (observer, feedback)
    }};
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use libafl::{
        corpus::InMemoryCorpus,
        feedbacks::ConstFeedback,
        schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
        state::StdState,
    };
    use crate::libafl_adapter::{input::EvmInput, observer::SharedCoverageMap};

    #[test]
    fn coverage_pipeline_builds() {
        let shared = SharedCoverageMap::new();
        // Verify the macro expands and types satisfy all constraints.
        let (observer, mut feedback) = build_coverage_pipeline!(shared);
        let mut objective = ConstFeedback::new(false);
        let rand = make_rand(42);
        let state = StdState::new(
            rand,
            InMemoryCorpus::<EvmInput>::new(),
            InMemoryCorpus::<EvmInput>::new(),
            &mut feedback,
            &mut objective,
        );
        assert!(state.is_ok(), "StdState creation failed: {:?}", state.err());

        // Verify scheduler builds.
        let _scheduler: IndexesLenTimeMinimizerScheduler<QueueScheduler, EvmInput, _> =
            IndexesLenTimeMinimizerScheduler::new(
                &observer,
                QueueScheduler::new(),
            );
    }

    #[test]
    fn make_rand_seeded() {
        let r1 = make_rand(12345);
        let r2 = make_rand(12345);
        // Two identical seeds should produce the same first output.
        // (Can't easily test without calling rand methods, but at least verify it builds.)
        let _ = r1;
        let _ = r2;
    }

    #[test]
    fn corpus_stats_fields() {
        let s = CorpusStats { total: 10, favored: 3, executions: 5000 };
        assert_eq!(s.total, 10);
        assert_eq!(s.favored, 3);
    }
}
