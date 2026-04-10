//! FocusedMode: Post-finding replay and minimization.
//!
//! When a finding is discovered, FocusedMode automatically:
//! 1. Replays the finding sequence to confirm it still triggers
//! 2. Applies deterministic shrinking (prefix/suffix/word removal)
//! 3. Perturbs arguments around failing values (±1, ±10, boundaries)
//! 4. Attempts to generalize to related selectors/contracts
//! 5. Outputs a minimal, high-quality reproducer

use std::time::Instant;

use crate::types::Transaction;
use crate::types::U256;

/// FocusedMode state machine for post-finding analysis.
#[derive(Debug, Clone)]
pub enum FocusedMode {
    /// Normal fuzzing mode.
    Normal,
    /// Finding discovered - entering focused mode.
    Entering {
        finding_index: usize,
        sequence: Vec<Transaction>,
        started_at: Instant,
    },
    /// Replay and confirm the finding.
    Confirming {
        finding_index: usize,
        replay_count: usize,
        confirmed: bool,
    },
    /// Shrink the reproducer.
    Shrinking {
        finding_index: usize,
        original_len: usize,
        best_len: usize,
        attempts: usize,
    },
    /// Perturb arguments to find minimal failing values.
    Perturbing {
        finding_index: usize,
        tx_index: usize,
        perturbation_count: usize,
    },
    /// Finding minimized and validated.
    Complete {
        finding_index: usize,
        minimized_len: usize,
    },
}

impl FocusedMode {
    /// Check if currently in focused mode.
    pub fn is_focused(&self) -> bool {
        !matches!(self, FocusedMode::Normal)
    }

    /// Get the finding index if in focused mode.
    pub fn finding_index(&self) -> Option<usize> {
        match self {
            FocusedMode::Normal => None,
            FocusedMode::Entering { finding_index, .. } => Some(*finding_index),
            FocusedMode::Confirming { finding_index, .. } => Some(*finding_index),
            FocusedMode::Shrinking { finding_index, .. } => Some(*finding_index),
            FocusedMode::Perturbing { finding_index, .. } => Some(*finding_index),
            FocusedMode::Complete { finding_index, .. } => Some(*finding_index),
        }
    }

    /// Transition from Normal to Entering focused mode.
    pub fn enter_focused_mode(&self, finding_index: usize, sequence: Vec<Transaction>) -> Self {
        FocusedMode::Entering {
            finding_index,
            sequence,
            started_at: Instant::now(),
        }
    }

    /// Transition from Entering to Confirming.
    pub fn start_confirming(&self) -> Self {
        match self {
            FocusedMode::Entering { finding_index, .. } => FocusedMode::Confirming {
                finding_index: *finding_index,
                replay_count: 0,
                confirmed: false,
            },
            _ => self.clone(),
        }
    }

    /// Transition from Confirming to Shrinking (when confirmed).
    pub fn start_shrinking(&self, original_len: usize) -> Self {
        match self {
            FocusedMode::Confirming { finding_index, confirmed: true, .. } => {
                FocusedMode::Shrinking {
                    finding_index: *finding_index,
                    original_len,
                    best_len: original_len,
                    attempts: 0,
                }
            }
            _ => self.clone(),
        }
    }

    /// Update shrink progress.
    pub fn update_shrink_progress(&self, new_best_len: usize) -> Self {
        match self {
            FocusedMode::Shrinking { finding_index, original_len, best_len: _, attempts } => {
                FocusedMode::Shrinking {
                    finding_index: *finding_index,
                    original_len: *original_len,
                    best_len: new_best_len,
                    attempts: attempts + 1,
                }
            }
            _ => self.clone(),
        }
    }

    /// Transition from Shrinking to Perturbing.
    pub fn start_perturbing(&self, tx_index: usize) -> Self {
        match self {
            FocusedMode::Shrinking { finding_index, .. } => FocusedMode::Perturbing {
                finding_index: *finding_index,
                tx_index,
                perturbation_count: 0,
            },
            _ => self.clone(),
        }
    }

    /// Complete focused mode.
    pub fn complete(&self, minimized_len: usize) -> Self {
        match self {
            FocusedMode::Perturbing { finding_index, .. } => FocusedMode::Complete {
                finding_index: *finding_index,
                minimized_len,
            },
            _ => self.clone(),
        }
    }
}

impl Default for FocusedMode {
    fn default() -> Self {
        FocusedMode::Normal
    }
}

/// Argument perturbation strategies for finding minimal failing values.
#[derive(Debug, Clone, Copy)]
pub enum PerturbationStrategy {
    /// Decrement by 1 (find lower boundary).
    Decrement1,
    /// Increment by 1 (find upper boundary).
    Increment1,
    /// Decrement by 10 (coarse search).
    Decrement10,
    /// Increment by 10 (coarse search).
    Increment10,
    /// Set to 0 (absolute minimum).
    Zero,
    /// Set to max value for the type.
    Max,
    /// Negate the value (if signed).
    Negate,
    /// Random value in [0, 2^32) range.
    Random32,
    /// Random value in [0, 2^64) range.
    Random64,
    /// Random value in [0, 2^128) range.
    Random128,
    /// Random value in [0, 2^256) range.
    Random256,
}

impl PerturbationStrategy {
    /// Get all perturbation strategies.
    pub fn all_strategies() -> &'static [PerturbationStrategy] {
        static STRATEGIES: &[PerturbationStrategy] = &[
            PerturbationStrategy::Decrement1,
            PerturbationStrategy::Increment1,
            PerturbationStrategy::Decrement10,
            PerturbationStrategy::Increment10,
            PerturbationStrategy::Zero,
            PerturbationStrategy::Max,
            PerturbationStrategy::Random32,
            PerturbationStrategy::Random64,
        ];
        STRATEGIES
    }

    /// Apply the perturbation strategy to a U256 value.
    pub fn apply_to(&self, value: &U256, rng: &mut impl rand::Rng) -> U256 {
        match self {
            PerturbationStrategy::Decrement1 => value.saturating_sub(U256::from(1u64)),
            PerturbationStrategy::Increment1 => value.saturating_add(U256::from(1u64)),
            PerturbationStrategy::Decrement10 => value.saturating_sub(U256::from(10u64)),
            PerturbationStrategy::Increment10 => value.saturating_add(U256::from(10u64)),
            PerturbationStrategy::Zero => U256::ZERO,
            PerturbationStrategy::Max => U256::MAX,
            PerturbationStrategy::Negate => {
                // Two's complement negation
                if *value == U256::ZERO {
                    *value
                } else {
                    !value + U256::from(1u64)
                }
            }
            PerturbationStrategy::Random32 => U256::from(rng.gen::<u32>()),
            PerturbationStrategy::Random64 => U256::from(rng.gen::<u64>()),
            PerturbationStrategy::Random128 => {
                let hi = U256::from(rng.gen::<u64>());
                let lo = U256::from(rng.gen::<u64>());
                (hi << 128) | lo
            }
            PerturbationStrategy::Random256 => {
                let w0 = U256::from(rng.gen::<u64>());
                let w1 = U256::from(rng.gen::<u64>());
                let w2 = U256::from(rng.gen::<u64>());
                let w3 = U256::from(rng.gen::<u64>());
                (w0 << 192) | (w1 << 128) | (w2 << 64) | w3
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn focused_mode_state_transitions() {
        let mode = FocusedMode::Normal;
        assert!(!mode.is_focused());

        let mode = mode.enter_focused_mode(0, vec![]);
        assert!(mode.is_focused());
        assert_eq!(mode.finding_index(), Some(0));

        let mode = mode.start_confirming();
        assert_eq!(mode.finding_index(), Some(0));

        let mode = FocusedMode::Confirming {
            finding_index: 0,
            replay_count: 0,
            confirmed: true,
        };
        let mode = mode.start_shrinking(100);
        assert!(matches!(mode, FocusedMode::Shrinking { .. }));

        let mode = mode.update_shrink_progress(50);
        assert!(matches!(mode, FocusedMode::Shrinking { best_len: 50, .. }));

        let mode = mode.start_perturbing(5);
        assert!(matches!(mode, FocusedMode::Perturbing { tx_index: 5, .. }));

        let mode = mode.complete(30);
        assert!(matches!(mode, FocusedMode::Complete { minimized_len: 30, .. }));
    }

    #[test]
    fn perturbation_strategies_apply_correctly() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let val = U256::from(1000u64);

        // Decrement
        assert_eq!(PerturbationStrategy::Decrement1.apply_to(&val, &mut rng), U256::from(999u64));
        assert_eq!(PerturbationStrategy::Decrement10.apply_to(&val, &mut rng), U256::from(990u64));

        // Increment
        assert_eq!(PerturbationStrategy::Increment1.apply_to(&val, &mut rng), U256::from(1001u64));
        assert_eq!(PerturbationStrategy::Increment10.apply_to(&val, &mut rng), U256::from(1010u64));

        // Boundaries
        assert_eq!(PerturbationStrategy::Zero.apply_to(&val, &mut rng), U256::ZERO);
        assert_eq!(PerturbationStrategy::Max.apply_to(&val, &mut rng), U256::MAX);

        // Negation
        let negated = PerturbationStrategy::Negate.apply_to(&val, &mut rng);
        // Verify that negating twice gives us back the original value
        let double_negated = PerturbationStrategy::Negate.apply_to(&negated, &mut rng);
        assert_eq!(double_negated, val, "Double negation should return original value");

        // Zero stays zero
        let zero = U256::ZERO;
        assert_eq!(PerturbationStrategy::Negate.apply_to(&zero, &mut rng), U256::ZERO);
    }

    #[test]
    fn perturbation_strategies_produce_variety() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let val = U256::from(5000u64);

        let mut seen = std::collections::HashSet::new();
        for strategy in PerturbationStrategy::all_strategies() {
            let perturbed = strategy.apply_to(&val, &mut rng);
            seen.insert(perturbed);
        }

        // Should produce at least 8 different values (some may collide)
        assert!(seen.len() >= 8, "Perturbation strategies should produce variety");
    }
}
