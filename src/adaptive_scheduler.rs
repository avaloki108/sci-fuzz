//! AdaptiveScheduler: UCB-based mutation strategy selection.
//!
//! Tracks success/attempts per mutation strategy and uses Upper Confidence Bound
//! to balance exploration (trying underused strategies) vs exploitation (using
//! what works). Automatically adapts to each contract's characteristics.
//!
//! ## UCB Formula
//!
//! For each strategy i:
//! ```text
//! ucb_i = success_ratio_i + sqrt(2 * ln(total) / attempts_i)
//! ```
//!
//! Where:
//! - `success_ratio_i = successes_i / attempts_i`
//! - `total` = total attempts across all strategies
//! - The second term is the exploration bonus (higher for less-used strategies)
//!
//! ## Strategy Decay
//!
//! Old statistics decay over time (multiply by 0.95) to adapt to changing
//! contract behavior as coverage increases.

use rand::Rng;

/// All mutation strategies available to the fuzzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationStrategy {
    /// Flip a single bit in calldata.
    CalldataBitFlip,
    /// Change a random byte in calldata.
    CalldataByteChange,
    /// Splice calldata from another transaction in corpus.
    CalldataSplice,
    /// Change msg.value.
    ValueChange,
    /// Change msg.sender.
    SenderChange,
    /// Remove a transaction from the sequence.
    SequenceRemove,
    /// Swap two transactions in the sequence.
    SequenceSwap,
    /// CmpLog-guided argument derivation (Redqueen-style).
    CmpLogGuided,
    /// Generate a completely new random transaction.
    RandomGenerate,
}

impl MutationStrategy {
    /// Get all mutation strategies.
    pub fn all_strategies() -> &'static [MutationStrategy] {
        static STRATEGIES: &[MutationStrategy] = &[
            MutationStrategy::CalldataBitFlip,
            MutationStrategy::CalldataByteChange,
            MutationStrategy::CalldataSplice,
            MutationStrategy::ValueChange,
            MutationStrategy::SenderChange,
            MutationStrategy::SequenceRemove,
            MutationStrategy::SequenceSwap,
            MutationStrategy::CmpLogGuided,
            MutationStrategy::RandomGenerate,
        ];
        STRATEGIES
    }

    /// Get the strategy name for logging.
    pub fn name(&self) -> &'static str {
        match self {
            MutationStrategy::CalldataBitFlip => "calldata_bit_flip",
            MutationStrategy::CalldataByteChange => "calldata_byte_change",
            MutationStrategy::CalldataSplice => "calldata_splice",
            MutationStrategy::ValueChange => "value_change",
            MutationStrategy::SenderChange => "sender_change",
            MutationStrategy::SequenceRemove => "sequence_remove",
            MutationStrategy::SequenceSwap => "sequence_swap",
            MutationStrategy::CmpLogGuided => "cmp_log_guided",
            MutationStrategy::RandomGenerate => "random_generate",
        }
    }
}

/// Per-strategy statistics for adaptive scheduling.
#[derive(Debug, Clone, Default)]
pub struct StrategyStats {
    /// Number of times this strategy was used.
    pub attempts: u64,
    /// Number of times this strategy produced new coverage or findings.
    pub successes: u64,
}

impl StrategyStats {
    /// Calculate success ratio (0.0 to 1.0).
    pub fn success_ratio(&self) -> f64 {
        if self.attempts == 0 {
            0.0
        } else {
            self.successes as f64 / self.attempts as f64
        }
    }

    /// Record a successful use of this strategy.
    pub fn record_success(&mut self) {
        self.attempts += 1;
        self.successes += 1;
    }

    /// Record a failed use of this strategy.
    pub fn record_failure(&mut self) {
        self.attempts += 1;
    }

    /// Decay old statistics (multiply by factor).
    pub fn decay(&mut self, factor: f64) {
        self.attempts = (self.attempts as f64 * factor) as u64;
        self.successes = (self.successes as f64 * factor) as u64;
    }
}

/// Adaptive scheduler for mutation strategy selection using UCB.
#[derive(Debug, Clone)]
pub struct AdaptiveScheduler {
    /// Per-strategy statistics.
    stats: std::collections::HashMap<MutationStrategy, StrategyStats>,
    /// Total attempts across all strategies (for UCB calculation).
    total_attempts: u64,
    /// Decay factor applied every 1000 attempts.
    decay_factor: f64,
    /// Attempts since last decay.
    attempts_since_decay: u64,
    /// Disable adaptive scheduling (fall back to uniform random).
    disabled: bool,
}

impl AdaptiveScheduler {
    /// Create a new adaptive scheduler.
    pub fn new() -> Self {
        Self {
            stats: std::collections::HashMap::new(),
            total_attempts: 0,
            decay_factor: 0.95,
            attempts_since_decay: 0,
            disabled: false,
        }
    }

    /// Disable adaptive scheduling (use uniform random selection).
    pub fn disable(&mut self) {
        self.disabled = true;
    }

    /// Enable adaptive scheduling.
    pub fn enable(&mut self) {
        self.disabled = false;
    }

    /// Check if adaptive scheduling is enabled.
    pub fn is_enabled(&self) -> bool {
        !self.disabled
    }

    /// Set the decay factor (0.0 to 1.0). Default: 0.95.
    pub fn set_decay_factor(&mut self, factor: f64) {
        self.decay_factor = factor.clamp(0.0, 1.0);
    }

    /// Calculate UCB score for a strategy.
    fn ucb_score(&self, strategy: MutationStrategy) -> f64 {
        let stats = self.stats.get(&strategy).cloned().unwrap_or_default();

        if stats.attempts == 0 {
            // Never tried -> maximum exploration bonus
            f64::INFINITY
        } else {
            let success_ratio = stats.success_ratio();
            let exploration_bonus = (2.0 * (self.total_attempts as f64).ln() / stats.attempts as f64).sqrt();
            success_ratio + exploration_bonus
        }
    }

    /// Select a strategy using UCB (or uniform random if disabled).
    pub fn select_strategy(&mut self, rng: &mut impl Rng) -> MutationStrategy {
        let strategies = MutationStrategy::all_strategies();

        if self.disabled || self.total_attempts < 10 {
            // Not enough data or disabled -> uniform random
            strategies[rng.gen_range(0..strategies.len())]
        } else {
            // UCB selection
            let mut best_strategy = strategies[0];
            let mut best_score = self.ucb_score(best_strategy);

            for &strategy in &strategies[1..] {
                let score = self.ucb_score(strategy);
                if score > best_score {
                    best_score = score;
                    best_strategy = strategy;
                }
            }

            best_strategy
        }
    }

    /// Record that a strategy produced new coverage or a finding.
    pub fn record_success(&mut self, strategy: MutationStrategy) {
        let stats = self.stats.entry(strategy).or_default();
        stats.record_success();
        self.total_attempts += 1;
        self.attempts_since_decay += 1;
        self.maybe_decay();
    }

    /// Record that a strategy was used but produced no new coverage/findings.
    pub fn record_failure(&mut self, strategy: MutationStrategy) {
        let stats = self.stats.entry(strategy).or_default();
        stats.record_failure();
        self.total_attempts += 1;
        self.attempts_since_decay += 1;
        self.maybe_decay();
    }

    /// Decay statistics if enough attempts have passed.
    fn maybe_decay(&mut self) {
        if self.attempts_since_decay >= 1000 {
            for stats in self.stats.values_mut() {
                stats.decay(self.decay_factor);
            }
            self.attempts_since_decay = 0;
        }
    }

    /// Get statistics for a strategy.
    pub fn get_stats(&self, strategy: MutationStrategy) -> StrategyStats {
        self.stats.get(&strategy).cloned().unwrap_or_default()
    }

    /// Get all statistics.
    pub fn get_all_stats(&self) -> &std::collections::HashMap<MutationStrategy, StrategyStats> {
        &self.stats
    }

    /// Reset all statistics.
    pub fn reset(&mut self) {
        self.stats.clear();
        self.total_attempts = 0;
        self.attempts_since_decay = 0;
    }
}

impl Default for AdaptiveScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn strategy_stats_success_ratio() {
        let mut stats = StrategyStats::default();
        assert_eq!(stats.success_ratio(), 0.0);

        stats.record_failure();
        assert_eq!(stats.success_ratio(), 0.0);

        stats.record_success();
        assert_eq!(stats.success_ratio(), 0.5);

        stats.record_success();
        assert_eq!(stats.success_ratio(), 2.0 / 3.0);
    }

    #[test]
    fn strategy_stats_decay() {
        let mut stats = StrategyStats { attempts: 100, successes: 50 };
        stats.decay(0.5);
        assert_eq!(stats.attempts, 50);
        assert_eq!(stats.successes, 25);
    }

    #[test]
    fn scheduler_initial_state() {
        let scheduler = AdaptiveScheduler::new();
        assert!(scheduler.is_enabled());
        assert_eq!(scheduler.total_attempts, 0);
    }

    #[test]
    fn scheduler_disable_enable() {
        let mut scheduler = AdaptiveScheduler::new();
        assert!(scheduler.is_enabled());

        scheduler.disable();
        assert!(!scheduler.is_enabled());

        scheduler.enable();
        assert!(scheduler.is_enabled());
    }

    #[test]
    fn scheduler_random_selection_before_data() {
        let mut scheduler = AdaptiveScheduler::new();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        // Before 10 attempts, should use uniform random
        let _strategy = scheduler.select_strategy(&mut rng);
        assert!(scheduler.total_attempts < 10);
    }

    #[test]
    fn scheduler_ucb_selection() {
        let mut scheduler = AdaptiveScheduler::new();

        // Record some attempts to establish baseline
        for _ in 0..20 {
            scheduler.record_failure(MutationStrategy::CalldataBitFlip);
        }

        // Untried strategy should have infinite UCB score
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let selected = scheduler.select_strategy(&mut rng);
        // Should select an untried strategy (not CalldataBitFlip)
        assert_ne!(selected, MutationStrategy::CalldataBitFlip);
    }

    #[test]
    fn scheduler_success_bias() {
        let mut scheduler = AdaptiveScheduler::new();

        // Make CalldataBitFlip very successful
        for _ in 0..10 {
            scheduler.record_success(MutationStrategy::CalldataBitFlip);
        }
        // Make other strategies fail
        for _ in 0..10 {
            scheduler.record_failure(MutationStrategy::CalldataByteChange);
        }

        let stats = scheduler.get_stats(MutationStrategy::CalldataBitFlip);
        assert_eq!(stats.attempts, 10);
        assert_eq!(stats.successes, 10);

        let score_best = scheduler.ucb_score(MutationStrategy::CalldataBitFlip);
        let score_worst = scheduler.ucb_score(MutationStrategy::CalldataByteChange);

        // Best strategy should have higher UCB score
        assert!(score_best > score_worst);
    }

    #[test]
    fn scheduler_decay() {
        let mut scheduler = AdaptiveScheduler::new();
        scheduler.set_decay_factor(0.5);

        // Record 1000 attempts to trigger decay
        for i in 0..1000 {
            if i % 2 == 0 {
                scheduler.record_success(MutationStrategy::CalldataBitFlip);
            } else {
                scheduler.record_failure(MutationStrategy::CalldataByteChange);
            }
        }

        let stats = scheduler.get_stats(MutationStrategy::CalldataBitFlip);
        // After decay by 0.5, attempts and successes should be exactly half
        assert_eq!(stats.attempts, 250);
        assert_eq!(stats.successes, 250);
    }

    #[test]
    fn scheduler_reset() {
        let mut scheduler = AdaptiveScheduler::new();
        scheduler.record_success(MutationStrategy::CalldataBitFlip);
        scheduler.record_failure(MutationStrategy::CalldataByteChange);

        assert_eq!(scheduler.total_attempts, 2);

        scheduler.reset();
        assert_eq!(scheduler.total_attempts, 0);
        assert!(scheduler.stats.is_empty());
    }

    #[test]
    fn mutation_strategy_names() {
        assert_eq!(MutationStrategy::CalldataBitFlip.name(), "calldata_bit_flip");
        assert_eq!(MutationStrategy::CmpLogGuided.name(), "cmp_log_guided");
        assert_eq!(MutationStrategy::RandomGenerate.name(), "random_generate");
    }
}
