//! Oracle engine — runs invariant checks and economic analysis after execution.
//!
//! The [`OracleEngine`] is the top-level entry point that the fuzzing loop
//! calls after every execution.  It delegates to an [`InvariantRegistry`] for
//! the actual violation checks and maintains the baseline balance snapshot
//! needed by balance-based invariants.

use std::collections::HashMap;

use crate::invariant::InvariantRegistry;
use crate::types::{Address, ExecutionResult, Finding, Transaction, U256};

// ---------------------------------------------------------------------------
// OracleEngine
// ---------------------------------------------------------------------------

/// Oracle engine that checks for violations after each execution.
///
/// Typical usage:
///
/// ```ignore
/// let mut oracle = OracleEngine::new(attacker_address);
/// oracle.set_initial_balances(balances);
///
/// // … after executing a transaction sequence …
/// let findings = oracle.check(&result, &sequence);
/// ```
pub struct OracleEngine {
    /// Invariant registry used for violation checks.
    registry: InvariantRegistry,
    /// The address considered the "attacker" for profit-detection invariants.
    attacker: Address,
    /// Balance baseline captured before the sequence under test.
    initial_balances: HashMap<Address, U256>,
}

impl OracleEngine {
    /// Create an engine pre-loaded with the default invariant set.
    pub fn new(attacker: Address) -> Self {
        Self {
            registry: InvariantRegistry::with_defaults(attacker),
            attacker,
            initial_balances: HashMap::new(),
        }
    }

    /// Create an engine with a caller-supplied invariant registry.
    pub fn with_invariants(attacker: Address, registry: InvariantRegistry) -> Self {
        Self {
            registry,
            attacker,
            initial_balances: HashMap::new(),
        }
    }

    /// Record the balance baseline that invariants compare against.
    ///
    /// This should be called once before starting a new sequence, typically
    /// by snapshotting the EVM balances of all monitored addresses.
    pub fn set_initial_balances(&mut self, balances: HashMap<Address, U256>) {
        self.initial_balances = balances;
    }

    /// Run every registered invariant against an execution result.
    ///
    /// Returns all [`Finding`]s produced — an empty `Vec` means no
    /// violations were detected.
    pub fn check(&self, result: &ExecutionResult, sequence: &[Transaction]) -> Vec<Finding> {
        self.registry
            .check_all(&self.initial_balances, result, sequence)
    }

    /// The attacker address this engine was configured with.
    pub fn attacker(&self) -> Address {
        self.attacker
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Bytes, ExecutionResult, Severity};

    /// Helper — build a minimal no-op execution result.
    fn empty_result() -> ExecutionResult {
        ExecutionResult::default()
    }

    #[test]
    fn no_findings_on_empty_result() {
        let engine = OracleEngine::new(Address::ZERO);
        let findings = engine.check(&empty_result(), &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_balance_increase() {
        let attacker = Address::ZERO;
        let mut engine = OracleEngine::new(attacker);

        // Baseline: attacker starts with 0.
        engine.set_initial_balances(HashMap::from([(attacker, U256::ZERO)]));

        // Simulate a result where attacker gained ether.
        let mut result = empty_result();
        result
            .state_diff
            .balance_changes
            .insert(attacker, (U256::ZERO, U256::from(1_000u64)));

        let tx = crate::types::Transaction {
            sender: attacker,
            to: Some(Address::ZERO),
            data: Bytes::new(),
            value: U256::ZERO,
            gas_limit: 30_000_000,
        };

        let findings = engine.check(&result, &[tx]);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn custom_registry() {
        let attacker = Address::ZERO;
        // Empty registry — should never produce findings.
        let registry = InvariantRegistry::new();
        let engine = OracleEngine::with_invariants(attacker, registry);

        let findings = engine.check(&empty_result(), &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn attacker_accessor() {
        let addr = Address::with_last_byte(0x42);
        let engine = OracleEngine::new(addr);
        assert_eq!(engine.attacker(), addr);
    }
}
