//! Oracle engine — runs invariant checks and economic analysis after execution.
//!
//! The [`OracleEngine`] is the top-level entry point that the fuzzing loop
//! calls after every execution.  It delegates to an [`InvariantRegistry`] for
//! the actual violation checks.  Balance/profit invariants compare against
//! `pre_sequence_balances` supplied per check (typically captured immediately
//! before executing the sequence under test, after restoring the base snapshot).

use std::collections::HashMap;

use crate::evm::EvmExecutor;
use crate::invariant::InvariantRegistry;
use crate::types::{Address, ExecutionResult, Finding, Transaction, U256};

/// ETH balance baseline for the default invariant set (attacker-only).
///
/// Call after restoring the EVM to the snapshot you are about to fuzz from so
/// balance/profit oracles compare against that state, not a stale campaign root.
pub fn capture_eth_baseline(executor: &EvmExecutor, attacker: Address) -> HashMap<Address, U256> {
    HashMap::from([(attacker, executor.get_balance(attacker))])
}

// ---------------------------------------------------------------------------
// OracleEngine
// ---------------------------------------------------------------------------

/// Oracle engine that checks for violations after each execution.
///
/// Typical usage:
///
/// ```ignore
/// let oracle = OracleEngine::new(attacker_address);
/// let pre = capture_eth_baseline(&executor, attacker_address);
/// // … after each tx in a sequence …
/// let findings = oracle.check(&pre, &crate::types::ProtocolProbeReport::default(), &result, &sequence);
/// ```
pub struct OracleEngine {
    /// Invariant registry used for violation checks.
    registry: InvariantRegistry,
    /// The address considered the "attacker" for profit-detection invariants.
    attacker: Address,
}

impl OracleEngine {
    /// Create an engine pre-loaded with the default invariant set.
    pub fn new(attacker: Address) -> Self {
        Self {
            registry: InvariantRegistry::with_defaults(attacker),
            attacker,
        }
    }

    /// Default invariants plus optional ABI-derived protocol profiles (see [`crate::protocol_semantics::build_protocol_profiles`]).
    pub fn new_with_protocol_profiles(
        attacker: Address,
        profiles: Option<crate::economic::ProtocolProfileMap>,
    ) -> Self {
        Self {
            registry: InvariantRegistry::with_defaults_and_profiles(attacker, profiles),
            attacker,
        }
    }

    /// Create an engine with a caller-supplied invariant registry.
    pub fn with_invariants(attacker: Address, registry: InvariantRegistry) -> Self {
        Self { registry, attacker }
    }

    /// Run every registered invariant against an execution result.
    ///
    /// `pre_sequence_balances` must reflect balances **before** the first
    /// transaction in `sequence` (i.e. at the restored base snapshot).
    ///
    /// Returns all [`Finding`]s produced — an empty `Vec` means no
    /// violations were detected.
    pub fn check(
        &self,
        pre_sequence_balances: &HashMap<Address, U256>,
        pre_sequence_probes: &crate::types::ProtocolProbeReport,
        result: &ExecutionResult,
        sequence: &[Transaction],
    ) -> Vec<Finding> {
        self.registry
            .check_all(pre_sequence_balances, pre_sequence_probes, result, sequence)
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
        let findings = engine.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &empty_result(), &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_balance_increase() {
        let attacker = Address::ZERO;
        let engine = OracleEngine::new(attacker);

        // Baseline: attacker starts with 0.
        let pre = HashMap::from([(attacker, U256::ZERO)]);

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

        let findings = engine.check(&pre, &crate::types::ProtocolProbeReport::default(), &result, &[tx]);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn custom_registry() {
        let attacker = Address::ZERO;
        // Empty registry — should never produce findings.
        let registry = InvariantRegistry::new();
        let engine = OracleEngine::with_invariants(attacker, registry);

        let findings = engine.check(&HashMap::new(), &crate::types::ProtocolProbeReport::default(), &empty_result(), &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn attacker_accessor() {
        let addr = Address::with_last_byte(0x42);
        let engine = OracleEngine::new(addr);
        assert_eq!(engine.attacker(), addr);
    }
}
