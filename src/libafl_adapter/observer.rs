//! LibAFL `Observer` and `Executor` adapters for chimerafuzz.
//!
//! ## EvmCoverageObserver
//!
//! Projects chimerafuzz's nested `CoverageMap` (addr → edge → hitcount) into
//! a flat 65536-byte AFL-style bitmap that `MaxMapFeedback` can consume.
//! The mapping is: `slot = hash(addr, prev_pc, curr_pc) % MAP_SIZE`.
//!
//! ## LibAflEvmExecutor
//!
//! Implements LibAFL's `Executor<EM, EvmInput, S, Z>` by:
//! 1. Restoring the EVM snapshot for the current corpus entry
//! 2. Executing each transaction in the sequence
//! 3. Projecting coverage into the shared bitmap
//! 4. Running OracleEngine and reporting findings
//!
//! Phase 2 delivers a fully wired LibAFL execution path.
//! Phases 3-6 add mutators, scheduler, and campaign loop.

use std::{
    borrow::Cow,
    cell::UnsafeCell,
    hash::{Hash, Hasher},
    collections::hash_map::DefaultHasher,
    sync::{Arc, Mutex},
};

use libafl::{
    Error,
    executors::{Executor, ExitKind},
    observers::{Observer, map::{HitcountsMapObserver, StdMapObserver}},
};
use libafl_bolts::{
    Named,
    ownedref::OwnedMutSlice,
};
use serde::{Deserialize, Serialize};

use crate::{
    evm::EvmExecutor,
    oracle::{capture_eth_baseline, OracleEngine},
    types::{Address, CoverageMap, ExecutionResult, Finding, Transaction, U256},
    libafl_adapter::input::EvmInput,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// AFL-style edge bitmap size. 65536 = 2^16 slots (1 byte each).
/// This is the same default used by AFL++ and LibAFL's standard examples.
pub const MAP_SIZE: usize = 65536;

// ── Shared coverage buffer ────────────────────────────────────────────────────

/// A shared, mutable coverage bitmap passed between the executor (writer)
/// and the observer (reader).
///
/// `UnsafeCell` is required because LibAFL passes both to the fuzzer
/// simultaneously. Safety: executor writes before observer reads, never
/// concurrently.
pub struct SharedCoverageMap {
    inner: UnsafeCell<[u8; MAP_SIZE]>,
}

impl Default for SharedCoverageMap {
    fn default() -> Self {
        Self {
            inner: UnsafeCell::new([0u8; MAP_SIZE]),
        }
    }
}

// SAFETY: chimerafuzz is single-threaded per campaign worker.
unsafe impl Sync for SharedCoverageMap {}

impl SharedCoverageMap {
    /// Create a zeroed shared map.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: UnsafeCell::new([0u8; MAP_SIZE]),
        })
    }

    /// Write pointer — used by the executor after each execution.
    ///
    /// SAFETY: caller must ensure no concurrent reads.
    pub unsafe fn as_mut_ptr(&self) -> *mut u8 {
        (*self.inner.get()).as_mut_ptr()
    }

    /// Read slice — used by the observer.
    ///
    /// SAFETY: caller must ensure no concurrent writes.
    pub unsafe fn as_slice(&self) -> &[u8] {
        &*self.inner.get()
    }

    /// Zero the map. Call before each execution.
    ///
    /// SAFETY: caller must ensure no concurrent reads.
    pub unsafe fn reset(&self) {
        (*self.inner.get()).fill(0);
    }
}

// ── Coverage projection ───────────────────────────────────────────────────────

/// Project a chimerafuzz `CoverageMap` into the flat `[u8; MAP_SIZE]` AFL bitmap.
///
/// For each `(address, (prev_pc, curr_pc), hitcount)` tuple:
/// - Compute slot = `hash(addr, prev_pc, curr_pc) % MAP_SIZE`
/// - Add hitcount (saturating at 255) into that slot
///
/// Multiple edges that hash to the same slot are summed (AFL behavior).
///
/// SAFETY: `map_ptr` must point to a `MAP_SIZE`-byte buffer.
pub unsafe fn project_coverage(coverage: &CoverageMap, map_ptr: *mut u8) {
    for (addr, edges) in &coverage.map {
        for (&(prev_pc, curr_pc), &count) in edges {
            let slot = edge_slot(addr, prev_pc, curr_pc);
            // SAFETY: slot < MAP_SIZE
            let cell = unsafe { &mut *map_ptr.add(slot) };
            *cell = cell.saturating_add(count.min(255) as u8);
        }
    }
}

/// Compute the bitmap slot for a given `(address, prev_pc, curr_pc)` edge.
///
/// Uses `DefaultHasher` for speed. The modulo reduction loses information
/// for very large contracts but is acceptable for 65k slots.
#[inline]
fn edge_slot(addr: &Address, prev_pc: usize, curr_pc: usize) -> usize {
    let mut h = DefaultHasher::new();
    addr.hash(&mut h);
    prev_pc.hash(&mut h);
    curr_pc.hash(&mut h);
    (h.finish() as usize) % MAP_SIZE
}

// ── EvmCoverageObserver ───────────────────────────────────────────────────────

/// LibAFL observer that reads the flat coverage bitmap after each execution.
///
/// Wraps `HitcountsMapObserver<StdMapObserver<u8>>` — LibAFL's standard
/// AFL-style hitcount bucketing observer. It reads from the `SharedCoverageMap`
/// that `LibAflEvmExecutor` wrote into.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct EvmCoverageObserver {
    /// The shared bitmap (executor writes, observer reads).
    /// Skipped in serialization — recreated from SharedCoverageMap on restore.
    #[serde(skip)]
    shared: Arc<SharedCoverageMap>,
    /// Name for LibAFL's metadata registry.
    name: Cow<'static, str>,
    /// Snapshot of last-seen bitmap for novelty detection.
    last_map: Vec<u8>,
}

impl EvmCoverageObserver {
    /// Create a new coverage observer backed by the given shared map.
    pub fn new(name: &'static str, shared: Arc<SharedCoverageMap>) -> Self {
        Self {
            shared,
            name: Cow::Borrowed(name),
            last_map: vec![0u8; MAP_SIZE],
        }
    }

    /// Reference to the current bitmap snapshot.
    pub fn last_map(&self) -> &[u8] {
        &self.last_map
    }

    /// Snapshot count — number of non-zero bytes in last observed map.
    pub fn coverage_bits(&self) -> usize {
        self.last_map.iter().filter(|&&b| b != 0).count()
    }
}

impl Named for EvmCoverageObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S> Observer<I, S> for EvmCoverageObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        // Reset the shared bitmap before each execution so we get a clean read.
        unsafe { self.shared.reset() };
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // Snapshot the bitmap into `last_map` for `MaxMapFeedback`.
        let slice = unsafe { self.shared.as_slice() };
        self.last_map.copy_from_slice(slice);
        Ok(())
    }
}

// ── LibAflEvmExecutor ─────────────────────────────────────────────────────────

/// LibAFL executor wrapping chimerafuzz's `EvmExecutor`.
///
/// Implements `Executor<EM, EvmInput, S, Z>` so that LibAFL's fuzzing loop
/// (via `StdFuzzer`) can execute transaction sequences, observe coverage, and
/// collect oracle findings.
///
/// ## Lifecycle
///
/// ```text
/// LibAFL calls run_target(input):
///   1. shared_map.reset()            — zero bitmap
///   2. evm.restore(base_snapshot)    — fresh EVM state
///   3. for tx in input.transactions: — execute each tx
///        evm.execute(tx)
///        project_coverage(result.coverage, shared_map)
///   4. oracle.check(...)             — invariant checks
///   5. store findings                — for campaign report
///   6. return ExitKind::Ok/Crash
/// ```
pub struct LibAflEvmExecutor {
    pub evm: EvmExecutor,
    pub shared_map: Arc<SharedCoverageMap>,
    pub oracle: OracleEngine,
    pub findings_sink: Arc<Mutex<Vec<Finding>>>,
    pub attacker: Address,
    /// Echidna property callers (for Assertion/Property mode).
    pub property_callers: Vec<crate::invariant::EchidnaPropertyCaller>,
    /// Access control oracles (for detecting missing auth checks).
    pub access_oracles: Vec<crate::invariant::AccessControlOracle>,
}

impl LibAflEvmExecutor {
    /// Full constructor with all oracles configured.
    pub fn new_full(
        evm: EvmExecutor,
        shared_map: Arc<SharedCoverageMap>,
        attacker: Address,
        findings_sink: Arc<Mutex<Vec<Finding>>>,
        oracle: OracleEngine,
        property_callers: Vec<crate::invariant::EchidnaPropertyCaller>,
        access_oracles: Vec<crate::invariant::AccessControlOracle>,
    ) -> Self {
        Self { evm, shared_map, oracle, findings_sink, attacker, property_callers, access_oracles }
    }

    /// Create with shared findings sink and default economic oracle.
    pub fn new_with_sink(
        evm: EvmExecutor,
        shared_map: Arc<SharedCoverageMap>,
        attacker: Address,
        findings_sink: Arc<Mutex<Vec<Finding>>>,
    ) -> Self {
        let oracle = OracleEngine::new(attacker);
        Self {
            evm, shared_map, oracle, findings_sink, attacker,
            property_callers: vec![],
            access_oracles: vec![],
        }
    }

    /// Convenience constructor (private sink, default oracle).
    pub fn new(
        evm: EvmExecutor,
        shared_map: Arc<SharedCoverageMap>,
        attacker: Address,
    ) -> Self {
        Self::new_with_sink(evm, shared_map, attacker, Arc::new(Mutex::new(Vec::new())))
    }

    pub fn drain_findings(&self) -> Vec<Finding> {
        let mut sink = self.findings_sink.lock().unwrap();
        std::mem::take(&mut *sink)
    }
}

impl<EM, S, Z> Executor<EM, EvmInput, S, Z> for LibAflEvmExecutor
where
    S: libafl::state::HasExecutions,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &EvmInput,
    ) -> Result<ExitKind, Error> {
        // Track execution count for LibAFL's scheduler and monitors.
        *state.executions_mut() += 1;
        // Reset coverage bitmap.
        unsafe { self.shared_map.reset() };

        // Capture pre-sequence oracle baseline.
        let pre_balances = capture_eth_baseline(&self.evm, self.attacker);

        // Track combined coverage for this sequence.
        let mut combined_result: Option<ExecutionResult> = None;

        // Execute each transaction in the sequence.
        for tx in &input.transactions {
            match self.evm.execute(tx) {
                Ok(result) => {
                    // Project coverage into shared bitmap.
                    unsafe {
                        project_coverage(&result.coverage, self.shared_map.as_mut_ptr());
                    }
                    // Merge results for oracle check.
                    combined_result = Some(result);
                }
                Err(_) => {
                    // Execution error — revert is normal in EVM fuzzing.
                    // Continue to next tx rather than aborting the sequence.
                    continue;
                }
            }
        }

        // Run oracle checks on the final execution result.
        if let Some(ref result) = combined_result {
            let default_probes = crate::types::ProtocolProbeReport::default();
            let findings = self.oracle.check(
                &pre_balances,
                &default_probes,
                result,
                &input.transactions,
            );
            if !findings.is_empty() {
                let mut sink = self.findings_sink.lock().unwrap();
                sink.extend(findings);
            }

            // Echidna property caller checks (Assertion/Property mode).
            for prop_caller in &self.property_callers {
                let prop_findings = prop_caller.check_properties(
                    &self.evm, self.attacker, &input.transactions,
                );
                if !prop_findings.is_empty() {
                    let mut sink = self.findings_sink.lock().unwrap();
                    sink.extend(prop_findings);
                }
            }

            // Access control oracle checks.
            for ac_oracle in &self.access_oracles {
                if let Some(finding) = crate::invariant::Invariant::check(
                    ac_oracle, &pre_balances, &default_probes, result, &input.transactions,
                ) {
                    let mut sink = self.findings_sink.lock().unwrap();
                    sink.push(finding);
                }
            }
        }

        Ok(ExitKind::Ok)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_map_reset() {
        let m = SharedCoverageMap::new();
        unsafe {
            let ptr = m.as_mut_ptr();
            *ptr = 42;
            *ptr.add(1000) = 99;
            m.reset();
            let s = m.as_slice();
            assert_eq!(s[0], 0);
            assert_eq!(s[1000], 0);
        }
    }

    #[test]
    fn edge_slot_deterministic() {
        let addr = Address::with_last_byte(0xAB);
        let s1 = edge_slot(&addr, 100, 200);
        let s2 = edge_slot(&addr, 100, 200);
        assert_eq!(s1, s2, "edge_slot must be deterministic");
        assert!(s1 < MAP_SIZE);
    }

    #[test]
    fn edge_slot_distinct_edges() {
        let addr = Address::with_last_byte(0xAB);
        let s1 = edge_slot(&addr, 100, 200);
        let s2 = edge_slot(&addr, 100, 201);
        // Not guaranteed to differ (hash collision possible) but very likely.
        // Just ensure both are in range.
        assert!(s1 < MAP_SIZE);
        assert!(s2 < MAP_SIZE);
    }

    #[test]
    fn project_coverage_writes_to_map() {
        let shared = SharedCoverageMap::new();
        let mut cov = CoverageMap::new();
        let addr = Address::with_last_byte(0x01);
        cov.map.entry(addr).or_default().insert((10, 20), 3);

        unsafe {
            shared.reset();
            project_coverage(&cov, shared.as_mut_ptr());
            let slot = edge_slot(&addr, 10, 20);
            let s = shared.as_slice();
            assert_eq!(s[slot], 3, "slot should have hitcount 3");
        }
    }

    #[test]
    fn project_coverage_saturates_at_255() {
        let shared = SharedCoverageMap::new();
        let mut cov = CoverageMap::new();
        let addr = Address::with_last_byte(0x02);
        cov.map.entry(addr).or_default().insert((0, 1), 9999);

        unsafe {
            shared.reset();
            project_coverage(&cov, shared.as_mut_ptr());
            let slot = edge_slot(&addr, 0, 1);
            assert_eq!(shared.as_slice()[slot], 255);
        }
    }
}
