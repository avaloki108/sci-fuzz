# Chimerafuzz LibAFL Integration — Design Document

**Date:** 2026-04-10
**Status:** Draft
**Goal:** Upgrade chimerafuzz from a custom fuzzing engine to a LibAFL-backed fuzzer that can find real bugs on competitive bounty targets.

---

## 1. Problem Statement

Chimerafuzz has a strong EVM execution layer (revm 19.7), ABI-aware mutation, economic oracles, and snapshot management. But in practice, it fails to find real bugs. The root causes:

1. **Weak mutation scheduling.** The UCB-based `AdaptiveScheduler` tries 9 strategies uniformly. It doesn't learn which mutations produce coverage on a per-target basis. AFL++/LibAFL use power schedules + MOpt that dramatically outperform uniform scheduling.

2. **No real CmpLog.** The `cmp_events` ring buffer collects `ComparisonEvent`s but they're never wired into mutation. This means the fuzzer can't solve `require(x == specificValue)` without `vm.assume` — it just brute-forces.

3. **No corpus minimization.** The `SnapshotCorpus` grows monotonically. Redundant inputs waste cycles. LibAFL's `MinimizerScheduler` keeps only inputs that contribute unique coverage.

4. **No structured/grammatical mutation.** Raw byte flipping destroys ABI-encoded calldata. The fuzzer generates well-formed calls but then mutates them with bit flips that break the encoding. LibAFL's `Nautilus` grammar mutator and `TokenMutations` handle this properly.

5. **Concolic solver is a stub.** `concolic/mod.rs` has 33 lines. It returns `Some(target)` for `solve_eq_const` — literally just returning the answer. Real concolic execution would extract path constraints from revm and solve them with Z3.

## 2. Architecture Overview

### Current Architecture
```
Campaign (campaign.rs, 2357 lines)
  ├── EvmExecutor (evm.rs, 1415 lines) — revm-based EVM
  ├── SnapshotCorpus (snapshot.rs, 629 lines) — state corpus
  ├── TxMutator (mutator.rs, 2182 lines) — mutation
  ├── CoverageFeedback (feedback.rs, 610 lines) — AFL-style buckets
  ├── OracleEngine (oracle.rs, 204 lines) — invariant checks
  ├── InvariantRegistry (invariant.rs, 2304 lines) — property checks
  ├── AdaptiveScheduler (adaptive_scheduler.rs) — UCB strategy
  └── SequenceShrinker (shrinker.rs) — testcase minimization
```

### Target Architecture
```
Campaign (refactored)
  ├── EvmExecutor (KEEP — revm-based EVM, our secret weapon)
  ├── LibAFL Fuzzer Loop
  │   ├── StdScheduledMutator (replaces TxMutator scheduling)
  │   │   ├── EvmAbiMutator (our ABI-aware mutations, as LibAFL Mutator trait)
  │   │   ├── CmpLogMutator (NEW — comparison-guided substitution)
  │   │   ├── TokenMutator (NEW — dictionary-based substitution)
  │   │   └── HavocMutator (LibAFL built-in, adapted for EVM tx sequences)
  │   ├── MapObserver (replaces CoverageFeedback raw edge tracking)
  │   ├── HitcountMapObserver (AFL-style bucketing, from feedback.rs)
  │   ├── MaxMapFeedback (new coverage detection)
  │   ├── Corpus + MinimizerScheduler (replaces SnapshotCorpus selection logic)
  │   └── PowerMutationalStage (replaces custom campaign loop)
  ├── SnapshotCorpus (KEEP — EVM state snapshots, but selection delegated to LibAFL scheduler)
  ├── OracleEngine (KEEP — our oracles are good)
  ├── InvariantRegistry (KEEP — property system is solid)
  ├── EvmCmpLogObserver (NEW — intercepts revm comparisons)
  └── Z3ConcolicStage (NEW — real concolic execution)
```

## 3. LibAFL Trait Mapping

LibAFL uses a trait-based architecture. Here's how chimerafuzz concepts map:

| Chimerafuzz Concept | LibAFL Trait/Struct | Notes |
|---------------------|---------------------|-------|
| `Transaction` | `Input` trait | Wrap in `EvmInput(Vec<Transaction>)` |
| `CoverageFeedback` | `MapObserver` + `MaxMapFeedback` | Already AFL-compatible |
| `SnapshotCorpus` | `Corpus` trait (use `CachedOnDiskCorpus` or `InMemoryCorpus`) | Keep snapshot logic, wrap in trait |
| `TxMutator` | `Mutator` trait | Each strategy becomes a separate `Mutator` impl |
| `AdaptiveScheduler` | `Scheduler` trait (use `MinimizerScheduler` + power metrics) | Replace entirely |
| Campaign loop | `StdFuzzer` + `MutationalStage` | LibAFL drives the loop |
| `OracleEngine` | Post-execution hook in custom `Executor` | Run oracles after each execution |
| `EvmExecutor` | Custom `Executor` impl wrapping revm | The core adapter |
| CmpLog events | `CmpMap` + `CmpValuesObserver` | Wire revm comparisons to LibAFL |
| `PowerMetadata` | `SchedulerMetadata` trait | Already compatible conceptually |

## 4. Implementation Plan — 7 Phases

### Phase 1: LibAFL Dependency + Input Trait (Foundation)
**Files:** `Cargo.toml`, new `src/libafl_input.rs`
**Estimated effort:** 1 session

- Add `libafl` and `libafl_bolts` to `Cargo.toml` as dependencies (path = `~/tools/fuzzers/LibAFL/crates/libafl`)
- Define `EvmInput` struct wrapping `Vec<Transaction>` that implements LibAFL's `Input` trait
- Define `EvmFeedback` struct wrapping our existing `CoverageFeedback` that implements LibAFL's `Feedback` trait
- Verify compilation with `cargo check`

### Phase 2: EvmExecutor Adapter (Executor Trait)
**Files:** new `src/libafl_executor.rs`
**Estimated effort:** 1-2 sessions

- Implement LibAFL's `Executor` trait for a new `LibAflEvmExecutor` that wraps our `EvmExecutor`
- The `execute()` method:
  1. Deserializes `EvmInput` into `Vec<Transaction>`
  2. Restores EVM state from snapshot
  3. Executes the transaction sequence via our existing `EvmExecutor`
  4. Runs `OracleEngine::check()` for invariant violations
  5. Updates coverage map (fed to LibAFL's observer)
  6. Returns `ExitKind` + any findings
- Wire up `MapObserver` backed by our existing edge coverage map
- Keep `EvmExecutor` untouched — adapter pattern only

### Phase 3: Mutator Migration (Mutator Trait)
**Files:** new `src/libafl_mutators/`, modify `src/mutator.rs`
**Estimated effort:** 2 sessions

- Create individual LibAFL `Mutator` implementations:
  - `AbiCalldataMutator` — ABI-aware function selector + argument mutation (from existing `TxMutator`)
  - `EvmHavocMutator` — multi-operation havoc on transaction sequences (from existing `mutate_sequence`)
  - `SenderValueMutator` — address and ETH value mutation (from existing strategies)
  - `SequenceStructureMutator` — insert/remove/swap tx in sequence (from existing `mutate_sequence`)
  - `SpliceMutator` — cross-corpus calldata splicing (from existing `splice`)
- Wire them into LibAFL's `StdScheduledMutator` with weighted selection
- Our `AdaptiveScheduler` UCB data feeds into the weights

### Phase 4: CmpLog Integration (The Game-Changer)
**Files:** modify `src/evm.rs`, new `src/libafl_cmplog.rs`
**Estimated effort:** 2 sessions

- Add comparison interception to revm's `Inspector`/`Hook` in `EvmExecutor`:
  - Capture every `EQ`, `LT`, `GT`, `SHA3` operand pair during execution
  - Store in a `CmpMap`-compatible structure (LibAFL's `CmpValuesObserver`)
- Implement `CmpLogMutator` that:
  1. Reads comparison events from the observer
  2. Identifies calldata offsets that feed into comparisons
  3. Substitutes comparison operands directly into calldata
  4. This breaks through `require(amount > threshold)` without brute force
- This is the single highest-impact upgrade. It's how AFL++ solves magic number barriers.

### Phase 5: Scheduler + Corpus (Smart Selection)
**Files:** new `src/libafl_scheduler.rs`, modify `src/snapshot.rs`
**Estimated effort:** 1 session

- Wrap `SnapshotCorpus` in LibAFL's `Corpus` trait
- Use `MinimizerScheduler` to keep only coverage-contributing inputs
- Port our `PowerMetadata` to LibAFL's `SchedulerMetadata`
- Use `IndexCorpus` for fast random access to snapshots
- Corpus persistence: LibAFL's `CachedOnDiskCorpus` for save/resume

### Phase 6: Campaign Loop Replacement
**Files:** new `src/libafl_campaign.rs`, modify `src/campaign.rs`
**Estimated effort:** 1-2 sessions

- Wire everything into `StdFuzzer`:
  ```rust
  let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
  let mut stages = tuple_list!(
      MutationalStage::new(StdScheduledMutator::new(mutators)),
      CalibrationsStage::new(),
      // future: ConcolicStage::new(),
  );
  fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
  ```
- Findings from `OracleEngine` are captured via a custom `EventManager`
- Campaign telemetry maps to LibAFL's `Monitor` trait
- Keep `Campaign::run()` as the public API, but internals delegate to LibAFL

### Phase 7: Concolic Execution (Advanced)
**Files:** modify `src/concolic/`, new `src/libafl_concolic.rs`
**Estimated effort:** 2 sessions

- Replace the stub `Z3SolverAdapter` with real path constraint extraction:
  1. During revm execution, collect every `JUMPI` condition and comparison
  2. Build a path constraint formula (conjunction of taken branches)
  3. Negate the last branch condition
  4. Solve with Z3 to get an input that takes the unexplored branch
- This is the "nuclear option" for breaking through coverage plateaus
- LibAFL's `ShadowStage` + `SimpleConcolicMutator` provide scaffolding
- Requires `z3` binary (already at `~/tools/z3/`)

## 5. What We Keep (Don't Rewrite)

These modules are **good** and stay as-is:

- **`EvmExecutor`** — revm execution, snapshots, cheatcodes. This is our competitive advantage.
- **`OracleEngine` + `InvariantRegistry`** — the oracle system is sophisticated and well-designed.
- **`SnapshotCorpus`** — EVM state management. Just wrap it in LibAFL's trait.
- **`Bootstrap` / `Project`** — Foundry integration, forge build, artifact parsing.
- **`SequenceShrinker`** — testcase minimization works well.
- **All oracles** — balance, reentrancy, ERC4626, AMM, lending, conservation. These are our finding generators.
- **`ProtocolSemantics` + `Economic`** — protocol detection and profiling.
- **`Cheatcodes`** — vm.prank/deal/warp/etc.
- **CLI** — all interface code stays the same.
- **Output** — SARIF, JUnit, Forge reproducers.

## 6. What Gets Replaced

- `AdaptiveScheduler` → LibAFL `MinimizerScheduler` + power schedule
- Campaign inner loop → `StdFuzzer::fuzz_loop()`
- Manual coverage bookkeeping → LibAFL observers + feedbacks
- Concolic stub → Real Z3-backed solver

## 7. Testing Strategy

### Unit Tests (per phase)
- Phase 1: `EvmInput` serialization roundtrip
- Phase 2: LibAFL executor runs a simple transaction, produces coverage
- Phase 3: Each mutator produces valid `EvmInput` from valid seed
- Phase 4: CmpLog mutator solves a `require(x == 42)` barrier
- Phase 5: Corpus selects high-novelty snapshots over redundant ones
- Phase 6: Full campaign discovers a known bug in EF/CF benchmark

### Integration Tests (benchmark matrix)
- Run existing `benchmark_matrix` against upgraded fuzzer
- Must pass all tests the current fuzzer passes (no regression)
- Must find at least 2 additional bugs from the matrix that current fuzzer misses

### Real-World Validation
- Fuzz a known-vulnerable contract (e.g., reentrancy vault) and confirm finding
- Fuzz a hardened Cantina target and measure coverage/sec vs old fuzzer
- Compare corpus growth curves (old vs new)

## 8. Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| LibAFL API churn (v0.16) | Medium | Pin to exact commit, update quarterly |
| revm 19.7 + LibAFL incompatibility | Low | LibAFL is executor-agnostic, we provide the adapter |
| Performance regression from abstraction layers | Medium | Profile with `criterion`, keep hot path inlined |
| Existing oracles break during refactor | Low | Phase 2 runs oracles through adapter, unchanged logic |
| Rust compilation time increases | Medium | LibAFL has feature flags to minimize deps |

## 9. Success Metrics

- **Coverage/sec:** 2x improvement on benchmark targets
- **Time to first finding:** 50% reduction on EF/CF benchmark matrix
- **New bugs found:** At least 3 additional entries from the benchmark matrix that current fuzzer misses
- **Real bounty finding:** Within 30 days of completing integration, find a valid Medium+ on a live Cantina bounty

## 10. Directory Structure After Integration

```
src/
├── libafl_adapter/          # NEW — LibAFL integration layer
│   ├── mod.rs               # Module root
│   ├── input.rs             # EvmInput (Input trait)
│   ├── executor.rs          # LibAflEvmExecutor (Executor trait)
│   ├── feedback.rs          # CoverageFeedback adapter (Feedback trait)
│   ├── observer.rs          # MapObserver + CmpLog observer
│   ├── scheduler.rs         # Corpus + MinimizerScheduler wrapper
│   ├── mutators/            # Individual Mutator trait impls
│   │   ├── mod.rs
│   │   ├── abi_calldata.rs  # ABI-aware mutation
│   │   ├── cmplog.rs        # CmpLog-guided mutation
│   │   ├── havoc.rs         # Multi-operation havoc
│   │   ├── splice.rs        # Cross-corpus splicing
│   │   ├── sender_value.rs  # Address + ETH value mutation
│   │   └── sequence.rs      # Sequence structure mutation
│   ├── campaign.rs          # StdFuzzer wiring
│   └── concolic.rs          # Z3-backed concolic stage
├── evm.rs                   # KEEP — revm execution (minor CmpLog hooks)
├── snapshot.rs              # KEEP — wrapped in Corpus trait
├── oracle.rs                # KEEP — called from executor adapter
├── invariant.rs             # KEEP — unchanged
├── mutator.rs               # KEEP — becomes backend for LibAFL mutators
├── feedback.rs              # KEEP — data source for LibAFL observer
├── ...                      # All other modules unchanged
```

## 11. Dependency Changes

```toml
# Cargo.toml additions
[dependencies]
libafl = { path = "../LibAFL/crates/libafl", features = ["std", "derive", "llmp"] }
libafl_bolts = { path = "../LibAFL/crates/libafl_bolts", features = ["std"] }
libafl_targets = { path = "../LibAFL/crates/libafl_targets", features = ["std"] }
```

No new binary dependencies. Z3 already installed at `~/tools/z3/`.

---

*This document is a living artifact. Update it as implementation reveals what works and what doesn't.*
