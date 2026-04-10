# Chimerafuzz LibAFL Upgrade — Roadmap & TODO

**Created:** 2026-04-10
**Design doc:** `DESIGN_LIBAFL_UPGRADE.md`
**Goal:** Make chimerafuzz find real bugs on competitive bounty targets

---

## Phase 1: Foundation — Input Trait + LibAFL Deps ⬜
**Status:** Not Started
**Effort:** 1 session (~4-6 hours)
**Goal:** LibAFL compiles, `EvmInput` implements `Input` trait

- [ ] Add `libafl`, `libafl_bolts`, `libafl_targets` to `Cargo.toml` (path deps)
- [ ] `cargo check` passes with LibAFL imported
- [ ] Create `src/libafl_adapter/mod.rs`
- [ ] Create `src/libafl_adapter/input.rs` — `EvmInput` struct wrapping `Vec<Transaction>`
- [ ] Implement `libafl::inputs::Input` for `EvmInput` (`.generate()`, serialization)
- [ ] Implement `libafl::inputs::HasBytes` if needed for raw mutation
- [ ] Unit test: `EvmInput` roundtrip serialization
- [ ] Commit: `feat: add LibAFL dependency and EvmInput type`

**Definition of Done:** `cargo check` passes. `EvmInput` can be created, serialized, and deserialized.

---

## Phase 2: Executor Adapter ⬜
**Status:** Not Started
**Effort:** 1-2 sessions (~8-12 hours)
**Goal:** LibAFL can execute an `EvmInput` through our `EvmExecutor`

- [ ] Create `src/libafl_adapter/executor.rs` — `LibAflEvmExecutor`
- [ ] Implement `libafl::executors::Executor` trait
- [ ] `execute()` method: deserialize `EvmInput` → restore snapshot → run tx sequence → collect coverage
- [ ] Create `src/libafl_adapter/observer.rs` — wrap our `CoverageFeedback` as LibAFL `MapObserver`
- [ ] Implement `libafl::feedbacks::Feedback` for our coverage data
- [ ] Wire `OracleEngine::check()` into executor as post-execution hook
- [ ] Findings from oracles are reported through LibAFL's `EventManager`
- [ ] Unit test: execute a simple `EvmInput`, observe coverage map update
- [ ] Unit test: oracle finding is captured by LibAFL event system
- [ ] Commit: `feat: LibAFL executor adapter with oracle integration`

**Definition of Done:** LibAFL can execute a transaction sequence through our EVM, observe coverage, and capture oracle findings.

---

## Phase 3: Mutator Migration ⬜
**Status:** Not Started
**Effort:** 2 sessions (~8-12 hours)
**Goal:** All chimerafuzz mutation strategies work as LibAFL `Mutator` impls

- [ ] Create `src/libafl_adapter/mutators/mod.rs`
- [ ] `abi_calldata.rs` — `AbiCalldataMutator` (selector + argument mutation from `TxMutator`)
- [ ] `sender_value.rs` — `SenderValueMutator` (address + ETH value mutation)
- [ ] `sequence.rs` — `SequenceStructureMutator` (insert/remove/swap tx in sequence)
- [ ] `splice.rs` — `SpliceMutator` (cross-corpus calldata splicing)
- [ ] `havoc.rs` — `EvmHavocMutator` (multi-operation havoc combining several mutations)
- [ ] Each implements `libafl::mutators::Mutator<EvmInput>`
- [ ] Wire into `StdScheduledMutator` with initial equal weights
- [ ] Port UCB weight data from `AdaptiveScheduler` to inform scheduling
- [ ] Unit tests: each mutator produces valid `EvmInput` from a valid seed
- [ ] Commit: `feat: LibAFL mutators for all EVM mutation strategies`

**Definition of Done:** LibAFL's `StdScheduledMutator` can run all our mutation strategies. Each produces structurally valid `EvmInput`.

---

## Phase 4: CmpLog Integration 🔥 (Highest Impact)
**Status:** Not Started
**Effort:** 2 sessions (~8-12 hours)
**Goal:** Fuzzer can solve comparison barriers without brute force

- [ ] Study LibAFL's `CmpValuesObserver` and `CmpMap` traits
- [ ] Add comparison interception to `EvmExecutor` via revm `Inspector` hooks:
  - [ ] Intercept `EQ`, `LT`, `GT`, `LTE`, `GTE` EVM opcodes
  - [ ] Intercept `SHA3` (keccak) inputs for hash comparison matching
  - [ ] Store operand pairs in a `CmpMap`-compatible buffer
- [ ] Create `src/libafl_adapter/mutators/cmplog.rs` — `CmpLogMutator`
  - [ ] Read comparison events from `CmpValuesObserver`
  - [ ] Map calldata offsets to comparison operands via dataflow tracking
  - [ ] Substitute operand values directly into calldata bytes
- [ ] Create `src/libafl_adapter/observer.rs` CmpLog section — `EvmCmpLogObserver`
- [ ] Integration test: fuzzer solves `require(x == 42)` within 1000 execs (was impossible before)
- [ ] Integration test: fuzzer solves `require(msg.sender == owner)` via address substitution
- [ ] Commit: `feat: CmpLog-guided mutation for comparison barrier solving`

**Definition of Done:** Fuzzer can pass through `require` statements that check exact values or addresses, without `vm.assume`. This is the single biggest impact upgrade.

---

## Phase 5: Scheduler + Corpus ⬜
**Status:** Not Started
**Effort:** 1 session (~4-6 hours)
**Goal:** Smart corpus selection that prioritizes high-novelty inputs

- [ ] Create `src/libafl_adapter/scheduler.rs`
- [ ] Implement `libafl::corpus::Corpus` trait for `SnapshotCorpus` (or wrap in `InMemoryCorpus`)
- [ ] Use `MinimizerScheduler` to keep only coverage-contributing inputs
- [ ] Port `PowerMetadata` fields to LibAFL's scheduler metadata
- [ ] Add corpus persistence via `CachedOnDiskCorpus` for save/resume
- [ ] Integration test: corpus grows slower than before (pruning works)
- [ ] Integration test: high-novelty snapshots are selected more often
- [ ] Commit: `feat: LibAFL scheduler with corpus minimization`

**Definition of Done:** Corpus automatically prunes redundant inputs. Power schedule allocates fuzzing budget to high-value snapshots.

---

## Phase 6: Campaign Loop Replacement ⬜
**Status:** Not Started
**Effort:** 1-2 sessions (~8-12 hours)
**Goal:** Full LibAFL fuzzing loop replaces custom campaign

- [ ] Create `src/libafl_adapter/campaign.rs` — `LibAflCampaign`
- [ ] Wire `StdFuzzer::new(scheduler, feedback, objective)`
- [ ] Configure `MutationalStage` with all mutators from Phase 3
- [ ] Add `CalibrationStage` for new corpus entries
- [ ] Custom `EventManager` captures oracle findings as LibAFL events
- [ ] Custom `Monitor` maps to existing `CampaignTelemetry`
- [ ] `Campaign::run()` delegates to `LibAflCampaign` internally
- [ ] CLI unchanged — `chimerafuzz forge` and `chimerafuzz audit` still work
- [ ] Integration test: full campaign runs on a simple Foundry project
- [ ] Integration test: benchmark matrix runs with new campaign loop
- [ ] Commit: `feat: LibAFL-backed campaign loop replaces custom implementation`

**Definition of Done:** `chimerafuzz forge --project .` runs end-to-end using LibAFL internals. All existing CLI commands work.

---

## Phase 7: Concolic Execution (Advanced) ⬜
**Status:** Not Started
**Effort:** 2 sessions (~8-12 hours)
**Goal:** Z3-backed constraint solving for coverage plateaus

- [ ] Study LibAFL's `SimpleConcolicMutator` and `ShadowStage`
- [ ] Replace stub in `src/concolic/mod.rs` with real implementation
- [ ] During revm execution, collect `JUMPI` conditions (path constraints)
- [ ] Build SMT-LIB2 formula: conjunction of taken branches
- [ ] Negate last unexplored branch, solve with Z3 (`~/tools/z3/`)
- [ ] Convert Z3 model to `EvmInput` (map variables to calldata offsets)
- [ ] Add as optional `ConcolicStage` in the LibAFL stage pipeline
- [ ] Integration test: concolic stage explores a branch that mutation alone can't reach
- [ ] Commit: `feat: Z3-backed concolic execution stage`

**Definition of Done:** When the fuzzer plateaus on coverage, concolic stage generates inputs that explore new branches. Requires Z3 binary.

---

## Phase 8: Validation + Tuning ⬜
**Status:** Not Started
**Effort:** 2 sessions (~8-12 hours)
**Goal:** Prove the upgrade works on real targets

- [ ] Run full EF/CF benchmark matrix with upgraded fuzzer
- [ ] Compare results: which additional bugs are found?
- [ ] Measure coverage/sec on 3+ real contracts (vs old fuzzer baseline)
- [ ] Tune mutator weights based on benchmark results
- [ ] Profile with `perf` or `flamegraph` — eliminate hot path bottlenecks
- [ ] Test on a live Cantina target (pick one with <3 prior audits)
- [ ] Document any new CLI flags or config options
- [ ] Update README with LibAFL-backed architecture description
- [ ] Commit: `feat: benchmark validation and performance tuning`

**Definition of Done:** Fuzzer finds ≥2 additional bugs from benchmark matrix that old fuzzer missed. Coverage/sec ≥2x on benchmark targets.

---

## Progress Tracker

| Phase | Status | Started | Completed | Notes |
|-------|--------|---------|-----------|-------|
| 1. Foundation | ⬜ Not Started | — | — | |
| 2. Executor | ⬜ Not Started | — | — | |
| 3. Mutators | ⬜ Not Started | — | — | |
| 4. CmpLog 🔥 | ⬜ Not Started | — | — | Highest impact |
| 5. Scheduler | ⬜ Not Started | — | — | |
| 6. Campaign Loop | ⬜ Not Started | — | — | |
| 7. Concolic | ⬜ Not Started | — | — | |
| 8. Validation | ⬜ Not Started | — | — | |

**Total estimated effort:** 12-16 sessions (~50-80 hours)
**Target completion:** 4-6 weeks (working sessions, not full-time)
**Critical path:** Phase 1 → 2 → 3 → 4 → 6 (Phases 5 and 7 are parallelizable)

---

## Quick Wins (Do First for Motivation)

If you want to see results fast, do these in order:

1. **Phase 1** (Foundation) — get LibAFL compiling, ~1 session
2. **Phase 2** (Executor) — LibAFL executing through our EVM, ~1 session  
3. **Phase 4** (CmpLog) — THIS is the game-changer. Do it before Phase 3 if you want maximum impact per hour. Even a partial CmpLog implementation (just EQ operand substitution) will dramatically improve results on contracts with access control checks.

After Phase 4, the fuzzer will be meaningfully better at finding real bugs. Phases 3, 5, 6 are polish and optimization. Phase 7 is advanced. Phase 8 is proof.
