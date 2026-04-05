# sci-fuzz — Smart Contract Invariant Fuzzer

A coverage-guided, snapshot-based EVM fuzzer that discovers invariant violations with minimal manual specification.

**Status: serious prototype.** The fuzzing loop runs, the EVM executes, the invariant checkers fire. What remains is proving it against real targets.

## What This Is

sci-fuzz is a Rust-based smart contract fuzzer built on [revm](https://github.com/bluealloy/revm). It combines ideas from ItyFuzz (snapshot-based state exploration), AFL++ (hitcount bucketing and power scheduling), EF/CF (structure-aware mutation and benchmarks), and Echidna (property-based testing) into a single tool.

The name stands for **S**mart **C**ontract **I**nvariant **Fuzz**er. The thesis is that the biggest barrier to effective smart contract fuzzing isn't execution speed — it's the cost of writing good invariants. sci-fuzz attacks that problem through automated invariant generation, template libraries, and economic oracle detection.

## What Works Today

- **EVM execution** via revm 19.7 with snapshot/restore (CacheDB cloning)
- **Real EVM instruction coverage** via a revm inspector that records per-contract instruction hitcounts during execution
- **Dual executor modes**: `Fast` (all safety checks off, best for exploration) and `Realistic` (balance enforcement on, reduces false positives from impossible states)
- **AFL++ hitcount bucketing** — tracks not just "was this PC hit?" but which hitcount bucket (1, 2, 4, 8, 16, 32, 64, 128+), using real instruction hitcounts from the executor so loop iteration differences count as new coverage
- **Power scheduling** — snapshot selection weighted by novelty × new-bits boost × depth bonus ÷ √exploration-count, ported from LibAFL's power schedule and now driven by real execution coverage instead of storage-write heuristics
- **Calibration phase** — runs seed transactions before the main loop to establish coverage baselines and populate the value dictionary
- **ABI-aware mutation** — extracts function selectors from ABI JSON, generates typed arguments (uint256, address, bool, bytes32), mutates with bit-flip, byte-replace, selector-swap, value-change, sender-swap
- **Value dictionary** — seeded from EVM bytecode (PUSH1–PUSH32 operand extraction) and grown from execution results (return data, log topics, storage writes)
- **5 invariant checkers**: BalanceIncrease, UnexpectedRevert, SelfDestruct, EchidnaProperty (log-based assertion detection), ERC20Supply (mint/burn monitoring)
- **Real Echidna property calling** — `EchidnaPropertyCaller` discovers `echidna_*` functions from ABI, calls them via `static_call` after each sequence, checks bool returns. This is the actual Echidna workflow, not just log watching.
- **Deterministic sequence shrinking** — findings are replayed from the same pre-sequence snapshot and reduced by prefix/suffix elimination, whole-tx removal, calldata-word reduction, `msg.value` reduction, and sender simplification
- **Foundry artifact ingestion** — `sci-fuzz forge --project /path/to/project` runs `forge build`, parses standard `out/` artifacts, extracts ABI plus creation/runtime bytecode, and hands selected contracts to the existing campaign
- **Structured benchmark pipeline** — `sci-fuzz benchmark` runs repeatable multi-seed benchmark cases, records first-hit / repro / finding metrics, and emits stable CSV + JSON result files plus grouped summaries
- **Comparison schema for Echidna / Forge** — benchmark rows now include `engine` and `status`, so the same artifact format can hold measured sci-fuzz runs alongside honest `unavailable` / `skipped` external comparison rows
- **Benchmark matrix** — 81 entries mapping EF/CF contracts to expected vulnerability types, with file-existence and category-coverage validation tests
- **133 benchmark contracts** from EF/CF covering reentrancy, selfdestruct, overflow, cross-function attacks, property tests, and assertion tests

## What Does Not Work Yet

Honesty matters more than marketing. These are real gaps:

- **No edge coverage yet.** sci-fuzz now records real per-instruction hitcounts from revm and feeds those into `CoverageFeedback`, but it does not yet record exact edge coverage (`prev_pc -> current_pc`) or perform block/sequence-level path canonicalization.
- **Shrinking is still a first pass.** The shrinker is deterministic and useful today, but it is not yet a full semantic reducer: it does not reason about ABI types, storage dependencies, or minimal base-state snapshots, and it does not guarantee globally minimal sequences.
- **No multi-worker parallelism.** The fuzzing loop is single-threaded. The `workers` config field exists but is not wired.
- **Foundry integration is still partial.** Project mode now invokes `forge build` and ingests standard artifacts from `out/`, but it does not execute setup scripts, deploy script flows, imported invariant harnesses, or library-specific bootstrapping.
- **External comparison execution is still partial.** `sci-fuzz benchmark` has a real measured path for sci-fuzz and a stable comparison schema for Echidna / Forge, but it does not yet orchestrate those tools end-to-end on shared targets. Their rows are reported as `unavailable` or `skipped`, never faked.
- **No on-chain forking.** The `audit` subcommand exists in the CLI but is not implemented.
- **Partial Echidna compatibility.** `EchidnaPropertyCaller` implements the core workflow (discover echidna_* functions, call them, check bool return). `EchidnaProperty` detects assertion events in logs. Neither handles revert/assert distinction with full Echidna fidelity, and the property-harness workflow (targetContract, configurable test limits, shrinking) is not implemented.
- **No Foundry fork/invariant parity.** There is no Foundry fork-mode execution, no `StdInvariant` harness import path, and no parity claim with Foundry's invariant runner.
- **The 207k execs/sec number is a smoke test.** It measures empty-target throughput. Real contracts with storage and complex logic will run at 1–5k execs/sec. The number demonstrates low framework overhead, not security-testing strength.

## Architecture

```text
campaign.rs    main loop: calibrate → select snapshot → generate/mutate → execute → check → learn
evm.rs         revm 19.7 wrapper: execute, deploy, static_call, snapshot/restore, Fast/Realistic modes, instruction coverage inspector
snapshot.rs    state corpus: novelty-weighted selection, power scheduling metadata, auto-pruning over real coverage
feedback.rs    AFL++ hitcount bucketing (8 classes), virgin-bits tracking, real-hitcount ingestion
mutator.rs     ABI-aware generation, 5 mutation strategies, value dictionary, bytecode constant extraction
invariant.rs   Invariant trait + 5 built-in checkers + EchidnaPropertyCaller
oracle.rs      routes execution results through invariant registry
types.rs       core types built on alloy-primitives (Address, U256, B256)
scoreboard.rs  stable benchmark result / summary schema + CSV / JSON writers
benchmark.rs   benchmark case loading, sci-fuzz measurement, comparison scaffolding
cli.rs         clap-based CLI: benchmark, forge, audit, test, ci, diff, version
```

## Installation

```bash
# From source (Rust 1.75+)
git clone https://github.com/your-org/sci-fuzz
cd sci-fuzz
cargo build --release
```

## Usage

```bash
# Fuzz the current Foundry project
sci-fuzz forge --timeout 120

# Fuzz a specific Foundry project in one command
sci-fuzz forge --project /path/to/foundry-project --timeout 120

# Deeper exploration with more snapshots
sci-fuzz forge --project /path/to/foundry-project --depth 32 --max-snapshots 8192 --timeout 600

# Reproducible run
sci-fuzz forge --seed 42 --timeout 60

# Run the built-in EF/CF benchmark preset and emit CSV/JSON evidence
sci-fuzz benchmark --preset efcf-demo --seeds 1,2,3 --max-execs 5000 --output-dir target/benchmark

# Benchmark a real Foundry project with the same schema
sci-fuzz benchmark --project /path/to/foundry-project --target Vault --property campaign --category Campaign --seeds 1,2,3 --max-execs 5000

# Show version
sci-fuzz version
```

## Running Tests

```bash
# All tests (unit + integration)
cargo test

# Just the benchmark matrix validation
cargo test --test benchmark_matrix

# Just the library unit tests
cargo test --lib
```

## Benchmark Matrix

The `tests/benchmark_matrix.rs` file tracks expected results for 81 contracts across 6 categories:

| Category | Contracts | Source |
|----------|-----------|--------|
| Reentrancy | 23 | EF/CF `tests/`, `reentrancy/` |
| EtherDrain | 30 | EF/CF `tests/` |
| Selfdestruct | 12 | EF/CF `tests/` |
| PropertyViolation | 7 | EF/CF `properties-tests/` |
| AccessControl | 5 | EF/CF `tests/` |
| IntegerOverflow | 2 | EF/CF `tests/` |

The matrix is still incomplete, but sci-fuzz now has a real benchmark artifact pipeline for filling it in. Raw benchmark rows can record:

- target / property / bug class / engine / status
- whether the expected issue was found
- first-hit execution count and first-hit wall-clock time
- total executions and elapsed time
- reproducer length before and after shrinking
- total finding count and deduped finding count

The built-in `efcf-demo` benchmark preset is real. A full 81-entry populated matrix is still aspirational until those cases are actually run and checked in.

## Benchmark Artifacts

`sci-fuzz benchmark` emits four files under the chosen output directory:

- `benchmark_results.csv`
- `benchmark_results.json`
- `benchmark_summary.csv`
- `benchmark_summary.json`

The raw result schema includes:

- `target`
- `property`
- `category`
- `mode`
- `seed`
- `found`
- `first_hit_execs`
- `first_hit_time_ms`
- `total_execs`
- `elapsed_ms`
- `repro_len_raw`
- `repro_len_shrunk`
- `finding_count`
- `deduped_finding_count`
- `engine`
- `status`

The grouped summary currently reports:

- hit rate across measured runs
- median first-hit execs
- median first-hit time
- median elapsed time
- median shrunk reproducer length
- counts of `measured`, `unavailable`, `failed`, and `skipped` rows

## What Informed the Design

Every design choice traces to a specific tool in the workspace:

| Decision | Source | Why |
|----------|--------|-----|
| Snapshot-based state corpus | ItyFuzz (ISSTA'23) | Re-executing long sequences to reach deep states is the core bottleneck |
| Hitcount bucketing | AFL++/LibAFL `feedbacks/map.rs` | Binary "hit or not" misses loop-iteration coverage differences |
| Power scheduling | LibAFL `schedulers/powersched.rs` | Uniform random wastes budget on over-explored states |
| ABI-aware mutation | Medusa's weighted strategies | Random bytes almost never produce valid function calls |
| Bytecode constant extraction | EF/CF `evm2cpp` | PUSH operands contain thresholds, magic values, and bounds the fuzzer needs |
| Echidna property interface | Echidna + EF/CF property tests | Compatibility with existing test suites is more valuable than a novel format |
| Assertion event detection | EF/CF assertion tests | Catches `assert()` failures and custom `AssertionFailed` events |
| Template invariants | Slither's 99 detectors | The detector taxonomy maps directly to invariant categories |
| Value dictionary from execution | Medusa's Slither integration | Return values and log data contain contract-relevant constants |
| Benchmark suite | EF/CF `data/` (133 contracts) | Claims without a truth set are self-congratulation |

Notably, LibAFL (v0.16.0) was analyzed but **not** used as a dependency. The type-parameter explosion (every trait generic over 3–5 types), edition-2024 MSRV requirement, and architectural mismatch (LibAFL's Stage pipeline doesn't fit our Plan→Select→Mutate→Execute→Validate→Learn loop) made it better to port the algorithms than adopt the framework.

## Proving the Claims

The minimum proof standard before sci-fuzz earns the label "credible tool":

1. **One real benchmark run** — the 81-entry matrix populated with actual pass/fail/time data
2. **One real Foundry target** — a nontrivial project fuzzing end-to-end with measured findings
3. **One minimized reproducer** — a finding with a shrunk transaction sequence
4. **One side-by-side measured comparison** — sci-fuzz vs Echidna / Forge on a shared target with shared properties

Progress today:

- The benchmark runner and artifact schema are implemented.
- Multi-seed sci-fuzz measurements are real.
- Echidna / Forge comparison rows are scaffolded but not yet measured.
- The full 81-entry matrix is not populated yet.

Until the shared-target comparison rows become measured rather than scaffolded, sci-fuzz remains a working prototype rather than a production-ready benchmarked tool.

## Project Stats

| Metric | Value |
|--------|-------|
| Rust source | ~5,500 lines across 13 modules |
| Unit tests | 106 passing |
| Benchmark contracts | 133 (from EF/CF) |
| Benchmark matrix entries | 81 with expected bug types |
| Dependencies | revm 19.7, alloy-primitives 0.8, clap 4, serde, rand, tiny-keccak |
| Build time (release) | ~17s |
| MSRV | Rust 1.75 (edition 2021) |

## License

MIT

## Acknowledgments

- [ItyFuzz](https://github.com/fuzzland/ityfuzz) — snapshot-based fuzzing architecture
- [LibAFL](https://github.com/AFLplusplus/LibAFL) — power scheduling and hitcount bucketing algorithms
- [EF/CF](https://github.com/uni-due-syssec/efcf-framework) — benchmark contracts and ABI-aware mutation design
- [Echidna](https://github.com/crytic/echidna) — property-based testing interface
- [Medusa](https://github.com/crytic/medusa) — weighted mutation strategies and value dictionary design
- [Slither](https://github.com/crytic/slither) — detector taxonomy informing invariant categories
- [CertoraProver](https://github.com/Certora/CertoraProver) — invariant specification language design
