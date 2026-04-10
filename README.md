# chimerafuzz — Next-Generation Smart Contract Fuzzer

> *The most advanced open-source EVM fuzzer ever built.*

**chimerafuzz** is a Rust-based, coverage-guided, snapshot-based smart contract fuzzer that discovers real vulnerabilities with minimal manual specification. It combines the best ideas from academic fuzzing research with practical exploit-oriented invariant detection — delivering a tool designed to find bugs that other fuzzers miss.

## The Vision

Most smart contract fuzzers today force you into one of two traps:

1. **Write everything by hand.** Define every property, set up every invariant, babysit the harness. The fuzzer is fast — *you're* the bottleneck.
2. **Run a scanner and hope.** Black-box mutation throws random bytes at your contracts. It finds nothing because it doesn't understand what a function call *is*.

chimerafuzz attacks the real bottleneck: **the cost of writing good invariants.** Instead of making you manually specify every property, it ships a built-in library of exploit-grade economic oracles, protocol-aware invariant checkers, and ABI-driven mutation that understands your contracts from the first run.

The goal: point it at a target, get real findings back.

## What Makes It Different

**Rust-native EVM execution.** Built on revm 19.7 — no Haskell, no Python, no JVM. Snapshot/restore, dual execution modes (Fast for exploration, Realistic for exploit validation), and real per-contract edge coverage with AFL++ hitcount bucketing. Framework overhead is measured in the hundreds of thousands of executions per second on empty targets; real contracts with storage run 1–5k execs/sec.

**Automatic invariant detection.** You don't need to write `echidna_reentrancy` or `echidna_access_control`. The fuzzer ships with built-in oracles that detect:
- Balance anomalies and unexpected ETH profit
- Reentrancy with state writes in nested calls
- Access control violations (non-owner calling `onlyOwner` functions)
- ERC-4626 vault manipulations (rate manipulation, impossible deposit/withdraw tuples, exchange rate jumps)
- ERC-20 accounting violations (mints without supply updates, transfers without balance changes)
- Uniswap V2 AMM sanity (amountOut exceeding reserves)
- Lending protocol health (net-unbacked borrow debt)
- Token-flow conservation (attacker gains exceeding target losses)
- Self-destruct detection
- Flashloan economic profit oracles

**Protocol-aware ABI analysis.** The fuzzer reads your contract ABIs and builds per-address protocol profiles — detecting whether something looks like a vault, a token, an AMM, or a lending pool. These profiles drive smarter mutation, better triage text, and false-positive reduction. No ABI? It still works — just with less signal.

**Foundry-native workflow.** `chimerafuzz forge --project .` runs `forge build`, ingests artifacts, deploys contracts into a revm instance, executes `setUp()` harnesses, handles `vm.warp`/`vm.roll`/`vm.prank`/`vm.deal`/`vm.expectRevert`/`vm.assume`/`vm.store`/`vm.load` cheatcodes, discovers `echidna_*` properties, and starts fuzzing. One command.

**On-chain auditing.** `chimerafuzz audit 0xAddr --rpc-url $RPC` forks mainnet state and fuzzes deployed contracts directly. Pin a block for reproducibility. Pass multiple addresses for multi-contract attack surfaces. Optional Etherscan ABI fetch.

**Differential fuzzing.** `chimerafuzz diff ImplA ImplB` deploys two implementations into isolated EVMs, drives identical call sequences, and reports divergences — success/revert mismatches, ABI-decoded output differences, and log discrepancies.

**CI-ready output.** SARIF 2.1.0 (GitHub Code Scanning, GitLab SAST), JUnit XML, and compilable Forge `.t.sol` reproducer skeletons. The `chimerafuzz ci` command runs a full campaign and exits with the right code for your pipeline.

**Corpus persistence.** Save and resume fuzzing sessions with `--corpus-dir`. Interesting inputs carry forward between runs.

## Use Cases

### Bug Bounty Hunting

Point chimerafuzz at a target repo or deployed contract and let the economic oracles find the money paths. The built-in profit oracles, vault manipulation detectors, and token-flow conservation checks are designed to surface exactly the kind of high-severity findings that pay out.

```bash
# Fuzz a local Foundry project
chimerafuzz forge --project ./target-repo --timeout 600 --depth 32

# Fuzz deployed contracts on mainnet
chimerafuzz audit 0xVaultAddr 0xTokenAddr --rpc-url $ETH_RPC_URL --timeout 300
```

### Audit Contest Sprinting

Time-boxed audit contests need maximum signal per minute. chimerafuzz's automatic invariant detection means you spend zero time writing harnesses and all your time analyzing findings. Run it alongside manual review to catch what you missed.

```bash
# Quick CI scan with SARIF output
chimerafuzz ci --project . --output-format sarif --output findings.sarif --fail-on-critical

# Differential: compare two implementations for divergent behavior
chimerafuzz diff OriginalImplementation PatchedImplementation --project . --max-execs 5000
```

### Protocol Team Security Regression

Ship chimerafuzz in your CI pipeline. The SARIF and JUnit output integrates with GitHub Actions, GitLab SAST, and any standard CI consumer. Forge `.t.sol` reproducers give you copy-paste test cases for every finding.

```yaml
# GitHub Actions
- name: Fuzz
  run: |
    chimerafuzz ci --project . --output-format sarif --output results.sarif --github-actions --fail-on-critical
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### On-Chain Monitoring

Fork mainnet, pin a block, fuzz deployed contracts, compare results across blocks. Useful for continuous monitoring of live protocols or pre-deployment security review.

```bash
# Fork and fuzz at a specific block
chimerafuzz forge --project ./my-project --fork-url $RPC --fork-block 19000000 --timeout 600
```

### Security Research & Benchmarking

The built-in EF/CF benchmark matrix (~86 entries mapping contracts to expected vulnerability types) gives you a structured way to measure and compare fuzzer performance.

```bash
# Run the benchmark matrix
chimerafuzz benchmark --preset efcf-matrix --seeds 1,2,3 --max-execs 5000 --output-dir target/bench

# Quick demo benchmark
chimerafuzz benchmark --preset efcf-demo --seeds 1 --max-execs 2000 --output-dir target/demo
```

## What Works Today

**Core Engine:**
- EVM execution via revm 19.7 with full snapshot/restore
- Per-contract edge coverage with AFL++ hitcount bucketing (8 classes)
- Power scheduling (novelty × new-bits × depth ÷ √exploration-count)
- Dual executor modes: Fast (max exploration) and Realistic (balance-enforced)
- ABI-aware mutation (typed argument generation, 5+ mutation strategies, value dictionary seeded from bytecode + execution)
- Deterministic sequence shrinking (prefix/suffix/word removal, sender simplification, optional ABI-aware argument reduction)
- Multi-worker parallel campaigns (shared coverage/corpus, per-worker executor)
- Ordered path IDs (per-tx and per-sequence rolling hash fingerprints for novelty detection)
- CmpLog-style comparison events (EQ/LT/GT/ISZERO operands fed into value dictionary)
- Concolic helper stubs (Z3 adapter surface, future branch-distance integration)
- Dependency planner MVP (dynamic read/write hints for call ordering)

**Foundry Integration:**
- Artifact ingestion from `forge build` output
- `setUp()` harness detection, deployment, and execution
- Forge VM cheatcodes: `vm.warp`, `vm.roll`, `vm.prank`, `vm.deal`, `vm.expectRevert`, `vm.assume`, `vm.store`, `vm.load`
- `echidna_*` property discovery and evaluation via `static_call`
- `foundry.toml` RPC URL inheritance for fork mode

**On-Chain / Fork Mode:**
- RPC-backed state fork with full block header alignment
- Shared `RpcCacheDB` for multi-worker fork campaigns
- Deployed contract audit mode (`chimerafuzz audit`)
- Etherscan ABI fetch when `ETHERSCAN_API_KEY` is set
- EIP-1167 minimal proxy detection

**Invariant Oracles (built-in, always active):**
- BalanceIncrease, UnexpectedRevert, SelfDestruct
- EchidnaProperty (log-based assertion + `echidna_*` function calling)
- FlashloanEconomicOracle
- ERC-20 attacker token gain oracle
- AccessControlOracle
- ReentrancyOracle
- TokenFlowConservationOracle
- LendingHealthOracle
- ERC20Supply (opt-in)

**Economic Oracles (exploit-grade, protocol-aware):**
- ERC-4626: impossible Deposit/Withdraw tuples, exchange rate jumps/plunges, same-tx multi-Deposit rate spread, rate shock without visible Transfer
- ERC-20: mint/burn without supply update, balance write without Transfer
- AMM: Uniswap V2 amountOut vs Sync reserves, unexplained Sync reserve changes
- Conservation: Deposit vs underlying Transfer, probe-informed preview vs event divergence
- Protocol probes: post-tx `static_call` probes for vault/token/AMM state (asset(), totalAssets(), totalSupply(), getReserves(), previewDeposit(), etc.)

**CI & Output:**
- SARIF 2.1.0, JUnit XML, Forge `.t.sol` reproducers
- `chimerafuzz ci` command with GitHub Actions annotations
- Corpus persistence via `--corpus-dir`

**Benchmarking:**
- EF/CF benchmark matrix (~86 entries, validated by tests)
- Multi-seed measurement with CSV/JSON artifact output
- Forge external comparison path for side-by-side measurement
- `efcf-matrix` preset for full matrix coverage reports

## What Does Not Work Yet

Honesty is a feature, not a bug. These are real gaps:

- **Shrinking is a first pass.** It doesn't reason about storage dependencies or guarantee globally minimal sequences.
- **No distributed fuzzing.** Multi-worker is in-process threads only; no multi-machine corpus sync.
- **Foundry integration has limits.** Script-based deploy flows, `StdInvariant`/`targetContract` wiring, and multi-contract setup scripts aren't implemented.
- **Economic oracles are heuristic.** Storage slot heuristics match common OZ layouts and break on proxies/diamonds. Conservation checks can false-positive on fee-on-transfer tokens, donations, and non-standard vaults. They're not sound accounting proofs.
- **Differential fuzzing doesn't prove equivalence.** No divergence within budget ≠ equivalent contracts.
- **Benchmark comparisons are partial.** Forge has a real measured path; other external engine rows are scaffolded.
- **The 207k execs/sec number is a smoke test.** Real contracts run 1–5k execs/sec. The number measures framework overhead, not security-testing strength.

## Architecture

```text
campaign.rs          Main loop: calibrate → (optional) parallel workers → corpus/feedback → execute → check → learn
harness.rs           Foundry setUp() selector + one-shot setup execution
evm.rs               revm 19.7 wrapper: execute, deploy, static_call, snapshot/restore, Fast/Realistic modes
path_id.rs           Rolling path hash, per-sequence fold
snapshot.rs          State corpus: novelty-weighted selection, power scheduling, auto-pruning
feedback.rs          AFL++ hitcount bucketing (8 classes), virgin-bits tracking, bounded path-ID novelty
mutator.rs           ABI-aware generation, 5+ mutation strategies, value dictionary
output.rs            SARIF 2.1 / JUnit XML / Forge .t.sol reproducer formatters
economic.rs          Exploit-oriented economic invariants (ERC-4626, ERC-20, AMM, lending)
conservation.rs      Log-order helpers for reserve/Sync conservation
conservation_oracles.rs  AMM Sync explanation, Deposit vs underlying Transfer
protocol_probes.rs   Post-tx static_call probes (vault/token/AMM state)
protocol_semantics.rs  ABI/event protocol classification for economic oracles
invariant.rs         Invariant trait + registry + EchidnaPropertyCaller + access control + reentrancy + lending
oracle.rs            Routes execution results through invariant registry
types.rs             Core types on alloy-primitives (Address, U256, B256)
scoreboard.rs        Benchmark result/summary schema + CSV/JSON writers
benchmark.rs         Benchmark case loading, measurement, Forge comparison, matrix reports
benchmark_matrix.rs  EF/CF expected bug-class table (~86 entries)
concolic/            Bounded SMT/solver helpers (MVP)
dependency_planner.rs Dynamic RW hints for sequence ordering (MVP)
cli.rs               CLI: forge, audit, ci, benchmark, diff, version
rpc.rs               JSON-RPC fork DB, chain ID, full block header parse
main.rs              CLI dispatch
```

## Installation

```bash
# From source (Rust 1.75+)
git clone https://github.com/your-org/chimerafuzz
cd chimerafuzz
cargo build --release

# The binary will be at target/release/chimerafuzz
```

## Quick Start

```bash
# Fuzz a Foundry project
chimerafuzz forge --project ./my-project --timeout 120

# Fuzz deployed contracts on mainnet
chimerafuzz audit 0xTarget1 0xTarget2 --rpc-url https://eth.llamarpc.com --timeout 300

# CI scan with SARIF output
chimerafuzz ci --project . --output-format sarif --output results.sarif --github-actions

# Compare two implementations
chimerafuzz diff ImplA ImplB --project . --seed 42

# Run benchmarks
chimerafuzz benchmark --preset efcf-matrix --seeds 1,2,3 --output-dir target/bench
```

## Usage

### Fuzz a Foundry Project

```bash
# Basic
chimerafuzz forge --project /path/to/project --timeout 120

# Deeper exploration
chimerafuzz forge --project /path/to/project --depth 32 --max-snapshots 8192 --timeout 600

# Reproducible run
chimerafuzz forge --seed 42 --timeout 60

# With corpus persistence (resumes across runs)
chimerafuzz forge --project /path/to/project --corpus-dir .chimerafuzz/corpus --timeout 600

# Fork mode (use on-chain state)
chimerafuzz forge --project /path/to/project --fork-url https://eth.llamarpc.com --fork-block 19000000
```

### Audit Deployed Contracts

```bash
# Single target
chimerafuzz audit 0xYourTarget --rpc-url https://eth.llamarpc.com --timeout 300

# Multiple targets (shared fork root)
chimerafuzz audit 0xVault 0xRouter 0xOracle --rpc-url https://eth.llamarpc.com --timeout 300

# With Etherscan ABI fetch
ETHERSCAN_API_KEY=your_key chimerafuzz audit 0xTarget --rpc-url $RPC --timeout 300
```

### CI Integration

```bash
# SARIF output for GitHub Code Scanning
chimerafuzz ci --project . --output-format sarif --output results.sarif --github-actions --fail-on-critical

# JUnit XML for GitLab/general CI
chimerafuzz ci --project . --output-format junit --output results.xml --corpus-dir .chimerafuzz/corpus
```

### Differential Execution

```bash
# Compare two implementations
chimerafuzz diff ImplA ImplB --project . --max-execs 2000 --depth 8 --seed 42
```

Reports divergences: success/revert mismatches, ABI-decoded output differences, raw return-data differences, and log topic0 sequence/count differences. Stops after first divergence and shrinks to a minimal reproducer.

### Benchmarking

```bash
# Quick demo
chimerafuzz benchmark --preset efcf-demo --seeds 1,2,3 --max-execs 5000 --output-dir target/benchmark

# Full EF/CF matrix
chimerafuzz benchmark --preset efcf-matrix --seeds 1 --max-execs 2000 --output-dir target/benchmark-matrix

# Benchmark a real Foundry project
chimerafuzz benchmark --project /path/to/project --target Vault --property campaign --category Campaign --seeds 1,2,3
```

## Design Influences

Every design choice traces to a specific technique:

| Decision | Inspired By | Why |
|----------|------------|-----|
| Snapshot-based state corpus | ItyFuzz (ISSTA'23) | Re-executing long sequences to reach deep states is the core bottleneck |
| Hitcount bucketing | AFL++/LibAFL | Binary "hit or not" misses loop-iteration coverage differences |
| Power scheduling | LibAFL | Uniform random wastes budget on over-explored states |
| ABI-aware mutation | Academic fuzzing literature | Random bytes almost never produce valid function calls |
| Bytecode constant extraction | EF/CF framework | PUSH operands contain thresholds and bounds the fuzzer needs |
| Echidna property interface | Echidna + EF/CF | Compatibility with existing test suites is more valuable than a novel format |
| Template invariants | Slither detector taxonomy | 99 detectors map directly to invariant categories |
| Value dictionary from execution | Coverage-guided fuzzing research | Return values and log data contain contract-relevant constants |
| Benchmark suite | EF/CF (133 contracts) | Claims without a truth set are self-congratulation |

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Forge VM cheatcodes | ✅ Complete |
| 2 | Extended mutation engine (depth, splice, time-aware) | ✅ Complete |
| 3 | Access control, reentrancy, token-flow oracles | ✅ Complete |
| 4 | CI output: SARIF, JUnit, Forge reproducers | ✅ Complete |
| 5 | Corpus persistence | ✅ Complete |
| 6 | Lending health oracle | ✅ Complete |
| 7 | Semantic shrinker (ABI-aware) | 🟨 Partial |
| 8 | Differential execution | ✅ MVP+ |
| 9 | Parallel corpus persistence | ✅ Complete |
| 10 | Measured benchmark matrix | 🟨 Partial |

**Next layers:** CmpLog-style branch-distance guidance, full concolic campaign stages, dependency-guided corpus selection, two-step access-control confirmation, and deeper semantic shrinking.

## Project Stats

| Metric | Value |
|--------|-------|
| Rust source | ~26,500 lines (30+ modules) |
| Library unit tests | 260+ passing |
| Benchmark contracts | 133 (EF/CF) |
| Benchmark matrix entries | ~86 with expected bug types |
| Dependencies | revm 19.7, alloy-primitives 0.8, clap 4, serde, rand, tiny-keccak |
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
- [revm](https://github.com/bluealloy/revm) — Rust EVM implementation
