# sci-fuzz — Smart Contract Invariant Fuzzer

A coverage-guided, snapshot-based EVM fuzzer that discovers invariant violations with minimal manual specification.

**Status: production-capable prototype.** Six improvement phases complete. The fuzzing loop, EVM executor, oracle stack (including lending health detection), CI output pipeline, and corpus persistence all run. What remains is measured validation against real targets, a semantic shrinker, and differential fuzzing.

## What This Is

sci-fuzz is a Rust-based smart contract fuzzer built on [revm](https://github.com/bluealloy/revm). It combines ideas from ItyFuzz (snapshot-based state exploration), AFL++ (hitcount bucketing and power scheduling), EF/CF (structure-aware mutation and benchmarks), and Echidna (property-based testing) into a single tool.

The name stands for **S**mart **C**ontract **I**nvariant **Fuzz**er. The thesis is that the biggest barrier to effective smart contract fuzzing isn't execution speed — it's the cost of writing good invariants. sci-fuzz attacks that problem through automated invariant generation, template libraries, and economic oracle detection.

## What Works Today

> Five improvement phases have been completed since initial prototype. New or significantly improved items are tagged **[Phase N]**.

- **EVM execution** via revm 19.7 with snapshot/restore (CacheDB cloning)
- **Per-contract control-flow edge coverage** via a revm inspector that records `(prev_pc, current_pc)` transitions (per attributed contract) with raw hitcounts during execution
- **Ordered path IDs (per tx and per sequence)** — [`ExecutionResult::tx_path_id`](src/types.rs) fingerprints the **order** of dynamic edges via a rolling hash finalized with `keccak256` (see [`path_id.rs`](src/path_id.rs)), using the same `(contract, prev_pc, current_pc)` attribution as coverage. The campaign combines successive tx path IDs into a sequence-level ID for novelty. [`PathFeedback`](src/feedback.rs) records first-seen tx/sequence path hashes with **bounded** FIFO-capped sets (default 50k each). Corpus snapshots can gain a small energy multiplier via [`PowerMetadata::path_bits`](src/snapshot.rs) when retained primarily for path-order novelty. **Not** a full exported BB trace; not a separate call-stack key beyond today’s bytecode/target attribution; hash collisions are possible in theory; in **multi-worker** mode each thread has its own executor while path state merges into shared feedback; **fork** mode uses the same machinery at `workers = 1`.
- **Dual executor modes**: `Fast` (all safety checks off, best for exploration) and `Realistic` (balance enforcement on, reduces false positives from impossible states)
- **AFL++ hitcount bucketing** — tracks not just "was this edge taken?" but which hitcount bucket (1, 2, 4, 8, 16, 32, 64, 128+), using real transition hitcounts from the executor so loop iteration differences count as new coverage
- **Power scheduling** — snapshot selection weighted by novelty × new-bits boost × depth bonus ÷ √exploration-count, ported from LibAFL's power schedule and now driven by real execution coverage instead of storage-write heuristics
- **RPC-backed fork / deployed-state execution** — When [`CampaignConfig::rpc_url`](src/types.rs) is set, the campaign builds an [`RpcCacheDB`](src/rpc.rs) (`eth_getBalance`, `eth_getCode`, `eth_getTransactionCount`, `eth_getStorageAt` at a pinned block or `latest`), probes the endpoint (`eth_blockNumber`), logs `eth_chainId`, aligns [`BlockEnv`](src/evm.rs) with **full** `eth_getBlockByNumber` header fields (number, timestamp, gas limit, base fee, difficulty, `mixHash` → `prevrandao`, `excessBlobGas` → blob fee via revm’s helper), and uses the forked DB as the **campaign root**. Targets with **no** creation/runtime bytecode are treated as **already deployed** at the configured address: the engine runs an enriched preflight (`eth_getCode`), logs code size and an **EIP-1167 minimal-proxy hint** when the pattern matches (for triage only; no automatic implementation lookup), and optionally **hydrates** empty [`ContractInfo::deployed_bytecode`](src/types.rs) from RPC so logs and value-dictionary seeding see non-zero bytecode (execution already used chain code). Configure via [`CampaignConfig::fork_hydrate_deployed_bytecode`](src/types.rs) (default `true`). Optional [`CampaignConfig::fork_expected_chain_id`](src/types.rs): mismatch with the RPC’s `eth_chainId` emits a warning. **Not** a Forge cheatcode VM: no `vm.*` semantics. [`RpcCacheDB::code_by_hash`](src/rpc.rs) is still a stub (empty); execution relies on bytecode in account info / `CacheDB` overlays — rare `code_by_hash`-only lookups may misbehave.
- **Project-mode fork** — `sci-fuzz forge --fork-url … --fork-block …` sets `rpc_url` / `rpc_block_number`. If `--fork-url` is omitted, `[profile.default] eth_rpc_url` from `foundry.toml` is used when present. CLI overrides `foundry.toml`. When forking **and** deploying local bytecode, the campaign logs that this is **not** Forge script replay.
- **Audit deployed contracts** — `sci-fuzz audit <addr> [<addr> …] --rpc-url …` **requires** an RPC URL (`ETH_RPC_URL` or `--rpc-url`). Pass **multiple addresses** to fuzz several predeployed contracts in one run (shared fork root). Optional Etherscan ABI fetch per address when `ETHERSCAN_API_KEY` is set; otherwise a one-line note that ABIs may be missing.
- **Attacker / sender model** — [`CampaignConfig::resolved_attacker`](src/types.rs) is the EOA: optional [`CampaignConfig::attacker_address`](src/types.rs), else default `0x4242…4242`. **Local** campaigns still seed **100 ETH** in the overlay DB. **Fork** campaigns: by default [`CampaignConfig::fork_attacker_balance_wei`](src/types.rs) (100 ETH) **replaces** the attacker balance in the overlay; set [`CampaignConfig::fork_preserve_attacker_balance`](src/types.rs) to keep the forked chain balance instead. CLI `--attacker` on `forge` / `audit` sets `attacker_address`. The same address is used for deploy/setup, mutator sender pool, Echidna property `static_call` context, and balance/profit oracles.
- **Multi-worker parallel campaign (local in-memory DB)** — Implemented in `campaign.rs` as `run_parallel_campaign`: after calibration, one OS thread per worker (`parallel_worker_loop`), each with its **own** `EvmExecutor`. Shared resources — coverage feedback, snapshot corpus, saved DB snapshots, finding dedupe, aggregated `CampaignReport` counters — sit behind **mutexes** and are updated from all workers.
  - **RPC mode:** If `rpc_url` is set, the campaign **forces `workers = 1`**. Fork/RPC-backed state is not shared safely across threads.
  - **Reproducibility:** With `workers > 1`, **scheduling is not fully reproducible** across runs (thread interleaving differs).
  - **Scaling:** **Lock contention** on shared corpus/state and a **shared mutator** (serialized selector / value-dictionary updates) can **cap throughput**; do not expect linear speedup vs worker count.
  - **Scope:** **No distributed fuzzing** — in-process threads only; no multi-machine corpus sync (see *What Does Not Work Yet*).
- **Calibration phase** — runs seed transactions before the main loop to establish coverage baselines and populate the value dictionary
- **ABI-aware mutation** — extracts function selectors from ABI JSON, generates typed arguments (uint256, address, bool, bytes32), mutates with bit-flip, byte-replace, selector-swap, value-change, sender-swap
- **Value dictionary** — seeded from EVM bytecode (PUSH1–PUSH32 operand extraction) and grown from execution results (return data, log topics, storage writes)
- **Core invariant checkers** (always registered): BalanceIncrease, UnexpectedRevert, SelfDestruct, EchidnaProperty (log-based assertion detection), FlashloanEconomicOracle (profit after mock flashloan scaffold). ETH balance baselines for profit-style checks are **per sequence**: captured immediately before executing the sequence (after restoring the selected snapshot), not once at campaign start — so non-root corpus snapshots compare against the correct pre-sequence balances.
- **Exploit-grade economic oracles** ([`economic.rs`](src/economic.rs)) with optional **ABI-derived protocol hints** ([`protocol_semantics.rs`](src/protocol_semantics.rs)): the campaign builds a per-address profile from each target’s JSON ABI (function/event names + soft name/path hints). Profiles **do not** recover storage layout; they drive **triage text**, **false-positive reduction** on some checks when ABI is present, and **honest fallbacks** when ABI is missing. All checks still use execution evidence (logs + per-tx `state_diff`, plus **sequence-cumulative logs** where noted):
  - ERC-4626 impossible `Deposit` / `Withdraw` event tuples (assets/shares consistency); findings include classification/triage footer.
  - ERC-20 **mint** and **burn** (large `Transfer` from/to `address(0)`) without an OpenZeppelin-style `_totalSupply` storage write (slot 2 heuristic) — descriptions note whether `totalSupply()` appears in the ABI.
  - ERC-20 balance mapping writes with no `Transfer` in the same tx — **suppressed** when ABI classifies the contract as non–ERC-20-like (reduces accidental hits on non-token layouts).
  - ERC-4626 exchange-rate **jumps** / **plunges** on consecutive **`Deposit`** / **`Withdraw`** events (cumulative log stream; default 5× threshold) — **suppressed** when ABI is present but shows no ERC-4626 signals (`erc4626_score == 0`), to reduce topic-collision noise.
  - ERC-4626 **same-transaction multi-`Deposit` rate spread** — same gating as rate jumps.
  - **ERC-4626 rate shock without visible `Transfer` to vault** — cumulative `Deposit`-implied rate jump with no ERC-20 `Transfer` to the vault in the same log stream (medium severity; native ETH / non-ERC-20 paths not modeled).
  - **Uniswap V2–shaped AMM sanity** — if `Sync(uint112,uint112)` and `Swap(address,uint256,uint256,uint256,uint256,address)` topics match, flags `amountOut` exceeding the last `Sync` reserves before the swap in **log order** (not full constant-product or multi-hop modeling).
  - **Reserve / conservation oracles** ([`conservation.rs`](src/conservation.rs), [`conservation_oracles.rs`](src/conservation_oracles.rs)) — first-pass **observable-flow** checks (not formal verification): **[`AmmSyncExplainedOracle`](src/conservation_oracles.rs)** flags two `Sync` events for the same pair whose reserves **change** with no intervening Uniswap V2–shaped `Swap` / `Mint` / `Burn` on that pair in **log order** (uses [`ExecutionResult::sequence_cumulative_logs`](src/types.rs) when present). **[`Erc4626DepositVsUnderlyingTransferOracle`](src/conservation_oracles.rs)** compares each `Deposit` event’s `assets` to the sum of ERC-20 `Transfer` deliveries **to the vault** on the probed underlying asset address in the **same transaction**, with optional triage text from a post-state `balanceOf(vault)` probe on the underlying token.
  - Optional [`PairwiseStorageDriftOracle`](src/economic.rs) for lending-style debt-vs-collateral **raw slot** comparison when wired manually (not in the default registry).
  - **Executor-backed protocol probes** ([`protocol_probes.rs`](src/protocol_probes.rs)) — after each successful transaction, the campaign fills [`ExecutionResult::protocol_probes`](src/types.rs) using [`EvmExecutor::static_call`](src/evm.rs) at **post-state** (same DB the next tx would see). Classification + per-target JSON ABI gate calls; a hard cap limits `static_call`s per step. **ERC-4626-like:** `asset()`, `totalAssets()`, **`balanceOf(vault)` on the underlying asset** (standard `balanceOf` selector when `asset()` resolves), and for each `Deposit` / `Withdraw` in this step’s logs, `previewDeposit` / `convertToShares` / `previewWithdraw` / `previewRedeem` on **event-derived amounts** where the ABI lists the function. **ERC-20-like:** `totalSupply()`, `balanceOf(attacker)`. **AMM/pair-like:** `getReserves()`. Missing ABI, missing functions, reverts, and decode failures are skipped gracefully.
  - **Probe-informed economic oracles:** [`Erc4626PreviewVsDepositEventOracle`](src/economic.rs) flags large divergence between `previewDeposit(assets)` and `Deposit` event minted shares (tolerance ~0.1% relative + a few wei). [`UniswapV2StyleSyncVsGetReservesOracle`](src/economic.rs) compares the last `Sync` reserves in the tx to post-state `getReserves()` (uint112-expanded vs ABI-decoded words). Other economic oracles unchanged; probe rows are available for triage text.
  - **Still not:** **complete** multi-asset / constant-product reserve proofs, **generic lending solvency**, full **bridge** custody semantics, ABI-driven storage slot discovery, or complete ERC-4626 / AMM coverage (see *What Does Not Work Yet*). Conservation checks are **heuristic** (donations + `sync()`, fee-on-transfer, non-standard events, and native ETH paths can confuse them).
- **Sequence-cumulative logs** — the campaign and shrink replay attach all logs from the current transaction sequence to [`ExecutionResult::sequence_cumulative_logs`](src/types.rs) so oracles can reason about multi-step event history without wrapping external fuzzers.
- **ERC20Supply** (optional via `InvariantRegistry::with_erc20`) — large mint/burn monitoring (legacy heuristic, separate from supply-vs-storage reconciliation above)
- **Real Echidna property calling** — `EchidnaPropertyCaller` discovers `echidna_*` functions from ABI, calls them via `static_call` after each sequence, checks bool returns. This is the actual Echidna workflow, not just log watching.
- **Deterministic sequence shrinking** — findings are replayed from the same pre-sequence snapshot and reduced by prefix/suffix elimination, whole-tx removal, calldata-word reduction, `msg.value` reduction, and sender simplification
- **Foundry artifact ingestion** — `sci-fuzz forge --project /path/to/project` runs `forge build`, parses standard `out/` artifacts, extracts ABI plus creation/runtime bytecode, and hands selected contracts to the existing campaign
- **Foundry harness / `setUp()` (first pass)** — the engine classifies `src/` runtime contracts vs `test/` harness candidates (ABI must include parameterless `setUp()` and creation bytecode). It deploys runtime targets first, then at most one harness (preferring a contract whose ABI also lists `echidna_*` properties), executes `setUp()` once through revm, then records the root snapshot and starts calibration/fuzzing. Lifecycle functions `setUp`, `beforeTest`, and `afterTest` are stripped from the mutator’s ABI so setup is not randomly re-invoked during fuzzing; `echidna_*` discovery still uses the full ABI on the deployed harness
- **Structured benchmark pipeline** — `sci-fuzz benchmark` runs repeatable multi-seed benchmark cases, records first-hit / repro / finding metrics, and emits stable CSV + JSON result files plus grouped summaries
- **Comparison schema for Echidna / Forge** — benchmark rows now include `engine` and `status`, so the same artifact format can hold measured sci-fuzz runs alongside honest `unavailable` / `skipped` external comparison rows
- **Benchmark matrix** — 81 entries mapping EF/CF contracts to expected vulnerability types, with file-existence and category-coverage validation tests
- **Forge VM cheatcodes** **[Phase 1]** — `vm.warp()`, `vm.roll()`, `vm.prank()`, `vm.deal()`, `vm.expectRevert()`, `vm.assume()`, `vm.store()`, and `vm.load()` are intercepted inside the revm execution loop. Harnesses that use these cheatcodes in `setUp()` and test functions now execute correctly instead of reverting.
- **Extended mutation engine** **[Phase 2]** — configurable mutation depth limits, sequence-splice mutations (cross-sequence segment recombination), and time-aware mutations (block timestamp / block number perturbation during calldata generation). These lift coverage on time-gated and multi-step state machines that were previously invisible to the fuzzer.
- **Access-control oracle** **[Phase 3]** — `AccessControlOracle` detects when a non-owner sender successfully calls a function that contains `onlyOwner` / `onlyRole`-pattern reverts for other senders. Auto-registers on contracts whose ABIs include standard `Ownable` / `AccessControl` event signatures.
- **Reentrancy oracle** **[Phase 3]** — `ReentrancyOracle` flags `SSTORE` writes inside nested calls (`call_depth > 1`) combined with net ETH profit. Integrates with the `CoverageInspector` via the `sstore_in_nested_call` flag on `ExecutionResult`.
- **Token-flow conservation oracle** **[Phase 3]** — `TokenFlowConservationOracle` detects ERC-20 balance drain: tracks pre/post-sequence `balanceOf` for a specified token and target, fires High/Critical when the attacker gains more tokens than the target loses.
- **CI output pipeline** **[Phase 4]** — `src/output.rs` provides three pure formatters:
  - `sarif_from_findings()` — SARIF 2.1.0 JSON (GitHub Code Scanning, GitLab SAST, any SARIF consumer). Deduplicates the `rules` array; maps Critical/High → `"error"`, Medium → `"warning"`, Low/Info → `"note"`.
  - `junit_from_findings()` — JUnit XML. Emits a passing testcase on clean runs so CI parsers always see at least one result.
  - `forge_reproducer()` — compilable Solidity `.t.sol` skeleton with `vm.prank()` + `call{value:}` for each transaction in the reproducer sequence.
- **`sci-fuzz ci` command** **[Phase 4]** — fully implemented (`handle_ci()` in `main.rs`). Runs a real campaign (50k execs, seed `0xcafebabe`, 2 workers, configurable timeout). Emits GitHub Actions `::error/warning/notice` annotations when `--github-actions` is passed. Writes Forge `.t.sol` reproducers to `test/repros/`. Exits with code `2` when critical/high findings meet configured thresholds (distinct from build error exit `1`).
- **Corpus persistence** **[Phase 5]** — `CampaignConfig::corpus_dir` (optional `PathBuf`) enables JSON-based corpus save/load across campaign runs. Load injects up to 64 prior entries at campaign start; save runs at campaign end after the main loop. All I/O failures are `tracing::warn!` only — corpus loss never terminates a run. CLI flags: `--corpus-dir` on both `forge` and `ci` subcommands.
- **Lending health oracle** **[Phase 6]** — `LendingHealthOracle` detects net-unbacked borrow debt by scanning sequence-cumulative logs for standard `Borrow` event signatures. Handles both a generic `Borrow(address,address,uint256)` shape and the Compound-v2 `Borrow(address,uint256,uint256,uint256)` shape (amount always decoded from `data[0..32]`). Paired `Repay` and `RepayBorrow` events are subtracted; only net open debt above `min_net_borrow` fires. Profile-gated via `is_lending_like()` (ABI lending score ≥ 3 from `protocol_semantics.rs`) when profiles are attached — silent on non-lending targets. Severity escalates from Medium to High when the attacker also gains ETH in the same sequence.

## What Does Not Work Yet

Honesty matters more than marketing. These are real gaps:

- **Path IDs are a compact fingerprint, not a perfect trace.** Full canonical basic-block traces, call-depth-indexed edge keys beyond the current contract attribution, and a global path database are still out of scope. Path novelty uses bounded caches — under extreme uniqueness pressure, older path IDs may be evicted and re-novel. Native mock-flashloan txs use a deterministic synthetic path ID (no bytecode inspector).
- **Shrinking is still a first pass.** The shrinker is deterministic and useful today, but it is not yet a full semantic reducer: it does not reason about ABI types, storage dependencies, or minimal base-state snapshots, and it does not guarantee globally minimal sequences.
- **No distributed fuzzing** — parallel workers are threads in one process only; there is no multi-machine corpus or coordinator (see multi-worker **Scope** above).
- **Parallel campaign corpus persistence not wired.** `corpus_dir` is loaded and saved only via the single-worker path in `run_with_report()`. The parallel `run_parallel_campaign()` path does not read from or write to the corpus directory.
- **Foundry integration gaps beyond basic cheatcodes.** Script-based deploy flows, library-specific bootstrapping, `StdInvariant` / `targetContract` wiring, and multi-contract setup scripts are not implemented. Phase 1 covered the common cheatcodes (`vm.warp`, `vm.roll`, `vm.prank`, `vm.deal`, `vm.expectRevert`, `vm.assume`, `vm.store`, `vm.load`), but full equivalence with Foundry's invariant runner is not the goal.
- **CLI stubs remaining: `sci-fuzz test` and `sci-fuzz diff`** print placeholder messages. `sci-fuzz ci` is now fully implemented. `sci-fuzz test` and `sci-fuzz diff` are not.
- **External comparison execution is still partial.** `sci-fuzz benchmark` has a real measured path for sci-fuzz and a stable comparison schema for Echidna / Forge, but it does not yet orchestrate those tools end-to-end on shared targets. Their rows are reported as `unavailable` or `skipped`, never faked.
- **Partial Echidna compatibility.** `EchidnaPropertyCaller` implements the core workflow (discover `echidna_*` functions, call them, check bool return). `EchidnaProperty` detects assertion events in logs. Neither handles revert/assert distinction with full Echidna fidelity, and the property-harness workflow (`targetContract`, configurable test limits, shrinking) is not implemented.
- **Economic and conservation oracles remain heuristic despite ABI hints and probes.** Storage slot layouts (ERC-20 `totalSupply` at slot 2, balances at mapping slot 0) still match common OpenZeppelin layouts and break on proxies, diamonds, and custom storage. Classification and gating reduce some noise but do not guarantee soundness. Rate-jump, same-tx spread, and “no Transfer to vault” checks can still false-positive on extreme rounding, first-liquidity edges, donation economics, or non-standard vaults. Probe-vs-event checks can false-positive on fee-on-transfer assets, donation-style reserve moves, or non-standard vaults/pairs. **Conservation** checks (Sync window explanation, Deposit vs underlying `Transfer`) improve triage for pools and vaults but are **not** sound accounting proofs; bridges are still not modeled. `LendingHealthOracle` covers common `Borrow`-event patterns but is not a full collateral-ratio proof — multi-asset positions, health-factor math, and liquidation thresholds are not modeled.
- **The 207k execs/sec number is a smoke test.** It measures empty-target throughput. Real contracts with storage and complex logic will run at 1–5k execs/sec. The number demonstrates low framework overhead, not security-testing strength.

## Architecture

```text
campaign.rs          main loop: calibrate → (optional) parallel workers → shared corpus/feedback → execute → check → learn
                     corpus save/load via corpus_dir at start/end of run_with_report()
harness.rs           Foundry-style setUp() selector + one-shot setup execution on the revm executor
evm.rs               revm 19.7 wrapper: execute, deploy, static_call, snapshot/restore, Fast/Realistic modes
                     edge coverage + ordered path stream + call_depth tracking + sstore_in_nested_call flag [Phase 3]
path_id.rs           rolling path hash, per-sequence fold, native-flashloan synthetic id
snapshot.rs          state corpus: novelty-weighted selection, power scheduling metadata, auto-pruning over real coverage
feedback.rs          AFL++ hitcount bucketing (8 classes), virgin-bits tracking, bounded path-ID novelty
mutator.rs           ABI-aware generation, 5 mutation strategies + splice + time-aware mutations [Phase 2], value dictionary
output.rs            SARIF 2.1 / JUnit XML / Forge .t.sol reproducer formatters [Phase 4]
economic.rs          exploit-oriented economic invariants (ERC-4626, ERC-20 accounting, AMM swap/sync sanity, optional lending drift, probe-informed checks)
conservation.rs      log-order helpers for reserve/Sync conservation reasoning
conservation_oracles.rs  AmmSyncExplainedOracle, Erc4626DepositVsUnderlyingTransferOracle
protocol_probes.rs   post-tx static_call probes (ERC-4626 / ERC-20 / AMM) into ExecutionResult
protocol_semantics.rs  best-effort ABI/event protocol classification and triage helpers for economic oracles
invariant.rs         Invariant trait + default registry + EchidnaPropertyCaller
                     AccessControlOracle, ReentrancyOracle, TokenFlowConservationOracle [Phase 3]
                     LendingHealthOracle [Phase 6]
oracle.rs            routes execution results through invariant registry; balance baselines supplied per check
types.rs             core types built on alloy-primitives (Address, U256, B256)
                     ExecutionResult: tx_path_id, sequence_cumulative_logs, protocol_probes, sstore_in_nested_call [Phase 3]
                     CampaignConfig: corpus_dir [Phase 5]
scoreboard.rs        stable benchmark result / summary schema + CSV / JSON writers
benchmark.rs         benchmark case loading, sci-fuzz measurement, comparison scaffolding
cli.rs               clap-based CLI: benchmark, forge, audit, test, ci (implemented), diff (stub), version
rpc.rs               JSON-RPC fork DB (RpcCacheDB), chain id, full block header parse/merge into BlockEnv
main.rs              CLI dispatch; handle_forge(), handle_ci() [Phase 4], handle_benchmark(), handle_audit()
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

# Persist corpus across runs (resumes from prior interesting inputs)
sci-fuzz forge --project /path/to/project --corpus-dir .sci-fuzz/corpus --timeout 600

# Foundry project + JSON-RPC fork (optional block pin; or set eth_rpc_url in foundry.toml)
sci-fuzz forge --project /path/to/project --fork-url https://eth.llamarpc.com --fork-block 19000000 --timeout 600

# Audit deployed contract(s) (requires ETH_RPC_URL or --rpc-url)
export ETH_RPC_URL=https://eth.llamarpc.com
sci-fuzz audit 0xYourTarget --chain mainnet --timeout 300
# Multiple predeployed targets on the same fork
sci-fuzz audit 0xVault 0xRouter 0xOracle --chain mainnet --timeout 300

# CI security scan — emits SARIF/JUnit, GitHub Actions annotations, Forge reproducers
sci-fuzz ci --project . --output-format sarif --output results.sarif --github-actions --fail-on-critical
sci-fuzz ci --project . --output-format junit --output results.xml --corpus-dir .sci-fuzz/corpus

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
- CI output (SARIF, JUnit, Forge reproducers) is implemented and tested.
- Corpus persistence across runs is implemented.

Until the shared-target comparison rows become measured rather than scaffolded, sci-fuzz remains a strong prototype rather than a fully validated production tool.

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Forge VM cheatcodes (`vm.warp`, `vm.roll`, `vm.prank`, `vm.deal`, `vm.expectRevert`, `vm.assume`, `vm.store`, `vm.load`) | ✅ Complete |
| Phase 2 | Mutation depth controls, sequence-splice mutations, time-aware mutations | ✅ Complete |
| Phase 3 | `AccessControlOracle`, `ReentrancyOracle`, `TokenFlowConservationOracle`; `sstore_in_nested_call` in executor | ✅ Complete |
| Phase 4 | CI output: SARIF 2.1, JUnit XML, Forge `.t.sol` reproducers; functional `sci-fuzz ci` command | ✅ Complete |
| Phase 5 | Corpus persistence: JSON save/load across runs, `--corpus-dir` flag | ✅ Complete |
| Phase 6 | `LendingHealthOracle`: borrow-event net-debt detection, profile-gated, severity escalation | ✅ Complete |
| Phase 7 | Semantic shrinker: ABI-type-aware reduction, storage-dependency ordering | ⬜ Not started |
| Phase 8 | `sci-fuzz diff`: differential fuzzing between two implementations | ⬜ Not started |
| Phase 9 | Parallel corpus persistence: wire `corpus_dir` into `run_parallel_campaign()` | ⬜ Not started |
| Phase 10 | Measured benchmark matrix: 81-entry matrix with real pass/fail/time data | ⬜ Not started |

## Project Stats

| Metric | Value |
|--------|-------|
| Rust source | ~13,800 lines in `src/` (21 modules) |
| Unit tests | 218+ passing (`cargo test --lib`) |
| New tests added across Phases 1–5 | 26+ (10 oracle, 12 output, 4 corpus) |
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
