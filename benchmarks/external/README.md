# External benchmark suites (Daedaluzz, SmartBugs)

This directory is reserved for **optional** third-party corpora used to measure recall/precision against labeled vulnerabilities.

## Daedaluzz

- Upstream: Consensys Diligence Daedaluzz (generated mazes / assertion benchmarks).
- Integration: generate contracts with the upstream tool, add a Foundry project under `benchmarks/external/daedaluzz/`, then run:
  `cargo run -- forge --project benchmarks/external/daedaluzz --timeout 600`

## SmartBugs curated

- Clone the SmartBugs curated dataset locally and point `chimerafuzz forge --project` at a harness that compiles each contract, or ingest artifacts similarly to `tests/contracts/efcf-core`.

Scripts in `scripts/bench_regression.sh` use only in-repo EF/CF fixtures by default; extend them once external trees are vendored.
