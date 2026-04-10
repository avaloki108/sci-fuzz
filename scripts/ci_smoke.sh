#!/usr/bin/env bash
# Fast CI sanity: unit tests + tiny benchmark preset.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
cargo test
cargo run -- benchmark --preset efcf-demo --engines chimerafuzz --seeds 1 --max-execs 100 --timeout 5 --output-dir target/benchmark-ci-smoke
