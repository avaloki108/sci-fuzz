#!/usr/bin/env bash
# Pinned regression: EF/CF demo + matrix report (chimerafuzz only).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${BENCH_OUT:-target/benchmark-regression}"
mkdir -p "$OUT"
cargo run --release -- benchmark --preset efcf-demo --engines chimerafuzz --seeds 1,2,3 --max-execs 5000 --timeout 30 --output-dir "$OUT/demo"
cargo run --release -- benchmark --preset efcf-matrix --engines chimerafuzz --seeds 1 --max-execs 3000 --timeout 20 --output-dir "$OUT/matrix"
echo "Wrote $OUT/demo and $OUT/matrix"
