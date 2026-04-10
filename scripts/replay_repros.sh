#!/usr/bin/env bash
# Replay saved findings from a corpus dir (requires JSON reproducers).
# Usage: CORPUS_DIR=./corpus ./scripts/replay_repros.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DIR="${CORPUS_DIR:-./corpus}"
if [[ ! -d "$DIR" ]]; then
  echo "No corpus dir at $DIR — set CORPUS_DIR or create findings first."
  exit 0
fi
for f in "$DIR"/finding_*.json; do
  [[ -e "$f" ]] || continue
  echo "Replaying $f"
  cargo run -- replay --project . --finding "$f" || echo "replay failed for $f"
done
