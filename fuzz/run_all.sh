#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run every fuzz target for SECONDS (default 600), JOBS at a time (default 4), then report crashes.
#   fuzz/run_all.sh [SECONDS] [JOBS]
set -euo pipefail
cd "$(dirname "$0")/.."
secs=${1:-600}
jobs=${2:-4}
mkdir -p fuzz/logs
targets=$(cargo +nightly fuzz list)
cargo +nightly fuzz build >/dev/null
printf '%s\n' $targets | xargs -P "$jobs" -I{} sh -c \
  "cargo +nightly fuzz run {} -- -max_total_time=$secs -rss_limit_mb=2048 > fuzz/logs/{}.log 2>&1; echo \"{} exit \$?\""
crashes=0
for t in $targets; do
  n=$(ls "fuzz/artifacts/$t" 2>/dev/null | wc -l | tr -d ' ')
  runs=$(grep -o 'Done [0-9]* runs' "fuzz/logs/$t.log" | tail -1 || true)
  echo "$t: ${runs:-no summary}; crash artifacts: $n"
  crashes=$((crashes + n))
done
[ "$crashes" = 0 ] && echo "ok: no crashes" || { echo "FAIL: $crashes crash artifact(s) in fuzz/artifacts"; exit 1; }
