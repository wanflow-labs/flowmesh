#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Differential for `ping`: official (ts2) vs flowmesh (fm1, flowmeshd) against the same targets.
# Latency and direct endpoints are normalized; stdout and stderr are compared separately.
#   ping_diff.sh [out-dir]
set -euo pipefail
out=${1:-$(mktemp -d)}
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }

echo "== flowmeshd in fm1 (reusing /target/fmd-state from cli_diff.sh)"
dc fm1 cargo build -q -p flowmesh-daemon -p flowmesh-cli
dc fm1 sh -c 'pkill -x flowmesh-dev || true; pkill -x flowmeshd || true; sleep 1
  ip link del flowmesh0 2>/dev/null || true
  nohup /target/debug/flowmeshd --state-dir /target/fmd-state --socket /tmp/fmd.sock > /tmp/flowmeshd.log 2>&1 &'
fm1() { dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }
ts2() { dc ts2 tailscale "$@"; }
for _ in $(seq 1 40); do fm1 status >/dev/null 2>&1 && break; sleep 0.5; done
fm1 status >/dev/null || { echo "FAIL: fm1 not Running (run cli_diff.sh first)"; exit 1; }

norm() { sed -E 's/ in [0-9.]+(ms|s)$/ in T/; s/via [0-9.]+:[0-9]+ /via DIRECT /'; }

# case <name> <mode> <ping args...>: mode "full" compares everything, "last" only the last stdout line.
fails=0
case_() {
  local name=$1 mode=$2; shift 2
  for side in ts2 fm1; do
    local rc=0
    "$side" ping "$@" > "$out/$side-$name.out" 2> "$out/$side-$name.err" || rc=$?
    echo "$rc" > "$out/$side-$name.rc"
  done
  local a b
  if [ "$mode" = last ]; then
    a=$(tail -1 "$out/ts2-$name.out" | norm); b=$(tail -1 "$out/fm1-$name.out" | norm)
  else
    a=$(norm < "$out/ts2-$name.out"); b=$(norm < "$out/fm1-$name.out")
  fi
  a="$a|$(cat "$out/ts2-$name.err")|rc=$(cat "$out/ts2-$name.rc")"
  b="$b|$(cat "$out/fm1-$name.err")|rc=$(cat "$out/fm1-$name.rc")"
  if [ "$a" = "$b" ]; then
    echo "ok   $name: $(echo "$b" | tr '\n' ' ')"
  else
    echo "FAIL $name"; echo "  official: $a"; echo "  flowmesh: $b"; fails=$((fails + 1))
  fi
}

case_ direct   last -c 5 ts1
# Only the relay path to ts1 (the DERP server is a different host, so it stays reachable).
for s in ts2 fm1; do dc "$s" ip route add blackhole 172.29.0.21/32; done
sleep 7   # let any direct path expire (trust window 6.5 s)
case_ relay    full -c 3 ts1
for s in ts2 fm1; do dc "$s" ip route del blackhole 172.29.0.21/32; done
case_ offline  full -c 2 100.64.0.10
case_ nopeer   full -c 1 100.64.99.99

[ "$fails" = 0 ] && echo "ok: every case matches" || { echo "FAIL: $fails case(s) differ"; exit 1; }
