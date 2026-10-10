#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Differential for `whois`: official (ts2) vs flowmesh (fm1, flowmeshd must be Running; see
# cli_diff.sh / ping_diff.sh). Text output, stderr and exit codes are compared exactly; for --json
# the CapMap, UserProfile and the node's ID/Name/Addresses/Tags are compared.
#   whois_diff.sh [out-dir]
set -euo pipefail
out=${1:-$(mktemp -d)}
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }
fm1() { dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }
ts2() { dc ts2 tailscale "$@"; }

dc fm1 cargo build -q -p flowmesh-cli
fm1 status >/dev/null || { echo "FAIL: fm1 not Running"; exit 1; }
fm1_ip=$(fm1 status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])')
fm_a=$(ts2 ip -4 fm-a 2>/dev/null | tr -d '\r' || true)

fails=0
capsorted() { python3 -c '
import sys
lines=sys.stdin.read().splitlines()
caps=sorted(l for l in lines if l.startswith("  - "))
it=iter(caps)
print("\n".join(next(it) if l.startswith("  - ") else l for l in lines))'; }
check() {
  local name=$1; shift
  for side in ts2 fm1; do
    local rc=0
    "$side" whois "$@" > "$out/$side-$name.out" 2> "$out/$side-$name.err" || rc=$?
    echo "$rc" > "$out/$side-$name.rc"
  done
  local a b
  # The official client lists capabilities in Go map order, which is random: compare them as a set.
  a="$(capsorted < "$out/ts2-$name.out")|$(cat "$out/ts2-$name.err")|rc=$(cat "$out/ts2-$name.rc")"
  b="$(capsorted < "$out/fm1-$name.out")|$(cat "$out/fm1-$name.err")|rc=$(cat "$out/fm1-$name.rc")"
  if [ "$a" = "$b" ]; then echo "ok   $name"; else
    echo "FAIL $name"; diff <(echo "$a") <(echo "$b") || true; fails=$((fails + 1)); fi
}
check_json() {
  local name=$1 addr=$2
  ts2 whois --json "$addr" > "$out/ts2-$name.json"
  fm1 whois --json "$addr" > "$out/fm1-$name.json"
  if python3 - "$out/ts2-$name.json" "$out/fm1-$name.json" <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
pick = lambda d: {"CapMap": d.get("CapMap"), "UserProfile": d.get("UserProfile"),
                  **{k: d["Node"].get(k) for k in ["ID", "Name", "Addresses", "Tags"]}}
pa, pb = pick(a), pick(b)
if pa != pb:
    print("  official:", pa); print("  flowmesh:", pb); sys.exit(1)
PY
  then echo "ok   $name (json)"; else echo "FAIL $name (json)"; fails=$((fails + 1)); fi
}

check ts1        100.64.0.1
check ts1-port   100.64.0.1:22
check ts1-v6     fd7a:115c:a1e0::1
check fm1-self   "$fm1_ip"
[ -n "$fm_a" ] && check fm-a "$fm_a"
check missing    100.64.99.99
check bad        notanip
check_json ts1   100.64.0.1
check_json fm1   "$fm1_ip"

[ "$fails" = 0 ] && echo "ok: every case matches" || { echo "FAIL: $fails case(s) differ"; exit 1; }
