#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Design §7.2, node key expired by the server: NeedsLogin with the reason, and an `up` with an auth
# key brings the node back. The official client (ts2) goes through the same steps as the reference.
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }
key=$(cat .authkey)
fm1() { dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }
ts2() { dc ts2 tailscale "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
# `status` exits 1 unless Running (cli.md §1); under pipefail that must not abort the script.
state() { { "$1" status --json || true; } | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["BackendState"], "|", "; ".join(d["Health"]))'; }
# The headscale node of a side, found by its mesh IP (names get random suffixes on re-registration).
node_id() {
  local ip
  ip=$("$1" status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])')
  dc headscale headscale nodes list -o json | python3 -c "
import json,sys
print(next(n['id'] for n in json.load(sys.stdin) if '$ip' in n['ip_addresses']))"
}
join() { # side hostname
  "$1" up --login-server=http://headscale.lab --hostname="$2" --accept-dns=false --authkey="$key" --timeout=30s >/dev/null 2>&1
}

echo "== flowmeshd in fm1, both sides Running"
dc fm1 cargo build -q -p flowmesh-daemon -p flowmesh-cli
dc fm1 sh -c 'pkill -x flowmesh-dev || true; pkill -x flowmeshd || true; sleep 2; ip link del flowmesh0 2>/dev/null || true
  nohup /target/debug/flowmeshd --state-dir /target/fmd-state --socket /tmp/fmd.sock > /tmp/flowmeshd.log 2>&1 &'
for _ in $(seq 1 20); do dc fm1 test -S /tmp/fmd.sock && break; sleep 0.5; done
fm1 status >/dev/null 2>&1 || join fm1 fm1 || fail "fm1 cannot join"
ts2 status >/dev/null 2>&1 || scripts/reset_ts2.sh >/dev/null || fail "ts2 cannot join"
echo "fm1: $(state fm1)"; echo "ts2: $(state ts2)"

echo "== expire both node keys on the server"
fm1_id=$(node_id fm1); ts2_id=$(node_id ts2)
dc headscale headscale nodes expire -i "$fm1_id" >/dev/null
dc headscale headscale nodes expire -i "$ts2_id" >/dev/null
for side in fm1 ts2; do
  got=""
  for _ in $(seq 1 20); do
    s=$(state "$side"); case "$s" in NeedsLogin*) got=$s; break ;; esac; sleep 0.5
  done
  [ -n "$got" ] || fail "$side did not reach NeedsLogin: $(state "$side")"
  rc=0; "$side" status >/dev/null 2>&1 || rc=$?
  echo "ok: $side -> $got (status exit $rc)"
  [ "$rc" = 1 ] || fail "$side status exit $rc"
done
case "$(state fm1)" in *"node key expired"*) echo "ok: fm1 Health gives the reason (design §7.2)" ;; *) fail "fm1 Health lacks the reason" ;; esac

echo "== log in again with an auth key"
join fm1 fm1 || fail "fm1 re-login failed: $(state fm1)"
echo "ok: fm1 -> $(state fm1)"
fm1 status >/dev/null || fail "fm1 not Running after re-login"
# The official client cannot log in again against this plain-HTTP lab (cli.md §6); reset it.
scripts/reset_ts2.sh >/dev/null && echo "(ts2 reset for the next scripts)"
