#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# A DERP server that restarts must be reconnected. After restarting the lab DERP, fm1
# (flowmeshd) must reach ts1 over the relay alone (direct path blackholed), and ts1 must reach fm1.
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }
fm1() { dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }
fail() { echo "FAIL: $*"; exit 1; }

fm1 status >/dev/null || fail "fm1 not Running"
fm1_ip=$(fm1 status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])')
dc fm1 ping -c 2 -W 3 100.64.0.1 >/dev/null || fail "fm1 cannot reach ts1 before the test"

echo "== restart the DERP server"
docker compose restart derp >/dev/null 2>&1
sleep 5
# Relay only: no direct UDP between fm1 and ts1.
dc fm1 ip route add blackhole 172.29.0.21/32
dc ts1 ip route add blackhole 172.29.0.31/32
trap 'dc fm1 ip route del blackhole 172.29.0.21/32 || true; dc ts1 ip route del blackhole 172.29.0.31/32 || true' EXIT
sleep 8   # direct paths expire (trust window 6.5 s)

ok=1
dc fm1 ping -c 5 -W 3 100.64.0.1 >/dev/null && echo "ok: fm1 -> ts1 over the relay after the DERP restart" || { echo "FAIL: fm1 -> ts1 over the relay"; ok=0; }
dc ts1 ping -c 5 -W 3 "$fm1_ip" >/dev/null && echo "ok: ts1 -> fm1 over the relay after the DERP restart" || { echo "FAIL: ts1 -> fm1 over the relay"; ok=0; }
[ "$ok" = 1 ] || exit 1
