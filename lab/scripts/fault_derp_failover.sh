#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# DERP region unreachable: move home to another region of the map.
#   A. The home relay goes down for everyone (container stopped): fm1 (flowmeshd) and the official
#      clients move to region 1001, and fm1 <-> ts1 works over the relay alone.
#   B. Only fm1 loses its home relay, silently (blackhole, the connection never closes): flowmesh's
#      liveness ping notices and home moves to 1001.
# Needs the second region (derp2, lab/headscale/derp-map.yaml) and flowmeshd Running in fm1.
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }
fm1() { dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
relay_of_self() { { fm1 status --json || true; } | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["Relay"])'; }
wait_relay() { # wanted-code seconds
  for _ in $(seq 1 "$2"); do [ "$(relay_of_self)" = "$1" ] && return 0; sleep 1; done
  return 1
}
restart_fm1() {
  dc fm1 cargo build -q -p flowmesh-daemon -p flowmesh-cli
  dc fm1 sh -c 'pkill -x flowmeshd || true; sleep 2; ip link del flowmesh0 2>/dev/null || true
    nohup /target/debug/flowmeshd --state-dir /target/fmd-state --socket /tmp/fmd.sock > /tmp/flowmeshd.log 2>&1 &'
  for _ in $(seq 1 40); do fm1 status >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "fm1 not Running"
}
cleanup() {
  docker compose start derp >/dev/null 2>&1 || true
  dc fm1 ip route del blackhole 172.29.0.11/32 2>/dev/null || true
  dc fm1 ip route del blackhole 172.29.0.21/32 2>/dev/null || true
  dc ts1 ip route del blackhole 172.29.0.31/32 2>/dev/null || true
}
trap cleanup EXIT

docker compose up -d derp derp2 >/dev/null 2>&1
restart_fm1
wait_relay wanflow-relay-1000 20 || fail "fm1 home is $(relay_of_self), expected region 1000 at start"
echo "fm1 home: $(relay_of_self)"

echo "== A. the home relay goes down for everyone"
docker compose stop derp >/dev/null 2>&1
wait_relay wanflow-relay-1001 40 && echo "ok: fm1 home moved to region 1001" || fail "fm1 home still $(relay_of_self)"
dc fm1 ip route add blackhole 172.29.0.21/32
dc ts1 ip route add blackhole 172.29.0.31/32
fm1_ip=$(fm1 status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])')
sleep 25   # direct paths expire; the official client also needs to notice and move home
dc fm1 ping -c 5 -W 3 100.64.0.1 >/dev/null && echo "ok: fm1 -> ts1 over region 1001" || fail "fm1 -> ts1 over the relay"
dc ts1 ping -c 5 -W 3 "$fm1_ip" >/dev/null && echo "ok: ts1 -> fm1 over region 1001" || fail "ts1 -> fm1 over the relay"
cleanup

echo "== B. only fm1 loses its home relay, silently"
restart_fm1
wait_relay wanflow-relay-1000 20 || fail "fm1 home is $(relay_of_self), expected region 1000 at start"
dc fm1 ip route add blackhole 172.29.0.11/32
# Liveness (15 s quiet + 5 s) then failover (10 s): about 30 s.
wait_relay wanflow-relay-1001 60 && echo "ok: silent loss detected, fm1 home moved to region 1001" || fail "fm1 home still $(relay_of_self)"
dc fm1 grep -q "no reply from the relay" /tmp/flowmeshd.log && echo "ok: detected by the liveness ping" || fail "not detected by liveness"
