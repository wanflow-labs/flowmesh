#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Home region choice by latency (derp.md "Connection liveness"): with 80 ms added towards one region,
# flowmeshd in fm1 picks the other at start, both ways round. (Without a delay the two lab relays
# differ by sub-millisecond jitter, so no particular choice can be asserted.) Needs derp and derp2.
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }
fm1() { dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
relay_of_self() { { fm1 status --json || true; } | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["Relay"])'; }
# Self.Relay follows the server's copy of our preferred region, so it lags the choice by a message.
wait_relay() {
  for _ in $(seq 1 15); do [ "$(relay_of_self)" = "$1" ] && return 0; sleep 1; done
  return 1
}
restart_fm1() {
  dc fm1 sh -c 'pkill -x flowmeshd || true; sleep 2; ip link del flowmesh0 2>/dev/null || true
    nohup /target/debug/flowmeshd --state-dir /target/fmd-state --socket /tmp/fmd.sock > /tmp/flowmeshd.log 2>&1 &'
  for _ in $(seq 1 40); do fm1 status >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "fm1 not Running"
}
slow() { # relay IP
  dc fm1 sh -c "tc qdisc add dev eth0 root handle 1: prio
    tc qdisc add dev eth0 parent 1:3 handle 30: netem delay 80ms
    tc filter add dev eth0 protocol ip parent 1:0 prio 3 u32 match ip dst $1/32 flowid 1:3"
}
trap 'dc fm1 tc qdisc del dev eth0 root 2>/dev/null || true' EXIT

docker compose up -d derp derp2 >/dev/null 2>&1
dc fm1 cargo build -q -p flowmesh-daemon -p flowmesh-cli

slow 172.29.0.11
restart_fm1
dc fm1 grep "home DERP latency" /tmp/flowmeshd.log
wait_relay wanflow-relay-1001 && echo "ok: region 1000 slow -> home region 1001" || fail "home $(relay_of_self) with region 1000 slow"

dc fm1 tc qdisc del dev eth0 root
slow 172.29.0.12
restart_fm1
dc fm1 grep "home DERP latency" /tmp/flowmeshd.log
wait_relay wanflow-relay-1000 && echo "ok: region 1001 slow -> home region 1000" || fail "home $(relay_of_self) with region 1001 slow"
