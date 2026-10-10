#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build and run flowmesh-dev inside the lab container fm1.
#   fm1.sh start   build and start in the background (log at /tmp/flowmesh-dev.log)
#   fm1.sh stop    stop
#   fm1.sh log     view the log
#   fm1.sh smoke   interop acceptance (requires start first)
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }

case "${1:-}" in
  start)
    dc fm1 cargo build -q -p flowmesh-dev
    dc -e "FM1_ARGS=${FM1_ARGS:-}" fm1 sh -c 'pkill -x flowmesh-dev || true; ip link del flowmesh0 2>/dev/null || true
      nohup /target/debug/flowmesh-dev --login-server http://headscale.lab --authkey-file /src/lab/.authkey \
        --state /target/fm1-state.json --hostname fm1 ${FM1_ARGS:-} > /tmp/flowmesh-dev.log 2>&1 &'
    for _ in $(seq 1 30); do
      dc fm1 grep -q "flowmesh0 up" /tmp/flowmesh-dev.log 2>/dev/null && break
      sleep 1
    done
    dc fm1 cat /tmp/flowmesh-dev.log
    ;;
  stop) dc fm1 sh -c 'pkill -x flowmesh-dev || true' ;;
  log) dc fm1 cat /tmp/flowmesh-dev.log ;;
  smoke)
    ts1=$(dc ts1 tailscale ip -4 | tr -d '\r')
    fm1=$(dc fm1 sh -c "ip -4 -o addr show flowmesh0 | awk '{print \$4}' | cut -d/ -f1" | tr -d '\r')
    dc fm1 ping -c 3 -W 3 "$ts1" >/dev/null && echo "ok: fm1 -> ts1 ($ts1) ping"
    dc ts1 ping -c 3 -W 3 "$fm1" >/dev/null && echo "ok: ts1 -> fm1 ($fm1) ping"
    dc ts1 tailscale status | grep fm1
    ;;
  acl)
    # flowmesh-filter on real traffic: under allow-all ts1 can open a TCP connection to fm1:5555; under deny-all it cannot, and ping is dropped too (filter.md F2, F5).
    fm1=$(dc fm1 sh -c "ip -4 -o addr show flowmesh0 | awk '{print \$4}' | cut -d/ -f1" | tr -d '\r')
    dc fm1 sh -c 'pkill -x nc || true; nohup nc -lk -p 5555 >/dev/null 2>&1 &'
    setpol() {
      printf '{"tagOwners":{"tag:relay-enabled":["lab@"]},"acls":%s}' "$1" \
        | dc headscale sh -c 'cat > /tmp/fm1-acl.json && headscale policy set -f /tmp/fm1-acl.json' >/dev/null
      sleep 4
    }
    setpol '[{"action":"accept","src":["*"],"dst":["*:*"]}]'
    dc ts1 sh -c "nc -z -w 3 $fm1 5555" && echo "ok: allow-all  ts1 -> fm1:5555 connects"
    setpol '[]'
    if dc ts1 sh -c "nc -z -w 3 $fm1 5555"; then echo "FAIL: deny-all still connects"; exit 1; fi
    echo "ok: deny-all   ts1 -> fm1:5555 blocked by flowmesh-filter"
    if dc ts1 ping -c 2 -W 2 "$fm1" >/dev/null; then echo "FAIL: deny-all ping passes"; exit 1; fi
    echo "ok: deny-all   ts1 -> fm1 ping blocked (F5)"
    setpol '[{"action":"accept","src":["*"],"dst":["*:*"]}]'
    dc ts1 sh -c "nc -z -w 3 $fm1 5555" && echo "ok: allow-all restored, connects again"
    ;;
  direct)
    # Direct path: ts1 sees fm1 as direct; after cutting direct UDP it falls back to DERP and stays reachable; after restoring it goes back to direct.
    fm1=$(dc fm1 sh -c "ip -4 -o addr show flowmesh0 | awk '{print \$4}' | cut -d/ -f1" | tr -d '\r')
    dc ts1 ping -c 6 -i 0.5 "$fm1" >/dev/null
    dc ts1 tailscale status | grep "$fm1" | grep -q "direct 172.29.0.31:" && echo "ok: ts1 -> fm1 direct"
    dc ts1 iptables -I INPUT -s 172.29.0.31 -p udp -j DROP
    dc ts1 ping -c 30 -i 0.5 -W 2 "$fm1" >/dev/null || true
    dc ts1 tailscale status | grep "$fm1" | grep -q 'relay "wanflow-relay-1000"' && echo "ok: direct blocked -> relay"
    dc ts1 ping -c 4 -i 0.5 -W 2 "$fm1" >/dev/null && echo "ok: still reachable over relay"
    dc ts1 iptables -D INPUT -s 172.29.0.31 -p udp -j DROP
    dc ts1 ping -c 24 -i 0.5 "$fm1" >/dev/null
    dc ts1 tailscale status | grep "$fm1" | grep -q "direct 172.29.0.31:" && echo "ok: unblocked -> direct again"
    ;;
  *) echo "usage: $0 start|stop|log|smoke|acl|direct"; exit 2 ;;
esac
