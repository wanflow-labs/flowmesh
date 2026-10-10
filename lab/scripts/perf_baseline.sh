#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Performance baseline (design §5.1 ⑥): TCP throughput both ways and latency through the tunnel to
# the same peer (ts1, official client), from flowmesh (fm1, flowmeshd, userspace WireGuard) and from
# wanflow-mesh (wm1), with the daemon's CPU use during each run. Numbers come from the Docker Desktop
# lab: compare them with each other, not with real hardware.
#   perf_baseline.sh [SECONDS]   (default 15 per run)
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }
secs=${1:-15}

# Measure the optimized binary (the lab normally runs debug builds): build and restart with it.
dc fm1 cargo build -q --release -p flowmesh-daemon
dc fm1 sh -c 'pkill -x flowmeshd || true; sleep 2; ip link del flowmesh0 2>/dev/null || true
  nohup /target/release/flowmeshd --state-dir /target/fmd-state --socket /tmp/fmd.sock > /tmp/flowmeshd.log 2>&1 &'
for _ in $(seq 1 40); do dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock status >/dev/null 2>&1 && break; sleep 0.5; done

dc ts1 sh -c 'pkill -x iperf3 || true; iperf3 -s -D -B 100.64.0.1 >/dev/null 2>&1'
sleep 1

# CPU seconds (user+system) used so far by the process named $2 in container $1.
cpu() {
  dc "$1" sh -c "pid=\$(pidof $2 | cut -d' ' -f1); awk '{print \$14+\$15}' /proc/\$pid/stat" | tr -d '\r'
}
tick=$(dc fm1 getconf CLK_TCK | tr -d '\r')

run() { # container daemon label extra-iperf-args
  local c=$1 d=$2 label=$3; shift 3
  dc "$c" ping -c 3 -q 100.64.0.1 >/dev/null 2>&1 || true   # make sure the path is up
  local c0 c1 bps
  c0=$(cpu "$c" "$d")
  bps=$(dc "$c" iperf3 -c 100.64.0.1 -t "$secs" -J "$@" | python3 -c 'import json,sys
d=json.load(sys.stdin); print(d["end"]["sum_received"]["bits_per_second"])')
  c1=$(cpu "$c" "$d")
  python3 -c "print('%-34s %8.0f Mbit/s   daemon CPU %5.1f%%' % ('$label', $bps/1e6, ($c1-$c0)/$tick/$secs*100))"
}
latency() { # container label  (Debian prints "rtt min/avg/max/mdev", BusyBox "round-trip min/avg/max")
  dc "$1" ping -c 50 -i 0.2 -q 100.64.0.1 | python3 -c '
import re,sys
m=re.search(r"= ([0-9.]+)/([0-9.]+)/([0-9.]+)", sys.stdin.read())
print("%-34s avg %s ms  (min %s, max %s)" % (sys.argv[1], m.group(2), m.group(1), m.group(3)))' "$2"
}

echo "== $(date -u +%FT%TZ), ${secs}s per run, peer ts1 (official 1.94.2)"
run fm1 flowmeshd "flowmesh -> ts1 (TCP)"
run fm1 flowmeshd "flowmesh <- ts1 (TCP, reverse)" -R
run wm1 wanflow-meshd "wanflow-mesh -> ts1 (TCP)"
run wm1 wanflow-meshd "wanflow-mesh <- ts1 (TCP, reverse)" -R
latency fm1 "flowmesh -> ts1 ping"
latency wm1 "wanflow-mesh -> ts1 ping"
dc ts1 sh -c 'pkill -x iperf3 || true'
