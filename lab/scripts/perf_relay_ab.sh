#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Throughput over the peer relay (direct UDP dropped, through tsr) and DERP (tsr dropped as well) for
# flowmeshd built from git REF and from the working tree, on the temporary pair fmA/fmB left by
# `KEEP=1 perf_ab.sh REF ...` (which also builds both into /target/m11-old and /target/m11).
#   perf_relay_ab.sh [SECONDS]   (default 10; needs tsr up, see peer_relay_up.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
secs=${1:-10}
shoot=nicolaka/netshoot:v0.13
key=$(cat .authkey)
fmb=172.29.0.72
tsr=172.29.0.23
ipt() { docker run --rm --network container:fmA --cap-add NET_ADMIN "$shoot" iptables "$@"; }
drop() { ipt "$1" OUTPUT -p udp -d "$2" -j DROP; ipt "$1" INPUT -p udp -s "$2" -j DROP; }
restore() {
  for h in $fmb $tsr; do
    while ipt -D OUTPUT -p udp -d "$h" -j DROP 2>/dev/null; do :; done
    while ipt -D INPUT -p udp -s "$h" -j DROP 2>/dev/null; do :; done
  done
  docker rm -f fmB-iperf >/dev/null 2>&1 || true
}
trap restore EXIT

start() { # binary directory, on both nodes
  for n in fmA fmB; do
    docker exec "$n" pkill -x flowmeshd || true
    while docker exec "$n" pidof flowmeshd >/dev/null; do sleep 0.2; done
    docker exec -d "$n" sh -c "exec $1/flowmeshd --state-dir /tmp/fmd --socket /tmp/fmd.sock > /tmp/fmd.log 2>&1"
    for _ in $(seq 1 40); do docker exec "$n" "$1/flowmesh" --socket=/tmp/fmd.sock status >/dev/null 2>&1 && break; sleep 0.5; done
  done
}
wait_path() { # bin pattern
  local ip line=""
  ip=$(docker exec fmB ip -4 -o addr show flowmesh0 | awk '{print $4}' | cut -d/ -f1)
  for _ in $(seq 1 90); do
    # Tunnel traffic, not just disco: a peer relay is requested for traffic without a direct path.
    docker run --rm --network container:fmA "$shoot" ping -c 1 -W 1 "$ip" >/dev/null 2>&1 || true
    line=$(docker exec fmA "$1/flowmesh" --socket=/tmp/fmd.sock ping -c 1 "$ip" 2>&1 | tail -1 || true)
    case "$line" in *$2*) return 0 ;; esac
    sleep 1
  done
  echo "no $2 path: $line" >&2; return 1
}
bps() { # extra iperf args
  local ip
  ip=$(docker exec fmB ip -4 -o addr show flowmesh0 | awk '{print $4}' | cut -d/ -f1)
  docker run --rm --network container:fmA "$shoot" iperf3 -c "$ip" -t "$secs" -J "$@" |
    python3 -c 'import json,sys
d=json.load(sys.stdin)
print("err" if "error" in d else "%.0f" % (d["end"]["sum_received"]["bits_per_second"]/1e6))'
}
docker rm -f fmB-iperf >/dev/null 2>&1 || true
docker run -d --rm --name fmB-iperf --network container:fmB "$shoot" iperf3 -s >/dev/null
for build in old:/target/m11-old/release new:/target/m11/release; do
  label=${build%%:*}; bin=${build#*:}
  restore; docker run -d --rm --name fmB-iperf --network container:fmB "$shoot" iperf3 -s >/dev/null
  start "$bin"
  drop -A $fmb
  wait_path "$bin" peer-relay
  printf '%-4s peer relay  A->B %6s  A<-B %6s Mbit/s\n' "$label" "$(bps)" "$(bps -R)"
  drop -A $tsr
  wait_path "$bin" DERP
  printf '%-4s DERP        A->B %6s  A<-B %6s Mbit/s\n' "$label" "$(bps)" "$(bps -R)"
done
