#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# A/B throughput: flowmeshd built from git REF against the working tree, on the same temporary
# pair (fmA 172.29.0.71, fmB 172.29.0.72), alternating ROUNDS times so lab drift hits both sides
# alike. iperf3 TCP both ways per round. Use it to judge one change; perf_pair.sh is the gate
# against wanflow-mesh.
#   perf_ab.sh REF [ROUNDS] [SECONDS]   (defaults 3 rounds, 10 s; KEEP=1 leaves the containers up)
set -euo pipefail
cd "$(dirname "$0")/.."
ref=${1:?usage: perf_ab.sh REF [ROUNDS] [SECONDS]}
rounds=${2:-3}
secs=${3:-10}
net=flowmesh-lab_lab
key=$(cat .authkey)
shoot=nicolaka/netshoot:v0.13
names=(fmA fmB)
ips=(172.29.0.71 172.29.0.72)
wt=target/ab-old # a worktree of REF inside the (ignored) target directory, visible as /src/$wt

cleanup() {
  docker rm -f fmB-iperf >/dev/null 2>&1 || true
  [ "${KEEP:-0}" = 1 ] && return
  for n in "${names[@]}"; do docker exec "$n" /target/m11/release/flowmesh --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true; done
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker rm -f "${names[@]}" fmB-iperf >/dev/null 2>&1 || true

git -C .. worktree remove --force "$wt" >/dev/null 2>&1 || true
git -C .. worktree add --detach "$wt" "$ref" >/dev/null
for i in 0 1; do
  docker run -d --name "${names[$i]}" --hostname "${names[$i]}" --ip "${ips[$i]}" --network "$net" \
    --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --init \
    -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -w /src flowmesh-lab/dev:local sleep infinity >/dev/null
done
echo "== building old ($ref) and new (working tree)"
docker exec -e CARGO_TARGET_DIR=/target/m11-old -w "/src/$wt" fmA cargo build -q --release -p flowmesh-daemon -p flowmesh-cli 2>&1 | grep -v '^info:' || true
docker exec -e CARGO_TARGET_DIR=/target/m11 fmA cargo build -q --release -p flowmesh-daemon -p flowmesh-cli 2>&1 | grep -v '^info:' || true
git -C .. worktree remove --force "$wt"

start() { # binary directory: (re)start both daemons with it and bring them up
  local bin=$1
  for n in "${names[@]}"; do
    docker exec "$n" sh -c 'pkill -x flowmeshd; while pidof flowmeshd >/dev/null; do sleep 0.2; done' || true
    docker exec -d "$n" "$bin/flowmeshd" --state-dir /tmp/fmd --socket /tmp/fmd.sock
    for _ in $(seq 1 40); do docker exec "$n" "$bin/flowmesh" --socket=/tmp/fmd.sock status >/dev/null 2>&1 && break; sleep 0.5; done
    docker exec "$n" "$bin/flowmesh" --socket=/tmp/fmd.sock up --login-server=http://headscale.lab \
      --hostname="$n" --accept-dns=false --authkey="$key" --timeout=30s >/dev/null
  done
}
measure() { # label: warm up, then one iperf3 run each way
  local ip
  ip=$(docker exec fmB ip -4 -o addr show flowmesh0 | awk '{print $4}' | cut -d/ -f1)
  for _ in $(seq 1 30); do
    docker run --rm --network container:fmA "$shoot" iperf3 -c "$ip" -t 1 >/dev/null 2>&1 && break
    sleep 1
  done
  local out=()
  for dir in "" -R; do
    out+=("$(docker run --rm --network container:fmA "$shoot" iperf3 -c "$ip" -t "$secs" -J $dir |
      python3 -c 'import json,sys
d=json.load(sys.stdin)
print("err" if "error" in d else "%.0f" % (d["end"]["sum_received"]["bits_per_second"]/1e6))')")
  done
  printf '%-4s %-3s A->B %6s  A<-B %6s Mbit/s\n' "$1" "$2" "${out[0]}" "${out[1]}"
}

docker run -d --rm --name fmB-iperf --network container:fmB "$shoot" iperf3 -s >/dev/null 2>&1 || true
for r in $(seq 1 "$rounds"); do
  start /target/m11-old/release
  measure old "$r"
  start /target/m11/release
  measure new "$r"
done
