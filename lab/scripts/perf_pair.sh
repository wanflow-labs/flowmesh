#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Throughput gate (M11): two flowmeshd nodes (fmA/fmB) and two wanflow-mesh nodes (wmA/wmB) as
# temporary containers on the lab network, direct path. iperf3 TCP both ways per pair, ping, and the
# sending daemon's CPU. The containers are removed at the end. Lab numbers (Docker Desktop): compare
# the two pairs with each other in the same run, not with real hardware.
#   perf_pair.sh [SECONDS]   (default 10 per run; KEEP=1 leaves the containers up)
# flowmeshd is built with --release into its own target directory (/target/m11), so the binary the
# soak node fm1 runs (/target/release) is never replaced.
set -euo pipefail
cd "$(dirname "$0")/.."
secs=${1:-10}
net=flowmesh-lab_lab
key=$(cat .authkey)
dev_img=flowmesh-lab/dev:local
wm_img=flowmesh-lab/wanflow-mesh:native
shoot=nicolaka/netshoot:v0.13
names=(fmA fmB wmA wmB)
ips=(172.29.0.71 172.29.0.72 172.29.0.73 172.29.0.74)

cleanup() { # log out first so the control server doesn't collect a node per run
  [ "${KEEP:-0}" = 1 ] && return
  for n in fmA fmB; do docker exec "$n" /target/m11/release/flowmesh --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true; done
  for n in wmA wmB; do docker exec "$n" wanflow-mesh logout >/dev/null 2>&1 || true; done
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker rm -f "${names[@]}" >/dev/null 2>&1 || true

common=(--network "$net" --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --init)
for i in 0 1; do
  docker run -d --name "${names[$i]}" --hostname "${names[$i]}" --ip "${ips[$i]}" "${common[@]}" \
    -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -w /src "$dev_img" sleep infinity >/dev/null
done
for i in 2 3; do
  docker run -d --name "${names[$i]}" --hostname "${names[$i]}" --ip "${ips[$i]}" "${common[@]}" \
    -e TS_NO_LOGS_NO_SUPPORT=true --entrypoint /bin/sh "$wm_img" \
    -c 'mkdir -p /var/run/tailscale /var/lib/wanflow-mesh && exec wanflow-meshd --state=/var/lib/wanflow-mesh/state --port=41641' >/dev/null
done

echo "== building flowmeshd (release, /target/m11)"
docker exec -e CARGO_TARGET_DIR=/target/m11 fmA cargo build -q --release -p flowmesh-daemon -p flowmesh-cli
bin=/target/m11/release
for n in fmA fmB; do
  docker exec -d "$n" "$bin/flowmeshd" --state-dir /tmp/fmd --socket /tmp/fmd.sock
done
fm() { docker exec "$1" "$bin/flowmesh" --socket=/tmp/fmd.sock "${@:2}"; }
wm() { docker exec "$1" wanflow-mesh "${@:2}"; }
for n in fmA fmB; do
  for _ in $(seq 1 40); do fm "$n" status >/dev/null 2>&1 && break; sleep 0.5; done
  fm "$n" up --login-server=http://headscale.lab --hostname="$n" --accept-dns=false --authkey="$key" --timeout=30s >/dev/null
done
for n in wmA wmB; do
  for _ in $(seq 1 40); do wm "$n" up --login-server=http://headscale.lab --hostname="$n" --accept-dns=false \
    --authkey="$key" --timeout=30s >/dev/null 2>&1 && break; sleep 1; done
done
fmB_ip=$(docker exec fmB ip -4 -o addr show flowmesh0 | awk '{print $4}' | cut -d/ -f1)
wmB_ip=$(wm wmB ip -4 | tr -d '\r')

# iperf3 server on the B side, in its network namespace (netshoot has iperf3, the images may not).
for n in fmB wmB; do
  docker run -d --rm --name "$n-iperf" --network "container:$n" "$shoot" iperf3 -s >/dev/null
done
trap 'docker rm -f fmB-iperf wmB-iperf >/dev/null 2>&1 || true; cleanup' EXIT

cpu() { # CPU seconds used so far by the process named $2 in container $1
  docker exec "$1" sh -c "awk '{print \$14+\$15}' /proc/\$(pidof $2 | cut -d' ' -f1)/stat"
}
tick=$(docker exec fmA getconf CLK_TCK)

run() { # client daemon label target extra-iperf-args
  local c=$1 d=$2 label=$3 t=$4; shift 4
  docker run --rm --network "container:$c" "$shoot" ping -c 3 -q "$t" >/dev/null 2>&1 || true
  local c0 c1 bps
  c0=$(cpu "$c" "$d")
  bps=$(docker run --rm --network "container:$c" "$shoot" iperf3 -c "$t" -t "$secs" -J "$@" |
    python3 -c 'import json,sys
d=json.load(sys.stdin)
if "error" in d: sys.exit("iperf3: " + d["error"])
print(d["end"]["sum_received"]["bits_per_second"])')
  c1=$(cpu "$c" "$d")
  python3 -c "print('%-30s %8.0f Mbit/s   daemon CPU %5.1f%%' % ('$label', $bps/1e6, ($c1-$c0)/$tick/$secs*100))"
}
latency() { # client label target
  docker run --rm --network "container:$1" "$shoot" ping -c 50 -i 0.2 -q "$3" | python3 -c '
import re,sys
m=re.search(r"= ([0-9.]+)/([0-9.]+)/([0-9.]+)", sys.stdin.read())
print("%-30s avg %s ms  (min %s, max %s)" % (sys.argv[1], m.group(2), m.group(1), m.group(3)))' "$2"
}
path() { # the last line of the client's own ping: the path must be direct for this gate to mean anything
  echo "  path $1: $("$@" 2>&1 | tr -d '\r' | tail -1)"
}

warm() { # client target: right after joining, new TCP connections can be refused until the packet
  # filter arrives (fail-closed), so wait until a 1-second iperf3 gets through
  for _ in $(seq 1 30); do
    docker run --rm --network "container:$1" "$shoot" iperf3 -c "$2" -t 1 >/dev/null 2>&1 && return
    sleep 1
  done
  echo "warning: $1 cannot reach iperf3 on $2" >&2
}
warm fmA "$fmB_ip"
warm wmA "$wmB_ip"

echo "== $(date -u +%FT%TZ), ${secs}s per run, direct path"
path fm fmA ping -c 3 "$fmB_ip"
path wm wmA ping -c 3 "$wmB_ip"
run fmA flowmeshd "flowmesh A -> B" "$fmB_ip"
run fmA flowmeshd "flowmesh A <- B (reverse)" "$fmB_ip" -R
run wmA wanflow-meshd "wanflow-mesh A -> B" "$wmB_ip"
run wmA wanflow-meshd "wanflow-mesh A <- B (reverse)" "$wmB_ip" -R
latency fmA "flowmesh ping" "$fmB_ip"
latency wmA "wanflow-mesh ping" "$wmB_ip"
