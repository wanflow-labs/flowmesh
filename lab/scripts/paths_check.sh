#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Data path regression on the temporary pair left by `KEEP=1 perf_ab.sh` or `KEEP=1 perf_pair.sh`
# (fmA 172.29.0.71, fmB 172.29.0.72, flowmeshd from /target/m11/release): for each path — direct,
# peer relay through tsr (direct UDP dropped; needs tsr up, see peer_relay_up.sh), DERP (tsr dropped
# too) — the path flowmesh reports, and a 100 MB transfer whose SHA-256 must match on both ends.
#   paths_check.sh   (restores the iptables rules it adds)
set -euo pipefail
cd "$(dirname "$0")/.."
shoot=nicolaka/netshoot:v0.13
bin=/target/m11/release
fmb=172.29.0.72
tsr=172.29.0.23
fm() { docker exec fmA "$bin/flowmesh" --socket=/tmp/fmd.sock "$@"; }
# iptables in fmA's network namespace (the dev image has none).
ipt() { docker run --rm --network container:fmA --cap-add NET_ADMIN "$shoot" iptables "$@"; }
ip=$(docker exec fmB ip -4 -o addr show flowmesh0 | awk '{print $4}' | cut -d/ -f1)

drop() { # add (-A) or delete (-D) UDP drops between fmA and $2
  ipt "$1" OUTPUT -p udp -d "$2" -j DROP
  ipt "$1" INPUT -p udp -s "$2" -j DROP
}
restore() {
  for h in $fmb $tsr; do
    while ipt -D OUTPUT -p udp -d "$h" -j DROP 2>/dev/null; do :; done
    while ipt -D INPUT -p udp -s "$h" -j DROP 2>/dev/null; do :; done
  done
  docker rm -f fmB-sink >/dev/null 2>&1 || true
}
trap restore EXIT

wait_path() { # pattern seconds: ping until the reported path matches
  local line=""
  for _ in $(seq 1 "$2"); do
    line=$(fm ping -c 1 "$ip" 2>&1 | tr -d '\r' | tail -1 || true)
    case "$line" in *$1*) echo "  path: $line"; return 0 ;; esac
    sleep 1
  done
  echo "  FAIL: no '$1' path; last: $line"; return 1
}

transfer() { # 100 MB fmA -> fmB over the tunnel, hashed on both ends
  docker exec fmA sh -c 'test -f /tmp/blob || head -c 100000000 /dev/urandom > /tmp/blob'
  local want got
  want=$(docker exec fmA sha256sum /tmp/blob | cut -d' ' -f1)
  docker rm -f fmB-sink >/dev/null 2>&1 || true
  docker run -d --name fmB-sink --network container:fmB "$shoot" sh -c 'nc -l -p 9000 | sha256sum > /tmp/sum; sleep 600' >/dev/null
  sleep 1
  docker exec fmA sh -c "cat /tmp/blob" | docker run -i --rm --network container:fmA "$shoot" nc -N -w 30 "$ip" 9000
  for _ in $(seq 1 30); do
    got=$(docker exec fmB-sink sh -c 'cat /tmp/sum 2>/dev/null' | cut -d' ' -f1)
    [ -n "$got" ] && break
    sleep 1
  done
  if [ "$got" = "$want" ]; then echo "  100 MB transfer: sha256 match"; else echo "  FAIL: sha256 $want sent, ${got:-nothing} received"; return 1; fi
}

echo "== direct"
wait_path "via $fmb" 20
transfer
echo "== peer relay (direct UDP fmA<->fmB dropped)"
drop -A $fmb
wait_path "peer-relay" 90
transfer
echo "== DERP (tsr dropped as well)"
drop -A $tsr
wait_path "DERP" 60
transfer
echo "== all paths passed"
