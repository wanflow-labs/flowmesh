#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Subnet router end to end (v1 gap: --advertise-routes). A temporary network fm-sub
# (10.99.0.0/24) holds srv (10.99.0.10:8080, answers with the address it sees). flowmeshd in fmR
# (lab 172.29.0.88, fm-sub 10.99.0.2) advertises 10.99.0.0/24; the route is approved on the control
# server; flowmeshd in fmC (172.29.0.89, --accept-routes) connects to srv through the mesh.
# Checks, with the iptables backend and then the nft backend:
#   SNAT on (default): srv sees fmR's 10.99.0.2;  --snat-subnet-routes=false: srv sees fmC's 100.x;
#   `down` removes the rules. Temporary containers and network only; removed at the end.
#   subnet_router_check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
shoot=nicolaka/netshoot:v0.13
bin=/target/m11/release
names=(srv fmR fmC)
cleanup() {
  for n in fmR fmC; do docker exec "$n" "$bin/flowmesh" --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true; done
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
  docker network rm fm-sub >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker image inspect flowmesh-lab/router:local >/dev/null 2>&1 || docker build -q -t flowmesh-lab/router:local router >/dev/null

# Not --internal: Docker drops packets with a source outside an internal network's subnet, which is
# exactly the SNAT-off case (source = the client's 100.x address).
docker network create --subnet 10.99.0.0/24 fm-sub >/dev/null
docker run -d --name srv --network fm-sub --ip 10.99.0.10 --cap-add NET_ADMIN "$shoot" \
  socat TCP4-LISTEN:8080,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' >/dev/null
# Without SNAT, srv must route replies to the mesh through the router.
docker exec srv ip route add 100.64.0.0/10 via 10.99.0.2
common=(--cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --init -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -w /src)
docker run -d --name fmR --hostname fmR --network "$net" --ip 172.29.0.88 "${common[@]}" \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 flowmesh-lab/router:local sleep infinity >/dev/null
docker network connect --ip 10.99.0.2 fm-sub fmR
docker run -d --name fmC --hostname fmC --network "$net" --ip 172.29.0.89 "${common[@]}" flowmesh-lab/dev:local sleep infinity >/dev/null
echo "== building flowmeshd"
docker exec -e CARGO_TARGET_DIR=/target/m11 fmR cargo build -q --release -p flowmesh-daemon -p flowmesh-cli 2>&1 | grep -v '^info:' || true

fm() { docker exec "$1" "$bin/flowmesh" --socket=/tmp/fmd.sock "${@:2}"; }
fmd() { # node [PATH for the daemon]
  docker exec "$1" pkill -x flowmeshd || true
  while docker exec "$1" pidof flowmeshd >/dev/null; do sleep 0.2; done
  docker exec -d "$1" sh -c "exec env PATH=${2:-\$PATH} $bin/flowmeshd --state-dir /tmp/fmd --socket /tmp/fmd.sock > /tmp/fmd.log 2>&1"
  for _ in $(seq 1 40); do fm "$1" status >/dev/null 2>&1 && break; sleep 0.5; done
}
seen_by_srv() { # what srv sees for a connection from fmC (empty when unreachable)
  local out=""
  for _ in $(seq 1 30); do
    out=$(docker run --rm --network container:fmC "$shoot" sh -c 'nc -w 3 10.99.0.10 8080 </dev/null' 2>/dev/null | tr -d '\r\n' || true)
    [ -n "$out" ] && break
    sleep 1
  done
  echo "$out"
}
check() { # label want
  local got
  got=$(seen_by_srv)
  if [ "$got" = "$2" ]; then echo "  $1: srv sees $got"; else echo "  FAIL $1: srv sees '${got:-nothing}', want $2"; exit 1; fi
}

fmd fmC
fm fmC up --login-server=http://headscale.lab --hostname=fmC --accept-dns=false --accept-routes --authkey="$key" --timeout=30s >/dev/null
fmc_ip=$(docker exec fmC ip -4 -o addr show flowmesh0 | awk '{print $4}' | cut -d/ -f1)

for backend in iptables nft; do
  echo "== router with the $backend backend"
  if [ "$backend" = nft ]; then
    # Hide iptables from the daemon: a PATH with nft and ip but no iptables.
    docker exec fmR mkdir -p /opt/nftonly
    docker exec fmR ln -sf /usr/sbin/nft /opt/nftonly/nft
    fmd fmR /opt/nftonly:/usr/bin:/bin
  else
    fmd fmR
  fi
  fm fmR up --login-server=http://headscale.lab --hostname=fmR --accept-dns=false \
    --advertise-routes=10.99.0.0/24 --authkey="$key" --timeout=30s 2>&1 | sed 's/^/  up: /'
  docker exec fmR grep -m1 "subnet router" /tmp/fmd.log | sed 's/^/  log: /'
  id=$(docker compose exec -T headscale headscale nodes list -o json | python3 -c '
import json,sys
ns=[n for n in json.load(sys.stdin) if n.get("given_name","").startswith("fmr") and n.get("online")]
print(ns[-1]["id"])')
  docker compose exec -T headscale headscale nodes approve-routes -i "$id" -r 10.99.0.0/24 >/dev/null
  check "SNAT on" 10.99.0.2
  fm fmR set --snat-subnet-routes=false
  check "SNAT off" "$fmc_ip"
  fm fmR set --snat-subnet-routes=true
  fm fmR down
  sleep 1
  if [ "$backend" = iptables ]; then
    left=$(docker exec fmR sh -c 'iptables-save; ip6tables-save' | grep -c "fm-" || true)
  else
    left=$(docker exec fmR nft list tables | grep -c flowmesh || true)
  fi
  [ "$left" = 0 ] && echo "  down: rules removed" || { echo "  FAIL down: $left rule lines left"; exit 1; }
  fm fmR logout >/dev/null 2>&1 || true
done
echo "== subnet router checks passed"
