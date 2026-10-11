#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exit node end to end. Topology (temporary containers, removed at the end):
#   srv 198.51.100.10 (TEST-NET-2, stands in for the internet) on fm-pub, answers with the address it sees
#   rtr 172.29.0.95 / 198.51.100.2, a plain router; the exit nodes reach fm-pub through it
#   fmE 172.29.0.96  flowmeshd offering an exit node (router image: iptables)
#   tsU 172.29.0.92  official client using fmE (joined through https://hs-tls.lab, see tls_proxy.sh)
# Checks: srv reached through fmE and sees fmE (SNAT); fmE's own LAN and private ranges refused; no
# TCP checksum errors at the user; with --stateful-filtering a connection from srv into the mesh is
# refused, without it it gets through.
#   exit_node_check.sh   (KEEP=1 leaves the containers up)
set -euo pipefail
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
shoot=nicolaka/netshoot:v0.13
bin=/target/m11/release
names=(srv rtr fmE tsU)
cleanup() {
  [ "${KEEP:-0}" = 1 ] && return
  docker exec fmE "$bin/flowmesh" --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true
  docker exec tsU tailscale logout >/dev/null 2>&1 || true
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
  docker network rm fm-pub >/dev/null 2>&1 || true
}
trap cleanup EXIT
KEEP=0 cleanup
certs=$(scripts/tls_proxy.sh up)
docker image inspect flowmesh-lab/router:local >/dev/null 2>&1 || docker build -q -t flowmesh-lab/router:local router >/dev/null

docker network create --subnet 198.51.100.0/24 fm-pub >/dev/null
docker run -d --name srv --network fm-pub --ip 198.51.100.10 --cap-add NET_ADMIN "$shoot" \
  socat TCP4-LISTEN:8080,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' >/dev/null
docker run -d --name rtr --network "$net" --ip 172.29.0.95 --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
  "$shoot" sleep infinity >/dev/null
docker network connect --ip 198.51.100.2 fm-pub rtr
docker exec srv ip route replace 172.29.0.0/24 via 198.51.100.2
docker exec srv ip route replace 100.64.0.0/10 via 198.51.100.2
docker exec rtr ip route replace 100.64.0.0/10 via 172.29.0.96

docker run -d --name fmE --hostname fmE --network "$net" --ip 172.29.0.96 --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun --init --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -w /src flowmesh-lab/router:local sleep infinity >/dev/null
docker exec fmE ip route add 198.51.100.0/24 via 172.29.0.95
echo "== building flowmeshd"
docker exec -e CARGO_TARGET_DIR=/target/m11 fmE cargo build -q --release -p flowmesh-daemon -p flowmesh-cli 2>&1 | grep -v '^info:' || true
docker exec -d fmE sh -c "exec $bin/flowmeshd --state-dir /tmp/fmd --socket /tmp/fmd.sock > /tmp/fmd.log 2>&1"
fm() { docker exec fmE "$bin/flowmesh" --socket=/tmp/fmd.sock "$@"; }
for _ in $(seq 1 40); do fm status >/dev/null 2>&1 && break; sleep 0.5; done
fm up --login-server=http://headscale.lab --hostname=fmE --accept-dns=false --advertise-exit-node \
  --authkey="$key" --timeout=30s 2>&1 | sed 's/^/  up: /'
docker exec fmE grep -m1 "subnet router" /tmp/fmd.log | sed 's/^/  log: /'
id=$(docker compose exec -T headscale headscale nodes list -o json | python3 -c '
import json,sys
ns=[n for n in json.load(sys.stdin) if n.get("given_name","").startswith("fme") and n.get("online")]
print(ns[-1]["id"])')
docker compose exec -T headscale headscale nodes approve-routes -i "$id" -r "0.0.0.0/0,::/0" >/dev/null

docker run -d --name tsU --hostname tsU --network "$net" --ip 172.29.0.92 --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" \
  --entrypoint tailscaled tailscale/tailscale:v1.94.2 --state=/tmp/ts.state --tun=tailscale0 >/dev/null
sleep 2
fme_ip=$(docker exec fmE ip -4 -o addr show flowmesh0 | awk '{print $4}' | cut -d/ -f1)
docker exec tsU tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=tsU \
  --accept-dns=false --exit-node="$fme_ip" --timeout=30s >/dev/null
tsu_ip=$(docker exec tsU tailscale ip -4)

csum() { docker exec tsU sh -c 'grep "^Tcp:" /proc/net/snmp' | python3 -c '
import sys
h,v=[l.split() for l in sys.stdin.read().strip().split("\n")]
print(dict(zip(h,v))["InCsumErrors"])'; }
fail=0
expect() { # label want got
  if [ "$2" = "$3" ]; then echo "  $1: $3"; else echo "  FAIL $1: got '${3:-nothing}', want '$2'"; fail=1; fi
}
reach() { docker exec tsU sh -c "nc -w 3 $1 $2 </dev/null" 2>/dev/null | tr -d '\r\n' || true; }

echo "== official client using the flowmesh exit node"
c0=$(csum)
got=""
for _ in $(seq 1 15); do got=$(reach 198.51.100.10 8080); [ -n "$got" ] && break; sleep 1; done
expect "internet through fmE, seen as" 172.29.0.96 "$got"
expect "fmE's LAN (172.29.0.95) refused" "" "$(docker exec tsU sh -c 'nc -w 3 -z 172.29.0.95 22 && echo open' 2>/dev/null || true)"
expect "TCP checksum errors at tsU" 0 "$(( $(csum) - c0 ))"
echo "== stateful filtering on fmE"
expect "srv -> tsU ping without it" ok "$(docker exec srv ping -c 2 -W 2 "$tsu_ip" >/dev/null 2>&1 && echo ok || echo blocked)"
fm set --stateful-filtering
sleep 3
expect "srv -> tsU ping with it" blocked "$(docker exec srv ping -c 2 -W 2 "$tsu_ip" >/dev/null 2>&1 && echo ok || echo blocked)"
got=$(reach 198.51.100.10 8080)
expect "tsU's own connection still works" 172.29.0.96 "$got"
[ "$fail" = 0 ] && echo "== exit node checks passed" || { echo "== exit node checks FAILED"; exit 1; }
