#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exit node end to end. Topology (temporary containers, removed at the end):
#   srv 198.51.100.10 (TEST-NET-2, stands in for the internet) on fm-pub, answers with the address it sees
#   rtr 172.29.0.95 / 198.51.100.2, a plain router; the exit nodes reach fm-pub through it
#   fmE 172.29.0.96  flowmeshd offering an exit node (router image: iptables)
#   tsU 172.29.0.92  official client using fmE (joined through https://hs-tls.lab, see tls_proxy.sh)
#   tsE 172.29.0.91  official client offering an exit node
#   fmU 172.29.0.97  flowmeshd using fmE, then tsE
# Checks: srv reached through fmE and sees fmE (SNAT); fmE's own LAN and private ranges refused; no
# TCP checksum errors at the user; with --stateful-filtering a connection from srv into the mesh is
# refused, without it it gets through. flowmesh as a user: through fmE and through tsE, its own
# control/DERP traffic stays off the tunnel (still Running, peers reachable), LAN blocked unless
# --exit-node-allow-lan-access, ExitNodeStatus in status --json, --shields-up refuses inbound pings.
#   exit_node_check.sh   (KEEP=1 leaves the containers up)
set -euo pipefail
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
shoot=nicolaka/netshoot:v0.13
bin=/target/m11/release
names=(srv rtr fmE tsU tsE fmU)
cleanup() {
  [ "${KEEP:-0}" = 1 ] && return
  docker exec fmE "$bin/flowmesh" --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true
  docker exec tsU tailscale logout >/dev/null 2>&1 || true
  docker exec tsE tailscale logout >/dev/null 2>&1 || true
  docker exec fmU "$bin/flowmesh" --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true
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
# The setting restarts fmE's engine: wait until tsU's own connections work again, so that the next
# check measures the filter and not the restart.
got=""
for _ in $(seq 1 20); do got=$(reach 198.51.100.10 8080); [ -n "$got" ] && break; sleep 1; done
expect "tsU's own connection still works" 172.29.0.96 "$got"
expect "srv -> tsU ping with it" blocked "$(docker exec srv ping -c 2 -W 2 "$tsu_ip" >/dev/null 2>&1 && echo ok || echo blocked)"
fm set --stateful-filtering=false

echo "== flowmesh client using exit nodes"
docker run -d --name tsE --hostname tsE --network "$net" --ip 172.29.0.91 --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  --entrypoint tailscaled tailscale/tailscale:v1.94.2 --state=/tmp/ts.state --tun=tailscale0 >/dev/null
docker exec tsE ip route add 198.51.100.0/24 via 172.29.0.95
docker exec rtr ip route replace 100.64.0.0/10 via 172.29.0.96
sleep 2
docker exec tsE tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=tsE \
  --accept-dns=false --advertise-exit-node --timeout=30s >/dev/null 2>&1
tid=$(docker compose exec -T headscale headscale nodes list -o json | python3 -c '
import json,sys
ns=[n for n in json.load(sys.stdin) if n.get("given_name","").startswith("tse") and n.get("online")]
print(ns[-1]["id"])')
docker compose exec -T headscale headscale nodes approve-routes -i "$tid" -r "0.0.0.0/0,::/0" >/dev/null
tse_ip=$(docker exec tsE tailscale ip -4)

docker run -d --name fmU --hostname fmU --network "$net" --ip 172.29.0.97 --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun --init -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -w /src \
  flowmesh-lab/dev:local sleep infinity >/dev/null
docker exec -d fmU sh -c "exec $bin/flowmeshd --state-dir /tmp/fmd --socket /tmp/fmd.sock > /tmp/fmd.log 2>&1"
fu() { docker exec fmU "$bin/flowmesh" --socket=/tmp/fmd.sock "$@"; }
for _ in $(seq 1 40); do fu status >/dev/null 2>&1 && break; sleep 0.5; done
fu up --login-server=http://headscale.lab --hostname=fmU --accept-dns=false --authkey="$key" --timeout=30s >/dev/null
ureach() { docker run --rm --network container:fmU "$shoot" sh -c "nc -w 3 $1 $2 </dev/null" 2>/dev/null | tr -d '\r\n' || true; }
via() { # exit-node label want
  fu set --exit-node="$1"
  local got=""
  for _ in $(seq 1 15); do got=$(ureach 198.51.100.10 8080); [ -n "$got" ] && break; sleep 1; done
  expect "fmU through $2, srv sees" "$3" "$got"
}
via "$fme_ip" "the flowmesh exit node" 172.29.0.96
expect "fmU still Running (own traffic off the tunnel)" Running \
  "$(fu status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["BackendState"])')"
expect "fmU -> tsU ping through the mesh" ok "$(docker run --rm --network container:fmU "$shoot" ping -c 2 -W 2 "$tsu_ip" >/dev/null 2>&1 && echo ok || echo lost)"
expect "ExitNodeStatus.TailscaleIPs" "['$fme_ip/32']" \
  "$(fu status --json | python3 -c 'import json,sys; print([a for a in json.load(sys.stdin)["ExitNodeStatus"]["TailscaleIPs"] if "." in a])')"
expect "LAN (rtr 172.29.0.95) without LAN access" blocked \
  "$(docker run --rm --network container:fmU "$shoot" ping -c 2 -W 2 172.29.0.95 >/dev/null 2>&1 && echo ok || echo blocked)"
fu set --exit-node-allow-lan-access
sleep 2
expect "LAN (rtr 172.29.0.95) with LAN access" ok \
  "$(docker run --rm --network container:fmU "$shoot" ping -c 2 -W 2 172.29.0.95 >/dev/null 2>&1 && echo ok || echo blocked)"
fu set --exit-node-allow-lan-access=false
via "$tse_ip" "the official exit node" 172.29.0.91
# By name: tsE's DNS name without the MagicDNS suffix (older lab records may hold other tse* names).
tse_name=$(docker exec tsE tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].split(".")[0])')
via "$tse_name" "the official exit node, by name ($tse_name)" 172.29.0.91
fu set --exit-node=
sleep 2
expect "no exit node: srv unreachable" "" "$(ureach 198.51.100.10 8080)"
expect "no exit node: policy rules gone" 0 "$(docker exec fmU ip rule | grep -c 'lookup 52' || true)"

echo "== shields-up on fmU"
fmu_ip=$(docker exec fmU ip -4 -o addr show flowmesh0 | awk '{print $4}' | cut -d/ -f1)
# Every set restarts fmU's engine: wait for the path to come back before judging a ping.
until_ok() { for _ in $(seq 1 20); do "$@" >/dev/null 2>&1 && { echo ok; return; }; sleep 1; done; echo blocked; }
expect "tsU -> fmU ping before" ok "$(until_ok docker exec tsU ping -c 1 -W 1 "$fmu_ip")"
fu set --shields-up
expect "fmU -> tsU ping with shields up" ok "$(until_ok docker run --rm --network container:fmU "$shoot" ping -c 1 -W 1 "$tsu_ip")"
expect "tsU -> fmU ping with shields up" blocked "$(docker exec tsU ping -c 3 -W 2 "$fmu_ip" >/dev/null 2>&1 && echo ok || echo blocked)"
[ "$fail" = 0 ] && echo "== exit node checks passed" || { echo "== exit node checks FAILED"; exit 1; }
