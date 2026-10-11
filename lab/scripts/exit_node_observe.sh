#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Observe the official client for the remaining up/set flags: exit node (offer and use),
# --exit-node-allow-lan-access, --shields-up, --stateful-filtering, --advertise-tags.
# Temporary containers: tsE (exit node, lab 172.29.0.91), tsU (user, lab 172.29.0.92), rtr (lab
# 172.29.0.95 + fm-net 10.98.0.2, a plain router), srv (10.98.0.10:8080 on fm-net, answers with the
# address it sees). tsE reaches fm-net through rtr, so for tsE 10.98.0.0/24 is a remote network (an
# exit node does not forward into its own directly connected networks), and nothing crosses Docker's
# NAT (whose replies arrive with bad checksums after forwarding in this lab).
#   exit_node_observe.sh OUT_DIR   (KEEP=1 leaves the containers up)
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
shoot=nicolaka/netshoot:v0.13
img=tailscale/tailscale:v1.94.2
names=(tsE tsU srv rtr)
cleanup() {
  for n in tsE tsU; do docker exec "$n" tailscale logout >/dev/null 2>&1 || true; done
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
  docker network rm fm-net >/dev/null 2>&1 || true
}
[ "${KEEP:-0}" = 1 ] || trap cleanup EXIT
cleanup
# Official clients through https: no "forced TLS" state after repeated `up` runs.
certs=$(scripts/tls_proxy.sh up)
login=https://hs-tls.lab
docker network create --subnet 10.98.0.0/24 fm-net >/dev/null
docker run -d --name srv --network fm-net --ip 10.98.0.10 --cap-add NET_ADMIN "$shoot" \
  socat TCP4-LISTEN:8080,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR' >/dev/null
docker run -d --name rtr --network "$net" --ip 172.29.0.95 --sysctl net.ipv4.ip_forward=1 "$shoot" sleep infinity >/dev/null
docker network connect --ip 10.98.0.2 fm-net rtr
docker exec srv ip route replace 172.29.0.0/24 via 10.98.0.2
ts() { # name ip extra-docker-args...
  docker run -d --name "$1" --hostname "$1" --network "$net" --ip "$2" --cap-add NET_ADMIN --cap-add NET_RAW \
    --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" \
    "${@:3}" --entrypoint tailscaled "$img" \
    --state=/tmp/ts.state --tun=tailscale0 >/dev/null
}
ts tsE 172.29.0.91 --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1
docker exec tsE ip route add 10.98.0.0/24 via 172.29.0.95
ts tsU 172.29.0.92
sleep 2
hs() { docker compose exec -T headscale headscale "$@"; }
node_id() { hs nodes list -o json | python3 -c '
import json,sys
ns=[n for n in json.load(sys.stdin) if n.get("given_name","").startswith(sys.argv[1]) and n.get("online")]
print(ns[-1]["id"])' "$1"; }
dump() { # node file
  {
    echo "## ip rule"; docker exec "$1" ip rule
    echo "## ip -6 rule"; docker exec "$1" ip -6 rule
    echo "## ip route show table 52"; docker exec "$1" ip route show table 52
    echo "## ip -6 route show table 52"; docker exec "$1" ip -6 route show table 52
    echo "## iptables-legacy-save"; docker exec "$1" iptables-legacy-save
    echo "## status --json (Self, ExitNodeStatus)"
    docker exec "$1" tailscale status --json | python3 -c '
import json,sys
d=json.load(sys.stdin)
s=d.get("Self",{})
print(json.dumps({"ExitNodeStatus": d.get("ExitNodeStatus"), "Self.Tags": s.get("Tags"), "Self.PrimaryRoutes": s.get("PrimaryRoutes"), "Self.AllowedIPs": s.get("AllowedIPs"), "Health": d.get("Health")}, indent=1))'
    # debug prefs shows private keys zeroed; the placeholder keeps the secret scan meaningful.
    echo "## debug prefs"; docker exec "$1" tailscale debug prefs | sed -E 's/privkey:[0-9a-f]+/<zeroed by tailscale>/g'
  } > "$out/$2"
}
srv_sees() { docker exec "$1" sh -c 'nc -w 3 10.98.0.10 8080 </dev/null' 2>&1 | tr -d '\r\n' || true; }
csum_errors() { docker exec "$1" sh -c 'grep "^Tcp:" /proc/net/snmp' | python3 -c '
import sys
h,v=[l.split() for l in sys.stdin.read().strip().split("\n")]
print(dict(zip(h,v))["InCsumErrors"])'; }

echo "== exit node offer"
docker exec tsE tailscale up --login-server=$login --authkey="$key" --hostname=tsE \
  --accept-dns=false --advertise-exit-node --timeout=30s > "$out/tsE-up.txt" 2>&1 || true
hs nodes approve-routes -i "$(node_id tse)" -r "0.0.0.0/0,::/0" > /dev/null
hs nodes list-routes -i "$(node_id tse)" > "$out/control-exit-routes.txt" 2>&1 || true
dump tsE tsE-offer.txt

echo "== exit node use"
docker exec tsU tailscale up --login-server=$login --authkey="$key" --hostname=tsU \
  --accept-dns=false --timeout=30s > /dev/null 2>&1
tse_ip=$(docker exec tsE tailscale ip -4)
docker exec tsU tailscale up --login-server=$login --authkey="$key" --hostname=tsU \
  --accept-dns=false --exit-node="$tse_ip" --timeout=30s > "$out/tsU-up-exit.txt" 2>&1 || true
sleep 3
dump tsU tsU-exit.txt
echo "srv sees (via exit): $(srv_sees tsU); TCP InCsumErrors at tsU: $(csum_errors tsU)" >> "$out/tsU-exit.txt"
docker exec tsU tailscale up --login-server=$login --hostname=tsU --accept-dns=false \
  --exit-node=nonexistent --timeout=10s > "$out/tsU-bad-exit.txt" 2>&1 || true
docker exec tsU tailscale up --login-server=$login --hostname=tsU --accept-dns=false \
  --exit-node=tse --timeout=10s > "$out/tsU-exit-by-name.txt" 2>&1 || true
docker exec tsU tailscale set --exit-node="$tse_ip" --exit-node-allow-lan-access
sleep 2
dump tsU tsU-exit-lan.txt

echo "== shields-up"
docker exec tsU tailscale set --exit-node= --exit-node-allow-lan-access=false --shields-up
sleep 2
dump tsU tsU-shields.txt
tsu_ip=$(docker exec tsU tailscale ip -4)
{
  echo "tsE -> tsU ping (system): $(docker exec tsE ping -c 2 -W 2 "$tsu_ip" >/dev/null 2>&1 && echo ok || echo blocked)"
  echo "tsU -> tsE ping (system): $(docker exec tsU ping -c 2 -W 2 "$tse_ip" >/dev/null 2>&1 && echo ok || echo blocked)"
  echo "tsE -> tsU tailscale ping: $(docker exec tsE tailscale ping -c 1 --timeout 3s "$tsu_ip" 2>&1 | tail -1)"
} >> "$out/tsU-shields.txt"

echo "== stateful-filtering"
docker exec tsE tailscale set --stateful-filtering
sleep 2
dump tsE tsE-stateful.txt

echo "== advertise-tags"
docker exec tsU tailscale set --shields-up=false
docker exec tsU tailscale up --login-server=$login --hostname=tsU --accept-dns=false \
  --advertise-tags=tag:relay-force --timeout=20s > "$out/tsU-tags-up.txt" 2>&1 || true
docker exec tsU tailscale up --login-server=$login --hostname=tsU --accept-dns=false \
  --advertise-tags=relay-force --timeout=10s > "$out/tsU-tags-bad.txt" 2>&1 || true
sleep 2
dump tsU tsU-tags.txt
hs nodes list -o json | python3 -c '
import json,sys
for n in json.load(sys.stdin):
    if n.get("given_name","").startswith("tsu"): print(n["given_name"], "forced", n.get("forced_tags"), "valid", n.get("valid_tags"), "invalid", n.get("invalid_tags"))' > "$out/control-tags.txt"
echo "written to $out"
