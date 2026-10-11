#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Observe the official client as a subnet router (v1 gap: --advertise-routes): a temporary container
# tsx (172.29.0.81) advertises 10.99.0.0/24; records the firewall rules it installs, its health
# messages with IP forwarding off and on, and what the control server shows. tsx is removed at the end.
#   subnet_router_observe.sh OUT_DIR
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$(dirname "$0")/.."
key=$(cat .authkey)
observe() { # ip_forward value: one temporary container per value
  local fwd=$1
  docker rm -f tsx >/dev/null 2>&1 || true
  docker run -d --name tsx --hostname tsx --network flowmesh-lab_lab --ip 172.29.0.81 \
    --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true \
    --sysctl net.ipv4.ip_forward="$fwd" --entrypoint tailscaled tailscale/tailscale:v1.94.2 \
    --state=/tmp/ts.state --tun=tailscale0 >/dev/null
  sleep 2
  {
    echo "## tailscale up output (ip_forward=$fwd)"
    docker exec tsx tailscale up --login-server=http://headscale.lab --authkey="$key" --hostname=tsx \
      --accept-dns=false --advertise-routes=10.99.0.0/24 --timeout=30s 2>&1 || true
    sleep 5
    echo "## ip_forward=$(docker exec tsx cat /proc/sys/net/ipv4/ip_forward)"
    echo "## tailscale status --json Health"
    docker exec tsx tailscale status --json | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("Health"), indent=1))'
    echo "## tailscale debug prefs (route/snat fields)"
    docker exec tsx tailscale debug prefs | grep -iE "route|snat|netfilter" || true
    echo "## iptables-legacy-save"
    docker exec tsx iptables-legacy-save 2>&1 || true
    echo "## ip6tables-legacy-save"
    docker exec tsx ip6tables-legacy-save 2>&1 || true
  } > "$out/forward-$fwd.txt"
  docker exec tsx tailscale logout >/dev/null 2>&1 || true
  docker rm -f tsx >/dev/null 2>&1 || true
}
trap 'docker rm -f tsx >/dev/null 2>&1 || true' EXIT
observe 0
observe 1
echo "written to $out"
