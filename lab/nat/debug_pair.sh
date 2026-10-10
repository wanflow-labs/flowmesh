#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Debug: under the given NAT types, watch the path evolution of tailscale ping from ts-b to ts-a, and ts-b's netcheck result.
# Usage: lab/nat/debug_pair.sh easy easy
set -euo pipefail
cd "$(dirname "$0")/.."
DC=(docker compose -f compose.yaml -f nat/compose.nat.yaml)
NAT_A=$1 NAT_B=$2 "${DC[@]}" up -d --force-recreate nat-a nat-b ts-a ts-b >/dev/null 2>&1
sleep 3
for c in ts-a ts-b; do
  "${DC[@]}" exec -T "$c" tailscale up --login-server=http://172.29.0.10 --authkey="$(cat .authkey)" --hostname="$c" --accept-dns=false --timeout=60s >/dev/null
done
ta=$("${DC[@]}" exec -T ts-a tailscale ip -4 | tr -d '\r')
"${DC[@]}" exec -T ts-b tailscale ping -c 15 "$ta" 2>&1 | tail -3 || true
"${DC[@]}" exec -T ts-b tailscale netcheck 2>&1 | grep -iE "udp|mapping|ipv4:|nearest" | head -5 || true
echo "nat-a POSTROUTING:"; "${DC[@]}" exec -T nat-a iptables -t nat -L POSTROUTING -n -v | tail -2
echo "nat-a conntrack udp:"; "${DC[@]}" exec -T nat-a sh -c 'cat /proc/net/nf_conntrack 2>/dev/null | grep udp | head -5 || true'
