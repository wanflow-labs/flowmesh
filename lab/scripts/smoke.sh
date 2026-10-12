#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Smoke test: ts1 can reach ts2 with the system ping; both ends choose the lab DERP as their home region.
set -euo pipefail
cd "$(dirname "$0")/.."

ip2=$(docker compose exec -T ts2 tailscale ip -4 | tr -d '\r')
docker compose exec -T ts1 ping -c 3 -W 2 "$ip2" >/dev/null
echo "ok: ts1 -> ts2 ($ip2) system ping"

for c in ts1 ts2; do
  relay=$(docker compose exec -T "$c" tailscale status --json \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"].get("Relay",""))')
  [ "$relay" = "wanflow-relay-1000" ] || { echo "FAIL: $c home relay='$relay'"; exit 1; }
  echo "ok: $c home relay $relay"
done

# Block direct UDP between ts1 and ts2 and check that traffic is relayed through DERP; restore at the end.
block() { docker compose exec -T ts1 iptables "$1" OUTPUT -d 172.29.0.22 -p udp -j DROP; docker compose exec -T ts2 iptables "$1" OUTPUT -d 172.29.0.21 -p udp -j DROP; }
trap 'block -D 2>/dev/null || true' EXIT
block -I
out=$(docker compose exec -T ts1 tailscale ping --c 20 --until-direct=false "$ip2" | grep "via DERP" | tail -1 || true)
case "$out" in
  *"via DERP(wanflow-relay-1000)"*) echo "ok: ts1 -> ts2 via DERP when direct UDP is blocked" ;;
  *) echo "FAIL: expected DERP path, got: $out"; exit 1 ;;
esac
