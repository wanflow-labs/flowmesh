#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# 冒烟测试：ts1 能用系统 ping 通 ts2；两端都把实验 DERP 选为 home 区域。
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

# 阻断 ts1 与 ts2 之间的直连 UDP，验证流量能经 DERP 中继；结束时恢复。
block() { docker compose exec -T ts1 iptables "$1" OUTPUT -d 172.29.0.22 -p udp -j DROP; docker compose exec -T ts2 iptables "$1" OUTPUT -d 172.29.0.21 -p udp -j DROP; }
trap 'block -D 2>/dev/null || true' EXIT
block -I
out=$(docker compose exec -T ts1 tailscale ping --c 20 --until-direct=false "$ip2" | grep "via DERP" | tail -1 || true)
case "$out" in
  *"via DERP(wanflow-relay-1000)"*) echo "ok: ts1 -> ts2 via DERP when direct UDP is blocked" ;;
  *) echo "FAIL: expected DERP path, got: $out"; exit 1 ;;
esac
