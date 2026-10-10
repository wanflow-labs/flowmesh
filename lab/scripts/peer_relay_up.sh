#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Start tsr as an official peer relay server and force ts1<->ts2 onto it: direct UDP between ts1
# and ts2 is dropped (both still reach DERP and tsr). Prints the evidence the official client gives.
#   peer_relay_up.sh [OUT_DIR]   (writes status/ping evidence there when given)
set -euo pipefail
# Resolve OUT_DIR before changing directory, so a relative path means relative to the caller.
out=${1:+$(mkdir -p "$1" && cd "$1" && pwd)}
cd "$(dirname "$0")/.."
dc() { docker compose --profile peer-relay "$@"; }
key=$(cat .authkey)
# --no-deps: never recreate headscale/derp from here (a running soak depends on them).
dc up -d --no-deps tsr >/dev/null
for _ in $(seq 1 30); do dc exec -T tsr tailscale status >/dev/null 2>&1 && break
  dc exec -T tsr tailscale up --login-server=http://headscale.lab --authkey="$key" --hostname=tsr --accept-dns=false >/dev/null 2>&1 || true
  sleep 1; done
dc exec -T tsr tailscale set --relay-server-port=40000
ts1=172.29.0.21; ts2=172.29.0.22
# Block direct UDP both ways (idempotent: -C checks before -A).
for pair in "ts1 $ts2" "ts2 $ts1"; do
  set -- $pair
  for chain in OUTPUT INPUT; do
    flag=$([ "$chain" = OUTPUT ] && echo -d || echo -s)
    dc exec -T "$1" sh -c "iptables -C $chain -p udp $flag $2 -j DROP 2>/dev/null || iptables -A $chain -p udp $flag $2 -j DROP"
  done
done
peer=$(dc exec -T ts2 tailscale ip -4 | tr -d '\r')
# The relay path takes a few discovery rounds; ping until the official client reports it.
for _ in $(seq 1 20); do
  line=$(dc exec -T ts1 tailscale ping -c 1 --timeout 3s "$peer" 2>&1 | tr -d '\r' | head -1 || true)
  echo "$line"
  case "$line" in *peer-relay*) break ;; esac
  sleep 2
done
if [ -n "$out" ]; then
  mkdir -p "$out"
  dc exec -T ts1 tailscale status --json > "$out/ts1-status.json"
  dc exec -T ts1 tailscale ping -c 5 "$peer" > "$out/ts1-ping.txt" 2>&1 || true
  dc exec -T tsr tailscale status --json > "$out/tsr-status.json"
fi
