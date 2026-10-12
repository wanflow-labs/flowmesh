#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Peer relay under the WanFlow relay modes: tag the flowmesh node fmr (container fm-relay)
# strict, prefer, then auto, and record which path ts2 sees to it. prefer and strict rule out direct
# paths, not the peer relay (OBS-20261010-peer-relay-behavior), so every mode should stay on the relay.
set -uo pipefail
cd "$(dirname "$0")/.."
fmr=$(docker exec fm-relay ip -4 -o addr show flowmesh0 | awk '{print $4}' | cut -d/ -f1)
id=$(docker compose exec -T headscale headscale nodes list -o json \
  | python3 -c "import json,sys; print([n['id'] for n in json.load(sys.stdin) if '$fmr' in n.get('ip_addresses',[])][0])")
echo "fmr $fmr (node $id)"
for spec in "strict tag:relay-enabled,tag:relay-force,tag:relay-strict" \
            "prefer tag:relay-enabled,tag:relay-force" "auto tag:relay-enabled"; do
  read -r mode tags <<< "$spec"
  docker compose exec -T headscale headscale nodes tag -i "$id" -t "$tags" >/dev/null
  sleep 4
  seen=$(docker exec fm-relay grep -o "relay mode now [A-Za-z]*" /tmp/fmr.log | tail -1)
  last=""
  for s in $(seq 1 25); do
    p=$(docker compose exec -T ts2 tailscale ping -c 1 --timeout 1s "$fmr" 2>&1 | head -1 | tr -d '\r' | sed -E 's/.* via ([^ ]+).*/\1/')
    [ "$p" != "$last" ] && echo "  $mode (flowmesh: ${seen:-no change logged}) t+${s}s ts2->fmr $p"
    last=$p
    sleep 1
  done
done
