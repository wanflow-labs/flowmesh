#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Production strict mode (relay-force + relay-strict) on wanflow-mesh (wm1): does it still send its endpoints to the peer via CallMeMaybe?
# The peer is fm1 (auto mode); fm1 decrypts every disco message wm1 sends it with its own key.
set -euo pipefail
cd "$(dirname "$0")/.."
hs() { docker compose exec -T headscale headscale "$@"; }
id_of() { hs nodes list -o json | python3 -c "import json,sys; print([n['id'] for n in json.load(sys.stdin) if n['given_name'].startswith('$1')][0])"; }
wm=$(id_of wm1); fm=$(id_of fm1)
hs nodes tag -i "$fm" -t tag:relay-enabled >/dev/null
hs nodes tag -i "$wm" -t tag:relay-enabled,tag:relay-force,tag:relay-strict >/dev/null
docker restart flowmesh-lab-wm1-1 >/dev/null
docker compose exec -T fm1 rm -rf /tmp/tap
FM1_ARGS="--tap-dir /tmp/tap" scripts/fm1.sh start >/dev/null 2>&1
sleep 8
docker compose exec -T fm1 sh -c 'ping -c 16 -i 0.5 -W 2 100.64.0.6 | tail -1'
echo "wm1 view of fm1: $(docker compose exec -T wm1 wanflow-mesh status | grep fm1 || true)"
hs nodes tag -i "$wm" -t tag:relay-enabled >/dev/null
