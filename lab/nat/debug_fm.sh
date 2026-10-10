#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Debug: in the current NAT setup, run tailscale ping from ts-b to fm-a and look at nat-a's conntrack for fm-a and fm-a's log.
set -euo pipefail
cd "$(dirname "$0")/.."
DC=(docker compose -f compose.yaml -f nat/compose.nat.yaml)
fm=$("${DC[@]}" exec -T fm-a sh -c "ip -4 -o addr show flowmesh0 | awk '{print \$4}' | cut -d/ -f1" | tr -d '\r')
"${DC[@]}" exec -T ts-b tailscale ping -c 12 "$fm" 2>&1 | tail -3 || true
echo "--- nat-a conntrack (fm-a 41641):"
"${DC[@]}" exec -T nat-a sh -c 'conntrack -L -p udp 2>/dev/null | grep 41641' || true
echo "--- ts-b sees fm-a endpoints:"
"${DC[@]}" exec -T ts-b tailscale debug netmap | python3 -c "import json,sys; [print(p['Name'], p.get('Endpoints')) for p in json.load(sys.stdin)['Peers'] if p['Name'].startswith('fm-a')]"
echo "--- fm-a log (non-netmap):"
"${DC[@]}" exec -T fm-a sh -c 'grep -v netmap: /tmp/flowmesh-dev.log | tail -4'
