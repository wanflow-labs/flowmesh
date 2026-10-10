#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Is a disco-key update dropped? The observer ts-b connects first, then the target (official ts-a or flowmesh fm-a) restarts with a new disco key.
# Compare ts-b's netmap disco key for the target with the one headscale stores.
# Usage: disco_staleness.sh ts-a|fm-a
set -euo pipefail
cd "$(dirname "$0")/.."
DC=(docker compose -f compose.yaml -f nat/compose.nat.yaml)
target=$1
NAT_A=easy NAT_B=easy "${DC[@]}" up -d --force-recreate nat-a nat-b ts-b >/dev/null 2>&1
sleep 2
"${DC[@]}" exec -T ts-b tailscale up --login-server=http://172.29.0.10 --authkey="$(cat .authkey)" --hostname=ts-b --accept-dns=false --timeout=60s >/dev/null
sleep 2
if [ "$target" = ts-a ]; then
  "${DC[@]}" up -d --force-recreate ts-a >/dev/null 2>&1
  sleep 2
  "${DC[@]}" exec -T ts-a tailscale up --login-server=http://172.29.0.10 --authkey="$(cat .authkey)" --hostname=ts-a --accept-dns=false --timeout=60s >/dev/null
else
  "${DC[@]}" exec -T fm-a sh -c 'pkill -x flowmesh-dev || true; ip link del flowmesh0 2>/dev/null || true
    nohup /target/debug/flowmesh-dev --login-server http://172.29.0.10 --authkey-file /src/lab/.authkey \
      --state /target/fm-a-state.json --hostname fm-a > /tmp/flowmesh-dev.log 2>&1 &'
fi
sleep 10
hs=$(docker compose exec -T headscale headscale nodes list -o json | python3 -c "import json,sys; print([n['disco_key'][:22] for n in json.load(sys.stdin) if n['given_name'].startswith('$target')][0])")
seen=$("${DC[@]}" exec -T ts-b tailscale debug netmap | python3 -c "import json,sys; print([p['DiscoKey'][:22] for p in json.load(sys.stdin)['Peers'] if p['Name'].startswith('$target')][0])")
echo "$target: headscale=$hs ts-b-sees=$seen $([ "$hs" = "$seen" ] && echo FRESH || echo STALE)"
