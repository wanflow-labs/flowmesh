#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Delete offline nodes in headscale (the NAT matrix creates new nodes each time it is recreated).
set -euo pipefail
cd "$(dirname "$0")/.."
ids=$(docker compose exec -T headscale headscale nodes list -o json \
  | python3 -c 'import json,sys; print(" ".join(str(n["id"]) for n in json.load(sys.stdin) if not n.get("online")))')
for id in $ids; do
  docker compose exec -T headscale headscale nodes delete -i "$id" --force >/dev/null
done
echo "pruned: ${ids:-none}"
