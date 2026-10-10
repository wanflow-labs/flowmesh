#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Design §7.3: logs never contain secrets. Looks for the lab auth key and fm1's private keys (from
# its state files) in every flowmesh log inside fm1. The secrets are only compared, never printed.
#   log_secrets_check.sh [extra log file inside fm1 ...]
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }

logs="/tmp/flowmeshd.log /tmp/flowmesh-dev.log $*"
# Secrets: the auth key, and every hex private key in the node state files.
private_keys() { # state file inside fm1
  dc fm1 sh -c "cat $1 2>/dev/null || true" | python3 -c 'import json,sys
text=sys.stdin.read().strip()
if text:
    for k,v in json.loads(text).items():
        if "private" in k: print(v)'
}
secrets=$( { cat .authkey; echo; private_keys /target/fmd-state/node.json; private_keys /target/fm1-state.json; } | grep -v '^$' )
count=$(echo "$secrets" | wc -l | tr -d ' ')
[ "$count" -ge 3 ] || { echo "FAIL: found only $count secrets to look for"; exit 1; }

leaks=0
while read -r s; do
  for f in $logs; do
    if dc fm1 sh -c "test -f $f && grep -qF -- '$s' $f"; then
      echo "LEAK: a secret (${#s} chars) appears in $f"; leaks=$((leaks + 1))
    fi
  done
done <<< "$secrets"
[ "$leaks" = 0 ] && echo "ok: none of $count secrets appears in: $logs" || { echo "FAIL: $leaks leak(s)"; exit 1; }
