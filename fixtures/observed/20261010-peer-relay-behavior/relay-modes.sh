#!/usr/bin/env bash
# Task 6 step 4: with direct UDP ts1<->ts2 dropped and tsr serving, tag ts1 prefer / strict / auto (the
# production tag sets) and record which path ts1 takes to ts2 and ts2 to ts1 in each mode.
set -uo pipefail
cd "$(dirname "$0")/../../../lab"
dc() { docker compose --profile peer-relay "$@"; }
ts1ip=$(dc exec -T ts1 tailscale ip -4 | tr -d '\r'); ts2ip=$(dc exec -T ts2 tailscale ip -4 | tr -d '\r')
id=$(dc exec -T headscale headscale nodes list -o json | python3 -c "import json,sys; print([n['id'] for n in json.load(sys.stdin) if '$ts1ip' in n.get('ip_addresses',[])][0])")
echo "ts1 node id $id"
path() { dc exec -T "$1" tailscale ping -c 1 --timeout 1s "$2" 2>&1 | head -1 | tr -d '\r' | sed -E 's/.* via ([^ ]+).*/\1/; s/^.*timed out.*$/timeout/'; }
for spec in "prefer tag:relay-enabled,tag:relay-force" "strict tag:relay-enabled,tag:relay-force,tag:relay-strict" "auto tag:relay-enabled"; do
  read -r mode tags <<< "$spec"
  dc exec -T headscale headscale nodes tag -i "$id" -t "$tags" >/dev/null
  echo "== $mode ($tags)"
  last=""
  for s in $(seq 1 45); do
    p1=$(path ts1 "$ts2ip"); p2=$(path ts2 "$ts1ip")
    cur="ts1->ts2 $p1 | ts2->ts1 $p2"
    [ "$cur" != "$last" ] && echo "  t+${s}s $cur"
    last=$cur
    sleep 1
  done
done
