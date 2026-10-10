#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Subnet route differential: official ts1 and flowmesh fm1 (both with accept-routes); at each step of approve / revoke / re-approve,
# compare whether 10.99.0.1 (advertised by ts2) is reachable. flowmesh must match the official client at every step.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose exec -T ts1 tailscale set --accept-routes=true
FM1_ARGS="--accept-routes" scripts/fm1.sh start >/dev/null 2>&1
reach() { docker compose exec -T "$1" sh -c 'ping -c 2 -W 2 10.99.0.1 >/dev/null 2>&1' && echo yes || echo no; }
fail=0
for step in approve revoke approve; do
  scripts/subnet_setup.sh "$step" >/dev/null
  sleep 4
  t=$(reach ts1); f=$(reach fm1)
  r=$(docker compose exec -T fm1 sh -c 'ip route show 10.99.0.0/24' | tr -d '\r')
  verdict=same; [ "$t" = "$f" ] || { verdict=MISMATCH; fail=1; }
  printf '%-8s official=%-3s flowmesh=%-3s fm1-route=[%s] %s\n' "$step" "$t" "$f" "$r" "$verdict"
done
exit $fail
