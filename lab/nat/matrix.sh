#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# NAT matrix differential: for each NAT type combination, ts-b (official, behind NAT B) pings fm-a (flowmesh) and ts-a (official reference) behind NAT A,
# and records the path ts-b sees for each. flowmesh is consistent with official when both get the same path class (direct/relay).
# Usage: lab/nat/matrix.sh [combo ...]   combos like easy:easy pr:pr hard:hard; default is the full set below
#   NETEM="delay 40ms 10ms loss 2%" adds that impairment (tc netem) on both routers' WAN links.
set -euo pipefail
cd "$(dirname "$0")/.."
DC=(docker compose -f compose.yaml -f nat/compose.nat.yaml)
LOGIN=http://172.29.0.10
combos=("$@")
[ ${#combos[@]} -eq 0 ] && combos=(easy:easy easy:pr pr:pr easy:hard pr:hard hard:hard)

path_class() { case "$1" in *direct*) echo direct ;; *relay*) echo relay ;; *) echo "?($1)" ;; esac; }
status_of() { "${DC[@]}" exec -T ts-b tailscale status | awk -v ip="$1" '$1==ip {sub(/^.*(active|idle|offline);? */,""); print}'; }

scripts/prune_nodes.sh >/dev/null
for combo in "${combos[@]}"; do
  a=${combo%:*}; b=${combo#*:}
  NAT_A=$a NAT_B=$b "${DC[@]}" up -d --force-recreate nat-a nat-b ts-a ts-b fm-a >/dev/null 2>&1
  sleep 3
  if [ -n "${NETEM:-}" ]; then
    for r in nat-a nat-b; do
      "${DC[@]}" exec -T "$r" sh -c "wan=\$(ip route get 172.29.0.10 | awk '{for(i=1;i<=NF;i++) if(\$i==\"dev\") print \$(i+1)}'); tc qdisc replace dev \$wan root netem $NETEM"
    done
  fi
  # Fairness: the reference ts-a and the subject fm-a are both on the line before the observer ts-b logs in (same relative order),
  # otherwise "who connected first" makes the observer miss the subject's disco-key update (see disco.md §7).
  "${DC[@]}" exec -T ts-a tailscale up --login-server=$LOGIN --authkey="$(cat .authkey)" --hostname=ts-a --accept-dns=false --timeout=60s >/dev/null
  "${DC[@]}" exec -T fm-a sh -c 'pkill -x flowmesh-dev || true; ip link del flowmesh0 2>/dev/null || true
    nohup /target/debug/flowmesh-dev --login-server http://172.29.0.10 --authkey-file /src/lab/.authkey \
      --state /target/fm-a-state.json --hostname fm-a > /tmp/flowmesh-dev.log 2>&1 &'
  for _ in $(seq 1 30); do
    "${DC[@]}" exec -T fm-a grep -q "flowmesh0 up" /tmp/flowmesh-dev.log 2>/dev/null && break
    sleep 1
  done
  "${DC[@]}" exec -T ts-b tailscale up --login-server=$LOGIN --authkey="$(cat .authkey)" --hostname=ts-b --accept-dns=false --timeout=60s >/dev/null
  fm=$("${DC[@]}" exec -T fm-a sh -c "ip -4 -o addr show flowmesh0 | awk '{print \$4}' | cut -d/ -f1" | tr -d '\r')
  ta=$("${DC[@]}" exec -T ts-a tailscale ip -4 | tr -d '\r')
  # Wait until ts-b has seen both targets come online via the control server, so a stale status isn't read.
  for _ in $(seq 1 40); do
    s=$("${DC[@]}" exec -T ts-b tailscale status)
    if echo "$s" | awk -v a="$fm" -v b="$ta" '($1==a || $1==b) && /offline/ {bad=1} END {exit bad}' \
       && echo "$s" | grep -q "^$fm " && echo "$s" | grep -q "^$ta "; then break; fi
    sleep 1
  done
  # Keep traffic flowing for 15 seconds so discovery has enough rounds (the discovery interval is 5 s).
  for ip in "$fm" "$ta"; do
    "${DC[@]}" exec -T ts-b sh -c "ping -c 30 -i 0.5 -W 2 $ip >/dev/null 2>&1 || true"
  done
  fm_path=$(status_of "$fm"); ta_path=$(status_of "$ta")
  verdict="MISMATCH"; [ "$(path_class "$fm_path")" = "$(path_class "$ta_path")" ] && verdict="same"
  printf '%-10s flowmesh(fm-a)=%-7s official(ts-a)=%-7s %s\n' "$combo" "$(path_class "$fm_path")" "$(path_class "$ta_path")" "$verdict"
  printf '           fm-a: %s\n           ts-a: %s\n' "$fm_path" "$ta_path"
done
