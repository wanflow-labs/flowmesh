#!/usr/bin/env bash
# Task 6 step 1: ts1 pings ts2 once per second through the official peer relay (tsr); stop tsr and
# time the switch to DERP, start it and time the switch back. Three runs. Direct UDP ts1<->ts2 stays dropped.
set -uo pipefail
cd "$(dirname "$0")/../../../lab"
dc() { docker compose --profile peer-relay "$@"; }
for spec in "ts1 172.29.0.22" "ts2 172.29.0.21"; do
  read -r c ip <<< "$spec"
  dc exec -T "$c" sh -c "iptables -C OUTPUT -p udp -d $ip -j DROP 2>/dev/null || iptables -A OUTPUT -p udp -d $ip -j DROP; iptables -C INPUT -p udp -s $ip -j DROP 2>/dev/null || iptables -A INPUT -p udp -s $ip -j DROP"
done
ts2=$(dc exec -T ts2 tailscale ip -4 | tr -d '\r')
path() { dc exec -T ts1 tailscale ping -c 1 --timeout 1s "$ts2" 2>&1 | head -1 | tr -d '\r' | sed -E 's/.* via ([^ ]+).*/\1/; s/^.*timed out.*$/timeout/'; }
wait_for() { # pattern max_seconds -> prints seconds until the path matches
  local t0; t0=$(date +%s)
  for _ in $(seq 1 "$2"); do
    p=$(path)
    case "$p" in *$1*) echo "$(( $(date +%s) - t0 ))s ($p)"; return ;; esac
    sleep 1
  done
  echo "not within $2 s (last: $p)"
}
echo "start: $(path)"
for run in 1 2 3; do
  wait_for peer-relay 60 >/dev/null
  dc stop -t 0 tsr >/dev/null 2>&1
  echo "run $run: tsr stopped -> DERP after $(wait_for DERP 120)"
  dc start tsr >/dev/null 2>&1
  echo "run $run: tsr started -> peer relay after $(wait_for peer-relay 180)"
done
