#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Peer relay differential: flowmesh (container fm-relay, node fmr) and the official client
# (ts1), each with direct UDP to ts2 dropped and pinging ts2 every second, both through tsr. Seen from
# ts2: when tsr stops, seconds until each falls back to DERP; when tsr returns, seconds until each is on
# the peer relay again. Same observer and same event for both: only the implementation differs.
#   peer_relay_diff.sh [RUNS]   (default 3; needs fm-relay running flowmesh-dev, see docs/protocol/peer-relay.md)
set -uo pipefail
cd "$(dirname "$0")/.."
runs=${1:-3}
dc() { docker compose --profile peer-relay "$@"; }
ts2=$(dc exec -T ts2 tailscale ip -4 | tr -d '\r')
fmr=$(docker exec fm-relay sh -c "ip -4 -o addr show flowmesh0 | awk '{print \$4}' | cut -d/ -f1" | tr -d '\r')
ts1=$(dc exec -T ts1 tailscale ip -4 | tr -d '\r')
for ip in 172.29.0.21 172.29.0.61; do
  dc exec -T ts2 sh -c "iptables -C OUTPUT -p udp -d $ip -j DROP 2>/dev/null || iptables -A OUTPUT -p udp -d $ip -j DROP; iptables -C INPUT -p udp -s $ip -j DROP 2>/dev/null || iptables -A INPUT -p udp -s $ip -j DROP"
done
# Steady traffic towards ts2 from both, for the whole run.
total=$(( runs * 240 + 60 ))
docker exec -d fm-relay sh -c "ping -i 1 -c $total $ts2 > /dev/null 2>&1"
dc exec -T -d ts1 sh -c "ping -i 1 -c $total $ts2 > /dev/null 2>&1"
path() { dc exec -T ts2 tailscale ping -c 1 --timeout 1s "$1" 2>&1 | head -1 | tr -d '\r' | sed -E 's/.* via ([^ (]+).*/\1/; s/^.*timed out.*$/timeout/'; }
# Seconds until both targets show a path containing $1 (max $2 s); prints "fmr=<s> ts1=<s>".
until_both() {
  local want=$1 max=$2 t0 tf="" tt="" now
  t0=$(date +%s)
  while :; do
    now=$(( $(date +%s) - t0 ))
    [ -z "$tf" ] && case "$(path "$fmr")" in *$want*) tf=$now ;; esac
    [ -z "$tt" ] && case "$(path "$ts1")" in *$want*) tt=$now ;; esac
    { [ -n "$tf" ] && [ -n "$tt" ]; } || [ "$now" -ge "$max" ] && break
    sleep 1
  done
  echo "fmr=${tf:-none} ts1=${tt:-none}"
}
echo "start: $(until_both peer-relay 60)  (both on the peer relay)"
for run in $(seq 1 "$runs"); do
  dc stop -t 0 tsr >/dev/null 2>&1
  echo "run $run: tsr stopped  -> DERP after:       $(until_both DERP 60)"
  dc start tsr >/dev/null 2>&1
  echo "run $run: tsr started  -> peer relay after: $(until_both peer-relay 120)"
done
