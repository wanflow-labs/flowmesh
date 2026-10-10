#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Soak test (design §5.5): flowmeshd in fm1 runs for HOURS (default 72) with steady traffic to a
# flowmesh peer (fmsd) and a wanflow-mesh peer (wm1), and with faults injected on a schedule:
#   every 3 h  the control server is unreachable from fm1 for 60 s
#   every 4 h  the DERP relay (region 1000) restarts
#   every 6 h  the control server restarts
# Every minute it records fm1's flowmeshd RSS, open fds, threads, BackendState and the cumulative
# reconnect events, plus ping loss; faults are logged with their time so every reconnect can be
# matched to one. Official clients are not traffic targets: against this plain-HTTP lab server they
# cannot recover from a control restart (cli.md §6).
#   soak.sh HOURS OUT_DIR     (analyse with soak_report.py OUT_DIR)
# Rehearsal: SOAK_MINUTES=12 FAULT_SCALE=60 runs 12 minutes with faults every 3/4/6 minutes.
set -uo pipefail
cd "$(dirname "$0")/.."
hours=${1:-72}
out=$(mkdir -p "${2:-soak}" && cd "${2:-soak}" && pwd)
dc() { docker compose --profile systemd exec -T "$@"; }
fm1() { dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }
ip_of() { "$@" status --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])'; }
event() { echo "$(date -u +%FT%TZ) $*" >> "$out/events.log"; }

fmsd_ip=$(ip_of dc fmsd flowmesh)
wm1_ip=$(dc wm1 wanflow-mesh ip -4 | tr -d '\r')
[ -n "$fmsd_ip" ] && [ -n "$wm1_ip" ] || { echo "fmsd and wm1 must be up (run interop_matrix.sh first)"; exit 1; }
event "start minutes=${SOAK_MINUTES:-$((hours * 60))} fault_scale=${FAULT_SCALE:-1} fmsd=$fmsd_ip wm1=$wm1_ip"

# Steady traffic: one ping per second to each peer, for the whole run (summaries land in the logs).
total=$(( ${SOAK_MINUTES:-$((hours * 60))} * 60 ))
scale=${FAULT_SCALE:-1}
n=$total
# Kill in its own call: a shell whose command line also starts the pings would match the pattern.
dc fm1 sh -c "pkill -f '[p]ing -i 1 -c' || true"
dc fm1 sh -c "nohup ping -i 1 -c $n $fmsd_ip > /tmp/soak-ping-fmsd.log 2>&1 &
  nohup ping -i 1 -c $n $wm1_ip > /tmp/soak-ping-wm1.log 2>&1 &"

echo "time,rss_kb,fds,threads,state,control_reconnects,derp_connects,ping_fmsd_tx,ping_fmsd_rx,ping_wm1_tx,ping_wm1_rx" > "$out/samples.csv"
start=$(date +%s)
end=$((start + total))
cut_every=$((3 * 3600 / scale)); derp_every=$((4 * 3600 / scale)); ctl_every=$((6 * 3600 / scale))
next_cut=$((start + cut_every)); next_derp=$((start + derp_every)); next_ctl=$((start + ctl_every))
while [ "$(date +%s)" -lt "$end" ]; do
  now=$(date +%s)
  if [ "$now" -ge "$next_cut" ]; then
    event "fault control-unreachable-60s"
    dc fm1 ip route add blackhole 172.29.0.10/32; sleep 60; dc fm1 ip route del blackhole 172.29.0.10/32
    next_cut=$((next_cut + cut_every))
  fi
  if [ "$now" -ge "$next_derp" ]; then
    event "fault derp-restart"; docker compose restart derp >/dev/null 2>&1; next_derp=$((next_derp + derp_every))
  fi
  if [ "$now" -ge "$next_ctl" ]; then
    event "fault control-restart"; docker compose restart headscale >/dev/null 2>&1; next_ctl=$((next_ctl + ctl_every))
  fi
  line=$(dc fm1 sh -c '
    pid=$(pidof flowmeshd)
    rss=$(awk "/VmRSS/ {print \$2}" /proc/$pid/status)
    fds=$(ls /proc/$pid/fd | wc -l)
    thr=$(awk "/Threads/ {print \$2}" /proc/$pid/status)
    ctl=$(grep -c "control: connected again" /tmp/flowmeshd.log)
    derp=$(grep -c "connected to DERP region" /tmp/flowmeshd.log)
    a=$(grep -c "bytes from" /tmp/soak-ping-fmsd.log); b=$(grep -c "bytes from" /tmp/soak-ping-wm1.log)
    echo "$rss,$fds,$thr,$ctl,$derp,$a,$b"' 2>/dev/null | tr -d '\r')
  state=$({ fm1 status --json 2>/dev/null || true; } | python3 -c 'import json,sys
try: print(json.load(sys.stdin)["BackendState"])
except Exception: print("unreachable")')
  IFS=, read -r rss fds thr ctl derp rxa rxb <<< "$line"
  elapsed=$((now - start))
  echo "$(date -u +%FT%TZ),$rss,$fds,$thr,$state,$ctl,$derp,$elapsed,$rxa,$elapsed,$rxb" >> "$out/samples.csv"
  sleep 60
done
event "end"
dc fm1 sh -c 'pkill -f "[p]ing -i 1 -c" || true; tail -3 /tmp/soak-ping-fmsd.log; tail -3 /tmp/soak-ping-wm1.log' > "$out/ping-summary.txt"
dc fm1 cat /tmp/flowmeshd.log > "$out/flowmeshd.log"
