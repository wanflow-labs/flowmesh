#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Recovery time after a peer restart: ts1 pings the target continuously; restart the target and measure the gap until ts1 gets a reply again.
# Usage: restart_recovery.sh fm1|wm1
set -euo pipefail
cd "$(dirname "$0")/.."
target=$1
ip=$( [ "$target" = fm1 ] && echo 100.64.0.5 || echo 100.64.0.6 )
docker compose exec -T ts1 sh -c "ping -c 4 -i 0.3 $ip >/dev/null"
docker compose exec -T -d ts1 sh -c "ping -i 0.2 -W 1 -D $ip > /tmp/recovery-$target.log 2>&1"
sleep 2
if [ "$target" = fm1 ]; then scripts/fm1.sh start >/dev/null 2>&1; else docker restart flowmesh-lab-wm1-1 >/dev/null; fi
sleep 25
docker compose exec -T ts1 sh -c 'pkill -x ping || true'
docker compose exec -T ts1 cat /tmp/recovery-$target.log | python3 -c '
import re, sys
ts = [float(m.group(1)) for m in (re.match(r"\[(\d+\.\d+)\]", l) for l in sys.stdin) if m]
gaps = [b - a for a, b in zip(ts, ts[1:])]
print("max reply gap around restart: %.1fs (replies=%d)" % (max(gaps) if gaps else -1, len(ts)))'
