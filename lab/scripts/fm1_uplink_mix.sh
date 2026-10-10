#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Debug: while ts1 pings fm1, tally the types of UDP packets fm1 sends to ts1 (disco by length / WireGuard).
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(mktemp -d)
docker run -d --rm --name fm1-mix-cap --net container:flowmesh-lab-ts1-1 -v "$out:/out" nicolaka/netshoot:v0.13 \
  tcpdump -i eth0 -n -U -w /out/mix.pcap udp and host 172.29.0.31 >/dev/null
sleep 1
docker compose exec -T ts1 sh -c 'ping -c 20 -i 0.5 -W 2 100.64.0.5 | tail -2' || true
docker stop fm1-mix-cap >/dev/null
docker run --rm -v "$out:/out" nicolaka/netshoot:v0.13 tshark -r /out/mix.pcap -T fields -e ip.src -e udp.length -e data.data 2>/dev/null \
  | python3 -c '
import sys, collections
c = collections.Counter()
for l in sys.stdin:
    src, ln, d = (l.rstrip("\n").split("\t") + ["", ""])[:3]
    if src == "172.29.0.31":
        c["disco%s" % ln if d.startswith("5453f09f92ac") else "wg"] += 1
print(dict(c))'
