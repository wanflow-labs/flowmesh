#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Interop matrix plus the outbound connection audit:
#   flowmesh <-> flowmesh (fm1 and fmsd, both flowmeshd): direct, then relay only
#   flowmesh <-> wanflow-mesh (wm1)
#   flowmesh <-> official client 1.94.2: ping_diff.sh and whois_diff.sh
#   relays: the lab relays run the WanFlow DERP image used in production
# While it runs, every packet fm1 sends on its LAN interface is captured; each destination must be
# the control server, a relay from the DERP map, or an endpoint a peer advertises in the netmap.
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose --profile systemd exec -T "$@"; }
key=$(cat .authkey)
fm1() { dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }
fmsd() { dc fmsd flowmesh "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
results=()
row() { results+=("$1"); echo "$1"; }
ip_of() { "$1" status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])'; }
cleanup() {
  dc fm1 sh -c 'pkill -x tcpdump || true' || true
  dc fm1 ip route del blackhole 172.29.0.32/32 2>/dev/null || true
  dc fmsd ip route del blackhole 172.29.0.31/32 2>/dev/null || true
}
trap cleanup EXIT

echo "== fm1 (flowmeshd) and a second flowmeshd node, fmsd"
dc fm1 cargo build -q -p flowmesh-daemon -p flowmesh-cli
fm1 status >/dev/null 2>&1 || { scripts/ping_diff.sh >/dev/null; fm1 status >/dev/null || fail "fm1 not Running"; }
docker compose --profile systemd up -d fmsd >/dev/null 2>&1
for _ in $(seq 1 40); do s=$(dc fmsd systemctl is-system-running 2>/dev/null || true); case "$s" in running|degraded) break ;; esac; sleep 0.5; done
tmp=$(mktemp -d)
docker compose cp fm1:/target/debug/flowmeshd "$tmp/flowmeshd" >/dev/null
docker compose cp fm1:/target/debug/flowmesh "$tmp/flowmesh" >/dev/null
docker compose --profile systemd cp "$tmp/flowmeshd" fmsd:/usr/sbin/flowmeshd >/dev/null
docker compose --profile systemd cp "$tmp/flowmesh" fmsd:/usr/bin/flowmesh >/dev/null
docker compose --profile systemd cp ../packaging/systemd/flowmeshd.service fmsd:/etc/systemd/system/flowmeshd.service >/dev/null
# restart, not just enable --now: a running daemon would keep executing the old binary.
dc fmsd sh -c 'systemctl daemon-reload; systemctl enable flowmeshd; systemctl restart flowmeshd' >/dev/null 2>&1
for _ in $(seq 1 20); do dc fmsd test -S /var/run/flowmesh/flowmeshd.sock && break; sleep 0.5; done
fmsd status >/dev/null 2>&1 || fmsd up --login-server=http://headscale.lab --hostname=fmsd --accept-dns=false --authkey="$key" --timeout=30s >/dev/null
fm1_ip=$(ip_of fm1); fmsd_ip=$(ip_of fmsd)
wm1_ip=$(fm1 status --json | python3 -c 'import json,sys
print(next(p["TailscaleIPs"][0] for p in json.load(sys.stdin)["Peer"].values() if p["HostName"]=="wm1" and p.get("Online")))')

echo "== start the outbound capture on fm1"
dc fm1 sh -c 'pkill -x tcpdump || true; rm -f /tmp/outbound.pcap
  nohup tcpdump -i eth0 -n -U -w /tmp/outbound.pcap "src host 172.29.0.31" > /tmp/outbound-tcpdump.log 2>&1 &
  sleep 1'

echo "== flowmesh <-> flowmesh"
# fmsd was just restarted: wait until fm1 sees it online before judging the path (the check
# raced the restart once and failed with both sides fine a minute later).
for _ in $(seq 1 30); do
  fm1 status --json | python3 -c 'import json,sys
sys.exit(0 if any(p["HostName"]=="fmsd" and p.get("Online") for p in json.load(sys.stdin)["Peer"].values()) else 1)' && break
  sleep 1
done
dc fm1 ping -c 3 -W 3 "$fmsd_ip" >/dev/null && dc fmsd ping -c 3 -W 3 "$fm1_ip" >/dev/null \
  && row "ok   flowmesh <-> flowmesh, direct" || row "FAIL flowmesh <-> flowmesh, direct"
dc fm1 ip route add blackhole 172.29.0.32/32
dc fmsd ip route add blackhole 172.29.0.31/32
sleep 8
dc fm1 ping -c 3 -W 3 "$fmsd_ip" >/dev/null && dc fmsd ping -c 3 -W 3 "$fm1_ip" >/dev/null \
  && row "ok   flowmesh <-> flowmesh, relay only" || row "FAIL flowmesh <-> flowmesh, relay only"
dc fm1 ip route del blackhole 172.29.0.32/32
dc fmsd ip route del blackhole 172.29.0.31/32

echo "== flowmesh <-> wanflow-mesh"
dc fm1 ping -c 3 -W 3 "$wm1_ip" >/dev/null && dc wm1 ping -c 3 -W 3 "$fm1_ip" >/dev/null \
  && row "ok   flowmesh <-> wanflow-mesh (wm1)" || row "FAIL flowmesh <-> wanflow-mesh (wm1)"

echo "== flowmesh <-> official client"
scripts/ping_diff.sh 2>&1 | tail -1 | grep -q "^ok" && row "ok   flowmesh <-> official 1.94.2: ping_diff" || row "FAIL flowmesh <-> official 1.94.2: ping_diff"
scripts/whois_diff.sh 2>&1 | tail -1 | grep -q "^ok" && row "ok   flowmesh <-> official 1.94.2: whois_diff" || row "FAIL flowmesh <-> official 1.94.2: whois_diff"

echo "== outbound audit"
# AUDIT_SELFTEST=1 sends one packet to an address no one allowed, to prove the audit catches it.
# (A real host on an unexpected port: an unknown address would only produce ARP, no IP packet.)
if [ "${AUDIT_SELFTEST:-}" = 1 ]; then dc fm1 sh -c 'timeout 2 bash -c "echo > /dev/tcp/172.29.0.10/81"' >/dev/null 2>&1 || true; fi
dc fm1 sh -c 'sleep 1; pkill -x tcpdump; sleep 1'
allowed=$(fm1 debug netmap | python3 -c '
import json,sys
d=json.load(sys.stdin)
ok={"172.29.0.10:80"}
for r in d["derpMap"]["Regions"].values():
    for n in r["Nodes"]:
        ip = n["IPv4"]
        ok.add("%s:%s" % (ip, n.get("DERPPort") or 443))
        ok.add("%s:%s" % (ip, n.get("STUNPort") or 3478))
for p in d["peers"]:
    for e in p.get("Endpoints") or []: ok.add(e)
print("\n".join(sorted(ok)))')
# tcpdump prints "a.b.c.d.port" for TCP/UDP and "a.b.c.d" for ICMP: keep the port only when present.
seen=$(dc fm1 sh -c 'tcpdump -r /tmp/outbound.pcap -nn -q 2>/dev/null' | python3 -c '
import sys
out=set()
for line in sys.stdin:
    f=line.split()
    if len(f) < 5 or f[1] != "IP": continue
    # ICMP errors (port unreachable, time exceeded) answer inbound packets; they open nothing.
    if "ICMP" in line and ("unreachable" in line or "time exceeded" in line): continue
    dst=f[4].rstrip(":").split(".")
    out.add(".".join(dst[:4]) + (":" + dst[4] if len(dst) == 5 else ""))
print("\n".join(sorted(out)))')
bad=$(comm -23 <(echo "$seen") <(echo "$allowed"))
echo "destinations seen: $(echo "$seen" | wc -l | tr -d ' ')"
if [ -z "$bad" ]; then row "ok   outbound audit: every destination is the control server, a relay, or a peer endpoint"
else row "FAIL outbound audit: unexpected destinations: $(echo "$bad" | tr '\n' ' ')"; fi

echo; echo "== matrix"; printf '%s\n' "${results[@]}"
printf '%s\n' "${results[@]}" | grep -q '^FAIL' && exit 1 || exit 0
