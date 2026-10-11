#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# flowmesh's query and operations commands against a live mesh, next to what the official client
# printed (cli_more_observe.sh): ip, exit-node list, dns status, netcheck, metrics, --operator.
# Temporary nodes: fqA (flowmeshd, 172.29.0.121) and an official exit node toE (172.29.0.122,
# joined through https://hs-tls.lab). Writes one file per command to OUT_DIR and fails on the
# first check that does not hold.
#   cli_more_check.sh OUT_DIR
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
bin=/target/m11/release
names=(fqA toE)
cleanup() {
  docker exec fqA "$bin/flowmesh" --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true
  docker exec toE tailscale logout >/dev/null 2>&1 || true
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
fail() { echo "FAIL: $*" >&2; exit 1; }

certs=$(scripts/tls_proxy.sh up)
docker run -d --name toE --hostname toE --network "$net" --ip 172.29.0.122 \
  --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true \
  -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" --sysctl net.ipv4.ip_forward=1 \
  --entrypoint tailscaled tailscale/tailscale:v1.94.2 --state=/tmp/ts.state --tun=tailscale0 >/dev/null
docker run -d --name fqA --hostname fqA --network "$net" --ip 172.29.0.121 \
  --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --init \
  -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -w /src flowmesh-lab/router:local sleep infinity >/dev/null
docker exec -e CARGO_TARGET_DIR=/target/m11 fqA cargo build -q --release -p flowmesh-daemon -p flowmesh-cli 2>&1 | grep -v '^info:' || true
docker exec -d fqA sh -c "exec $bin/flowmeshd --state-dir /tmp/fmd --socket /tmp/fmd.sock > /tmp/fmd.log 2>&1"
fm() { docker exec ${FM_USER[@]+"${FM_USER[@]}"} fqA "$bin/flowmesh" --socket=/tmp/fmd.sock "$@"; }
FM_USER=()
for _ in $(seq 1 40); do fm status >/dev/null 2>&1 && break; sleep 0.5; done
run() { # file args...: the command line, its output and exit code
  local f=$1; shift
  { echo "\$ flowmesh $*"; fm "$@" 2>&1; echo "[exit $?]"; } > "$out/$f" || true
}

# Not running yet.
run ip-stopped.txt ip
run netcheck-stopped.txt netcheck
grep -q "no current flowmesh IPs; state: NeedsLogin" "$out/ip-stopped.txt" || fail "ip while stopped"
grep -q "flowmesh is not running" "$out/netcheck-stopped.txt" || fail "netcheck while stopped"

sleep 1
docker exec toE tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=toE --accept-dns=false \
  --advertise-exit-node --timeout=30s >/dev/null 2>&1
fm up --login-server=http://headscale.lab --authkey="$key" --hostname=fqA --timeout=30s >/dev/null
id=$(docker compose exec -T headscale headscale nodes list -o json | python3 -c '
import json,sys
ns=[n for n in json.load(sys.stdin) if n.get("given_name","").startswith("toe") and n.get("online")]
print(ns[-1]["id"])')
docker compose exec -T headscale headscale nodes approve-routes -i "$id" -r "0.0.0.0/0,::/0" >/dev/null
toe=$(docker exec toE tailscale ip -4)
toe_name=$(docker exec toE tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].split(".")[0])')
for _ in $(seq 1 30); do fm exit-node list 2>/dev/null | grep -q "$toe" && break; sleep 1; done

run ip.txt ip
run ip-4.txt ip -4
run ip-6.txt ip -6
run ip-1.txt ip -1
run ip-4-6.txt ip -4 -6
run ip-peer-name.txt ip "$toe_name"
run ip-peer-ip.txt ip "$toe"
run ip-unknown.txt ip nosuchnode
run ip-too-many.txt ip a b
[ "$(fm ip -4)" = "$(docker exec fqA ip -4 -o addr show | awk '/100\.64\./ {print $4}' | cut -d/ -f1)" ] || fail "ip -4"
[ "$(fm ip -4 "$toe_name")" = "$toe" ] || fail "ip <peer name>"
[ "$(fm ip -1 | wc -l)" -eq 1 ] || fail "ip -1"
grep -q "mutually exclusive" "$out/ip-4-6.txt" || fail "ip -4 -6"
grep -q '^error looking up IP of "nosuchnode"' "$out/ip-unknown.txt" || fail "ip unknown"

run exit-node-list.txt exit-node list
run exit-node-list-filter.txt exit-node list --filter=nowhere
grep -q "^ $toe .*${toe_name}\." "$out/exit-node-list.txt" || fail "exit-node list row"
grep -q '^ IP              HOSTNAME' "$out/exit-node-list.txt" || fail "exit-node list header"
grep -q 'no exit nodes found for "nowhere"' "$out/exit-node-list-filter.txt" || fail "exit-node list --filter"

run dns-status.txt dns status
run dns-status-all.txt dns status --all
grep -q "MagicDNS: enabled tailnet-wide" "$out/dns-status.txt" || fail "dns status: MagicDNS"
grep -qE "Other devices in your tailnet can reach this device at fqa(-[a-z0-9]+)?\.mesh\." "$out/dns-status.txt" || fail "dns status: name"
grep -q "flowmesh DNS: enabled" "$out/dns-status.txt" || fail "dns status: accept-dns"
grep -q "^  - 127.0.0.11" "$out/dns-status.txt" || fail "dns status: system nameserver"
grep -q "^Additional DNS Records:" "$out/dns-status-all.txt" || fail "dns status --all"
! grep -q "in-addr.arpa" "$out/dns-status.txt" || fail "dns status: MagicDNS-only routes listed (official hides them)"

run netcheck.txt netcheck
run netcheck-json.txt netcheck --format=json
run netcheck-bad-format.txt netcheck --format=xml
grep -q "^	\* UDP: true" "$out/netcheck.txt" || fail "netcheck: UDP"
grep -q "^	\* IPv4: yes, 172.29.0.121:" "$out/netcheck.txt" || fail "netcheck: IPv4"
grep -q "^	\* Nearest DERP: " "$out/netcheck.txt" || fail "netcheck: nearest"
grep -q "^		- " "$out/netcheck.txt" || fail "netcheck: latency lines"
sed -n '/^{/,/^}/p' "$out/netcheck-json.txt" | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["UDP"] and r["PreferredDERP"] and r["RegionLatency"], r' \
  || fail "netcheck json"
grep -q 'unknown output format "xml"' "$out/netcheck-bad-format.txt" || fail "netcheck bad format"

# Traffic for the counters: direct pings to the exit node.
fm ping -c 5 "$toe" >/dev/null 2>&1 || true
docker exec fqA ping -c 20 -i 0.2 -W 1 "$toe" >/dev/null 2>&1 || true
run metrics-print.txt metrics print
fm metrics write /tmp/flowmesh.prom
docker exec fqA cat /tmp/flowmesh.prom > "$out/metrics-write.prom"
python3 - "$out/metrics-print.txt" <<'PY' || fail "metrics"
import re, sys
m = {}
for line in open(sys.argv[1]):
    g = re.match(r'^(tailscaled_\w+(?:\{[^}]*\})?) (\d+)$', line)
    if g: m[g.group(1)] = int(g.group(2))
assert m["tailscaled_advertised_routes"] == 0, m
assert m["tailscaled_home_derp_region_id"] > 0, m
sent = sum(v for k, v in m.items() if k.startswith("tailscaled_outbound_packets_total"))
got = sum(v for k, v in m.items() if k.startswith("tailscaled_inbound_packets_total"))
assert sent >= 20 and got >= 20, (sent, got)
PY
grep -q "^tailscaled_outbound_packets_total" "$out/metrics-write.prom" || fail "metrics write"

# --operator: who may change settings without root.
{
  echo "\$ ls -l /tmp/fmd.sock"; docker exec fqA ls -l /tmp/fmd.sock
  FM_USER=(-u nobody)
  echo "\$ (as nobody) flowmesh status"; fm status 2>&1 | head -2; echo "[exit ${PIPESTATUS[0]}]"
  echo "\$ (as nobody) flowmesh set --shields-up"; fm set --shields-up 2>&1; echo "[exit $?]"
  FM_USER=()
  echo "\$ flowmesh set --operator=nobody"; fm set --operator=nobody 2>&1; echo "[exit $?]"
  FM_USER=(-u nobody)
  echo "\$ (as nobody, the operator) flowmesh set --shields-up"; fm set --shields-up 2>&1; echo "[exit $?]"
  echo "\$ (as nobody, the operator) flowmesh set --operator=daemon"; fm set --operator=daemon 2>&1; echo "[exit $?]"
  echo "\$ (as nobody, the operator) flowmesh set --shields-up=false"; fm set --shields-up=false 2>&1; echo "[exit $?]"
  FM_USER=(-u daemon)
  echo "\$ (as daemon, not the operator) flowmesh set --shields-up"; fm set --shields-up 2>&1; echo "[exit $?]"
  FM_USER=()
  echo "\$ flowmesh debug prefs"; fm debug prefs 2>&1 | grep -E 'operator_user|shields_up'
} > "$out/operator-access.txt" 2>&1 || true
python3 - "$out/operator-access.txt" <<'PY' || fail "operator"
import sys
t = open(sys.argv[1]).read()
blocks = t.split("$ ")
def block(prefix):
    return next(b for b in blocks if b.startswith(prefix))
assert "[exit 1]" in block("(as nobody) flowmesh set --shields-up"), t
assert "Use 'sudo flowmesh --socket=/tmp/fmd.sock set --shields-up'." in block("(as nobody) flowmesh set"), t
assert "[exit 0]" in block("(as nobody, the operator) flowmesh set --shields-up\n"), t
assert "only root can change the operator" in block("(as nobody, the operator) flowmesh set --operator"), t
assert "[exit 0]" in block("(as nobody, the operator) flowmesh set --shields-up=false"), t
assert "[exit 1]" in block("(as daemon, not the operator)"), t
assert '"operator_user": "nobody"' in t and '"shields_up": false' in t, t
PY
echo "all checks passed; outputs in $out"
