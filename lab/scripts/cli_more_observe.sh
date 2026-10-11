#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Observe the official CLI's query and operations commands: ip, netcheck, exit-node list, dns status,
# metrics, and --operator. Temporary official clients (joined through https://hs-tls.lab, see
# tls_proxy.sh): toA (172.29.0.111) and toE (172.29.0.112, offering an exit node). Outputs go to
# OUT_DIR, one file per command. Containers are removed at the end.
#   cli_more_observe.sh OUT_DIR
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
img=tailscale/tailscale:v1.94.2
names=(toA toE)
cleanup() {
  for n in "${names[@]}"; do docker exec "$n" tailscale logout >/dev/null 2>&1 || true; done
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
certs=$(scripts/tls_proxy.sh up)
ips=(172.29.0.111 172.29.0.112)
for i in 0 1; do
  docker run -d --name "${names[$i]}" --hostname "${names[$i]}" --network "$net" --ip "${ips[$i]}" \
    --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true \
    -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" --sysctl net.ipv4.ip_forward=1 \
    --entrypoint tailscaled "$img" --state=/tmp/ts.state --tun=tailscale0 >/dev/null
done
sleep 2
ts() { docker exec toA tailscale "$@" 2>&1; }
run() { # file args...: record the command line, its output and exit code
  local f=$1; shift
  { echo "\$ tailscale $*"; docker exec toA tailscale "$@" 2>&1; echo "[exit $?]"; } > "$out/$f" || true
}
# Before login: what the query commands say when not running.
run ip-stopped.txt ip
run netcheck-stopped.txt netcheck
docker exec toA tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=toA --accept-dns=false --timeout=30s >/dev/null
docker exec toE tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=toE --accept-dns=false \
  --advertise-exit-node --timeout=30s >/dev/null 2>&1
id=$(docker compose exec -T headscale headscale nodes list -o json | python3 -c '
import json,sys
ns=[n for n in json.load(sys.stdin) if n.get("given_name","").startswith("toe") and n.get("online")]
print(ns[-1]["id"])')
docker compose exec -T headscale headscale nodes approve-routes -i "$id" -r "0.0.0.0/0,::/0" >/dev/null
sleep 3
toe=$(docker exec toE tailscale ip -4)
toe_name=$(docker exec toE tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].split(".")[0])')

run ip.txt ip
run ip-4.txt ip -4
run ip-6.txt ip -6
run ip-1.txt ip -1
run ip-4-6.txt ip -4 -6
run ip-peer-name.txt ip "$toe_name"
run ip-peer-ip.txt ip "$toe"
run ip-peer-4.txt ip -4 "$toe_name"
run ip-unknown.txt ip nosuchnode
run ip-too-many.txt ip a b
run netcheck.txt netcheck
run netcheck-json.txt netcheck --format=json
run netcheck-bad-format.txt netcheck --format=xml
run exit-node-list.txt exit-node list
run exit-node-list-filter.txt exit-node list --filter=nowhere
run exit-node-list-json.txt exit-node list --json
run exit-node-help.txt exit-node --help
run dns-status.txt dns status
run dns-status-all.txt dns status --all
run dns-help.txt dns --help
run metrics-help.txt metrics --help
run metrics-print.txt metrics print
# --operator: who may use the CLI without root.
run operator-set.txt set --operator=nobody
run operator-prefs.txt debug prefs
run operator-bad.txt set --operator=nosuchuser
{
  echo "\$ ls -l /var/run/tailscale/tailscaled.sock"; docker exec toA ls -l /var/run/tailscale/tailscaled.sock
  echo "\$ (as nobody) tailscale status"; docker exec -u nobody toA tailscale status 2>&1 | head -3; echo "[exit ${PIPESTATUS[0]}]"
  echo "\$ (as nobody) tailscale set --shields-up"; docker exec -u nobody toA tailscale set --shields-up 2>&1; echo "[exit $?]"
  echo "\$ (as daemon, not the operator) tailscale set --shields-up"; docker exec -u daemon toA tailscale set --shields-up=false 2>&1; echo "[exit $?]"
} > "$out/operator-access.txt" 2>&1 || true
run operator-clear.txt set --operator=
echo "written to $out"
