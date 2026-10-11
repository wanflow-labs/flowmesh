#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Does changing a setting interrupt the mesh? For each `set` change on node A, a 0.2 s ping from B
# to A runs across the change; records lost pings and whether A's disco key changed (a restarted
# engine gets a new one). CLIENT=official (two temporary official clients, joined through
# https://hs-tls.lab) or CLIENT=flowmesh (two temporary flowmeshd nodes).
#   set_live_observe.sh OUT_FILE
set -euo pipefail
out=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
shoot=nicolaka/netshoot:v0.13
client=${CLIENT:-official}
bin=/target/m11/release
names=(lvA lvB)
cleanup() {
  for n in "${names[@]}"; do
    docker exec "$n" tailscale logout >/dev/null 2>&1 || true
    docker exec "$n" "$bin/flowmesh" --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true
  done
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
ips=(172.29.0.101 172.29.0.102)
if [ "$client" = official ]; then
  certs=$(scripts/tls_proxy.sh up)
  for i in 0 1; do
    docker run -d --name "${names[$i]}" --hostname "${names[$i]}" --network "$net" --ip "${ips[$i]}" \
      --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true \
      -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" --sysctl net.ipv4.ip_forward=1 \
      --entrypoint tailscaled tailscale/tailscale:v1.94.2 --state=/tmp/ts.state --tun=tailscale0 >/dev/null
  done
  sleep 2
  cli() { docker exec "$1" tailscale "${@:2}"; }
  for n in "${names[@]}"; do
    cli "$n" up --login-server=https://hs-tls.lab --authkey="$key" --hostname="$n" --accept-dns=false --timeout=30s >/dev/null
  done
  disco() { docker exec lvA tailscale debug netmap 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["SelfNode"]["DiscoKey"][:20])' 2>/dev/null || echo "?"; }
else
  for i in 0 1; do
    docker run -d --name "${names[$i]}" --hostname "${names[$i]}" --network "$net" --ip "${ips[$i]}" \
      --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --init --sysctl net.ipv4.ip_forward=1 \
      -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -w /src flowmesh-lab/router:local sleep infinity >/dev/null
  done
  docker exec -e CARGO_TARGET_DIR=/target/m11 lvA cargo build -q --release -p flowmesh-daemon -p flowmesh-cli 2>&1 | grep -v '^info:' || true
  cli() { docker exec "$1" "$bin/flowmesh" --socket=/tmp/fmd.sock "${@:2}"; }
  for n in "${names[@]}"; do
    docker exec -d "$n" sh -c "exec $bin/flowmeshd --state-dir /tmp/fmd --socket /tmp/fmd.sock > /tmp/fmd.log 2>&1"
    for _ in $(seq 1 40); do cli "$n" status >/dev/null 2>&1 && break; sleep 0.5; done
    cli "$n" up --login-server=http://headscale.lab --authkey="$key" --hostname="$n" --accept-dns=false --timeout=30s >/dev/null
  done
  disco() { cli lvA debug netmap 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["self"]["DiscoKey"][:20])' 2>/dev/null || echo "?"; }
fi
a_ip=$(docker exec lvA ip -4 -o addr show | awk '/100\.64\./ {print $4}' | cut -d/ -f1)
for _ in $(seq 1 30); do docker run --rm --network container:lvB "$shoot" ping -c 1 -W 1 "$a_ip" >/dev/null 2>&1 && break; sleep 1; done

change() { # label set-args...
  local before after sent recv
  before=$(disco)
  # Not --rm: the summary must survive the container's exit for `docker logs`.
  docker rm -f lv-ping >/dev/null 2>&1 || true
  docker run -d --name lv-ping --network container:lvB "$shoot" ping -i 0.2 -c 40 -W 1 "$a_ip" >/dev/null
  sleep 2
  cli lvA set "${@:2}" >/dev/null 2>&1 || echo "  ($1: set failed)" >> "$out"
  sleep 8
  local summary
  summary=$(docker logs lv-ping 2>&1 | grep "packets transmitted" || true)
  docker rm -f lv-ping >/dev/null 2>&1 || true
  after=$(disco)
  local verdict=CHANGED
  [ "$before" = "$after" ] && verdict=same
  case "$before$after" in *"?"*) verdict="unknown ($before -> $after)" ;; esac
  printf '%-34s %-58s disco %s\n' "$1" "${summary:-no ping summary}" "$verdict" >> "$out"
}
echo "== $client $(date -u +%FT%TZ)" > "$out"
change "shields-up on" --shields-up
change "shields-up off" --shields-up=false
change "accept-routes on" --accept-routes
change "advertise-routes 10.97.0.0/24" --advertise-routes=10.97.0.0/24
change "advertise-routes cleared" --advertise-routes=
change "hostname lvA2" --hostname=lvA2
change "accept-dns on" --accept-dns=true
change "accept-dns off" --accept-dns=false
change "advertise-exit-node on" --advertise-exit-node
change "stateful-filtering on" --stateful-filtering
change "snat-subnet-routes off" --snat-subnet-routes=false
cat "$out"
