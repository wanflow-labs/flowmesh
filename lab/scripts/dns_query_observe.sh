#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Observe the official `tailscale dns query`, and run the same cases on flowmesh. Temporary nodes:
# toQ (official, joined through https://hs-tls.lab) and fqQ (flowmeshd). Each gets one file per
# case in OUT_DIR/{official,flowmesh}. CLIENT=official|flowmesh|both (default both).
#   dns_query_observe.sh OUT_DIR
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
bin=/target/m11/release
client=${CLIENT:-both}
names=(toQ fqQ)
cleanup() {
  docker exec toQ tailscale logout >/dev/null 2>&1 || true
  docker exec fqQ "$bin/flowmesh" --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

cases() { # runner: print "file<TAB>args" lines
  cat <<EOF
no-args.txt	dns query
peer-short.txt	dns query toq
peer-fqdn.txt	dns query toq.mesh.lab.internal
peer-aaaa.txt	dns query toq.mesh.lab.internal aaaa
extra-record.txt	dns query svc.mesh.lab.internal
unknown-mesh-name.txt	dns query nosuch.mesh.lab.internal
forwarded.txt	dns query example.com
forwarded-txt.txt	dns query example.com txt
forwarded-mx.txt	dns query example.com mx
reverse-ptr.txt	dns query 1.0.64.100.in-addr.arpa ptr
reverse-unknown.txt	dns query 250.0.64.100.in-addr.arpa ptr
mesh-apex.txt	dns query mesh.lab.internal
bad-type.txt	dns query example.com bogus
too-many.txt	dns query a b c
EOF
}

run_cases() { # dir cli...
  local dir=$1; shift
  mkdir -p "$dir"
  while IFS=$'\t' read -r f args; do
    # shellcheck disable=SC2086
    { echo "\$ $args"; "$@" $args 2>&1; echo "[exit $?]"; } > "$dir/$f" || true
  done < <(cases)
}

if [ "$client" != flowmesh ]; then
  certs=$(scripts/tls_proxy.sh up)
  docker run -d --name toQ --hostname toQ --network "$net" --ip 172.29.0.151 \
    --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true \
    -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" \
    --entrypoint tailscaled tailscale/tailscale:v1.94.2 --statedir=/tmp/ts --tun=tailscale0 >/dev/null
  sleep 2
  docker exec toQ tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=toQ --accept-dns=${ACCEPT_DNS:-false} --timeout=30s >/dev/null
  sleep 2
  run_cases "$out/official" docker exec toQ tailscale
fi
if [ "$client" != official ]; then
  # Alias toQ: Docker's DNS answers the bare name as it did for the official container.
  docker run -d --name fqQ --hostname fqQ --network "$net" --network-alias toQ --ip 172.29.0.152 \
    --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --init \
    -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -w /src flowmesh-lab/router:local sleep infinity >/dev/null
  docker exec -e CARGO_TARGET_DIR=/target/m11 fqQ cargo build -q --release -p flowmesh-daemon -p flowmesh-cli 2>&1 | grep -v '^info:' || true
  docker exec -d fqQ sh -c "exec $bin/flowmeshd --state-dir /tmp/fmd --socket /tmp/fmd.sock > /tmp/fmd.log 2>&1"
  for _ in $(seq 1 40); do docker exec fqQ "$bin/flowmesh" --socket=/tmp/fmd.sock status >/dev/null 2>&1 && break; sleep 0.5; done
  docker exec fqQ "$bin/flowmesh" --socket=/tmp/fmd.sock up --login-server=http://headscale.lab --authkey="$key" --hostname=toQ --accept-dns=${ACCEPT_DNS:-false} --timeout=30s >/dev/null
  sleep 2
  run_cases "$out/flowmesh" docker exec fqQ "$bin/flowmesh" --socket=/tmp/fmd.sock
fi
echo "written to $out"
