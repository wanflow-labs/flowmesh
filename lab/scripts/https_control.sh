#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# https control URLs: a temporary TLS terminator hs-tls.lab (172.29.0.85, socat with a throwaway CA)
# in front of the lab control server. Checks: flowmeshd trusting the CA (SSL_CERT_FILE) joins through
# https://hs-tls.lab; the official client joins through the same URL; flowmeshd without the CA is
# refused with a certificate error. Temporary containers only; removed at the end.
#   https_control.sh   (flowmeshd from /target/m11/release, built by the script)
set -euo pipefail
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
shoot=nicolaka/netshoot:v0.13
bin=/target/m11/release
certs=$(mktemp -d "${TMPDIR:-/tmp}/fm-https.XXXXXX")
names=(hs-tls fmT tsT)
cleanup() {
  docker exec fmT "$bin/flowmesh" --socket=/tmp/fmd.sock logout >/dev/null 2>&1 || true
  docker exec tsT tailscale logout >/dev/null 2>&1 || true
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker rm -f "${names[@]}" >/dev/null 2>&1 || true

# Throwaway CA and a server certificate for hs-tls.lab.
docker run --rm -v "$certs:/c" "$shoot" sh -ec '
  cd /c
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=flowmesh lab CA" -keyout ca.key -out ca.pem 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=hs-tls.lab" -keyout server.key -out server.csr 2>/dev/null
  printf "subjectAltName=DNS:hs-tls.lab\n" > san.ext
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile san.ext -out server.crt 2>/dev/null
  cat server.crt server.key > server.pem'
docker run -d --name hs-tls --network "$net" --ip 172.29.0.85 --network-alias hs-tls.lab -v "$certs:/c:ro" "$shoot" \
  socat openssl-listen:443,reuseaddr,fork,cert=/c/server.pem,verify=0 tcp:172.29.0.10:80 >/dev/null

echo "== building flowmeshd"
docker run -d --name fmT --hostname fmT --network "$net" --ip 172.29.0.86 --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun --init -v flowmesh-lab_fm1-target:/target -v "$PWD/..:/src" -v "$certs:/c:ro" -w /src \
  flowmesh-lab/dev:local sleep infinity >/dev/null
docker exec -e CARGO_TARGET_DIR=/target/m11 fmT cargo build -q --release -p flowmesh-daemon -p flowmesh-cli 2>&1 | grep -v '^info:' || true

fmd() { # start flowmeshd in fmT, with or without the CA
  docker exec fmT pkill -x flowmeshd || true
  while docker exec fmT pidof flowmeshd >/dev/null; do sleep 0.2; done
  docker exec -d fmT sh -c "exec env $1 $bin/flowmeshd --state-dir /tmp/fmd --socket /tmp/fmd.sock > /tmp/fmd.log 2>&1"
  for _ in $(seq 1 40); do docker exec fmT "$bin/flowmesh" --socket=/tmp/fmd.sock status >/dev/null 2>&1 && break; sleep 0.5; done
}
up() { docker exec fmT "$bin/flowmesh" --socket=/tmp/fmd.sock up --login-server=https://hs-tls.lab \
  --hostname=fmT --accept-dns=false --authkey="$key" --timeout=30s 2>&1; }

echo "== flowmesh without the CA: must be refused"
fmd SSL_CERT_FILE=/nonexistent
if out=$(up); then echo "  FAIL: joined without trusting the CA"; exit 1; fi
echo "$out" | sort -u | sed 's/^/  refused: /'

echo "== official client through the same URL"
docker run -d --name tsT --hostname tsT --network "$net" --ip 172.29.0.87 --cap-add NET_ADMIN --cap-add NET_RAW \
  --device /dev/net/tun -e TS_NO_LOGS_NO_SUPPORT=true -e SSL_CERT_FILE=/c/ca.pem -v "$certs:/c:ro" \
  --entrypoint tailscaled tailscale/tailscale:v1.94.2 --state=/tmp/ts.state --tun=tailscale0 >/dev/null
sleep 2
docker exec tsT tailscale up --login-server=https://hs-tls.lab --authkey="$key" --hostname=tsT \
  --accept-dns=false --timeout=30s >/dev/null 2>&1 && echo "  official client joined" || echo "  official client failed"
docker exec tsT tailscale status 2>&1 | head -1 | sed 's/^/  /'
echo "== flowmesh trusting the CA"
fmd SSL_CERT_FILE=/c/ca.pem
up >/dev/null
docker exec fmT "$bin/flowmesh" --socket=/tmp/fmd.sock status | head -1 | sed 's/^/  /'
tst=$(docker exec tsT tailscale ip -4 | tr -d '\r')
for _ in $(seq 1 10); do
  line=$(docker exec fmT "$bin/flowmesh" --socket=/tmp/fmd.sock ping -c 1 "$tst" 2>&1 | tail -1 || true)
  case "$line" in pong*) break ;; esac
  sleep 1
done
echo "  flowmesh -> official client: $line"

