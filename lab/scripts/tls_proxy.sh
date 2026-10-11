#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# A TLS terminator for the lab control server: hs-tls.lab (172.29.0.85:443, socat) forwards to
# headscale.lab:80 with a throwaway CA. Official clients joined through https://hs-tls.lab do not
# fall into the "forced TLS" state a plain-HTTP control server causes after a reconnect, so several
# `up` runs in a row work. Clients trust the CA via SSL_CERT_FILE=<dir>/ca.pem (mount the dir).
#   tls_proxy.sh up     (prints the certificate directory)
#   tls_proxy.sh down
set -euo pipefail
cd "$(dirname "$0")/.."
dir=$(cd .. && pwd)/target/lab-tls
case "${1:-}" in
  up)
    mkdir -p "$dir"
    if [ ! -f "$dir/server.pem" ]; then
      docker run --rm -v "$dir:/c" nicolaka/netshoot:v0.13 sh -ec '
        cd /c
        openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=flowmesh lab CA" -keyout ca.key -out ca.pem 2>/dev/null
        openssl req -newkey rsa:2048 -nodes -subj "/CN=hs-tls.lab" -keyout server.key -out server.csr 2>/dev/null
        printf "subjectAltName=DNS:hs-tls.lab\n" > san.ext
        openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -extfile san.ext -out server.crt 2>/dev/null
        cat server.crt server.key > server.pem'
    fi
    if ! docker ps --format '{{.Names}}' | grep -qx hs-tls; then
      docker rm -f hs-tls >/dev/null 2>&1 || true
      docker run -d --name hs-tls --network flowmesh-lab_lab --ip 172.29.0.85 --network-alias hs-tls.lab \
        -v "$dir:/c:ro" nicolaka/netshoot:v0.13 \
        socat openssl-listen:443,reuseaddr,fork,cert=/c/server.pem,verify=0 tcp:172.29.0.10:80 >/dev/null
    fi
    echo "$dir"
    ;;
  down)
    docker rm -f hs-tls >/dev/null 2>&1 || true
    ;;
  *)
    echo "usage: tls_proxy.sh up|down" >&2
    exit 2
    ;;
esac
