#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Observe the official client's MagicDNS: with accept-dns on ts2, look at resolv.conf and the 100.100.100.100 answers to a set of queries.
# Usage: dns_observe.sh <out-dir>
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$(dirname "$0")/.."
mkdir -p "$out"
docker compose exec -T ts2 tailscale set --accept-dns=true
sleep 3
docker compose exec -T ts2 cat /etc/resolv.conf > "$out/ts2-resolv.conf"
queries=(
  "ts1.mesh.lab.internal A" "ts1.mesh.lab.internal AAAA" "ts1 A" "TS1.MESH.LAB.INTERNAL A"
  "svc.mesh.lab.internal A" "svc.mesh.lab.internal AAAA" "nosuch.mesh.lab.internal A" "mesh.lab.internal A"
  "1.0.64.100.in-addr.arpa PTR" "99.0.64.100.in-addr.arpa PTR" "ts1.mesh.lab.internal TXT" "ts1.mesh.lab.internal MX"
  "example.com A" "headscale.lab A"
)
: > "$out/answers.txt"
for q in "${queries[@]}"; do
  set -- $q
  ans=$(docker run --rm --net container:flowmesh-lab-ts2-1 nicolaka/netshoot:v0.13 dig +tries=1 +time=3 @100.100.100.100 "$1" "$2" 2>&1 \
        | awk '/status:/ {s=$6} /^;; ANSWER SECTION:/ {a=1; next} a && NF==0 {a=0} a {printf "%s %s %s|", $4, $5, $1} END {print s}')
  echo "$1 $2 => $ans" | tee -a "$out/answers.txt"
done
docker compose exec -T ts2 tailscale set --accept-dns=false
