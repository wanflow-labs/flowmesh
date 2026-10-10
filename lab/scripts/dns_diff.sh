#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# MagicDNS differential acceptance: send fm1 (flowmesh --accept-dns) the same query set used to observe the official client
# (OBS-20261010-magicdns/answers.txt) and compare line by line. Forwarded queries (bare names, outside domains) compare rcode only.
set -euo pipefail
cd "$(dirname "$0")/.."
FM1_ARGS="--accept-dns" scripts/fm1.sh start >/dev/null 2>&1
for _ in $(seq 1 20); do
  docker compose exec -T fm1 grep -q "MagicDNS:" /tmp/flowmesh-dev.log && break
  sleep 1
done
echo "fm1 resolv.conf:"; docker compose exec -T fm1 cat /etc/resolv.conf | sed 's/^/  /'
fail=0
while IFS= read -r line; do
  q=${line%% => *}; expected=${line#* => }
  set -- $q
  got=$(docker run --rm --net container:flowmesh-lab-fm1-1 nicolaka/netshoot:v0.13 dig +tries=1 +time=3 @100.100.100.100 "$1" "$2" 2>&1 \
        | awk '/status:/ {s=$6} /^;; ANSWER SECTION:/ {a=1; next} a && NF==0 {a=0} a {printf "%s %s %s|", $4, $5, $1} END {print s}')
  case "$1" in ts1|example.com|headscale.lab) cmp_exp=${expected##*|}; cmp_got=${got##*|}; kind=forward ;; *) cmp_exp=$expected; cmp_got=$got; kind=local ;; esac
  if [ "$cmp_exp" = "$cmp_got" ]; then echo "ok   [$kind] $q"; else echo "DIFF [$kind] $q: official=$expected flowmesh=$got"; fail=1; fi
done < ../fixtures/observed/20261010-magicdns/answers.txt
docker compose exec -T fm1 sh -c 'pkill -x flowmesh-dev; sleep 1; echo "after stop:"; cat /etc/resolv.conf | sed "s/^/  /"; ls /target/resolv.conf.backup 2>/dev/null || echo "  (backup removed)"'
exit $fail
