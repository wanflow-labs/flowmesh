#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Undo peer_relay_up.sh: remove the UDP drops between ts1 and ts2 and stop tsr.
set -uo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose --profile peer-relay "$@"; }
ts1=172.29.0.21; ts2=172.29.0.22
for pair in "ts1 $ts2" "ts2 $ts1"; do
  set -- $pair
  dc exec -T "$1" sh -c "while iptables -D OUTPUT -p udp -d $2 -j DROP 2>/dev/null; do :; done; while iptables -D INPUT -p udp -s $2 -j DROP 2>/dev/null; do :; done"
done
dc stop tsr >/dev/null
