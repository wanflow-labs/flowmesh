#!/usr/bin/env bash
# Task 3 conditions. tsr must be stopped (no working relay). One probe run per condition, 100 s each.
#   A: direct UDP dropped, ts1 pings ts2 every second for the whole run
#   B: direct UDP dropped, no traffic after the first ping
#   C: ts1 pings every second; the drops are removed at 40 s
set -uo pipefail
cd "$(dirname "$0")/../../../lab"
dc() { docker compose "$@"; }
drops() { # add|del
  local op=$1
  for spec in "ts1 172.29.0.22" "ts2 172.29.0.21"; do
    read -r c ip <<< "$spec"
    if [ "$op" = add ]; then
      dc exec -T "$c" sh -c "iptables -C OUTPUT -p udp -d $ip -j DROP 2>/dev/null || iptables -A OUTPUT -p udp -d $ip -j DROP; iptables -C INPUT -p udp -s $ip -j DROP 2>/dev/null || iptables -A INPUT -p udp -s $ip -j DROP"
    else
      dc exec -T "$c" sh -c "while iptables -D OUTPUT -p udp -d $ip -j DROP 2>/dev/null; do :; done; while iptables -D INPUT -p udp -s $ip -j DROP 2>/dev/null; do :; done"
    fi
  done
}
count_drops() { dc exec -T ts1 sh -c 'iptables -S | grep -c DROP' | tr -d '\r'; }
ts2=$(dc exec -T ts2 tailscale ip -4 | tr -d '\r')
run() { # name traffic(yes|no) remove_at(seconds or -)
  local name=$1 traffic=$2 remove_at=$3
  drops add
  echo "== $name: drops on ts1 = $(count_drops)"
  dc exec -T -d fm1 sh -c "rm -rf /tmp/cond-$name && /target/debug/flowmesh-probe --login-server http://headscale.lab --authkey-file /src/lab/.authkey --state /tmp/probe2.json --hostname probe2 --dump /tmp/cond-$name --derp-region 1000 --duration 100 > /tmp/cond-$name.log 2>&1"
  sleep 8
  for s in $(seq 0 89); do
    if [ "$traffic" = yes ] || [ "$s" = 0 ]; then
      dc exec -T ts1 tailscale ping -c 1 --timeout 1s "$ts2" 2>&1 | head -1 | sed "s/^/  t+$s /" | grep -E "t\+(0|39|41|60|89) " || true
    fi
    if [ "$s" = "$remove_at" ]; then drops del; echo "  t+$s drops removed (now $(count_drops))"; fi
    sleep 1
  done
  sleep 6
  echo "  0x08 received (ms since probe start):"; dc exec -T fm1 sh -c "cut -f1,2 /tmp/cond-$name/disco.tsv 2>/dev/null | sed 's/\.mesh.*//' | tr '\n' ' '"; echo
}
run A yes -
run B no -
run C yes 40
drops del
echo "final drops on ts1: $(count_drops)"
