#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Control server unreachable: established tunnels keep working, Health says so, and after
# the server returns the netmap is live again (a rename made on the server reaches fm1).
# Needs flowmeshd Running in fm1 (cli_diff.sh / ping_diff.sh leave it so).
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose exec -T "$@"; }
fm1() { dc fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock "$@"; }
health() { fm1 status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Health"])'; }
fail() { echo "FAIL: $*"; exit 1; }
# Never leave the control server paused (scenario B), whatever way the script ends.
trap 'docker unpause flowmesh-lab-headscale-1 >/dev/null 2>&1 || true' EXIT

fm1 status >/dev/null || fail "fm1 not Running"
read -r ts1_id ts1_name < <(dc headscale headscale nodes list -o json | python3 -c '
import json,sys; n=next(n for n in json.load(sys.stdin) if n["given_name"].startswith("ts1")); print(n["id"], n["given_name"])')
[ "$ts1_name" = ts1 ] || dc headscale headscale nodes rename -i "$ts1_id" ts1 >/dev/null
dc fm1 ping -c 2 -W 3 100.64.0.1 >/dev/null

echo "== A. stop the control server for 15 s while pinging ts1"
dc fm1 sh -c '(ping -i 0.5 -c 70 -W 1 100.64.0.1 > /tmp/fault-ping.log 2>&1 &)'
docker compose stop headscale >/dev/null 2>&1
saw=""
for _ in $(seq 1 15); do
  h=$(health)
  case "$h" in *control*) saw=$h; break ;; esac
  sleep 1
done
[ -n "$saw" ] && echo "ok: Health reports the outage: $saw" || echo "FAIL: Health silent during the outage"
docker compose start headscale >/dev/null 2>&1
# Wait for the background ping to finish (it prints its summary only at the end).
loss=""
for _ in $(seq 1 60); do
  loss=$(dc fm1 sh -c "grep -o '[0-9]*% packet loss' /tmp/fault-ping.log" || true)
  [ -n "$loss" ] && break
  sleep 1
done
echo "ping during the outage: $loss"
[ "$loss" = "0% packet loss" ] || fail "tunnel traffic lost during the control outage"
[ -n "$saw" ] || fail "Health did not report the outage"

echo "== a change made on the server after it returns must reach fm1"
dc headscale headscale nodes rename -i "$ts1_id" ts1-renamed >/dev/null
seen=""
for _ in $(seq 1 30); do
  if fm1 status --json | grep -q '"ts1-renamed\.'; then seen=1; break; fi
  sleep 1
done
dc headscale headscale nodes rename -i "$ts1_id" ts1 >/dev/null
[ -n "$seen" ] || fail "netmap frozen: the rename never reached fm1"
echo "ok: netmap live again after the outage"
case "$(health)" in *control*) fail "Health still reports the outage after recovery" ;; esac
echo "ok: Health clear after recovery"



echo "== B. the control server stops answering without closing the connection (half-open)"
# `docker pause` freezes headscale: the kernel keeps the TCP connection, but no message comes. This is
# what a server crash or a NAT timeout looks like from the client (a `docker restart` produces it
# only sometimes). The client must notice by itself and redial once the server answers again.
before=$(dc fm1 awk 'NR>1 && $3 ~ /:0050$/ && $4 == "01" {print $2}' /proc/net/tcp | tr -d '\r')
marks=$({ dc fm1 grep -c "presumed dead" /tmp/flowmeshd.log || true; } | tr -d '\r')
docker pause flowmesh-lab-headscale-1 >/dev/null
seen=""
for _ in $(seq 1 180); do
  [ "$({ dc fm1 grep -c "presumed dead" /tmp/flowmeshd.log || true; } | tr -d '\r')" -gt "$marks" ] && { seen=1; break; }
  sleep 1
done
docker unpause flowmesh-lab-headscale-1 >/dev/null
[ -n "$seen" ] && echo "ok: the silent stream was presumed dead" || fail "the half-open control connection was never noticed"
for _ in $(seq 1 90); do
  after=$(dc fm1 awk 'NR>1 && $3 ~ /:0050$/ && $4 == "01" {print $2}' /proc/net/tcp | tr -d '\r')
  [ -n "$after" ] && [ "$after" != "$before" ] && break
  sleep 1
done
[ -n "$after" ] && [ "$after" != "$before" ] && echo "ok: a new control connection ($before -> $after)" || fail "control connection unchanged ($before -> $after)"
dc headscale headscale nodes rename -i "$ts1_id" ts1-renamed >/dev/null
seen=""
for _ in $(seq 1 30); do
  if fm1 status --json | grep -q '"ts1-renamed\.'; then seen=1; break; fi
  sleep 1
done
dc headscale headscale nodes rename -i "$ts1_id" ts1 >/dev/null
[ -n "$seen" ] || fail "netmap frozen after the half-open outage"
echo "ok: netmap live again"
docker compose restart ts1 ts2 wm1 >/dev/null 2>&1
# The official clients cannot reconnect to the plain-HTTP lab server after it restarts (they force
# port 443 after a noise dial, cli.md §6); restart them so later scripts start from a healthy lab.
echo "(restarted the official clients and wm1 for the next scripts)"
