#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Acceptance for packaging/systemd/flowmeshd.service in a container with systemd as PID 1 (fmsd):
# join under the unit's sandbox, MagicDNS takeover, read-only access for other users, restart
# restores Running, stop restores the system, and the sandbox exposure score.
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { docker compose --profile systemd exec -T "$@"; }
key=$(cat .authkey)
fail() { echo "FAIL: $*"; exit 1; }

echo "== build binaries (fm1) and start a fresh fmsd"
dc fm1 cargo build -q -p flowmesh-daemon -p flowmesh-cli
docker compose --profile systemd rm -sf fmsd >/dev/null 2>&1 || true
docker compose --profile systemd up -d fmsd >/dev/null
for _ in $(seq 1 40); do
  state=$(dc fmsd systemctl is-system-running 2>/dev/null | tr -d '\r' || true)
  case "$state" in running|degraded) break ;; esac
  sleep 0.5
done
echo "systemd: $state"

tmp=$(mktemp -d)
docker compose cp fm1:/target/debug/flowmeshd "$tmp/flowmeshd" >/dev/null
docker compose cp fm1:/target/debug/flowmesh "$tmp/flowmesh" >/dev/null
docker compose --profile systemd cp "$tmp/flowmeshd" fmsd:/usr/sbin/flowmeshd >/dev/null
docker compose --profile systemd cp "$tmp/flowmesh" fmsd:/usr/bin/flowmesh >/dev/null
docker compose --profile systemd cp ../packaging/systemd/flowmeshd.service \
  fmsd:/etc/systemd/system/flowmeshd.service >/dev/null
orig_resolv=$(dc fmsd cat /etc/resolv.conf)

echo "== install and start the unit"
dc fmsd systemd-analyze verify /etc/systemd/system/flowmeshd.service
dc fmsd systemctl daemon-reload
dc fmsd systemctl enable --now flowmeshd >/dev/null 2>&1
for _ in $(seq 1 20); do dc fmsd test -S /run/flowmesh/flowmeshd.sock && break; sleep 0.5; done
dc fmsd test -S /run/flowmesh/flowmeshd.sock || { dc fmsd journalctl -u flowmeshd --no-pager | tail -20; fail "no socket"; }
echo "ok: flowmeshd active, socket present"

dc fmsd flowmesh up --login-server=http://headscale.lab --hostname=fmsd --authkey="$key" --timeout=30s \
  || { dc fmsd journalctl -u flowmeshd --no-pager | tail -30; fail "up"; }
dc fmsd flowmesh status >/dev/null || fail "not Running after up"
echo "ok: joined under the sandbox (Running)"

dc fmsd grep -q "^nameserver 100.100.100.100" /etc/resolv.conf || fail "resolv.conf not taken over"
dc fmsd test -f /var/lib/flowmesh/resolv.conf.backup || fail "backup not in the state directory"
echo "ok: resolv.conf taken over in place (backup in /var/lib/flowmesh)"

ts1=$(dc ts1 tailscale ip -4 | tr -d '\r')
dc fmsd ping -c 3 -W 3 "$ts1" >/dev/null || fail "ping ts1 $ts1"
echo "ok: fmsd -> ts1 ($ts1) ping"

mode=$(dc fmsd stat -c %a /var/lib/flowmesh/prefs.json | tr -d '\r')
[ "$mode" = 600 ] || fail "prefs.json mode $mode"
echo "ok: prefs.json is 0600"

dc fmsd runuser -u nobody -- flowmesh status >/dev/null || fail "nobody cannot read status"
if out=$(dc fmsd runuser -u nobody -- flowmesh down 2>&1); then fail "nobody could run down"; fi
echo "$out" | grep -q "requires root" || fail "unexpected refusal: $out"
echo "ok: other users can read status but not change anything"

dc fmsd systemctl restart flowmeshd
for _ in $(seq 1 40); do dc fmsd flowmesh status >/dev/null 2>&1 && break; sleep 0.5; done
dc fmsd flowmesh status >/dev/null || fail "not Running after restart"
echo "ok: Running again after systemctl restart"

dc fmsd systemctl stop flowmeshd
now_resolv=$(dc fmsd cat /etc/resolv.conf)
[ "$now_resolv" = "$orig_resolv" ] || fail "resolv.conf not restored"
if dc fmsd ip link show flowmesh0 >/dev/null 2>&1; then fail "flowmesh0 still present"; fi
dc fmsd test ! -e /var/lib/flowmesh/resolv.conf.backup || fail "backup left behind"
echo "ok: stop restored resolv.conf and removed flowmesh0"

echo "== sandbox exposure (systemd-analyze security)"
dc fmsd systemd-analyze security flowmeshd --no-pager | tail -1
