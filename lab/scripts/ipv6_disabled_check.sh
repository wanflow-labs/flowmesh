#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# A host with IPv6 turned off (net.ipv6.conf.*.disable_ipv6=1, common on servers) must still join.
# The kernel refuses the mesh IPv6 address there (EACCES), so the interface comes up IPv4-only
# instead of the whole engine failing and restarting forever. Installs the package in a systemd
# container with IPv6 disabled, joins the lab, reaches an IPv4 peer, and checks the log says why
# IPv6 is missing.
#   ipv6_disabled_check.sh PACKAGE.deb [FLOWMESHD]   FLOWMESHD replaces the packaged daemon (to test
#                                                      a build before it is packaged)
set -euo pipefail
deb=$(cd "$(dirname "${1:?usage: ipv6_disabled_check.sh PACKAGE.deb [FLOWMESHD]}")" && pwd)/$(basename "$1")
bin=${2:+$(cd "$(dirname "$2")" && pwd)/$(basename "$2")}
cd "$(dirname "$0")/.."
key=$(cat .authkey)
c=fm-pkg-noipv6
fail() {
  echo "FAIL: $*"
  docker exec "$c" journalctl -u flowmeshd --no-pager 2>/dev/null | tail -20
  docker exec "$c" flowmesh status 2>/dev/null | tail -5
  exit 1
}

target=$(docker compose exec -T headscale headscale nodes list -o json | python3 -c '
import json, sys
nodes = [n for n in json.load(sys.stdin) if n.get("online") and n["name"] != "'"$c"'"]
print(next(a for n in nodes for a in n["ip_addresses"] if ":" not in a))')

docker rm -f "$c" >/dev/null 2>&1 || true
docker run -d --name "$c" --hostname "$c" --privileged --cgroupns=host \
  --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 --sysctl net.ipv6.conf.default.disable_ipv6=1 \
  --network flowmesh-lab_lab --ip 172.29.0.36 flowmesh-lab/systemd-ubuntu:local >/dev/null
for _ in $(seq 1 40); do
  s=$(docker exec "$c" systemctl is-system-running 2>/dev/null || true)
  case "$s" in running|degraded) break ;; esac; sleep 0.5
done
[ "$(docker exec "$c" sysctl -n net.ipv6.conf.default.disable_ipv6)" = 1 ] || fail "IPv6 is not disabled in the container"

docker cp "$deb" "$c:/tmp/flowmesh.deb"
docker exec "$c" dpkg -i /tmp/flowmesh.deb >/dev/null || fail "install"
if [ -n "$bin" ]; then
  docker cp "$bin" "$c:/usr/sbin/flowmeshd"
  docker exec "$c" chmod 0755 /usr/sbin/flowmeshd
fi
docker exec "$c" systemctl enable --now flowmeshd >/dev/null 2>&1
for _ in $(seq 1 20); do docker exec "$c" test -S /run/flowmesh/flowmeshd.sock && break; sleep 0.5; done
docker exec "$c" flowmesh up --login-server=http://headscale.lab --hostname="$c" --accept-dns=false \
  --authkey="$key" --timeout=30s || fail "up"
[ "$(docker exec "$c" flowmesh status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["BackendState"])')" = Running ] \
  || fail "not Running"

ok=""
for _ in $(seq 1 10); do docker exec "$c" ping -c 1 -W 2 "$target" >/dev/null 2>&1 && { ok=1; break; }; done
[ -n "$ok" ] || fail "ping $target over the mesh"
# Read the journal first: `journalctl | grep -q` under pipefail fails on the SIGPIPE grep leaves behind.
journal=$(docker exec "$c" journalctl -u flowmeshd --no-pager)
grep -q "IPv6 is disabled" <<<"$journal" || fail "the log does not say why the mesh IPv6 address is missing"
grep -q "up as \[100\.[0-9.]*/32\]" <<<"$journal" || fail "the up line should list only the IPv4 address"
[ -z "$(docker exec "$c" ip -6 addr show dev flowmesh0 2>/dev/null)" ] || fail "an IPv6 address is on flowmesh0"
echo "ok: IPv6 disabled host joined IPv4-only and reached $target"
docker rm -f "$c" >/dev/null
