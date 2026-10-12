#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the release packages on clean systemd containers (Debian 12, Ubuntu 24.04: .deb; Rocky 9:
# .rpm), start the service, join the lab mesh, reach fm1 (a flowmesh peer: the official clients may be
# stuck after the control-server faults other scripts inject), then remove the package: the service is
# stopped and the binaries are gone, the node identity in /var/lib/flowmesh stays.
#   package_check.sh DIST_DIR     (packages for this host's architecture are used)
set -euo pipefail
dist=$(cd "${1:?usage: package_check.sh DIST_DIR}" && pwd)
cd "$(dirname "$0")/.."
key=$(cat .authkey)
case "$(docker version --format '{{.Server.Arch}}')" in
  arm64|aarch64) deb_arch=arm64; rpm_arch=aarch64 ;;
  amd64|x86_64) deb_arch=amd64; rpm_arch=x86_64 ;;
esac
deb=$(ls "$dist"/flowmesh_*_"$deb_arch".deb)
rpm=$(ls "$dist"/flowmesh-*."$rpm_arch".rpm)
net=flowmesh-lab_lab
target=$(docker compose exec -T fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock status --json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])')
fail() { echo "FAIL: $*"; exit 1; }

check() { # name image ip package install-cmd remove-cmd
  local name=$1 image=$2 ip=$3 pkg=$4 install=$5 remove=$6 c="fm-pkg-$1"
  echo "== $name ($(basename "$pkg"))"
  docker rm -f "$c" >/dev/null 2>&1 || true
  docker run -d --name "$c" --hostname "$c" --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --network "$net" --ip "$ip" "$image" >/dev/null
  for _ in $(seq 1 40); do
    s=$(docker exec "$c" systemctl is-system-running 2>/dev/null || true)
    case "$s" in running|degraded) break ;; esac; sleep 0.5
  done
  docker cp "$pkg" "$c:/tmp/$(basename "$pkg")"
  docker exec "$c" sh -c "$install /tmp/$(basename "$pkg")" >/dev/null || fail "$name: install"
  docker exec "$c" systemctl is-enabled flowmeshd >/dev/null 2>&1 && fail "$name: service enabled by the package"
  docker exec "$c" systemctl enable --now flowmeshd >/dev/null 2>&1
  for _ in $(seq 1 20); do docker exec "$c" test -S /run/flowmesh/flowmeshd.sock && break; sleep 0.5; done
  docker exec "$c" flowmesh up --login-server=http://headscale.lab --hostname="$c" --accept-dns=false \
    --authkey="$key" --timeout=30s || fail "$name: up"
  # A new node is reachable once the peer's netmap includes it (a few seconds after `up`).
  ok=""
  for _ in $(seq 1 10); do docker exec "$c" ping -c 1 -W 2 "$target" >/dev/null 2>&1 && { ok=1; break; }; done
  [ -n "$ok" ] || fail "$name: ping fm1 ($target)"
  docker exec "$c" test -f /usr/share/flowmesh/flowmeshd-ssh.service || fail "$name: flowmeshd-ssh.service not installed"
  echo "ok: installed (not enabled), joined, reached fm1"
  docker exec "$c" sh -c "$remove" >/dev/null 2>&1 || fail "$name: remove"
  docker exec "$c" systemctl is-active flowmeshd >/dev/null 2>&1 && fail "$name: service still active after removal"
  docker exec "$c" test -e /usr/sbin/flowmeshd && fail "$name: binary left behind"
  docker exec "$c" test -f /var/lib/flowmesh/node.json || fail "$name: node identity removed"
  echo "ok: removed: service stopped, binaries gone, node identity kept"
  docker rm -f "$c" >/dev/null
}

check debian12 flowmesh-lab/systemd:local 172.29.0.33 "$deb" "dpkg -i" "dpkg -r flowmesh"
check ubuntu2404 flowmesh-lab/systemd-ubuntu:local 172.29.0.34 "$deb" "dpkg -i" "dpkg -r flowmesh"
check rocky9 flowmesh-lab/systemd-rocky:local 172.29.0.35 "$rpm" "rpm -i" "rpm -e flowmesh"
echo "ok: all distributions"
