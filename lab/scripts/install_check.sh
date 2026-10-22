#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# packaging/install.sh on many distributions: each container runs the script from a local mirror of
# a release (DIST_DIR, as built by build/release.sh + build/package.sh), joins the lab mesh and must
# reach fm1; the script runs a second time (nothing to do), then --uninstall. systemd images run
# their init; the others take the "no init system" path. Packages for this host's architecture.
# The join passes no --hostname, like the console's script when no device name is given: the node
# must register under the container's host name (an empty name left headscale unable to build its
# map). The "localhost" case checks the fallback when the system has no real name.
#   install_check.sh DIST_DIR [NAME...]   (default: all; names below)
set -euo pipefail
dist=$(cd "${1:?usage: install_check.sh DIST_DIR [NAME...]}" && pwd)
shift
cd "$(dirname "$0")/.."
key=$(cat .authkey)
net=flowmesh-lab_lab
version=$(sed -n 's/.*  flowmesh-\([0-9.]*\)-linux-x86_64\.tar\.gz$/\1/p' "$dist/SHA256SUMS" | head -1)
target=$(docker compose exec -T fm1 /target/debug/flowmesh --socket=/tmp/fmd.sock status --json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["TailscaleIPs"][0])')

# name  image  ip  expected-method  systemd(1/0)  [extra install.sh flags]
cases="
debian12     flowmesh-lab/systemd:local         172.29.0.191 deb 1 --ssh --advertise-exit-node
ubuntu2404   flowmesh-lab/systemd-ubuntu:local  172.29.0.192 deb 1
rocky9       flowmesh-lab/systemd-rocky:local   172.29.0.193 rpm 1
debian-slim  debian:bookworm-slim               172.29.0.194 deb 0
oraclelinux  mysql/mysql-server:8.0             172.29.0.195 rpm 0
alpine       alpine:3.20                        172.29.0.198 tar 0 --advertise-exit-node
localhost    alpine:3.20                        172.29.0.199 tar 0
"

# The host name the node reported, by its mesh IP; "<no given name>" when headscale could not name it
# (the given name gets a random suffix when the name is taken, so it is only checked for presence).
hs_node_name() {
  # </dev/null: the case list comes in on the loop's stdin, which docker exec would otherwise eat
  docker compose exec -T headscale headscale nodes list -o json </dev/null | python3 -c '
import json, sys
ip = sys.argv[1]
n = next((n for n in json.load(sys.stdin) or [] if ip in (n.get("ip_addresses") or [])), None)
print("<no such node>" if n is None else (n.get("name") or "") if n.get("given_name") else "<no given name>")' "$1"
}

# The mirror: vX.Y.Z/ and latest/ both point at the release files.
mirror=fm-mirror
docker rm -f "$mirror" >/dev/null 2>&1 || true
docker run -d --name "$mirror" --network "$net" --ip 172.29.0.190 \
  -v "$dist:/usr/share/nginx/html/v$version:ro" -v "$dist:/usr/share/nginx/html/latest:ro" nginx:alpine >/dev/null
started=()
cleanup() {
  for c in "${started[@]}"; do docker exec "$c" flowmesh logout >/dev/null 2>&1 || true; docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker rm -f "$mirror" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

while read -r name image ip want sysd flags; do
  [ -n "$name" ] || continue
  if [ $# -gt 0 ] && ! printf '%s\n' "$@" | grep -qx "$name"; then continue; fi
  c="fm-inst-$name"
  # the host name the node must register under; "localhost" means "no name": the client falls back
  # to linux-<machine-id prefix>, or "flowmesh" without a machine id (as in this image)
  host=$c want_name=$c
  [ "$name" = localhost ] && host=localhost want_name=flowmesh
  echo "== $name ($image)"
  docker rm -f "$c" >/dev/null 2>&1 || true
  if [ "$sysd" = 1 ]; then
    docker run -d --name "$c" --hostname "$host" --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
      -v /sys/fs/cgroup:/sys/fs/cgroup:rw --network "$net" --ip "$ip" "$image" >/dev/null
    for _ in $(seq 1 40); do
      s=$(docker exec "$c" systemctl is-system-running 2>/dev/null || true)
      case "$s" in running|degraded) break ;; esac; sleep 0.5
    done
  else
    docker run -d --name "$c" --hostname "$host" --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun \
      --network "$net" --ip "$ip" --entrypoint sleep "$image" infinity >/dev/null
  fi
  started+=("$c")
  # Only what the script needs and a minimal image may lack: a downloader.
  docker exec "$c" sh -c 'command -v curl >/dev/null || command -v wget >/dev/null ||
    { (apt-get update -qq && apt-get install -y -qq curl) || (dnf -y -q install curl) || (microdnf -y install curl) || (yum -y -q install curl) ||
      (zypper -q -n install curl) || (pacman -Sy --noconfirm curl) || apk add -q curl; } >/dev/null 2>&1'
  # The check itself pings fm1 through the tunnel (kernel ICMP over flowmesh0).
  docker exec "$c" sh -c 'command -v ping >/dev/null ||
    { (apt-get install -y -qq iputils-ping) || (microdnf -y install iputils) || (dnf -y -q install iputils) || apk add -q iputils; } >/dev/null 2>&1'
  docker cp ../packaging/install.sh "$c:/tmp/install.sh"
  out=$(docker exec "$c" sh /tmp/install.sh --mirror=http://172.29.0.190 --login-server=http://headscale.lab \
    --auth-key="$key" ${flags:+$flags} -- --accept-dns=false 2>&1) || { echo "$out"; fail "$name: install"; }
  echo "   ${out//$'\n'/$'\n'   }"
  echo "$out" | grep -q "($want, " || fail "$name: expected the $want method"
  ok=""
  for _ in $(seq 1 10); do docker exec "$c" ping -c 1 -W 2 "$target" >/dev/null 2>&1 && { ok=1; break; }; done
  [ -n "$ok" ] || fail "$name: ping fm1 ($target)"
  meship=$(docker exec "$c" flowmesh ip -4)
  got_name=$(hs_node_name "$meship")
  [ "$got_name" = "$want_name" ] || fail "$name: registered as \"$got_name\", want \"$want_name\" (host name $host)"
  health=$(docker exec "$c" flowmesh status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Health"])')
  [ "$health" = "[]" ] || fail "$name: Health $health"
  case " $flags " in *" --ssh "*)
    docker exec "$c" grep -q "SSH server" /etc/systemd/system/flowmeshd.service || fail "$name: SSH unit not installed" ;;
  esac
  case " $flags " in *" --advertise-exit-node "*)
    [ "$(docker exec "$c" cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || fail "$name: IP forwarding off" ;;
  esac
  echo "ok: $name installed ($want${flags:+, $flags}), joined as $got_name, reached fm1, Health clear"
  again=$(docker exec "$c" sh /tmp/install.sh --mirror=http://172.29.0.190 2>&1) || { echo "$again"; fail "$name: second run"; }
  echo "$again" | grep -q "already installed" || { echo "$again"; fail "$name: second run reinstalled"; }
  echo "$again" | grep -q "still on the mesh" || { echo "$again"; fail "$name: second run does not see the node on the mesh"; }
  docker exec "$c" sh /tmp/install.sh --uninstall >/dev/null 2>&1 || fail "$name: uninstall"
  docker exec "$c" sh -c 'test ! -e /usr/sbin/flowmeshd && test ! -e /usr/bin/flowmesh' || fail "$name: binaries left after uninstall"
  echo "ok: $name second run is a no-op, uninstall removes it"
done <<< "$cases"
echo "ok: all"
