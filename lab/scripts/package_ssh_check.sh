#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The SSH server when flowmeshd runs from the installed .deb under systemd (Debian 12 container).
# Under the packaged, sandboxed flowmeshd.service the server must not start and Health must name
# flowmeshd-ssh.service; under flowmeshd-ssh.service alice and root log in from fm1, land in their
# home directories and can write there. Prints what it sees; compare with docs/protocol/ssh.md.
#   package_ssh_check.sh DEB [UNIT_FILE] [BIN_DIR]
#     UNIT_FILE replaces the packaged unit; BIN_DIR holds flowmeshd and flowmesh to test instead of
#     the packaged ones (absolute paths)
set -euo pipefail
deb=$1 unit=${2:-} bindir=${3:-}
cd "$(dirname "$0")/.."
key=$(cat .authkey)
c=fm-pkg-ssh
hs() { docker compose exec -T headscale headscale "$@"; }
saved=$(mktemp)
hs policy get > "$saved"
cleanup() {
  docker exec "$c" flowmesh logout >/dev/null 2>&1 || true
  docker rm -f "$c" >/dev/null 2>&1 || true
  docker compose cp "$saved" headscale:/tmp/policy-restore.json >/dev/null 2>&1 &&
    hs policy set -f /tmp/policy-restore.json >/dev/null 2>&1 && echo "policy restored" >&2
  rm -f "$saved"
}
trap cleanup EXIT
python3 - "$saved" > /tmp/fm-policy-ssh.json <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
p["ssh"] = [{"action": "accept", "src": ["tag:relay-enabled"], "dst": ["tag:relay-enabled"],
             "users": ["root", "alice", "autogroup:nonroot"]}]
print(json.dumps(p, indent=2))
PY
docker compose cp /tmp/fm-policy-ssh.json headscale:/tmp/policy-ssh.json >/dev/null
hs policy set -f /tmp/policy-ssh.json >/dev/null

docker rm -f "$c" >/dev/null 2>&1 || true
docker run -d --name "$c" --hostname "$c" --privileged --cgroupns=host \
  --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --network flowmesh-lab_lab --ip 172.29.0.36 flowmesh-lab/systemd:local >/dev/null
for _ in $(seq 1 40); do
  s=$(docker exec "$c" systemctl is-system-running 2>/dev/null || true)
  case "$s" in running|degraded) break ;; esac; sleep 0.5
done
docker cp "$deb" "$c:/tmp/fm.deb"
docker exec "$c" dpkg -i /tmp/fm.deb >/dev/null
if [ -n "$bindir" ]; then
  docker cp "$bindir/flowmeshd" "$c:/usr/sbin/flowmeshd"
  docker cp "$bindir/flowmesh" "$c:/usr/bin/flowmesh"
fi
if [ -n "$unit" ]; then
  docker cp "$unit" "$c:/usr/lib/systemd/system/flowmeshd.service"
  docker exec "$c" systemctl daemon-reload
fi
docker exec "$c" useradd -m -s /bin/sh alice
docker exec "$c" systemctl enable --now flowmeshd >/dev/null 2>&1
for _ in $(seq 1 20); do docker exec "$c" test -S /var/run/flowmesh/flowmeshd.sock && break; sleep 0.5; done
docker exec "$c" flowmesh up --login-server=http://headscale.lab --hostname="$c" --accept-dns=false \
  --authkey="$key" --ssh --timeout=30s
ip=$(docker exec "$c" flowmesh ip -4)
echo "node $ip"
sleep 3
echo "== health"
docker exec "$c" flowmesh status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Health"])'
for u in alice root; do
  echo "== ssh $u@$ip id; pwd; touch ~/x && echo wrote-home"
  docker compose exec -T fm1 timeout 20 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes "$u@$ip" 'id; pwd; touch ~/x && echo wrote-home' 2>&1 | tail -5 || true
done
echo "== daemon log"
docker exec "$c" journalctl -u flowmeshd --no-pager | grep -i -E "ssh|child|denied|error|permission" | tail -15
