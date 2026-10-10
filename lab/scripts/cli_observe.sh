#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Observe the official CLI's state transitions: BackendState after down / up / logout / up, the exit code of status, and the JSON field structure.
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$(dirname "$0")/.."
st() {
  docker compose exec -T ts2 tailscale status --json > "$out/status-$1.json" 2>/dev/null || true
  code=0; docker compose exec -T ts2 tailscale status >/dev/null 2>&1 || code=$?
  bs=$(python3 -c "import json; print(json.load(open('$out/status-$1.json')).get('BackendState'))")
  echo "$1: BackendState=$bs  'status' exit=$code"
}
st initial
docker compose exec -T ts2 tailscale down; st after-down
docker compose exec -T ts2 tailscale up --timeout=30s >/dev/null 2>&1 || true; st after-up
docker compose exec -T ts2 tailscale logout; st after-logout
docker compose exec -T ts2 tailscale up --login-server=http://headscale.lab --authkey="$(cat .authkey)" --hostname=ts2 --accept-dns=false --timeout=30s >/dev/null; st after-relogin
python3 - "$out/status-initial.json" > "$out/status-keys.txt" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print("top:", sorted(d.keys()))
print("Self:", sorted(d["Self"].keys()))
print("Peer[*]:", sorted(next(iter(d["Peer"].values())).keys()))
PY
cat "$out/status-keys.txt"
