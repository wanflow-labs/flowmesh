#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# 采集黑盒观测样本：官方客户端视角的状态和偏好设置，以及 headscale 视角的节点和策略。
# 用法：lab/scripts/capture.sh [label]，默认 label 为 baseline。
set -euo pipefail
cd "$(dirname "$0")/.."
label="${1:-baseline}"
out="../fixtures/observed/$(date +%Y%m%d)-${label}"
mkdir -p "$out"

for c in ts1 ts2; do
  docker compose exec -T "$c" tailscale status --json > "$out/$c-status.json"
  docker compose exec -T "$c" tailscale debug prefs > "$out/$c-prefs.json"
  docker compose exec -T "$c" tailscale debug netmap > "$out/$c-netmap.json"
done
docker compose exec -T headscale headscale nodes list -o json > "$out/headscale-nodes.json"
docker compose exec -T headscale headscale policy get > "$out/headscale-policy.json"

python3 scripts/redact.py "$out" "$(cat .authkey)"

ts_version=$(docker compose exec -T ts1 tailscale version | head -1 | tr -d '\r')
hs_commit=$(docker image inspect flowmesh-lab/headscale:native --format '{{index .Config.Labels "flowmesh.lab.headscale-commit"}}')
python3 - "$out" "$label" "$ts_version" "$hs_commit" <<'PY'
import json, os, sys, datetime
out, label, ts_version, hs_commit = sys.argv[1:]
files = sorted(f for f in os.listdir(out) if f != "manifest.json")
json.dump({
    "label": label,
    "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "official_client": ts_version,
    "headscale": f"lab control server @{hs_commit} (built by lab/scripts/build-images.sh)",
    "derp_image": "lab relay image (lab/.env)",
    "files": files,
    "note": "lab-only keys; captured from flowmesh lab, see lab/README.md",
}, open(os.path.join(out, "manifest.json"), "w"), indent=2)
print(f"captured {len(files)} files into {out}")
PY
