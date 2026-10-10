#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# 启动实验环境：自签 DERP 证书 → 起容器 → 建用户、设策略、发 key → 两个官方客户端入网。
set -euo pipefail
cd "$(dirname "$0")/.."

hs() { docker compose exec -T headscale headscale "$@"; }

# Two relay regions: 1000 (derp.lab) and 1001 (derp2.lab), for region failover (design §7.2).
for host in derp.lab derp2.lab; do
  if [ ! -f "derp/certs/$host.crt" ]; then
    mkdir -p derp/certs
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=$host" -addext "subjectAltName=DNS:$host" \
      -keyout "derp/certs/$host.key" -out "derp/certs/$host.crt"
  fi
done

docker image inspect flowmesh-lab/headscale:native >/dev/null 2>&1 || scripts/build-images.sh
docker compose up -d

for _ in $(seq 1 90); do
  hs users list >/dev/null 2>&1 && break
  sleep 1
done
hs users list >/dev/null

hs users list -o json | python3 -c 'import json,sys; sys.exit(0 if any(u["name"]=="lab" for u in json.load(sys.stdin) or []) else 1)' \
  || hs users create lab >/dev/null
hs policy set -f /etc/headscale/policy.json >/dev/null

user_id=$(hs users list -o json | python3 -c 'import json,sys; print([u["id"] for u in json.load(sys.stdin) if u["name"]=="lab"][0])')
hs preauthkeys create --user "$user_id" --reusable --expiration 24h --tags tag:relay-enabled -o json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])' > .authkey

for c in ts1 ts2 wm1; do
  cli=tailscale
  [ "$c" = wm1 ] && cli=wanflow-mesh
  docker compose exec -T "$c" "$cli" up \
    --login-server=http://headscale.lab \
    --authkey="$(cat .authkey)" --hostname="$c" --accept-dns=false --timeout=60s
done
echo "lab up: $(hs nodes list -o json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))') nodes"
