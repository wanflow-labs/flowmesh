#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds the control server image for the host architecture (source location in lab/.env, template in lab/.env.example).
# Reason: when an amd64 headscale image runs under emulation on an arm64 host, the Noise handshake fails with
# "chacha20poly1305: message authentication failed" (crypto goes wrong under the emulator), so a native image is required.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "lab/.env missing: copy lab/.env.example and fill it in"; exit 1; }
set -a; . ./.env; set +a
src=${FLOWMESH_LAB_HEADSCALE_SRC:?set in lab/.env}
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) goarch=arm64 ;; x86_64|amd64) goarch=amd64 ;; *) echo "unsupported arch $arch"; exit 1 ;; esac
commit=$(git -C "$src" rev-parse --short HEAD)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$src" && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -o "$tmp/headscale" ./cmd/headscale)
cp "$src/Dockerfile" "$tmp/"
docker build -q --platform "linux/$goarch" --label "flowmesh.lab.headscale-commit=$commit" -t flowmesh-lab/headscale:native "$tmp" >/dev/null
echo "built flowmesh-lab/headscale:native ($goarch, control server @$commit)"

# wanflow-mesh (WanFlow's Tailscale fork): reference implementation for WanFlow-specific semantics (relay-only, etc.).
# Needs Go 1.25, so it is built inside the official Go container.
mesh_src=$(cd "${FLOWMESH_LAB_MESH_SRC:?set in lab/.env}" && pwd)
mesh_commit=$(git -C "$mesh_src" rev-parse --short HEAD)
mtmp=$(mktemp -d)
docker run --rm -v "$mesh_src:/src:ro" -v "$mtmp:/out" -w /src -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false golang:1.25.5 \
  sh -c 'go build -o /out/wanflow-meshd ./cmd/tailscaled && go build -o /out/wanflow-mesh ./cmd/tailscale'
cat > "$mtmp/Dockerfile" <<'DOCKERFILE'
FROM alpine:3.20
RUN apk add --no-cache iptables ip6tables iproute2 ca-certificates
COPY wanflow-meshd wanflow-mesh /usr/local/bin/
DOCKERFILE
docker build -q --label "flowmesh.lab.wanflow-mesh-commit=$mesh_commit" -t flowmesh-lab/wanflow-mesh:native "$mtmp" >/dev/null
rm -rf "$mtmp"
echo "built flowmesh-lab/wanflow-mesh:native (wanflow-mesh@$mesh_commit)"
