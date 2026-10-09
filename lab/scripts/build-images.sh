#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# 用 ../../control-server 源码为本机架构构建 headscale 镜像。
# 原因：在 arm64 主机上模拟运行 amd64 的 headscale 镜像时，Noise 握手会报
# "chacha20poly1305: message authentication failed"（模拟器下加密运算出错），所以必须使用原生镜像。
set -euo pipefail
cd "$(dirname "$0")/.."
src=../../control-server
arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) goarch=arm64 ;; x86_64|amd64) goarch=amd64 ;; *) echo "unsupported arch $arch"; exit 1 ;; esac
commit=$(git -C "$src" rev-parse --short HEAD)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$src" && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -o "$tmp/headscale" ./cmd/headscale)
cp "$src/Dockerfile" "$tmp/"
docker build -q --platform "linux/$goarch" --label "flowmesh.lab.headscale-commit=$commit" -t flowmesh-lab/headscale:native "$tmp" >/dev/null
echo "built flowmesh-lab/headscale:native ($goarch, lab control server @$commit)"
