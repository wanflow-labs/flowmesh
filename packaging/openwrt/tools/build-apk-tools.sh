#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds apk-tools 3 (`apk mkpkg`, `apk mkndx`) from the upstream release that OpenWrt v25.12.6 ships
# (3.0.5). Downloads the release tarball, checks its SHA-256, builds with meson and ninja (needs a C
# compiler, pkg-config, OpenSSL and zlib headers; MESON=/path for another meson, >= 0.64).
#   packaging/openwrt/tools/build-apk-tools.sh <out_dir>      -> <out_dir>/apk
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <out_dir>" >&2; exit 2; }
APK_TOOLS_VERSION=3.0.5
# From the upstream GitHub mirror: gitlab.alpinelinux.org answers GitHub Actions runners with HTTP 418
# (bot protection). The mirror's tag archive unpacks to the same tree as the GitLab release archive
# (compared file by file); only the tarball bytes, and so the SHA-256, differ.
APK_TOOLS_SHA256=8795712ce02457d29c0beb18f82851b408d1d47f98a0cbbbd33ab5ea496f665d
url="https://github.com/alpinelinux/apk-tools/archive/refs/tags/v$APK_TOOLS_VERSION.tar.gz"
MESON=${MESON:-meson}
mkdir -p "$1"
out=$(cd "$1" && pwd)
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
curl -fsSL --retry 3 -o "$src/apk-tools.tar.gz" "$url"
echo "$APK_TOOLS_SHA256  $src/apk-tools.tar.gz" | sha256sum -c --quiet - ||
  { echo "checksum mismatch: $url" >&2; exit 1; }
tar -xzf "$src/apk-tools.tar.gz" -C "$src"
cd "$src/apk-tools-$APK_TOOLS_VERSION"
$MESON setup build -Dlua=disabled -Ddocs=disabled -Dhelp=disabled -Dpython=disabled -Dzstd=disabled \
  -Ddefault_library=static > /dev/null
ninja -C build src/apk > /dev/null
install -m0755 build/src/apk "$out/apk"
"$out/apk" --version
