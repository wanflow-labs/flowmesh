#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# OpenWrt packages from the release tarballs (build/release.sh): for every architecture in
# arches.txt, an opkg package and an apk-tools 3 package (OpenWrt 25.12 and later), assembled here
# without the OpenWrt SDK. All timestamps are SOURCE_DATE_EPOCH, so the packages reproduce.
#   packaging/openwrt/build-packages.sh <dist_dir> <out_dir>
# Reads <dist_dir>/flowmesh-<version>-openwrt-<family>.tar.gz; writes, per architecture,
#   <out_dir>/<arch>/flowmesh_<version>-1_<arch>.ipk
#   <out_dir>/<arch>/flowmesh-<version>-r1.apk      (its arch field is <arch>)
# Needs GNU tar, gzip and apk-tools 3 (`apk mkpkg`; APK=/path/to/apk to choose one). The packages
# are unsigned: the feed's index carries the signature.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <dist_dir> <out_dir>" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
dist=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
APK=${APK:-apk}

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -1)
release=1
# apk versions do not allow '-' inside the upstream version (0.2.0-rc1 -> 0.2.0_rc1).
apk_version="${version//-/_}-r$release"
ipk_version="$version-$release"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct 2>/dev/null || true)}
case "$SOURCE_DATE_EPOCH" in
  ''|*[!0-9]*) echo "SOURCE_DATE_EPOCH must be set (got '$SOURCE_DATE_EPOCH')" >&2; exit 1 ;;
esac
export TZ=UTC LC_ALL=C
umask 022
"$APK" --version | grep -q '^apk-tools 3\.' || { echo "apk-tools 3 required (APK=$APK)" >&2; exit 1; }

pkg=flowmesh
depends="kmod-tun ip-full"
license=Apache-2.0
url=https://github.com/wanflow-labs/flowmesh
description="Wanflow FlowMesh: joins this router to a FlowMesh mesh network (flowmeshd daemon and flowmesh command)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Deterministic tar.gz of directory $1's contents ("./..." entries, like OpenWrt's ipkg-build).
tgz() {
  find "$1" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  tar --format=gnu --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -C "$1" -cf - . | gzip -n -9
}

# The installed files for one release family.
stage_root() {
  local family=$1 root=$2
  local tarball="$dist/flowmesh-$version-openwrt-$family.tar.gz"
  [ -f "$tarball" ] || { echo "missing $tarball (run build/release.sh first)" >&2; exit 1; }
  local src="$work/src-$family"
  mkdir -p "$src"
  tar -xzf "$tarball" -C "$src" --strip-components=1
  install -Dm0755 "$src/flowmeshd" "$root/usr/sbin/flowmeshd"
  install -Dm0755 "$src/flowmesh" "$root/usr/bin/flowmesh"
  install -Dm0644 "$src/LICENSE" "$root/usr/share/licenses/flowmesh/LICENSE"
  install -Dm0644 "$src/NOTICE" "$root/usr/share/licenses/flowmesh/NOTICE"
  local f="$here/flowmesh/files"
  install -Dm0755 "$f/flowmesh.init" "$root/etc/init.d/flowmesh"
  install -Dm0644 "$f/flowmesh.config" "$root/etc/config/flowmesh"
  install -Dm0755 "$f/flowmesh.defaults" "$root/etc/uci-defaults/90-flowmesh"
  install -Dm0755 "$f/flowmesh-fw.sh" "$root/usr/libexec/flowmesh-fw"
  install -Dm0644 "$f/flowmesh.keep" "$root/lib/upgrade/keep.d/flowmesh"
}

build_ipk() {
  local arch=$1 root=$2 dest=$3 c="$work/ipk-control" p="$work/ipk-outer"
  rm -rf "$c" "$p"
  mkdir -p "$c" "$p"
  local size
  size=$(find "$root" -type f -printf '%s\n' | awk '{ s += $1 } END { print s }')
  cat > "$c/control" <<EOF
Package: $pkg
Version: $ipk_version
Depends: ${depends// /, }
Source: $url
SourceName: $pkg
License: $license
Section: net
SourceDateEpoch: $SOURCE_DATE_EPOCH
URL: $url
Architecture: $arch
Installed-Size: $size
Description: $description
EOF
  echo /etc/config/flowmesh > "$c/conffiles"
  install -m0755 "$here/flowmesh/control/postinst" "$c/postinst"
  install -m0755 "$here/flowmesh/control/prerm" "$c/prerm"
  echo 2.0 > "$p/debian-binary"
  tgz "$root" > "$p/data.tar.gz"
  tgz "$c" > "$p/control.tar.gz"
  touch -d "@$SOURCE_DATE_EPOCH" "$p"/*
  # Member order as opkg-build writes it.
  tar --format=gnu --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -C "$p" -cf - ./debian-binary ./data.tar.gz ./control.tar.gz | gzip -n -9 > "$dest"
}

build_apk() {
  local arch=$1 root=$2 dest=$3
  find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  # Files are recorded with their owner: run as (namespaced) root so they belong to root.
  local asroot=()
  [ "$(id -u)" = 0 ] || asroot=(unshare -r)
  "${asroot[@]}" "$APK" mkpkg \
    --info "name:$pkg" \
    --info "version:$apk_version" \
    --info "description:$description" \
    --info "arch:$arch" \
    --info "license:$license" \
    --info "origin:$pkg" \
    --info "url:$url" \
    --info "depends:$depends" \
    --script "post-install:$here/flowmesh/control/postinst" \
    --script "post-upgrade:$here/flowmesh/control/postinst" \
    --script "pre-deinstall:$here/flowmesh/control/prerm" \
    --files "$root" \
    --output "$dest"
}

n=0
while read -r arch family; do
  case "$arch" in ''|'#'*) continue ;; esac
  root="$work/root-$family"
  [ -d "$root" ] || stage_root "$family" "$root"
  mkdir -p "$out/$arch"
  build_ipk "$arch" "$root" "$out/$arch/${pkg}_${ipk_version}_${arch}.ipk"
  build_apk "$arch" "$root" "$out/$arch/$pkg-$apk_version.apk"
  n=$((n + 1))
done < "$here/arches.txt"
echo "$n architectures: $out/<arch>/{${pkg}_${ipk_version}_<arch>.ipk,$pkg-$apk_version.apk}"
