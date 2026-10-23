#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# OpenWrt packages from the release tarballs (build/release.sh): for every architecture in
# arches.txt, an opkg package and an apk-tools 3 package (OpenWrt 25.12 and later) of flowmesh, plus
# the architecture-independent LuCI page luci-app-flowmesh, assembled here without the OpenWrt SDK.
# All timestamps are SOURCE_DATE_EPOCH, so the packages reproduce.
#   packaging/openwrt/build-packages.sh <dist_dir> <out_dir>
# Reads <dist_dir>/flowmesh-<version>-openwrt-<family>.tar.gz; writes, per architecture,
#   <out_dir>/<arch>/flowmesh_<version>-<n>_<arch>.ipk
#   <out_dir>/<arch>/flowmesh-<version>-r<n>.apk      (its arch field is <arch>)
# and once
#   <out_dir>/all/luci-app-flowmesh_<version>-<n>_all.ipk
#   <out_dir>/all/luci-app-flowmesh-<version>-r<n>.apk  (arch noarch)
# where <n> is the package release, FLOWMESH_PKG_RELEASE (default 1).
# A feed for one architecture is <out_dir>/<arch>/ plus the files of <out_dir>/all/ (the feed
# builder copies them in). luci-app-flowmesh depends on flowmesh of the same version.
# Needs GNU tar, gzip, apk-tools 3 (`apk mkpkg`; APK=/path/to/apk to choose one) and LuCI's po2lmo
# (PO2LMO=/path/to/po2lmo; when unset it is built with tools/build-po2lmo.sh, which downloads its
# pinned source). The packages are unsigned: the feed's index carries the signature.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <dist_dir> <out_dir>" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
dist=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
APK=${APK:-apk}

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -1)
# The package release (opkg -<n>, apk -r<n>): 1 for every new version. A rebuild of the same version
# that must reach routers which have it already takes the next number (the upgrade test builds 1, 2
# and 3 this way).
release=${FLOWMESH_PKG_RELEASE:-1}
case "$release" in
  ''|0*|*[!0-9]*) echo "FLOWMESH_PKG_RELEASE must be a number from 1 (got '$release')" >&2; exit 1 ;;
esac
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

luci_pkg=luci-app-flowmesh
luci_description="Wanflow FlowMesh: LuCI page (Services > FlowMesh)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

PO2LMO=${PO2LMO:-}
if [ -z "$PO2LMO" ]; then
  "$here/tools/build-po2lmo.sh" "$work/tools" > /dev/null
  PO2LMO=$work/tools/po2lmo
fi

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
  install -Dm0755 "$f/flowmesh-watch.sh" "$root/usr/libexec/flowmesh-watch"
  install -Dm0644 "$f/flowmesh-prefs.sh" "$root/usr/share/flowmesh/prefs.sh"
  install -Dm0644 "$f/flowmesh.keep" "$root/lib/upgrade/keep.d/flowmesh"
}

# The installed files of luci-app-flowmesh.
stage_luci() {
  local root=$1 d="$here/luci-app-flowmesh" po lang
  install -Dm0755 "$d/root/usr/libexec/flowmesh-luci" "$root/usr/libexec/flowmesh-luci"
  install -Dm0644 "$d/root/usr/share/luci/menu.d/luci-app-flowmesh.json" \
    "$root/usr/share/luci/menu.d/luci-app-flowmesh.json"
  install -Dm0644 "$d/root/usr/share/rpcd/acl.d/luci-app-flowmesh.json" \
    "$root/usr/share/rpcd/acl.d/luci-app-flowmesh.json"
  (cd "$d/htdocs" && find . -type f -name '*.js') | sort | while read -r f; do
    install -Dm0644 "$d/htdocs/$f" "$root/www/$f"
  done
  for po in "$d"/po/*/flowmesh.po; do
    lang=$(basename "$(dirname "$po")")
    # LuCI's language codes for these directories (luci.mk LUCI_LC_ALIAS); others are lower-cased.
    case "$lang" in
      zh_Hans) lang=zh-cn ;; zh_Hant) lang=zh-tw ;; pt_BR) lang=pt-br ;; nb_NO) lang=no ;; bn_BD) lang=bn ;;
      *) lang=$(echo "$lang" | tr 'A-Z_' 'a-z-') ;;
    esac
    mkdir -p "$root/usr/lib/lua/luci/i18n"
    "$PO2LMO" "$po" "$root/usr/lib/lua/luci/i18n/flowmesh.$lang.lmo"
  done
}

# build_ipk <arch> <root> <dest> <name> <depends (opkg syntax)> <section> <description>
#   <scripts dir (postinst, prerm, postrm: those present)> [conffile]
build_ipk() {
  local arch=$1 root=$2 dest=$3 name=$4 deps=$5 section=$6 desc=$7 scripts=$8 conffile=${9:-}
  local c="$work/ipk-control" p="$work/ipk-outer" s
  rm -rf "$c" "$p"
  mkdir -p "$c" "$p"
  local size
  size=$(find "$root" -type f -printf '%s\n' | awk '{ s += $1 } END { print s }')
  cat > "$c/control" <<EOF
Package: $name
Version: $ipk_version
Depends: $deps
Source: $url
SourceName: $name
License: $license
Section: $section
SourceDateEpoch: $SOURCE_DATE_EPOCH
URL: $url
Architecture: $arch
Installed-Size: $size
Description: $desc
EOF
  [ -z "$conffile" ] || echo "$conffile" > "$c/conffiles"
  for s in postinst prerm postrm; do
    [ ! -f "$scripts/$s" ] || install -m0755 "$scripts/$s" "$c/$s"
  done
  echo 2.0 > "$p/debian-binary"
  tgz "$root" > "$p/data.tar.gz"
  tgz "$c" > "$p/control.tar.gz"
  touch -d "@$SOURCE_DATE_EPOCH" "$p"/*
  # Member order as opkg-build writes it.
  tar --format=gnu --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -C "$p" -cf - ./debian-binary ./data.tar.gz ./control.tar.gz | gzip -n -9 > "$dest"
}

# build_apk <arch> <root> <dest> <name> <depends (apk syntax)> <description> <scripts dir>
build_apk() {
  local arch=$1 root=$2 dest=$3 name=$4 deps=$5 desc=$6 scripts=$7
  find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  # opkg script names -> apk script types.
  # post-upgrade is postinst with PKG_UPGRADE=1, the variable opkg sets for an upgrade (as OpenWrt's
  # own apk packages do).
  local sargs=()
  if [ -f "$scripts/postinst" ]; then
    { printf '#!/bin/sh\nPKG_UPGRADE=1\nexport PKG_UPGRADE\n'; sed 1d "$scripts/postinst"; } > "$work/post-upgrade"
    sargs+=(--script "post-install:$scripts/postinst" --script "post-upgrade:$work/post-upgrade")
  fi
  [ ! -f "$scripts/prerm" ] || sargs+=(--script "pre-deinstall:$scripts/prerm")
  [ ! -f "$scripts/postrm" ] || sargs+=(--script "post-deinstall:$scripts/postrm")
  # Files are recorded with their owner: run as (namespaced) root so they belong to root.
  local asroot=()
  [ "$(id -u)" = 0 ] || asroot=(unshare -r)
  "${asroot[@]}" "$APK" mkpkg \
    --info "name:$name" \
    --info "version:$apk_version" \
    --info "description:$desc" \
    --info "arch:$arch" \
    --info "license:$license" \
    --info "origin:$name" \
    --info "url:$url" \
    --info "depends:$deps" \
    "${sargs[@]}" \
    --files "$root" \
    --output "$dest"
}

n=0
while read -r arch family; do
  case "$arch" in ''|'#'*) continue ;; esac
  root="$work/root-$family"
  [ -d "$root" ] || stage_root "$family" "$root"
  mkdir -p "$out/$arch"
  build_ipk "$arch" "$root" "$out/$arch/${pkg}_${ipk_version}_${arch}.ipk" "$pkg" "${depends// /, }" net \
    "$description" "$here/flowmesh/control" /etc/config/flowmesh
  build_apk "$arch" "$root" "$out/$arch/$pkg-$apk_version.apk" "$pkg" "$depends" "$description" \
    "$here/flowmesh/control"
  n=$((n + 1))
done < "$here/arches.txt"
echo "$n architectures: $out/<arch>/{${pkg}_${ipk_version}_<arch>.ipk,$pkg-$apk_version.apk}"

# luci-app-flowmesh needs the flowmesh of the same version (it uses /usr/share/flowmesh/prefs.sh);
# rpcd-mod-file runs its helper (luci-base pulls it in too).
lroot="$work/root-luci"
stage_luci "$lroot"
mkdir -p "$out/all"
build_ipk all "$lroot" "$out/all/${luci_pkg}_${ipk_version}_all.ipk" "$luci_pkg" \
  "flowmesh (= $ipk_version), luci-base, rpcd-mod-file" luci "$luci_description" \
  "$here/luci-app-flowmesh/control"
build_apk noarch "$lroot" "$out/all/$luci_pkg-$apk_version.apk" "$luci_pkg" \
  "flowmesh=$apk_version luci-base rpcd-mod-file" "$luci_description" "$here/luci-app-flowmesh/control"
echo "and $out/all/{${luci_pkg}_${ipk_version}_all.ipk,$luci_pkg-$apk_version.apk}"
