#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rehearsal of mirror-sync.sh against a fake GitHub (file:// URLs, FLOWMESH_RELEASES_URL) in a
# temporary directory: the first mirror of a release with an OpenWrt feed, an unchanged round, a new
# release switching the feed, a release whose feed is broken (the old feed stays), and a release
# without a feed (the feed is left alone). Linux (GNU coreutils), no network.
#   packaging/mirror-sync_test.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fails=0
check() { local d=$1; shift; if "$@"; then echo "PASS  $d"; else echo "FAIL  $d"; fails=$((fails + 1)); fi; }

# A feed tarball with the layout build-feed.sh writes (the files are stand-ins; signatures are
# checked by routers, not by the mirror). $2 = "broken": a package does not match its index.
make_feed() {
  local v=$1 mode=${2:-} w="$t/feedsrc" a
  rm -rf "$w"; mkdir -p "$w/openwrt/keys"
  printf '#!/bin/sh\necho feed %s\n' "$v" > "$w/openwrt/add-feed.sh"
  echo usign-pub > "$w/openwrt/keys/flowmesh-usign.pub"; echo apk-pub > "$w/openwrt/keys/flowmesh-apk.pem"
  for a in x86_64 aarch64_generic; do
    mkdir -p "$w/openwrt/ipk/$a" "$w/openwrt/apk/$a"
    echo "flowmesh $v $a" > "$w/openwrt/ipk/$a/flowmesh_${v}-1_$a.ipk"
    printf 'Package: flowmesh\nVersion: %s-1\nFilename: flowmesh_%s-1_%s.ipk\nSHA256sum: %s\nDescription: x\n\n' \
      "$v" "$v" "$a" "$(sha256sum "$w/openwrt/ipk/$a/flowmesh_${v}-1_$a.ipk" | cut -d' ' -f1)" > "$w/openwrt/ipk/$a/Packages"
    gzip -n -c "$w/openwrt/ipk/$a/Packages" > "$w/openwrt/ipk/$a/Packages.gz"
    echo sig > "$w/openwrt/ipk/$a/Packages.sig"
    echo "flowmesh $v $a" > "$w/openwrt/apk/$a/flowmesh-$v-r1.apk"
    echo index > "$w/openwrt/apk/$a/packages.adb"
  done
  [ "$mode" = broken ] && echo corrupted >> "$w/openwrt/ipk/aarch64_generic/flowmesh_${v}-1_aarch64_generic.ipk"
  tar -czf "$3" -C "$w" openwrt
}

# publish <version> [feed|nofeed|broken]: make it the latest release of the fake GitHub.
publish() {
  local v=$1 mode=${2:-feed} r="$t/github/download/v$1"
  mkdir -p "$r" "$t/github/latest/download"
  echo "linux $v" > "$r/flowmesh-$v-linux-x86_64.tar.gz"
  echo "install $v" > "$r/install.sh"
  case "$mode" in
    feed) make_feed "$v" "" "$r/flowmesh-openwrt-feed-$v.tar.gz" ;;
    broken) make_feed "$v" broken "$r/flowmesh-openwrt-feed-$v.tar.gz" ;;
  esac
  (cd "$r" && sha256sum -- * > SHA256SUMS)
  cp "$r/SHA256SUMS" "$t/github/latest/download/SHA256SUMS"
}

dest=$t/www
sync() { FLOWMESH_RELEASES_URL="file://$t/github" STAGING="$t/staging" "$here/mirror-sync.sh" "$dest" > "$t/log" 2>&1; }
feed_version() { sed -n 's/^echo feed //p' "$dest/openwrt/add-feed.sh" 2>/dev/null; }

publish 0.1.5
sync; st=$?
sed 's/^/   | /' "$t/log"
check "first round succeeds" [ $st -eq 0 ]
check "latest -> v0.1.5 with the feed tarball mirrored" test -f "$dest/latest/flowmesh-openwrt-feed-0.1.5.tar.gz"
check "openwrt -> openwrt-v0.1.5 (a symlink)" eval '[ "$(readlink "$dest/openwrt")" = openwrt-v0.1.5 ]'
check "the feed is served: add-feed.sh, keys, ipk and apk indexes" eval '
  [ "$(feed_version)" = 0.1.5 ] && test -s "$dest/openwrt/keys/flowmesh-usign.pub" &&
  test -s "$dest/openwrt/ipk/x86_64/Packages.sig" && test -s "$dest/openwrt/apk/aarch64_generic/packages.adb"'
check "nothing left in staging" eval '[ -z "$(ls "$t/staging" | grep openwrt)" ]'

sync; st=$?
check "unchanged round: succeeds without unpacking again" eval '[ $st -eq 0 ] && ! grep -q unpacking "$t/log"'

rm "$dest/openwrt/ipk/x86_64/Packages.gz"
sync; st=$?
check "a damaged feed is repaired" eval '[ $st -eq 0 ] && test -s "$dest/openwrt/ipk/x86_64/Packages.gz"'

publish 0.1.6
sync; st=$?
sed 's/^/   | /' "$t/log"
check "new release: openwrt -> openwrt-v0.1.6" eval '[ $st -eq 0 ] && [ "$(readlink "$dest/openwrt")" = openwrt-v0.1.6 ] && [ "$(feed_version)" = 0.1.6 ]'
check "new release: only the latest feed is kept" eval '[ "$(ls -d "$dest"/openwrt-v* | wc -l)" = 1 ]'

publish 0.1.7 broken
sync; st=$?
sed 's/^/   | /' "$t/log"
check "broken feed: the round fails, the release itself is mirrored" eval '[ $st -ne 0 ] && [ "$(readlink "$dest/latest")" = v0.1.7 ]'
check "broken feed: the 0.1.6 feed is still served" eval '[ "$(readlink "$dest/openwrt")" = openwrt-v0.1.6 ] && [ "$(feed_version)" = 0.1.6 ]'
check "broken feed: no half-unpacked feed left" eval '[ "$(ls -d "$dest"/openwrt-v* | wc -l)" = 1 ] && [ -z "$(ls "$t/staging" | grep openwrt)" ]'

publish 0.1.8 nofeed
sync; st=$?
check "release without a feed: succeeds, feed left alone" eval '[ $st -eq 0 ] && [ "$(readlink "$dest/latest")" = v0.1.8 ] && [ "$(feed_version)" = 0.1.6 ]'

rm "$dest/openwrt"; mkdir "$dest/openwrt"
publish 0.1.9
sync; st=$?
check "a real directory at openwrt is not replaced (logged, round fails)" eval '[ $st -ne 0 ] && [ ! -L "$dest/openwrt" ] && grep -q "not a symlink" "$t/log"'

echo "mirror-sync rehearsal: $fails failed"
exit "$fails"
