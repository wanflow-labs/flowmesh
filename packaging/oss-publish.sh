#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Publishes a release to an OSS bucket that serves the same layout as packaging/mirror-sync.sh:
#   PREFIX/vX.Y.Z/<release files>   immutable once written, cached for a year
#   PREFIX/latest/<release files>   the newest release; SHA256SUMS is written last
#   PREFIX/openwrt/                 the newest OpenWrt feed, unpacked; indexes are written last
# Run by .github/workflows/release.yml after the GitHub Release is published. Objects are only
# added or overwritten, never deleted: files named for an older version stay in latest/ and
# openwrt/, but no SHA256SUMS or feed index points at them.
#   packaging/oss-publish.sh VERSION DIR
# DIR holds the release's files with its SHA256SUMS (as `gh release download` leaves them).
# Environment: OSS_BUCKET (required), OSS_PREFIX (default flowmesh), OSSUTIL (default ossutil);
# credentials and region come from OSS_ACCESS_KEY_ID, OSS_ACCESS_KEY_SECRET, OSS_SESSION_TOKEN and
# OSS_REGION, which ossutil reads itself. OSSUTIL=echo prints the uploads instead (dry run).
set -eu
[ $# -eq 2 ] || { echo "usage: $0 VERSION DIR" >&2; exit 2; }
version=$1
dir=$2
: "${OSS_BUCKET:?OSS_BUCKET must name the bucket}"
prefix=${OSS_PREFIX:-flowmesh}
ossutil=${OSSUTIL:-ossutil}
dest="oss://$OSS_BUCKET/$prefix"

LONG='public, max-age=31536000, immutable'
SHORT='public, max-age=300'

# The files a release consists of: everything SHA256SUMS lists at top level (binaries inside the
# tarballs are listed as dir/file), plus SHA256SUMS itself last.
release_files() {
  sed -n 's/^[0-9a-f]\{64\}  \([^/]*\)$/\1/p' "$dir/SHA256SUMS"
  echo SHA256SUMS
}

put() { # put FILE KEY CACHE_CONTROL
  "$ossutil" cp -f --cache-control "$3" "$1" "$dest/$2"
}

[ -f "$dir/SHA256SUMS" ] || { echo "$dir/SHA256SUMS is missing" >&2; exit 1; }
grep -q "  flowmesh-$version-linux-x86_64\.tar\.gz\$" "$dir/SHA256SUMS" ||
  { echo "$dir/SHA256SUMS is not the list of release $version" >&2; exit 1; }
for f in $(release_files); do
  [ "$f" = SHA256SUMS ] && continue
  [ -f "$dir/$f" ] || { echo "$dir/$f is missing" >&2; exit 1; }
  want=$(sed -n "s/^\([0-9a-f]\{64\}\)  $f\$/\1/p" "$dir/SHA256SUMS")
  got=$(sha256sum "$dir/$f" | cut -d' ' -f1)
  [ "$got" = "$want" ] || { echo "checksum mismatch for $f" >&2; exit 1; }
done

# 1. The version directory. SHA256SUMS goes last, so a reader that finds it finds every file.
for f in $(release_files); do
  put "$dir/$f" "v$version/$f" "$LONG"
done

# 2. The OpenWrt feed: packages and keys first, then the indexes, add-feed.sh last.
feed="$dir/flowmesh-openwrt-feed-$version.tar.gz"
if [ -f "$feed" ]; then
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  tar -xzf "$feed" -C "$work"
  [ -s "$work/openwrt/add-feed.sh" ] || { echo "$feed has no openwrt/add-feed.sh" >&2; exit 1; }
  (
    cd "$work/openwrt"
    is_index() { case $1 in */Packages|*/Packages.gz|*/Packages.sig|*/packages.adb|add-feed.sh) return 0 ;; esac; return 1; }
    find . -type f | sed 's|^\./||' | LC_ALL=C sort > "$work/files"
    while read -r f; do is_index "$f" || put "$f" "openwrt/$f" "$SHORT"; done < "$work/files"
    # An index and its signature go up back to back: Packages and Packages.gz, then Packages.sig.
    while read -r f; do
      case $f in */Packages|*/Packages.gz|*/packages.adb) put "$f" "openwrt/$f" "$SHORT" ;; esac
    done < "$work/files"
    while read -r f; do
      case $f in */Packages.sig) put "$f" "openwrt/$f" "$SHORT" ;; esac
    done < "$work/files"
    put add-feed.sh openwrt/add-feed.sh "$SHORT"
  )
fi

# 3. latest/: the same files, SHA256SUMS last (install.sh reads the version from it).
for f in $(release_files); do
  put "$dir/$f" "latest/$f" "$SHORT"
done
echo "published $version to $dest"
