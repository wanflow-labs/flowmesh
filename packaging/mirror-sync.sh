#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Keep a download mirror of FlowMesh releases, for hosts that reach GitHub slowly. The mirror has the
# layout install.sh --mirror expects:
#
#   DEST/v0.1.2/<release files>   one directory per version (the newest KEEP are kept)
#   DEST/latest -> v0.1.2         switched only after every file of the new version checked out
#   DEST/openwrt -> openwrt-v0.1.2  the OpenWrt package feed of the latest version (only that one):
#                                 flowmesh-openwrt-feed-<v>.tar.gz unpacked, so that
#                                 `wget -qO- <mirror>/openwrt/add-feed.sh | sh` works
#
# Each round reads the latest release's SHA256SUMS from GitHub; a version not mirrored yet is
# downloaded into STAGING/vX.Y.Z, every file is checked against SHA256SUMS (install.sh too),
# and only then the directory is renamed into place and `latest` repointed. A failed round changes
# nothing that is served; files already checked are kept and a partial download is resumed, so slow
# links get there over several rounds. A round also repairs a mirror whose files were removed.
# The feed is unpacked from the checked tarball into STAGING, checked (every package its index
# lists, with its SHA-256; the signed indexes), renamed into place and switched to by repointing the
# `openwrt` symlink, like `latest`; the previous feed is then removed. Releases without a feed
# tarball leave the feed alone.
#
#   mirror-sync.sh DEST                 one round (cron)
#   mirror-sync.sh --loop SECONDS DEST  rounds forever (supervisor); failures are logged and retried
#
# Environment: FLOWMESH_REPO (default wanflow-labs/flowmesh), KEEP (default 3), STAGING (default
# DEST/.staging; put it outside the web root so unchecked files are never served — it must be on the
# same file system as DEST, since a finished version is moved into place by rename),
# FLOWMESH_RELEASES_URL (default https://github.com/$FLOWMESH_REPO/releases; tests use file://).
set -eu

REPO=${FLOWMESH_REPO:-wanflow-labs/flowmesh}
KEEP=${KEEP:-3}
loop=
if [ "${1:-}" = --loop ]; then loop=${2:?--loop needs SECONDS}; shift 2; fi
DEST=${1:?usage: mirror-sync.sh [--loop SECONDS] DEST}
STAGING=${STAGING:-$DEST/.staging}

log() { printf '%s mirror-sync: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fetch() { curl -fsSL --retry 3 --connect-timeout 20 --max-time 3600 -o "$2" "$1"; }
# Resume a partial file (GitHub release assets honour ranges).
fetch_resume() { curl -fsSL --retry 3 --connect-timeout 20 --max-time 3600 -C - -o "$2" "$1"; }
sha256() { sha256sum "$1" | cut -d' ' -f1; }

# Files a mirror serves: everything SHA256SUMS lists at top level (binaries inside the tarballs
# are listed as dir/file and are not separate downloads), plus SHA256SUMS itself.
release_files() { sed -n 's/^[0-9a-f]\{64\}  \([^/]*\)$/\1/p' "$1"; }

# feed_ok DIR: an unpacked OpenWrt feed is whole: add-feed.sh, the keys, and per architecture the
# opkg index with its signature and every package it lists (size and SHA-256), the apk index and
# packages. (The signatures themselves are checked by the routers; the tarball by SHA256SUMS.)
feed_ok() {
  [ -s "$1/add-feed.sh" ] && [ -s "$1/keys/flowmesh-usign.pub" ] && [ -s "$1/keys/flowmesh-apk.pem" ] || return 1
  n=0
  for d in "$1"/ipk/*/; do
    [ -s "$d/Packages" ] && [ -s "$d/Packages.gz" ] && [ -s "$d/Packages.sig" ] || return 1
    grep -q '^SHA256sum: ' "$d/Packages" || return 1
    awk '/^Filename: /{ f = $2 } /^SHA256sum: /{ print $2 "  " f }' "$d/Packages" |
      (cd "$d" && sha256sum -c --quiet -) > /dev/null 2>&1 || return 1
    a=$(basename "$d")
    [ -s "$1/apk/$a/packages.adb" ] && ls "$1/apk/$a"/*.apk > /dev/null 2>&1 || return 1
    n=$((n + 1))
  done
  [ "$n" -gt 0 ]
}

# sync_feed VERSION DIR: switch DEST/openwrt to the feed in DIR's flowmesh-openwrt-feed-VERSION.tar.gz.
sync_feed() {
  tarball="$2/flowmesh-openwrt-feed-$1.tar.gz"
  feed="$DEST/openwrt-v$1"
  [ -f "$tarball" ] || return 0
  [ "$(readlink "$DEST/openwrt" 2>/dev/null)" = "openwrt-v$1" ] && feed_ok "$feed" && return 0
  log "unpacking the OpenWrt feed of v$1"
  t="$STAGING/openwrt-v$1"
  rm -rf "$t" && mkdir -p "$t" || return 1
  tar -xzf "$tarball" -C "$t" || { rm -rf "$t"; log "cannot unpack $tarball"; return 1; }
  feed_ok "$t/openwrt" || { rm -rf "$t"; log "the OpenWrt feed of v$1 is incomplete; feed not switched"; return 1; }
  rm -rf "$feed.new" && mv "$t/openwrt" "$feed.new" && rm -rf "$t" "$feed" && mv "$feed.new" "$feed" || return 1
  if [ -e "$DEST/openwrt" ] && [ ! -L "$DEST/openwrt" ]; then
    log "$DEST/openwrt is not a symlink (not made by mirror-sync.sh): remove it to publish the feed"; return 1
  fi
  if ! { ln -sfn "openwrt-v$1" "$DEST/.openwrt.new" && mv -T "$DEST/.openwrt.new" "$DEST/openwrt"; }; then
    log "cannot repoint openwrt"; return 1
  fi
  log "openwrt -> openwrt-v$1"
  for old in "$DEST"/openwrt-v*; do
    [ -d "$old" ] && [ "$old" != "$feed" ] && rm -rf "$old"
  done
  return 0
}

is_complete() { # is_complete DIR: every listed file is there with the right checksum
  [ -f "$1/SHA256SUMS" ] || return 1
  for f in $(release_files "$1/SHA256SUMS"); do
    want=$(sed -n "s/^\([0-9a-f]\{64\}\)  $f\$/\1/p" "$1/SHA256SUMS")
    [ -f "$1/$f" ] && [ "$(sha256 "$1/$f")" = "$want" ] || return 1
  done
}

sync_once() {
  # Every step returns on failure by itself: under `( sync_once ) || …` the shell's -e is off.
  mkdir -p "$DEST" "$STAGING" || return 1
  # One round at a time (two rounds would write the same staging files).
  exec 9>"$STAGING/.lock" || return 1
  if command -v flock >/dev/null 2>&1 && ! flock -n 9; then log "another round is running; skipping"; return 0; fi
  rm -f "$STAGING"/sums.* # left by a round that was killed
  base=${FLOWMESH_RELEASES_URL:-https://github.com/$REPO/releases}
  sums=$(mktemp "$STAGING/sums.XXXXXX") || return 1
  trap 'rm -f "$sums"' EXIT
  fetch "$base/latest/download/SHA256SUMS" "$sums" || { log "cannot read the latest release from GitHub; retrying next round"; return 1; }
  version=$(sed -n 's/.*  flowmesh-\([0-9][0-9.]*\)-linux-x86_64\.tar\.gz$/\1/p' "$sums" | head -1)
  [ -n "$version" ] || { log "cannot tell the version from SHA256SUMS"; return 1; }
  dir="$DEST/v$version"
  tmp="$STAGING/v$version"

  if is_complete "$dir"; then
    :
  else
    log "mirroring v$version"
    mkdir -p "$tmp" || return 1
    # A changed SHA256SUMS (a re-published version) invalidates what was kept.
    if [ -f "$tmp/SHA256SUMS" ] && ! cmp -s "$sums" "$tmp/SHA256SUMS"; then rm -rf "$tmp"; mkdir -p "$tmp" || return 1; fi
    cp "$sums" "$tmp/SHA256SUMS" || return 1
    for f in $(release_files "$tmp/SHA256SUMS"); do
      want=$(sed -n "s/^\([0-9a-f]\{64\}\)  $f\$/\1/p" "$tmp/SHA256SUMS")
      [ -f "$tmp/$f" ] && [ "$(sha256 "$tmp/$f")" = "$want" ] && continue
      # Repairing a published version: reuse its files that still check out.
      if [ -f "$dir/$f" ] && [ "$(sha256 "$dir/$f")" = "$want" ]; then cp "$dir/$f" "$tmp/$f" || return 1; continue; fi
      fetch_resume "$base/download/v$version/$f" "$tmp/$f" || { log "download of $f interrupted; resuming next round"; return 1; }
      got=$(sha256 "$tmp/$f")
      if [ "$got" != "$want" ]; then
        rm -f "$tmp/$f"
        log "checksum mismatch for $f (got $got, want $want): discarded, v$version not mirrored"
        return 1
      fi
      log "  $f ok"
    done
    # Publish copies, not the staged files themselves: a download left running by a killed round
    # still holds a staged file open and would keep writing into whatever that file becomes.
    rm -rf "$dir.new" "$dir.old"
    cp -R "$tmp" "$dir.new" && chmod 0755 "$dir.new" && chmod 0644 "$dir.new"/* || return 1
    is_complete "$dir.new" || { rm -rf "$dir.new"; log "v$version does not check out; retrying next round"; return 1; }
    if [ -d "$dir" ]; then mv "$dir" "$dir.old" || return 1; fi
    mv "$dir.new" "$dir" || { log "cannot move v$version into place"; return 1; }
    rm -rf "$dir.old" "$tmp"
    log "v$version mirrored ($(release_files "$dir/SHA256SUMS" | wc -l | tr -d ' ') files)"
  fi
  rm -f "$sums"
  trap - EXIT

  if [ "$(readlink "$DEST/latest" 2>/dev/null)" != "v$version" ]; then
    if ! { ln -sfn "v$version" "$DEST/.latest.new" && mv -T "$DEST/.latest.new" "$DEST/latest"; }; then
      log "cannot repoint latest"; return 1
    fi
    log "latest -> v$version"
  fi

  # Keep the newest KEEP versions; never the one latest points to.
  # shellcheck disable=SC2010 # version directory names are vX.Y.Z only
  ls -1 "$DEST" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/^v//' |
    sort -t. -k1,1n -k2,2n -k3,3n | head -n "-$KEEP" | while read -r old; do
      [ "v$old" = "v$version" ] && continue
      rm -rf "${DEST:?}/v$old"
      log "removed v$old"
    done
  # Staging left by versions that are no longer the latest.
  for stale in "$STAGING"/v*; do
    [ -d "$stale" ] && [ "$stale" != "$tmp" ] && rm -rf "$stale"
  done
  sync_feed "$version" "$dir"
}

if [ -z "$loop" ]; then
  sync_once
  exit
fi
log "watching $REPO every ${loop}s into $DEST"
while :; do
  ( sync_once ) || log "round failed; retrying in ${loop}s"
  sleep "$loop"
done
