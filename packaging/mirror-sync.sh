#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Keep a download mirror of FlowMesh releases, for hosts that reach GitHub slowly. The mirror has the
# layout install.sh --mirror expects:
#
#   DEST/v0.1.2/<release files>   one directory per version (the newest KEEP are kept)
#   DEST/latest -> v0.1.2         switched only after every file of the new version checked out
#
# Each round reads the latest release's SHA256SUMS from GitHub; a version not mirrored yet is
# downloaded into a temporary directory, every file is checked against SHA256SUMS (install.sh too),
# and only then the directory is renamed into place and `latest` repointed. A failed round changes
# nothing that is served. A round also repairs a mirror whose files were removed.
#
#   mirror-sync.sh DEST                 one round (cron)
#   mirror-sync.sh --loop SECONDS DEST  rounds forever (supervisor); failures are logged and retried
#
# Environment: FLOWMESH_REPO (default wanflow-labs/flowmesh), KEEP (default 3).
set -eu

REPO=${FLOWMESH_REPO:-wanflow-labs/flowmesh}
KEEP=${KEEP:-3}
loop=
if [ "${1:-}" = --loop ]; then loop=${2:?--loop needs SECONDS}; shift 2; fi
DEST=${1:?usage: mirror-sync.sh [--loop SECONDS] DEST}

log() { printf '%s mirror-sync: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fetch() { curl -fsSL --retry 3 --connect-timeout 20 --max-time 900 -o "$2" "$1"; }
sha256() { sha256sum "$1" | cut -d' ' -f1; }

# Files a mirror serves: everything SHA256SUMS lists at top level (binaries inside the tarballs
# are listed as dir/file and are not separate downloads), plus SHA256SUMS itself.
release_files() { sed -n 's/^[0-9a-f]\{64\}  \([^/]*\)$/\1/p' "$1"; }

is_complete() { # is_complete DIR: every listed file is there with the right checksum
  [ -f "$1/SHA256SUMS" ] || return 1
  for f in $(release_files "$1/SHA256SUMS"); do
    want=$(sed -n "s/^\([0-9a-f]\{64\}\)  $f\$/\1/p" "$1/SHA256SUMS")
    [ -f "$1/$f" ] && [ "$(sha256 "$1/$f")" = "$want" ] || return 1
  done
}

sync_once() {
  mkdir -p "$DEST"
  base="https://github.com/$REPO/releases"
  tmp=$(mktemp -d "$DEST/.incoming.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT
  fetch "$base/latest/download/SHA256SUMS" "$tmp/SHA256SUMS"
  version=$(sed -n 's/.*  flowmesh-\([0-9][0-9.]*\)-linux-x86_64\.tar\.gz$/\1/p' "$tmp/SHA256SUMS" | head -1)
  [ -n "$version" ] || { log "cannot tell the version from SHA256SUMS"; return 1; }
  dir="$DEST/v$version"

  if is_complete "$dir"; then
    :
  else
    log "mirroring v$version"
    for f in $(release_files "$tmp/SHA256SUMS"); do
      fetch "$base/download/v$version/$f" "$tmp/$f"
      want=$(sed -n "s/^\([0-9a-f]\{64\}\)  $f\$/\1/p" "$tmp/SHA256SUMS")
      got=$(sha256 "$tmp/$f")
      [ "$got" = "$want" ] || { log "checksum mismatch for $f (got $got, want $want): v$version not mirrored"; return 1; }
    done
    chmod 0755 "$tmp"
    chmod 0644 "$tmp"/*
    rm -rf "$dir.old"
    [ -d "$dir" ] && mv "$dir" "$dir.old"
    mv "$tmp" "$dir"
    rm -rf "$dir.old"
    log "v$version mirrored ($(release_files "$dir/SHA256SUMS" | wc -l | tr -d ' ') files)"
  fi
  rm -rf "$tmp"
  trap - EXIT

  if [ "$(readlink "$DEST/latest" 2>/dev/null)" != "v$version" ]; then
    ln -sfn "v$version" "$DEST/.latest.new"
    mv -T "$DEST/.latest.new" "$DEST/latest"
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
