#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Keep a download mirror of FlowMesh releases, for hosts that reach GitHub slowly. The mirror has the
# layout install.sh --mirror expects:
#
#   DEST/v0.1.2/<release files>   one directory per version (the newest KEEP are kept)
#   DEST/latest -> v0.1.2         switched only after every file of the new version checked out
#
# Each round reads the latest release's SHA256SUMS from GitHub; a version not mirrored yet is
# downloaded into STAGING/vX.Y.Z, every file is checked against SHA256SUMS (install.sh too),
# and only then the directory is renamed into place and `latest` repointed. A failed round changes
# nothing that is served; files already checked are kept and a partial download is resumed, so slow
# links get there over several rounds. A round also repairs a mirror whose files were removed.
#
#   mirror-sync.sh DEST                 one round (cron)
#   mirror-sync.sh --loop SECONDS DEST  rounds forever (supervisor); failures are logged and retried
#
# Environment: FLOWMESH_REPO (default wanflow-labs/flowmesh), KEEP (default 3), STAGING (default
# DEST/.staging; put it outside the web root so unchecked files are never served — it must be on the
# same file system as DEST, since a finished version is moved into place by rename).
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
  base="https://github.com/$REPO/releases"
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
  return 0
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
