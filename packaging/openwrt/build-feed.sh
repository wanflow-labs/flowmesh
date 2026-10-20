#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The signed OpenWrt package feed, from the output of build-packages.sh:
#   USIGN_KEY=<usign secret key> APK_KEY=<apk private key (PEM)> \
#     packaging/openwrt/build-feed.sh <pkgs_dir> <dist_dir>
# writes <dist_dir>/flowmesh-openwrt-feed-<version>.tar.gz, which unpacks to
#   openwrt/ipk/<arch>/   flowmesh and luci-app-flowmesh .ipk, Packages, Packages.gz, Packages.sig (usign)
#   openwrt/apk/<arch>/   flowmesh and luci-app-flowmesh .apk, packages.adb (signed apk-tools 3 index)
#   openwrt/add-feed.sh   the one-line installer (add-feed.sh with the arches and keys filled in)
#   openwrt/keys/         the public keys
# for every architecture in arches.txt (luci-app-flowmesh, from <pkgs_dir>/all/, is copied into each).
# The keys must be the pair of the public keys in keys/ (checked before anything is signed), and every
# index is verified against those public keys after signing. Signatures differ from run to run
# (ECDSA), so the tarball is not reproducible; the packages in it are (build-packages.sh).
# Needs GNU tar, gzip, openssl, usign (USIGN=/path; tools/build-usign.sh builds it) and apk-tools 3
# (APK=/path).
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: USIGN_KEY=... APK_KEY=... $0 <pkgs_dir> <dist_dir>" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
pkgs=$(cd "$1" && pwd)
mkdir -p "$2"
dist=$(cd "$2" && pwd)
USIGN=${USIGN:-usign}
APK=${APK:-apk}
: "${USIGN_KEY:?USIGN_KEY must name the usign secret key file}"
: "${APK_KEY:?APK_KEY must name the apk private key file (PEM)}"
usign_pub=$here/keys/flowmesh-usign.pub
apk_pub=$here/keys/flowmesh-apk.pem

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -1)
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct 2>/dev/null || true)}
case "$SOURCE_DATE_EPOCH" in
  ''|*[!0-9]*) echo "SOURCE_DATE_EPOCH must be set (got '$SOURCE_DATE_EPOCH')" >&2; exit 1 ;;
esac
export TZ=UTC LC_ALL=C
umask 022
"$APK" --version | grep -q '^apk-tools 3\.' || { echo "apk-tools 3 required (APK=$APK)" >&2; exit 1; }

# The private keys belong to the committed public keys.
[ "$("$USIGN" -F -s "$USIGN_KEY")" = "$("$USIGN" -F -p "$usign_pub")" ] ||
  { echo "USIGN_KEY is not the secret key of $usign_pub" >&2; exit 1; }
cmp -s <(openssl pkey -in "$APK_KEY" -pubout -outform DER) <(openssl pkey -pubin -in "$apk_pub" -outform DER) ||
  { echo "APK_KEY is not the private key of $apk_pub" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
feed=$work/openwrt
mkdir -p "$feed/ipk" "$feed/apk" "$feed/keys" "$work/apk-keys"
cp "$usign_pub" "$apk_pub" "$feed/keys/"
cp "$apk_pub" "$work/apk-keys/"
mkdir -p "$work/apk-root"

# opkg index: what OpenWrt's scripts/ipkg-make-index.sh writes (each package's control file, with
# Filename, Size and SHA256sum before Description), signed over the uncompressed Packages.
ipk_index() {
  local f
  for f in *.ipk; do
    tar -xzOf "$f" ./control.tar.gz | tar -xzOf - ./control |
      awk -v f="$f" -v s="$(stat -c %s "$f")" -v h="$(sha256sum "$f" | cut -d' ' -f1)" '
        /^Description:/ { print "Filename: " f; print "Size: " s; print "SHA256sum: " h }
        { print }'
    echo
  done
}

arches=()
while read -r arch _; do
  case "$arch" in ''|'#'*) continue ;; esac
  [ -d "$pkgs/$arch" ] || { echo "missing $pkgs/$arch (run build-packages.sh)" >&2; exit 1; }
  arches+=("$arch")

  d=$feed/ipk/$arch
  mkdir -p "$d"
  cp "$pkgs/$arch"/*.ipk "$pkgs/all"/*.ipk "$d/"
  (cd "$d" && ipk_index > Packages)
  gzip -n -9 -c "$d/Packages" > "$d/Packages.gz"
  "$USIGN" -S -m "$d/Packages" -s "$USIGN_KEY" -x "$d/Packages.sig"
  "$USIGN" -V -q -m "$d/Packages" -p "$usign_pub" -x "$d/Packages.sig" ||
    { echo "$d/Packages.sig does not verify" >&2; exit 1; }
  [ "$(grep -c '^Package: ' "$d/Packages")" = 2 ] || { echo "$d/Packages: expected 2 packages" >&2; exit 1; }

  d=$feed/apk/$arch
  mkdir -p "$d"
  cp "$pkgs/$arch"/*.apk "$pkgs/all"/*.apk "$d/"
  # The packages are unsigned; the signed index carries their hashes. --root: never the host's apk.
  (cd "$d" && "$APK" mkndx --root "$work/apk-root" --allow-untrusted --sign-key "$APK_KEY" \
      --output packages.adb ./*.apk > /dev/null)
  # Verify the signature with only the committed public key trusted.
  "$APK" --root "$work/apk-root" --keys-dir "$work/apk-keys" verify "$d/packages.adb" > /dev/null ||
    { echo "$d/packages.adb does not verify" >&2; exit 1; }
done < "$here/arches.txt"
[ ${#arches[@]} -gt 0 ] || { echo "no architectures in arches.txt" >&2; exit 1; }

# add-feed.sh with the architectures and the public keys filled in.
awk -v arches="${arches[*]}" -v usign_file="$usign_pub" -v apk_file="$apk_pub" '
  function cat(file,   line, out) { out = ""; while ((getline line < file) > 0) out = out (out == "" ? "" : "\n") line; close(file); return out }
  BEGIN { usign = cat(usign_file); apk = cat(apk_file) }
  { gsub(/@ARCHES@/, arches) }
  $0 == "@USIGN_KEY@" { print usign; n++; next }
  $0 == "@APK_KEY@" { print apk; n++; next }
  { print }
  END { if (n != 2) exit 1 }' "$here/add-feed.sh" > "$feed/add-feed.sh"
! grep -q '@[A-Z_]*@' "$feed/add-feed.sh" || { echo "add-feed.sh: placeholder left" >&2; exit 1; }
chmod 0755 "$feed/add-feed.sh"

out=$dist/flowmesh-openwrt-feed-$version.tar.gz
find "$feed" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
tar --format=gnu --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    -C "$work" -cf - openwrt | gzip -n -9 > "$out.tmp"
mv "$out.tmp" "$out"
echo "$out: ${#arches[@]} architectures (usign key $("$USIGN" -F -p "$usign_pub"))"
