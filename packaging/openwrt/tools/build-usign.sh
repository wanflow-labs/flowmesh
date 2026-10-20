#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds OpenWrt's usign (the signature tool of opkg feeds) from upstream source pinned to the
# openwrt/usign commit that OpenWrt v25.12.6 ships (package/system/usign). Downloads its sources,
# checks their SHA-256, compiles with cc (no libubox: usign's own base64, as with -DUSE_LIBUBOX=off).
#   packaging/openwrt/tools/build-usign.sh <out_dir>      -> <out_dir>/usign
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <out_dir>" >&2; exit 2; }
USIGN_COMMIT=c4c72b1b07945ee192361dc751291a7c98d6adcd   # openwrt/usign, as pinned by OpenWrt v25.12.6
base="https://raw.githubusercontent.com/openwrt/usign/$USIGN_COMMIT"
files=(
  "7d858e8969f62e439b1d01203c0ec5779aa197790d0d7d846050d16895de80a7 main.c"
  "114ff7bf17f5eeb1a8484b31d81d4291c5155a715ef34c759d0893f12912eb9d base64.c"
  "02e026b7cf59a2a94bbd8506f1bd1792c31869361705f4d8c4b8dd4010bf5636 base64.h"
  "7b74b95da5c0ee37af3b82ad8e8c84dc327efd9d10a4375ff38ddcd87ea7ba61 ed25519.c"
  "07ee4ccf3c98d7328dd8e20f0f0ead2a645395eea6e9dcaf62a69e52fa4570e6 ed25519.h"
  "45a5d84b1dea3dfd71ba074a1fc407a68cf67b9a1699e477b63958bed85c4698 edsign.c"
  "0a2eedf7754d337222b0a0970d9f546d0be26dbf4ce93f1a45292cf877b56b6a edsign.h"
  "9998fae805cf380970e97604fe9fe1cc53199791150c502cfb807a3fea7c7f8c f25519.c"
  "3605a05785be3b4fe2c77d062f437e6ce3adac3ba8c99bfa821acf3456fdb9f2 f25519.h"
  "bceae45a016f177abe0741ac0b0deed6263b979834eded887e07f773906c43a2 fprime.c"
  "73bba26d24986e8c4fc39239ead58a35a49ad689a6a3c444f52e8f1546c58867 fprime.h"
  "866c73cbfbb3c52ac343f9a23abbca7716c8aa32d98fff490a85ed33a2411d20 sha512.c"
  "c8d8e57d7fd39f0112eaea4ca898cb9dfcd53e8537c1ac48879f8edf70567d99 sha512.h"
)
mkdir -p "$1"
out=$(cd "$1" && pwd)
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
for f in "${files[@]}"; do
  sum=${f%% *} path=${f#* }
  curl -fsSL --retry 3 -o "$src/$path" "$base/$path"
  echo "$sum  $src/$path" | sha256sum -c --quiet - || { echo "checksum mismatch: $path" >&2; exit 1; }
done
CC=${CC:-cc}
cd "$src"
# CMakeLists.txt's flags, without -Werror (newer compilers add warnings) and -g3.
"$CC" -O2 -std=gnu99 -o "$out/usign" ed25519.c edsign.c f25519.c fprime.c sha512.c main.c base64.c
echo "$out/usign (openwrt/usign $USIGN_COMMIT)"
