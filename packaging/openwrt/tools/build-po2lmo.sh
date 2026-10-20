#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds LuCI's po2lmo (translation .po -> .lmo) from upstream source pinned to the openwrt/luci
# commit that OpenWrt v25.12.6 ships (feeds.conf.default). The .lmo format is the same for LuCI in
# OpenWrt 21.02 through 25.12. Downloads six files, checks their SHA-256, compiles with cc.
#   packaging/openwrt/tools/build-po2lmo.sh <out_dir>      -> <out_dir>/po2lmo
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <out_dir>" >&2; exit 2; }
LUCI_COMMIT=75a306df84a020c57a631ef5b4c02ace56d93387   # openwrt/luci, as pinned by OpenWrt v25.12.6
base="https://raw.githubusercontent.com/openwrt/luci/$LUCI_COMMIT/modules/luci-base/src"
files=(
  "567caad86e85332a026bc502e10f3f16eb5ef8cb0a7637623217c1a1ba2111ef po2lmo.c"
  "1c42aaa581a2a9f6333bce2acd39d3651765b74f6f2513af0a3e295434b06153 lib/lmo.c"
  "0cba114fdc0588cd2d372881c1380ae4f4736043aef0d029dfa486c4dde87206 lib/lmo.h"
  "92b89b38b4076dd2ce093784ba781cbb405f3d7fa6068e05ac6ff0e4cb3bdc01 lib/plural_formula.y"
  "2db13d122c17fa204073aec232a1949714b8c8df6e150b8727557750b5848e35 contrib/lemon.c"
  "f0a1197034470e664534f49955e11be36573a76fcb3363a65bbd2abbd0f03968 contrib/lempar.c"
)
mkdir -p "$1"
out=$(cd "$1" && pwd)
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
mkdir -p "$src/lib" "$src/contrib"
for f in "${files[@]}"; do
  sum=${f%% *} path=${f#* }
  curl -fsSL --retry 3 -o "$src/$path" "$base/$path"
  echo "$sum  $src/$path" | sha256sum -c --quiet - || { echo "checksum mismatch: $path" >&2; exit 1; }
done
CC=${CC:-cc}
cd "$src"
# The steps of modules/luci-base/src/Makefile (targets contrib/lemon, lib/plural_formula.c, po2lmo).
"$CC" -std=gnu17 -o contrib/lemon contrib/lemon.c
./contrib/lemon -q lib/plural_formula.y
for c in po2lmo.c lib/lmo.c lib/plural_formula.c; do
  "$CC" -O2 -DNDEBUG -c -o "${c%.c}.o" "$c"
done
"$CC" -o "$out/po2lmo" po2lmo.o lib/lmo.o lib/plural_formula.o
echo "$out/po2lmo (openwrt/luci $LUCI_COMMIT)"
