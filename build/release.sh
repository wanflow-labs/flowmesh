#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Reproducible release build (design §6.2): static musl binaries for x86_64 and aarch64, packed into
# deterministic tarballs with SHA256SUMS. Same script in the pinned container (make release) and on a
# plain Linux host with the toolchain installed by build/setup-toolchain.sh (the second builder).
#   build/release.sh [OUT_DIR]   (default dist/)
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-dist}
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl"

# Everything that could vary between builders is fixed here.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
export RUSTFLAGS="--remap-path-prefix=$PWD=/flowmesh --remap-path-prefix=$CARGO_HOME=/cargo -C strip=symbols"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-target/release-build}
export TZ=UTC LC_ALL=C

rustc --version | grep -q '^rustc 1.88.0 ' || { echo "rustc 1.88.0 required, got: $(rustc --version)"; exit 1; }
zig version | grep -qx '0.13.0' || { echo "zig 0.13.0 required"; exit 1; }

rm -rf "$out"
mkdir -p "$out"
for t in $targets; do
  cargo zigbuild --release --locked --target "$t" -p flowmesh-daemon -p flowmesh-cli
  arch=${t%%-*}
  stage="$out/flowmesh-$version-linux-$arch"
  mkdir -p "$stage"
  cp "$CARGO_TARGET_DIR/$t/release/flowmeshd" "$CARGO_TARGET_DIR/$t/release/flowmesh" "$stage/"
  cp LICENSE NOTICE packaging/systemd/flowmeshd.service "$stage/"
  chmod 0755 "$stage/flowmeshd" "$stage/flowmesh"
  chmod 0644 "$stage/LICENSE" "$stage/NOTICE" "$stage/flowmeshd.service"
  find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -C "$out" -cf - "$(basename "$stage")" | gzip -n -9 > "$stage.tar.gz"
done
(cd "$out" && sha256sum flowmesh-*.tar.gz */flowmeshd */flowmesh > SHA256SUMS)
cat "$out/SHA256SUMS"
