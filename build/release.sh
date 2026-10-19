#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Reproducible release build: static musl binaries packed into deterministic tarballs with SHA256SUMS.
#   flowmesh-$v-linux-{x86_64,aarch64}       servers and desktops: all features, systemd units
#   flowmesh-$v-openwrt-{x86_64,aarch64,armv7}  routers: no SSH server, size-optimised profile
# (packaging/openwrt/arches.txt maps OpenWrt architectures onto the openwrt-* families.)
# Same script in the pinned container (make release) and on a plain Linux host with the toolchain
# installed by build/setup-toolchain.sh (the second builder).
#   build/release.sh [OUT_DIR]   (default dist/)
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-dist}
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl"
# armv7 is the hard-float target: it needs VFP (VFPv3-D16 or later; NEON is detected at run time),
# so FPU-less boards are not covered and are left out of packaging/openwrt/arches.txt.
openwrt_targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf"

# Everything that could vary between builders is fixed here.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || true)}
# An empty value would not fail on its own (zig cc rejects it deep inside the build): check it here.
case "$SOURCE_DATE_EPOCH" in
  ''|*[!0-9]*) echo "SOURCE_DATE_EPOCH must be the last commit's time (got '$SOURCE_DATE_EPOCH'; no git here? pass it in)"; exit 1 ;;
esac
export CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
export RUSTFLAGS="--remap-path-prefix=$PWD=/flowmesh --remap-path-prefix=$CARGO_HOME=/cargo -C strip=symbols"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-target/release-build}
export TZ=UTC LC_ALL=C
# Modes go into the tarballs: a builder's umask (002 for many login users) must not leak in.
umask 022

# The host architecture is a build input: cargo hashes `rustc -vV` (which names the host) into every
# crate's metadata, and that changes type ids, symbol names and then code generation. Releases are
# built on x86_64 hosts; elsewhere use `make release` (linux/amd64 container, emulated).
[ "$(uname -m)" = x86_64 ] || { echo "release builds run on an x86_64 host (this is $(uname -m)): use make release"; exit 1; }
rustc --version | grep -q '^rustc 1.88.0 ' || { echo "rustc 1.88.0 required, got: $(rustc --version)"; exit 1; }
zig version | grep -qx '0.13.0' || { echo "zig 0.13.0 required"; exit 1; }
cargo cyclonedx --version | grep -qx 'cargo-cyclonedx-cyclonedx 0.5.9' || { echo "cargo-cyclonedx 0.5.9 required"; exit 1; }

rm -rf "$out"
mkdir -p "$out"
for t in $targets; do
  cargo zigbuild --release --locked --target "$t" -p flowmesh-daemon -p flowmesh-cli
  arch=${t%%-*}
  stage="$out/flowmesh-$version-linux-$arch"
  mkdir -p "$stage"
  cp "$CARGO_TARGET_DIR/$t/release/flowmeshd" "$CARGO_TARGET_DIR/$t/release/flowmesh" "$stage/"
  cp LICENSE NOTICE packaging/systemd/flowmeshd.service packaging/systemd/flowmeshd-ssh.service "$stage/"
  chmod 0755 "$stage" "$stage/flowmeshd" "$stage/flowmesh"
  chmod 0644 "$stage/LICENSE" "$stage/NOTICE" "$stage/flowmeshd.service" "$stage/flowmeshd-ssh.service"
  find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -C "$out" -cf - "$(basename "$stage")" | gzip -n -9 > "$stage.tar.gz"

  # SBOM (CycloneDX 1.5) for each shipped binary. cargo-cyclonedx writes one file per workspace binary
  # next to its Cargo.toml; keep the two we ship and drop the rest. Its timestamp follows
  # SOURCE_DATE_EPOCH; workspace crates are referenced by absolute path, mapped to /flowmesh like the
  # binaries' --remap-path-prefix.
  cargo cyclonedx -q -f json --spec-version 1.5 --describe binaries --target "$t"
  for b in flowmeshd flowmesh; do
    f=$(find crates -name "${b}_bin.cdx.json")
    sed "s|path+file://$PWD/|path+file:///flowmesh/|g" "$f" > "$out/$b-$version-linux-$arch.cdx.json"
  done
  # Every workspace member gets one (xtask too, outside crates/): clean them all, not the output.
  find . -path ./target -prune -o -path "./$out" -prune -o -name '*_bin.cdx.json' -type f -print0 | xargs -0 rm -f
done
# Router builds, separate from the linux-* set above (whose bytes must not change): no default
# features (no SSH server), the size-optimised release-openwrt profile, no systemd units.
for t in $openwrt_targets; do
  cargo zigbuild --profile release-openwrt --locked --no-default-features --target "$t" -p flowmesh-daemon -p flowmesh-cli
  arch=${t%%-*}
  stage="$out/flowmesh-$version-openwrt-$arch"
  mkdir -p "$stage"
  cp "$CARGO_TARGET_DIR/$t/release-openwrt/flowmeshd" "$CARGO_TARGET_DIR/$t/release-openwrt/flowmesh" "$stage/"
  cp LICENSE NOTICE "$stage/"
  chmod 0755 "$stage" "$stage/flowmeshd" "$stage/flowmesh"
  chmod 0644 "$stage/LICENSE" "$stage/NOTICE"
  find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -C "$out" -cf - "$(basename "$stage")" | gzip -n -9 > "$stage.tar.gz"

  # Same SBOM step, with the same feature selection as the binaries (no SSH dependencies).
  cargo cyclonedx -q -f json --spec-version 1.5 --describe binaries --no-default-features --target "$t"
  for b in flowmeshd flowmesh; do
    f=$(find crates -name "${b}_bin.cdx.json")
    sed "s|path+file://$PWD/|path+file:///flowmesh/|g" "$f" > "$out/$b-$version-openwrt-$arch.cdx.json"
  done
  find . -path ./target -prune -o -path "./$out" -prune -o -name '*_bin.cdx.json' -type f -print0 | xargs -0 rm -f
done
# Every workspace reference must be the mapped one (the build directory may itself be /flowmesh).
if grep -ho 'path+file://[^"#]*' "$out"/*.cdx.json | grep -v '^path+file:///flowmesh/'; then
  echo "SBOM names the build directory"; exit 1
fi
(cd "$out" && sha256sum flowmesh-*.tar.gz *.cdx.json */flowmeshd */flowmesh > SHA256SUMS)
cat "$out/SHA256SUMS"
