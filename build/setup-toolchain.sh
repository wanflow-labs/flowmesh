#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the pinned release toolchain in the current user's home (no root, nothing system-wide):
# rustup + Rust 1.88.0 with both musl targets, zig 0.13.0 (checksum-verified), cargo-zigbuild 0.19.8.
# Removing ~/.rustup, ~/.cargo and ~/.local/zig-0.13.0 undoes it.
set -euo pipefail
ZIG=0.13.0
case "$(uname -m)" in
  x86_64) zig_arch=x86_64; zig_sum=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea ;;
  aarch64) zig_arch=aarch64; zig_sum=041ac42323837eb5624068acd8b00cd5777dac4cf91179e8dad7a7e90dd0c556 ;;
  *) echo "unsupported host $(uname -m)"; exit 1 ;;
esac
if ! command -v rustup >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/rustup" ]; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
fi
export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install 1.88.0 --profile minimal \
  --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl
zig_dir="$HOME/.local/zig-$ZIG"
if [ ! -x "$zig_dir/zig" ]; then
  tmp=$(mktemp -d)
  curl -sSfL -o "$tmp/zig.tar.xz" "https://ziglang.org/download/$ZIG/zig-linux-$zig_arch-$ZIG.tar.xz"
  echo "$zig_sum  $tmp/zig.tar.xz" | sha256sum -c -
  mkdir -p "$zig_dir"
  tar -xJf "$tmp/zig.tar.xz" -C "$zig_dir" --strip-components=1
  rm -rf "$tmp"
fi
cargo +1.88.0 install cargo-zigbuild --version 0.19.8 --locked
echo "export PATH=\"$zig_dir:\$HOME/.cargo/bin:\$PATH\"  # add to the environment before build/release.sh"
