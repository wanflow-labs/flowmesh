# Reproducible builds

flowmesh release binaries can be rebuilt byte for byte from the source (design §6.2). This page says how, and records the comparisons made.

## Rebuilding

Either in the pinned container:

```
make release            # builds build/Dockerfile, then runs build/release.sh in it → dist/
make reproduce SUMS=path/to/published/SHA256SUMS
```

or on any x86_64 Linux host, with nothing installed system-wide (`release.sh` refuses other hosts, see [Host architecture](#host-architecture)):

```
build/setup-toolchain.sh        # Rust 1.88.0 + both musl targets, zig 0.13.0 (checksum-verified), cargo-zigbuild 0.19.8, in $HOME
export PATH="$HOME/.local/zig-0.13.0:$HOME/.cargo/bin:$PATH"
build/release.sh dist
```

`dist/SHA256SUMS` lists the tarballs, the four binaries and the four SBOMs.

## SBOM

Each shipped binary gets a CycloneDX 1.5 SBOM per target (`dist/flowmeshd-<version>-linux-<arch>.cdx.json`, `dist/flowmesh-…`), made by cargo-cyclonedx 0.5.9 from `Cargo.lock`: every crate compiled into that binary for that target, with version, license and package URL. It is reproducible like the binaries: its timestamp is `SOURCE_DATE_EPOCH`, it has no random serial number, and workspace crates are referenced as `path+file:///flowmesh/crates/…` whatever the build directory (`release.sh` fails if the build directory still appears).

## Signing

Releases are signed with cosign by the maintainer holding the release key; the build scripts never touch a key, and nothing here has signed anything yet. After `make release` and a second builder's `make reproduce` agree:

```
cosign sign-blob --key cosign.key --bundle dist/SHA256SUMS.bundle dist/SHA256SUMS
```

`SHA256SUMS` covers every artifact, so one signature covers the release. A user checks it with the published public key, then the files:

```
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.bundle SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Rebuilding (`make reproduce SUMS=SHA256SUMS`) checks the same file without trusting the key at all.

## What is pinned

| Input | How |
|---|---|
| Compiler | Rust 1.88.0 (`rust-toolchain.toml`, checked by `release.sh`) |
| C cross compiler for `ring` | zig 0.13.0, tarball checked against its published SHA-256 |
| Cross build driver | cargo-zigbuild 0.19.8 (`--locked`) |
| Dependencies | `Cargo.lock`, `cargo build --locked` |
| Code generation | `codegen-units = 1`, fat LTO, `strip = true`, `-C strip=symbols` |
| Paths | `--remap-path-prefix` maps the source tree to `/flowmesh` and `CARGO_HOME` to `/cargo` |
| Time | `SOURCE_DATE_EPOCH` = the last commit's time; tar entries carry it as mtime |
| Archives | tar `--sort=name`, owner/group 0 numeric, `gzip -n` (no name, no timestamp) |
| Container base | `debian:bookworm-slim` pinned by digest (only for the container builder) |

## Comparisons

### 2026-10-10, commit cb34de5 (`SOURCE_DATE_EPOCH=1791636167`)

Two builders that share nothing but the source and the pinned versions:

| | Builder A | Builder B |
|---|---|---|
| Machine | x86_64 VM (Ubuntu 24.04), bare host | Apple Silicon Mac, Docker Desktop, `linux/amd64` emulated |
| Environment | `build/setup-toolchain.sh` in `$HOME`, umask 002 | `make release` (pinned `debian:bookworm-slim` image), umask 022 |
| Source | `git archive` into `~/flowmesh-head` | the working tree, mounted at `/flowmesh` |

All ten entries of `SHA256SUMS` are identical:

```
    b23edcc455df8ed5eb9cc4b2393cc2f44b86f26bace3f2d4560e9c53fdb6bdc8  flowmesh-0.1.0-linux-aarch64.tar.gz
    aa47daffc1e954d7b80baa18c409e2850bd8a0ab64bcb648345f78919e5eb766  flowmesh-0.1.0-linux-x86_64.tar.gz
    7d3f965c59f42877473699f80018634f29682fd770aec7977a08690a99e05a20  flowmesh-0.1.0-linux-aarch64.cdx.json
    a65cf811a34c9c4e5b77360d5301d52f786a2d9612d7b82552692870819506d6  flowmesh-0.1.0-linux-x86_64.cdx.json
    15d27c7add2b18989a949ae3673ac99497db769c66608f4829c4d90f1cbec2f5  flowmeshd-0.1.0-linux-aarch64.cdx.json
    ee3346e9abf000071eb843ce3fb3abd2155c1a4769a5f0d46c2f004d0dffd3aa  flowmeshd-0.1.0-linux-x86_64.cdx.json
    3662815d7473794f37f5ff3598687e36a5315a2372a1de27a4b6742a3d1ae529  flowmesh-0.1.0-linux-aarch64/flowmeshd
    356dcd14d875a3a58d0c33225d2b7e8a65114237914fb2cce7381a96208fe8b9  flowmesh-0.1.0-linux-x86_64/flowmeshd
    8c34b6b2d957505b91ed5fc6942d7d794341ba97536d3c5fc014a12cbe981444  flowmesh-0.1.0-linux-aarch64/flowmesh
    b3b3d631b421ff53048335465b39d4d5c47ac8d64afc9ac476dd34dd2a453ec7  flowmesh-0.1.0-linux-x86_64/flowmesh
```

### What it took

The first comparisons (commit a43a0aa) failed in two ways, both fixed:

- **Directory mode in the tarballs.** Builder A's login umask (002) gave the staging directory mode 0775, the container's gave 0755: same binaries, different tarballs. `release.sh` now sets `umask 022` and chmods the directory.
- **Host architecture.** Built on an aarch64 host, every binary differed from the x86_64 builds, by 16 bytes of code and a handful of 64-bit constants. The dependency file names already differed (`libserde-5884d124…` on aarch64, `libserde-7f069d4d…` on both x86_64 builders): cargo hashes `rustc -vV`, which names the host, into each crate's metadata, and that hash reaches type ids, symbol names and then code generation. An emulated amd64 container and the bare x86_64 machine agreed byte for byte, so the host architecture is treated as a build input.

## Host architecture

Release builds run on x86_64 hosts. `release.sh` refuses any other host, and `make release` always runs the `linux/amd64` image, emulated on arm64 machines (about 30 minutes on an Apple Silicon Mac instead of 5). Both target architectures (x86_64 and aarch64 binaries) are built on that host.
