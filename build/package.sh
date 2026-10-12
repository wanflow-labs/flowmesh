#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# deb and rpm packages from the release tarballs in OUT_DIR (made by build/release.sh), with
# timestamps fixed by SOURCE_DATE_EPOCH so the packages reproduce too. The service is installed
# but not enabled (docs/install.md); state in /var/lib/flowmesh is never removed by the packages.
#   build/package.sh [OUT_DIR]   (default dist/)
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(cd "${1:-dist}" && pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export TZ=UTC LC_ALL=C
summary="Mesh networking client compatible with Tailscale control servers (flowmeshd and flowmesh)"

for arch in x86_64 aarch64; do
  case $arch in x86_64) deb_arch=amd64 ;; aarch64) deb_arch=arm64 ;; esac
  src="$out/flowmesh-$version-linux-$arch"
  [ -x "$src/flowmeshd" ] || { echo "missing $src (run build/release.sh first)"; exit 1; }

  # --- deb ---
  root=$(mktemp -d)
  install -Dm0755 "$src/flowmeshd" "$root/usr/sbin/flowmeshd"
  install -Dm0755 "$src/flowmesh" "$root/usr/bin/flowmesh"
  install -Dm0644 "$src/flowmeshd.service" "$root/lib/systemd/system/flowmeshd.service"
  install -Dm0644 "$src/flowmeshd-ssh.service" "$root/usr/share/flowmesh/flowmeshd-ssh.service"
  install -Dm0644 "$src/LICENSE" "$root/usr/share/doc/flowmesh/copyright"
  install -Dm0644 "$src/NOTICE" "$root/usr/share/doc/flowmesh/NOTICE"
  mkdir -p "$root/DEBIAN"
  cat > "$root/DEBIAN/control" <<CTL
Package: flowmesh
Version: $version
Architecture: $deb_arch
Maintainer: flowmesh maintainers
Section: net
Priority: optional
Description: $summary
 Statically linked; no dependencies. The flowmeshd service is installed but not enabled.
CTL
  cat > "$root/DEBIAN/postinst" <<'SH'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
SH
  cat > "$root/DEBIAN/prerm" <<'SH'
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then systemctl stop flowmeshd || true; fi
SH
  cat > "$root/DEBIAN/postrm" <<'SH'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
SH
  chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"
  find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  dpkg-deb --root-owner-group -Zxz --build "$root" "$out/flowmesh_${version}_${deb_arch}.deb" >/dev/null
  rm -rf "$root"

  # --- rpm ---
  top=$(mktemp -d)
  mkdir -p "$top/SOURCES" "$top/SPECS"
  cp "$src/flowmeshd" "$src/flowmesh" "$src/flowmeshd.service" "$src/flowmeshd-ssh.service" "$src/LICENSE" "$src/NOTICE" "$top/SOURCES/"
  cat > "$top/SPECS/flowmesh.spec" <<SPEC
Name: flowmesh
Version: $version
Release: 1
Summary: $summary
License: Apache-2.0
%description
Statically linked; no dependencies. The flowmeshd service is installed but not enabled.
%install
install -Dm0755 %{_sourcedir}/flowmeshd %{buildroot}/usr/sbin/flowmeshd
install -Dm0755 %{_sourcedir}/flowmesh %{buildroot}/usr/bin/flowmesh
install -Dm0644 %{_sourcedir}/flowmeshd.service %{buildroot}/usr/lib/systemd/system/flowmeshd.service
install -Dm0644 %{_sourcedir}/flowmeshd-ssh.service %{buildroot}/usr/share/flowmesh/flowmeshd-ssh.service
install -Dm0644 %{_sourcedir}/LICENSE %{buildroot}/usr/share/licenses/flowmesh/LICENSE
install -Dm0644 %{_sourcedir}/NOTICE %{buildroot}/usr/share/doc/flowmesh/NOTICE
%files
/usr/sbin/flowmeshd
/usr/bin/flowmesh
/usr/lib/systemd/system/flowmeshd.service
/usr/share/flowmesh/flowmeshd-ssh.service
%license /usr/share/licenses/flowmesh/LICENSE
%doc /usr/share/doc/flowmesh/NOTICE
%post
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
%preun
if [ \$1 -eq 0 ] && [ -d /run/systemd/system ]; then systemctl stop flowmeshd || true; fi
%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
SPEC
  rpmbuild -bb --quiet --target "$arch" \
    --define "_topdir $top" --define "_build_id_links none" \
    --define "source_date_epoch_from_changelog 0" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    --define "_buildhost reproducible" \
    --define "__strip /bin/true" --define "__brp_strip /bin/true" \
    --define "debug_package %{nil}" \
    "$top/SPECS/flowmesh.spec"
  cp "$top/RPMS/$arch/flowmesh-$version-1.$arch.rpm" "$out/"
  rm -rf "$top"
done
# Rewrites release.sh's list with the packages added: every artifact, SBOMs included.
(cd "$out" && sha256sum flowmesh-*.tar.gz *.deb *.rpm *.cdx.json */flowmeshd */flowmesh > SHA256SUMS)
cat "$out/SHA256SUMS"
