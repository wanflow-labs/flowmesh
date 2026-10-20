#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Adds the Wanflow FlowMesh package feed to this OpenWrt router, with the key its index is signed
# with, for opkg (OpenWrt 21.02 to 24.10) or apk (OpenWrt 25.12 and later):
#
#   wget -qO- https://dl.wanflow.com/flowmesh/openwrt/add-feed.sh | sh
#
# then `opkg update && opkg install luci-app-flowmesh` (apk: `apk update && apk add luci-app-flowmesh`).
# Running it again replaces the feed entry instead of adding a second one. FLOWMESH_FEED_BASE sets
# another feed address (a mirror). The public keys are part of this script, so the feed's index is
# trusted only if it was signed by the FlowMesh release keys, wherever it is downloaded from.
#
# This file is a template: packaging/openwrt/build-feed.sh fills in the supported architectures
# (arches.txt) and the public keys (keys/) when it builds the feed.
set -eu

BASE=${FLOWMESH_FEED_BASE:-https://dl.wanflow.com/flowmesh/openwrt}
BASE=${BASE%/}
ARCHES="@ARCHES@"

die() { echo "add-feed.sh: $*" >&2; exit 1; }

[ -r /etc/openwrt_release ] || die "this is not OpenWrt (no /etc/openwrt_release)"
arch=$(. /etc/openwrt_release && echo "${DISTRIB_ARCH:-}")
[ -n "$arch" ] || die "DISTRIB_ARCH is not set in /etc/openwrt_release"
case " $ARCHES " in
	*" $arch "*) ;;
	*) die "FlowMesh has no packages for this router's architecture ($arch). Supported: $ARCHES" ;;
esac

if command -v apk >/dev/null 2>&1 && [ -d /etc/apk ]; then
	mkdir -p /etc/apk/keys /etc/apk/repositories.d
	cat > /etc/apk/keys/flowmesh.pem <<'EOF'
@APK_KEY@
EOF
	echo "$BASE/apk/$arch/packages.adb" > /etc/apk/repositories.d/flowmesh.list
	echo "FlowMesh feed added: $BASE/apk/$arch (key /etc/apk/keys/flowmesh.pem)"
	echo "Install with: apk update && apk add luci-app-flowmesh"
elif command -v opkg >/dev/null 2>&1; then
	command -v opkg-key >/dev/null 2>&1 || die "opkg-key is missing (install usign)"
	conf=/etc/opkg/customfeeds.conf
	key=$(mktemp)
	trap 'rm -f "$key" "$conf.flowmesh"' EXIT
	cat > "$key" <<'EOF'
@USIGN_KEY@
EOF
	opkg-key add "$key" >/dev/null
	[ -f "$conf" ] || : > "$conf"
	# Every other line of the file stays as it is; ours is replaced.
	{ grep -v '^src/gz flowmesh ' "$conf" || true; echo "src/gz flowmesh $BASE/ipk/$arch"; } > "$conf.flowmesh"
	cat "$conf.flowmesh" > "$conf"
	echo "FlowMesh feed added: $BASE/ipk/$arch (in $conf)"
	grep -q '^option check_signature' /etc/opkg.conf 2>/dev/null ||
		echo "Warning: option check_signature is not set in /etc/opkg.conf, so opkg verifies no feed's signature." >&2
	echo "Install with: opkg update && opkg install luci-app-flowmesh"
else
	die "neither opkg nor apk was found"
fi
