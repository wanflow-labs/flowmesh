# OpenWrt package tests

`run.sh` boots an official OpenWrt x86-64 image (`generic-ext4-combined`) in QEMU/KVM, installs a
`flowmesh` package built by `../build-packages.sh` and checks it end to end: the service, the state
directory and sysupgrade keep list, the firewall zone (as fw3 or fw4 actually loads it, see below),
joining a mesh, traffic from a LAN host to another mesh node through the router, settings applied by
`reload` without a restart, a reboot (still online, no key re-entered), `stop` (no forwarding rules
left) and removal (no zone or forwardings left, other zones unchanged, identity kept).

Firewall per release: 21.02 uses fw3 (iptables); 22.03 and later use fw4 (nftables). Package manager:
opkg up to 24.10, apk from 25.12.

## Requirements

A Linux x86_64 host with `/dev/kvm`, `qemu-system-x86_64`, `jq`, `curl`, passwordless `sudo` (for the
tap device, a bridge and two network namespaces) and Internet access (the VM installs `kmod-tun`
and `ip-full` from the official package feeds through QEMU user networking).

## The lab

`lab.sh up <work_dir> <headscale_binary> <flowmesh-<v>-linux-x86_64.tar.gz>` starts:

| Part | Where |
|---|---|
| Control server: an upstream headscale release (v0.26.x), sqlite, embedded relay and STUN | `http://10.231.0.1:18480` (STUN UDP 18478) |
| A second mesh node (the plain Linux release binary), accepting subnet routes | namespace `owt-peer`, 10.231.0.2 |
| The router's LAN: bridge `owtbr0` (the host reaches the VM over SSH here) | 192.168.1.2/24 |
| A LAN client, default route via the router | namespace `owt-lan`, 192.168.1.50 |

It writes `<work_dir>/lab.env` (control server URL, a reusable pre-auth key, the peer's mesh address).
The addresses can be changed with the `OWT_*` variables at the top of `lab.sh`.
`lab.sh down <work_dir>` stops both processes (by their recorded PIDs) and removes the namespaces,
the bridge and the lab's files.

The relay is not reachable over plain HTTP, so the nodes talk directly (they share the host); that is
enough for these tests.

## Running

    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) APK=/path/to/apk \
        packaging/openwrt/build-packages.sh dist pkgs
    packaging/openwrt/test/lab.sh up owt-work /path/to/headscale dist/flowmesh-<v>-linux-x86_64.tar.gz
    for v in 21.02.7 23.05.5 24.10.8; do
        OWT_WORK=owt-work packaging/openwrt/test/run.sh $v pkgs/x86_64/flowmesh_<v>-1_x86_64.ipk
    done
    OWT_WORK=owt-work packaging/openwrt/test/run.sh 25.12.6 pkgs/x86_64/flowmesh-<v>-r1.apk
    packaging/openwrt/test/lab.sh down owt-work

The first argument is an OpenWrt release (downloaded once into `$OWT_WORK/img`, checked against the
release's `sha256sums`) or the path of an image. Each check prints `PASS` or `FAIL`; the exit status is
the number of failures. One VM runs at a time (it uses the fixed tap `owttap0` and LAN address
192.168.1.1); it is stopped and its disk deleted when `run.sh` exits.

`apk mkpkg` needs apk-tools 3. Hosts without it can build it from the upstream release that the
OpenWrt release ships (3.0.5 for 25.12): `meson setup build -Dlua=disabled -Ddocs=disabled
-Dhelp=disabled -Dpython=disabled -Dzstd=disabled && ninja -C build`, then `APK=build/src/apk`.

## The package feed

Given the feed (`build-feed.sh`) instead of a package, `run.sh` tests it the way users install:

    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) USIGN=/path/to/usign APK=/path/to/apk \
        USIGN_KEY=/path/to/usign.sec APK_KEY=/path/to/apk.key \
        packaging/openwrt/build-feed.sh pkgs dist
    for v in 21.02.7 23.05.5 24.10.8 25.12.6; do
        APK=/path/to/apk OWT_WORK=owt-work packaging/openwrt/test/run.sh $v dist/flowmesh-openwrt-feed-<v>.tar.gz
    done

It serves three copies of the feed from this host on the lab LAN (`python3 -m http.server` on
`$OWT_LAN_HOST_IP:$OWT_FEED_PORT`, default port 18490): `good`; `badindex`, whose index was tampered
with (opkg: `Packages` edited under its old signature; apk: the index re-signed with a throwaway key,
which needs `APK` and `openssl` here); and `badpkg`, a genuine index with altered packages. The
router runs the feed's own `add-feed.sh` (`wget -qO- <base>/add-feed.sh | FLOWMESH_FEED_BASE=<base> sh`).
Checks: an unsupported architecture is refused; `badindex` is rejected by `opkg update` / `apk update`
and nothing can be installed from it; `badpkg`'s packages are refused at install; `add-feed.sh` run
twice leaves one feed entry and one key; `luci-app-flowmesh` installs from `good` with plain
`opkg install` / `apk add` (no `--force-*`, no `--allow-untrusted`) and pulls in `flowmesh`; then all
the package checks above run, and removal removes both packages. The router must also be able to
download over HTTPS (the default feed address is `https://`).

`tools/build-usign.sh` and `tools/build-apk-tools.sh` build the pinned usign and apk-tools that the
release workflow uses (`build-apk-tools.sh` needs meson, ninja, pkg-config and the OpenSSL and zlib
headers).

## luci-app-flowmesh

The page's pure modules (join code parsing, status reading) are tested with node, on any machine:

    node --test packaging/openwrt/luci-app-flowmesh/tests/*.test.mjs

`tests/luci-shim.mjs` loads each module the way LuCI does (its `'require'` lines, then the source as a
factory body), providing only `baseclass`. The rpcd helper is tested on OpenWrt itself (it needs
jshn, uci and procd), in a VM with the `flowmesh` package installed:

    sh packaging/openwrt/luci-app-flowmesh/tests/helper_test.sh

`build-packages.sh` writes luci-app-flowmesh to `<out_dir>/all/` (opkg `Architecture: all`, apk
`arch: noarch`); install it next to the `flowmesh` package of the same version.
