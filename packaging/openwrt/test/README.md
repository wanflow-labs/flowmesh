# OpenWrt package tests

`run.sh` boots an official OpenWrt x86-64 image (`generic-ext4-combined`) in QEMU/KVM, installs a
`flowmesh` package built by `../build-packages.sh` and checks it end to end: the service, the state
directory and sysupgrade keep list, the firewall zone (as fw3 or fw4 actually loads it, see below)
and its helper's locking (no truncation through a symlink, staged changes restored on SIGTERM, a
held lock given up after 60 s), joining a mesh from the command line as `docs/install.md` describes,
traffic from a LAN host to another mesh node through the router, settings applied by `reload`
without a restart, the LAN using an exit node (below), a reboot (still online, no key re-entered), the Linux `install.sh` refusing to
run on OpenWrt, `stop` (no forwarding rules left) and removal (no zone or forwardings left, other
zones unchanged, identity kept).

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
| A second mesh node (the plain Linux release binary), accepting subnet routes, an approved exit node | namespace `owt-peer`, 10.231.0.2 |
| "The Internet" behind that exit node: an HTTP server answering with the client's address | 198.51.100.1:18492, a dummy device in `owt-peer`; blackholed on the host, so the router's uplink cannot reach it |
| The router's LAN: bridge `owtbr0` (the host reaches the VM over SSH here) | 192.168.1.2/24 |
| A LAN client, default route via the router | namespace `owt-lan`, 192.168.1.50 |
| DNS on the control server: an extra record outside the mesh suffix and a split-DNS domain | `app.owt-extra.test` -> 100.64.0.200; `corp.owt-split.test`, resolved by a small DNS server on 10.77.53.53:53 in `owt-peer`, inside 10.77.53.0/24, a subnet route the peer shares (approved), so the router reaches it through the mesh only with `accept_routes` on (10.77.0.53 for every name in it: a private answer, which only gets through dnsmasq's rebind protection because the split domain has a rebind exception); and `bad.owt-split.test` with invalid resolvers (`999.1.1.1`, `fe80::1::2`), which the watcher must skip |

It writes `<work_dir>/lab.env` (control server URL, a reusable pre-auth key, the peer's mesh address).
The addresses can be changed with the `OWT_*` variables at the top of `lab.sh`.
`lab.sh down <work_dir>` stops both processes (by their recorded PIDs) and removes the namespaces,
the bridge and the lab's files. `lab.sh peer-stop <work_dir>` stops the peer's daemon (by its PID),
`lab.sh peer-start <work_dir>` starts it again with its state and waits until it is Running: run.sh
uses them to take the exit node offline. `lab.sh hs-stop|hs-start <work_dir>` stop and start the
control server (same database): run.sh uses them to restart the router's daemon while the control
server cannot be reached.

The relay is not reachable over plain HTTP, so the nodes talk directly (they share the host); that is
enough for these tests. The router reaches the control server and the peer over the lab LAN (run.sh
adds UCI host routes, `network.owt_lab_host` and `owt_lab_peer`, via this host; lab.sh routes the peer back to 192.168.1.1):
QEMU user networking is a symmetric NAT, and without a relay the peer could not send to the router
through it, which the watcher's IP-level probe of the exit node would rightly report as offline.

## The exit node checks

With `use_exit_node` set to the peer, the LAN host's request to 198.51.100.1 must arrive from the
router's mesh address (the router translates what it forwards to the exit node), while the router's
own traffic keeps to its uplink (`ip route get`, and the same request from the router fails). The
LAN's IPv6 to the uplink must be rejected by the rule `flowmesh_exit_block_ipv6` (UCI, and in the
running fw3/fw4 ruleset): the uplink here is QEMU user networking, whose IPv6 (fec0::/64) answers
only the router itself, so what is checked is the router's ICMPv6 reject, not a missing answer. The
LAN host gets an IPv6 default route via the router's ULA address for this, and the ULA prefix is
shared and approved so that IPv6 to the peer's mesh address keeps working. Also checked: the
defaults of `kill_switch` and `lan_dns`, what `flowmesh_cli` sends, the watcher's
`exit-state.json` (`offline_fallback` keeps the exit node off on reload), `/etc/init.d/firewall
restart` and `reload` leaving the exit node working, an exit node that is not in the mesh (with the
kill switch on the rule `flowmesh_exit_kill_switch` rejects all LAN -> WAN forwarding, before and
after a working exit node; off, the LAN goes direct, probed by a TCP connection through the router to
this host's public address), and that
`stop` and package removal leave no exit routing, SNAT or IPv6 rule behind.

## The watcher

`flowmesh-watch` runs as the service's second procd instance. run.sh first runs its unit tests in the
VM (`flowmesh/tests/watch_test.sh`, a fake `flowmesh`: probe debouncing, missing exit nodes, the
consistency re-apply, the domain set, dnsmasq entries next to the user's, SIGTERM), then checks it
for real. Mesh names: with a user's own `server='/corp.example/10.0.0.53'` and `rebind_domain`
in place, dnsmasq forwards only the mesh suffix to 100.100.100.100 (with a rebind exception: the
client runs with `--accept-dns=false`, so its resolver fails every name that is not the mesh's),
the extra record is in `/tmp/hosts/flowmesh`, and the split-DNS domain goes to its own resolver (with
a rebind exception: its private answer must get through); the
LAN host resolves the peer's mesh name, the extra record (a name under it is not failed) and a name
in the split domain through the router (`dig`); nothing is reloaded while nothing changes;
`lan_dns=0`, logging out, `stop` and package removal remove the watcher's entries and hosts file
and leave the user's. Applies are serialized (`/var/lock/flowmesh-apply.lock`): reloads every
second while the watcher switches over end with the state file, the daemon and the firewall in
agreement. The exit node: the peer is stopped and started (`lab.sh peer-stop/peer-start`). Kill switch
on: `offline_blocked`, the LAN reaches neither the exit node's Internet nor the uplink, the router
keeps resolving names and its control connection, nothing is re-applied. Kill switch off: the LAN is
on the uplink within 15 s (IPv6 open, UCI unchanged, a reload keeps it there) and back on the exit
node within 15 s of the peer being Running again. Data plane dead while the exit node stays online (the peer drops what comes out of its
tunnel; its daemon and the discovery-level `flowmesh ping` keep working): the watcher, whose
probe is a discovery ping followed by an ICMP echo through the tunnel, reports `offline_blocked` within 15 s and `active`
again once the drop is lifted. ICMP from the router to the exit node filtered from the moment
it is chosen (as a mesh ACL may do): the exit node stays `active` on discovery answers (noted once
in the log) and the LAN keeps using it. Also: a chosen exit node that is not in the mesh
is reported `missing`, and a restart in that state with the kill switch off leaves the LAN on the
uplink without a reload by hand; while the exit node is refused with the kill switch on, a LAN host
trying the uplink every 0.2 s never gets through (the kill switch rule goes in before the daemon
drops the exit node). Split DNS: with `accept_routes=0` the split domain (its resolver is in the
peer's subnet route) gets no dnsmasq entry and the watcher logs why; with `accept_routes=1` it is
forwarded and resolves.

FlowMesh itself not running: the control server is stopped (`lab.sh hs-stop`) and the router's
daemon ended with SIGTERM (procd starts it again; with no control server it stays Starting, with no
map and no exit routing). Kill switch on: within 15 s the rule `flowmesh_exit_kill_switch` keeps
the LAN off the uplink, state `down_blocked`, IPv6 block kept, also after a reload; the control
server back: `active`, the rule lifted, the LAN through the exit node. The user's own Disconnect,
Reconnect, Log out and join through the LuCI helper (`flowmesh-luci down|reconnect|logout|up`; run
from a copy when only the `flowmesh` package is installed): after Disconnect and Log out the LAN uses
the uplink with neither rule, state `stopped`, also 12 s and a reload later; after Reconnect and the
join it goes through the exit node again. After the reboot check: `enabled=0` with the IPv6 block and
a kill switch rule in place, then `reboot -f` (no shutdown scripts): the router comes up with no
daemon, neither rule and the LAN on the uplink.

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

## Upgrades

With `OWT_UPGRADE_FROM` naming two older feeds, `run.sh` tests upgrading through them to the feed
given as its argument. Three builds of the same version that differ only in the package release
(`FLOWMESH_PKG_RELEASE`, default 1) are enough:

    for n in 1 2 3; do
        FLOWMESH_PKG_RELEASE=$n SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) APK=/path/to/apk \
            packaging/openwrt/build-packages.sh dist pkgs-$n
        SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) USIGN=/path/to/usign APK=/path/to/apk \
            USIGN_KEY=/path/to/usign.sec APK_KEY=/path/to/apk.key \
            packaging/openwrt/build-feed.sh pkgs-$n feed-$n
    done
    for v in 21.02.7 24.10.8 25.12.6; do
        OWT_UPGRADE_FROM="feed-1/flowmesh-openwrt-feed-<v>.tar.gz feed-2/flowmesh-openwrt-feed-<v>.tar.gz" \
            OWT_WORK=owt-work packaging/openwrt/test/run.sh $v feed-3/flowmesh-openwrt-feed-<v>.tar.gz
    done

The router installs luci-app-flowmesh from feed 1, joins with the LuCI helper and turns on LAN
sharing and the exit node under its own name. Upgraded to feed 2 (`opkg upgrade` / `apk upgrade`):
`/etc/config/flowmesh` is unchanged and in effect, the service is enabled and running on the new
binary, the node is Running with the same mesh address and the control server has no second node,
and the firewall zone and each forwarding exist once. Then the service is disabled and stopped, and
upgraded to feed 3: it stays disabled and stopped, the settings stay. Last, a sysupgrade with the
same image (settings kept): the packages are gone, `/etc/config/flowmesh` and `/etc/flowmesh/` are
not, and after `add-feed.sh` and a reinstall the node is back with the same address, no key needed.
This mode replaces the usual checks.

### From the first version

`OWT_UPGRADE_V1` names the released feed of the first version instead (the GitHub Release attachment
`flowmesh-openwrt-feed-0.1.8.tar.gz`; run.sh verifies it against `SHA256SUMS` beside it or `OWT_UPGRADE_V1_SHA256` and stops on a mismatch or when neither is given), and the feed
argument is this build's. The released feed carries the real signing keys, and its own `add-feed.sh`
imports them, so it installs the way users do, with no `--allow-untrusted`. This build's version
must sort higher than the released one: the scratch build here is `0.1.9` (the `version` in
`Cargo.toml` and the lock file, bumped in a copy of the tree; `build/release.sh` and
`build-packages.sh` derive everything from it).

    OWT_UPGRADE_V1=v0.1.8/flowmesh-openwrt-feed-0.1.8.tar.gz OWT_WORK=owt-work \
        packaging/openwrt/test/run.sh 24.10.8 feed/flowmesh-openwrt-feed-0.1.9.tar.gz

The router installs `luci-app-flowmesh` from the released feed, joins with the LuCI helper and sets
what the first version had: a name, LAN sharing with two `lan_routes`, an exit node offer and
`accept_routes`. After `opkg upgrade` / `apk upgrade`: those settings are in effect, and
`/etc/config/flowmesh` is byte for byte the user's (the package manager keeps it and puts the new
file beside it as `-opkg` / `.apk-new`); `use_exit_node` is empty and `kill_switch` and `lan_dns` are
not written; the daemon runs on the new binary under the same identity and mesh address (no second
node); no exit node is in use, and there is no exit routing, SNAT, IPv6 block or kill switch rule;
the watcher runs; the LAN host resolves the peer's mesh name through the router; the firewall zone
and forwardings exist once. Last, an exit node is set and removed on the upgraded router.

### The router's LAN address

In the normal modes, while the exit node is in use, the router's LAN moves from 192.168.1.1/24 to
192.168.5.1/24 (`uci set network.lan.ipaddr`, `ifup lan`) and back. The lab follows (a second address
on the bridge, a route in the peer, the lab routes' gateway; the LAN host takes an address in the new
subnet). The LAN host must reach the router, and table 52's throw routes must have followed, within
15 s of `ifup lan`. The lab routes the router-to-peer underlay over the LAN, so a LAN address change cuts it until the
daemon announces the new address; real deployments reach the router over the WAN or a relay. The
lab therefore restarts the service, and the checks after that run after the restart.

## luci-app-flowmesh

The page's pure modules (join code parsing, status reading) are tested with node, on any machine:

    node --test packaging/openwrt/luci-app-flowmesh/tests/*.test.mjs

`tests/luci-shim.mjs` loads each module the way LuCI does (its `'require'` lines, then the source as a
factory body), providing only `baseclass`. The rpcd helper is tested on OpenWrt itself (it needs
jshn, uci and procd), in a VM with the `flowmesh` package installed:

    sh packaging/openwrt/luci-app-flowmesh/tests/helper_test.sh

`build-packages.sh` writes luci-app-flowmesh to `<out_dir>/all/` (opkg `Architecture: all`, apk
`arch: noarch`); install it next to the `flowmesh` package of the same version.
