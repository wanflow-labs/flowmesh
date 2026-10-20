#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the flowmesh package on a real OpenWrt (official x86-64 image, QEMU/KVM) and check it:
# service, persistence, sysupgrade keep list, firewall zone (fw3 and fw4), mesh traffic from the LAN,
# reboot, stop, removal. Exit status is the number of failed checks (0: all passed).
#
#   run.sh <openwrt-version | image.img[.gz]> <flowmesh .ipk or .apk>
#   run.sh <openwrt-version | image.img[.gz]> <flowmesh-openwrt-feed-<v>.tar.gz or its openwrt/ dir>
#
# With a feed (build-feed.sh), the router adds it with the feed's add-feed.sh (served from this host
# over the lab LAN; FLOWMESH_FEED_BASE points it there) and installs luci-app-flowmesh from it with
# plain opkg/apk (no --force-*, no --allow-untrusted); first a copy with a tampered index and one with
# tampered packages must both be refused. Tampering with the apk index needs APK (apk-tools 3) and
# openssl on this host.
#
# Needs the lab from lab.sh (OWT_WORK, default ./owt-work, holds lab.env), KVM, qemu-system-x86_64
# and passwordless sudo (tap device, network namespaces). An OpenWrt version (e.g. 24.10.8) is
# downloaded from downloads.openwrt.org into OWT_IMG_DIR (default $OWT_WORK/img) and checked against
# the release's sha256sums. The VM's WAN is QEMU user networking (packages are installed from the
# official feeds), its LAN a tap on the lab bridge.
set -uo pipefail

[ $# -eq 2 ] || { echo "usage: run.sh <openwrt-version | image.img[.gz]> <package>" >&2; exit 100; }
target=$1
pkg=$2
OWT_WORK=$(realpath -m "${OWT_WORK:-owt-work}")
OWT_IMG_DIR=${OWT_IMG_DIR:-$OWT_WORK/img}
# shellcheck disable=SC1091
. "$OWT_WORK/lab.env" || { echo "no lab: run lab.sh up first" >&2; exit 100; }

fails=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
# check <description> <command...>: the command's exit status decides.
check() {
  local d=$1
  shift
  if "$@"; then pass "$d"; else fail "$d"; fi
}
# Retry a command for up to $1 seconds.
eventually() {
  local t=$1
  shift
  local end=$((SECONDS + t))
  while :; do
    "$@" && return 0
    [ $SECONDS -ge $end ] && return 1
    sleep 2
  done
}

SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR)
r() { ssh "${SSH_OPTS[@]}" "root@$OWT_ROUTER_LAN_IP" "$@"; }

# --- the image -------------------------------------------------------------------------------
if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  img="$OWT_IMG_DIR/openwrt-$target-x86-64-generic-ext4-combined.img.gz"
  if [ ! -f "$img" ]; then
    mkdir -p "$OWT_IMG_DIR"
    base="https://downloads.openwrt.org/releases/$target/targets/x86/64"
    curl -sfL -o "$img.part" "$base/$(basename "$img")" || { echo "download failed: $target" >&2; exit 100; }
    want=$(curl -sfL "$base/sha256sums" | awk -v f="*$(basename "$img")" '$2 == f { print $1 }')
    got=$(sha256sum "$img.part" | cut -d' ' -f1)
    [ -n "$want" ] && [ "$want" = "$got" ] || { echo "checksum mismatch for $img" >&2; rm -f "$img.part"; exit 100; }
    mv "$img.part" "$img"
  fi
else
  img=$target
fi
label=$(basename "$img" | sed 's/^openwrt-//; s/-x86-64.*//')

# --- the VM ----------------------------------------------------------------------------------
vm=$(mktemp -d "$OWT_WORK/vm.XXXXXX")
qemu_pid=
http_pid=
cleanup() {
  if [ -n "$http_pid" ]; then kill "$http_pid" 2>/dev/null; wait "$http_pid" 2>/dev/null; fi
  if [ -n "$qemu_pid" ] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid"
    for _ in $(seq 1 20); do kill -0 "$qemu_pid" 2>/dev/null || break; sleep 0.5; done
  fi
  sudo ip link del owttap0 2>/dev/null
  rm -rf "$vm"
}
trap cleanup EXIT

case "$img" in
  *.gz) gunzip -c "$img" > "$vm/disk.img" 2>/dev/null ;;   # OpenWrt images have trailing data: gzip warns
  *) cp "$img" "$vm/disk.img" ;;
esac
sudo ip tuntap add owttap0 mode tap user "$(id -un)" || exit 100
sudo ip link set owttap0 master owtbr0 up
qemu-system-x86_64 -enable-kvm -m 256 -smp 2 -display none \
  -drive "file=$vm/disk.img,format=raw,if=virtio" \
  -netdev tap,id=lan,ifname=owttap0,script=no,downscript=no -device virtio-net-pci,netdev=lan,mac=52:54:00:77:00:01 \
  -netdev user,id=wan -device virtio-net-pci,netdev=wan,mac=52:54:00:77:00:02 \
  -serial "file:$vm/serial.log" -daemonize -pidfile "$vm/qemu.pid" 2>/dev/null || exit 100
qemu_pid=$(cat "$vm/qemu.pid")
eventually 120 eval 'r true 2>/dev/null' || { echo "VM did not come up"; tail -20 "$vm/serial.log"; exit 100; }
echo "== $label: $(r '. /etc/openwrt_release; echo $DISTRIB_DESCRIPTION')"

if r 'command -v opkg' >/dev/null; then pm=opkg; else pm=apk; fi
if r 'command -v fw4' >/dev/null; then fw=fw4; else fw=fw3; fi
echo "   package manager: $pm, firewall: $fw"

# Firewall inventory, via the VM's own uci: "zone <name>" and "fwd <src>><dest>" lines, sorted.
fw_inventory() {
  r "uci -q -X show firewall" | awk '
    { i = index($0, "="); key = substr($0, 1, i - 1); val = substr($0, i + 1); gsub("\047", "", val); n = split(key, p, ".") }
    n == 2 { type[p[2]] = val; next }
    n == 3 { opt[p[2] "." p[3]] = val }
    END { for (k in opt) { split(k, q, "."); s = q[1]; o = q[2]
            if (type[s] == "zone" && o == "name") print "zone " opt[k]
            if (type[s] == "forwarding" && o == "src") print "fwd " opt[k] ">" opt[s ".dest"] } }' | sort
}
has_line() { grep -qxF "$2" <<< "$1"; }
running() { [ "$(r /etc/init.d/flowmesh status 2>/dev/null)" = running ]; }
backend_state() { r 'flowmesh status --json 2>/dev/null | jsonfilter -e @.BackendState 2>/dev/null'; }
backend_running() { [ "$(backend_state)" = Running ]; }
pref() { r "flowmesh debug prefs 2>/dev/null | jsonfilter -e '@.$1' 2>/dev/null"; }
lan_ping() { sudo ip netns exec owt-lan ping -c 2 -W 2 "$OWT_PEER_MESH_IP" >/dev/null 2>&1; }
# (Output captured first: grep -q exiting early would kill ssh with SIGPIPE, and pipefail sees that.)
fw_runtime_has_zone() {
  local out
  if [ $fw = fw4 ]; then
    out=$(r 'nft list ruleset') && grep -q '"flowmesh0"' <<< "$out"
  else
    out=$(r 'iptables -S') && grep -q -- '-i flowmesh0' <<< "$out"
  fi
}
# The daemon's own subnet-router rules: an "inet flowmesh" table (nft) or "fm-forward" chains (iptables).
# Only one of the tools exists on a given release, so the remote side always exits 0 (pipefail).
own_rules() { r 'nft list tables 2>/dev/null; iptables -S 2>/dev/null; true'; }
own_rules_present() {
  local out
  out=$(own_rules) && grep -qE 'table inet flowmesh|fm-forward' <<< "$out"
}
own_rules_absent() {
  local out
  out=$(own_rules) && ! grep -qE 'table inet flowmesh|fm-forward' <<< "$out"
}
no_daemon() { ! r 'pidof flowmeshd' >/dev/null; }

before=$(fw_inventory)

# --- install from the feed ----------------------------------------------------------------------
feed=
case "$pkg" in
  *.tar.gz) mkdir -p "$vm/feed"; tar -xzf "$pkg" -C "$vm/feed" 2>/dev/null; feed=$vm/feed/openwrt ;;
  *) [ -d "$pkg" ] && feed=$pkg ;;
esac
OWT_FEED_PORT=${OWT_FEED_PORT:-18490}
furl="http://$OWT_LAN_HOST_IP:$OWT_FEED_PORT"
# The router runs the feed's own add-feed.sh, as users do: wget -qO- <base>/add-feed.sh | sh.
add_feed() { r "wget -qO- $furl/$1/add-feed.sh | FLOWMESH_FEED_BASE=$furl/$1 sh"; }
our_installed() {
  if [ $pm = opkg ]; then r 'opkg list-installed' | grep -E '^(flowmesh|luci-app-flowmesh) '
  else r 'apk info 2>/dev/null' | grep -xE 'flowmesh|luci-app-flowmesh'; fi
}
if [ -n "$feed" ]; then
  if [ $pm = opkg ]; then fmt=ipk; feed_index=Packages; else fmt=apk; feed_index=packages.adb; fi
  check "feed has add-feed.sh and the $fmt index for x86_64" test -s "$feed/add-feed.sh" -a -s "$feed/$fmt/x86_64/$feed_index"
  # The default address must be where the download mirror publishes the feed (this test overrides it).
  check "add-feed.sh defaults to https://dl.wanflow.com/flowmesh/openwrt" \
    grep -qxF 'BASE=${FLOWMESH_FEED_BASE:-https://dl.wanflow.com/flowmesh/openwrt}' "$feed/add-feed.sh"
  www=$vm/www
  mkdir -p "$www"
  cp -a "$feed" "$www/good" 2>/dev/null; cp -a "$feed" "$www/badindex" 2>/dev/null; cp -a "$feed" "$www/badpkg" 2>/dev/null
  # badindex: opkg's Packages edited under its old signature; apk's index re-signed with a key nobody trusts.
  if [ $pm = opkg ]; then
    d=$www/badindex/ipk/x86_64
    sed -i 's/^\(Description: .*LuCI.*\)$/\1 (tampered)/' "$d/Packages" 2>/dev/null &&
      gzip -n -9 -c "$d/Packages" > "$d/Packages.gz"
  else
    d=$www/badindex/apk/x86_64
    openssl ecparam -name prime256v1 -genkey -noout -out "$vm/rogue.pem" 2>/dev/null
    mkdir -p "$vm/apkroot"
    (cd "$d" && "${APK:-apk}" mkndx --root "$vm/apkroot" --allow-untrusted --sign-key "$vm/rogue.pem" \
        --output packages.adb ./*.apk) >/dev/null 2>&1 || echo "   (could not re-sign the apk index: set APK)"
  fi
  # badpkg: the index is genuine, our packages are not the ones it lists.
  for f in "$www/badpkg/$fmt/x86_64"/*flowmesh*."$fmt"; do [ -f "$f" ] && printf 'tampered' >> "$f"; done
  python3 -m http.server "$OWT_FEED_PORT" --bind "$OWT_LAN_HOST_IP" --directory "$www" > "$vm/http.log" 2>&1 &
  http_pid=$!
  eventually 10 curl -sf -o /dev/null "$furl/good/add-feed.sh"

  check "the router can download over HTTPS (the default feed address is https)" \
    eventually 30 r 'wget -q -O /dev/null https://downloads.openwrt.org/'

  # An architecture without packages is refused, and nothing is written.
  out=$(r "cp /etc/openwrt_release /tmp/owt_release
           sed -i 's/^DISTRIB_ARCH=.*/DISTRIB_ARCH=\"mips_24kc\"/' /etc/openwrt_release
           wget -qO- $furl/good/add-feed.sh | FLOWMESH_FEED_BASE=$furl/good sh; echo \"exit=\$?\"
           cp /tmp/owt_release /etc/openwrt_release" 2>&1)
  sed 's/^/   | /' <<< "$out"
  check "add-feed.sh refuses an unsupported architecture (mips_24kc), writes no feed" eval '
    grep -q "exit=1" <<< "$out" && grep -q "mips_24kc" <<< "$out" &&
    ! r "grep -qs flowmesh /etc/opkg/customfeeds.conf || test -e /etc/apk/repositories.d/flowmesh.list"'

  # Tampered index: refused at update; nothing of ours can be installed.
  add_feed badindex > /dev/null 2>&1
  if [ $pm = opkg ]; then
    out=$(r 'opkg update 2>&1'); reject='Signature check failed'
  else
    out=$(r 'apk update 2>&1'); reject='UNTRUSTED signature'
  fi
  grep -iE 'flowmesh|signature|untrusted' <<< "$out" | head -4 | sed 's/^/   | /'
  check "tampered index is rejected by $pm update ($reject)" grep -q "$reject" <<< "$out"
  if [ $pm = opkg ]; then out=$(r 'opkg install luci-app-flowmesh 2>&1'); else out=$(r 'apk add luci-app-flowmesh 2>&1'); fi
  st=$?
  tail -2 <<< "$out" | sed 's/^/   | /'
  check "tampered index: luci-app-flowmesh cannot be installed" eval '[ $st -ne 0 ] && [ -z "$(our_installed)" ]'

  # Tampered packages under a genuine index: refused at install.
  add_feed badpkg > /dev/null 2>&1
  # (The index is accepted: the package is listed. The refusal comes at install.)
  if [ $pm = opkg ]; then
    r 'opkg update' > /dev/null 2>&1; listed=$(r 'opkg list luci-app-flowmesh'); out=$(r 'opkg install luci-app-flowmesh 2>&1')
  else
    r 'apk update' > /dev/null 2>&1; listed=$(r 'apk search luci-app-flowmesh'); out=$(r 'apk add luci-app-flowmesh 2>&1')
  fi
  st=$?
  grep -iE 'flowmesh|hash|checksum|sha256|mismatch|bad' <<< "$out" | head -4 | sed 's/^/   | /'
  check "packages that do not match the signed index are refused, nothing of ours installed" \
    eval '[ -n "$listed" ] && [ $st -ne 0 ] && [ -z "$(our_installed)" ]'

  # The genuine feed; adding it twice leaves one entry.
  add_feed good 2>&1 | sed 's/^/   | /'
  add_feed good > /dev/null 2>&1
  if [ $pm = opkg ]; then
    want="src/gz flowmesh $furl/good/ipk/x86_64"
    check "add-feed.sh twice: one feed entry in customfeeds.conf, the genuine feed" \
      eval '[ "$(r "grep \"^src/gz flowmesh \" /etc/opkg/customfeeds.conf")" = "$want" ]'
    keyline=$(sed -n 2p "$feed/keys/flowmesh-usign.pub")
    check "add-feed.sh twice: the usign key is in /etc/opkg/keys once" \
      eval '[ -n "$keyline" ] && [ "$(r "grep -rlF \"$keyline\" /etc/opkg/keys | wc -l")" = 1 ]'
  else
    want="$furl/good/apk/x86_64/packages.adb"
    check "add-feed.sh twice: one repository line in /etc/apk/repositories.d/flowmesh.list, the genuine feed" \
      eval '[ "$(r "cat /etc/apk/repositories.d/flowmesh.list")" = "$want" ]'
    check "add-feed.sh: /etc/apk/keys/flowmesh.pem is the feed's key" \
      eval '[ -s "$feed/keys/flowmesh-apk.pem" ] && [ "$(r "cat /etc/apk/keys/flowmesh.pem")" = "$(cat "$feed/keys/flowmesh-apk.pem")" ]'
  fi
  # The packages come from the feed; their dependencies from the official feeds. No --force-*,
  # no --allow-untrusted.
  if [ $pm = opkg ]; then
    r 'opkg update >/dev/null 2>&1; opkg install luci-app-flowmesh' > "$vm/install.log" 2>&1
  else
    r 'apk update >/dev/null 2>&1; apk add luci-app-flowmesh' > "$vm/install.log" 2>&1
  fi
  install_status=$?
  sed 's/^/   | /' "$vm/install.log" | tail -15
  check "luci-app-flowmesh installs from the feed (pulls in flowmesh)" [ $install_status -eq 0 ]
  check "both flowmesh and luci-app-flowmesh are installed" eval '[ "$(our_installed | wc -l)" = 2 ]'
  check "the LuCI page is in place" r 'test -f /www/luci-static/resources/view/flowmesh/overview.js'
  if [ $pm = opkg ]; then r 'opkg list-installed | grep flowmesh'; else r 'apk info -v 2>/dev/null | grep flowmesh'; fi | sed 's/^/   | installed: /'

# --- install a package file ---------------------------------------------------------------------
elif pkg_name=$(basename "$pkg") && [ -f "$pkg" ] && r "cat > /tmp/$pkg_name" < "$pkg"; then
  if [ $pm = opkg ]; then
    r "opkg update >/dev/null && opkg install /tmp/$pkg_name" > "$vm/install.log" 2>&1
  else
    r "apk update >/dev/null && apk add --allow-untrusted /tmp/$pkg_name" > "$vm/install.log" 2>&1
  fi
  install_status=$?
  sed 's/^/   | /' "$vm/install.log" | tail -15
  check "package installs" [ $install_status -eq 0 ]
else
  fail "package file $pkg exists and is uploaded"
fi

check "service is running" eventually 20 running
check "/etc/flowmesh is a directory" r 'test -d /etc/flowmesh'
check "keep.d lists the state dir and the UCI config" \
  r 'grep -qx /etc/flowmesh/ /lib/upgrade/keep.d/flowmesh && grep -qx /etc/config/flowmesh /lib/upgrade/keep.d/flowmesh'
check "flock is available (flowmesh-fw serializes with it)" r 'command -v flock >/dev/null'
check "kmod-tun and ip-full were pulled in" r 'test -e /dev/net/tun && test -x /usr/libexec/ip-full'

after=$(fw_inventory)
check "firewall: exactly one zone added, named flowmesh" eval '
  [ "$(grep -c "^zone " <<< "$after")" -eq $(( $(grep -c "^zone " <<< "$before") + 1 )) ] && has_line "$after" "zone flowmesh"'
check "firewall: forwardings lan>flowmesh and flowmesh>lan" \
  eval 'has_line "$after" "fwd lan>flowmesh" && has_line "$after" "fwd flowmesh>lan"'
check "firewall: zone is device flowmesh0, ACCEPT, no masquerading" r '
  for s in $(uci -q -X show firewall | sed -n "s/^firewall\.\([^.]*\)\.name=.flowmesh.$/\1/p"); do
    [ "$(uci -q get firewall.$s.device)" = flowmesh0 ] && [ "$(uci -q get firewall.$s.input)" = ACCEPT ] &&
    [ "$(uci -q get firewall.$s.forward)" = ACCEPT ] && [ "$(uci -q get firewall.$s.output)" = ACCEPT ] &&
    [ "$(uci -q get firewall.$s.masq)" = 0 ] && exit 0
  done; exit 1'
check "firewall ($fw): the zone is in the running ruleset" fw_runtime_has_zone
if [ $fw = fw4 ]; then
  r 'nft list ruleset' | grep -E 'flowmesh0|zone_flowmesh' | head -4 | sed 's/^/   | /'
else
  r 'iptables -S' | grep -E 'flowmesh0|zone_flowmesh' | head -4 | sed 's/^/   | /'
fi

# Changes staged (not applied) in the firewall config, e.g. by LuCI, must survive our edits.
r "uci set firewall.@defaults[0].owt_staged=1; FLOWMESH_FW_NORELOAD=1 /usr/libexec/flowmesh-fw exitnode-on; FLOWMESH_FW_NORELOAD=1 /usr/libexec/flowmesh-fw exitnode-off" >/dev/null 2>&1
check "flowmesh-fw leaves the user's staged firewall changes staged" \
  r 'test -x /usr/libexec/flowmesh-fw && uci -q changes firewall | grep -q owt_staged && ! grep -q owt_staged /etc/config/firewall'
r 'uci revert firewall' >/dev/null 2>&1

# The lock file is opened as root without truncating: a symlink planted at its path costs the
# target nothing.
r 'echo keep > /tmp/owt-victim; rm -f /var/lock/flowmesh-fw.lock; ln -s /tmp/owt-victim /var/lock/flowmesh-fw.lock
   FLOWMESH_FW_NORELOAD=1 /usr/libexec/flowmesh-fw exitnode-off' >/dev/null 2>&1
check "flowmesh-fw does not truncate a file symlinked at its lock path" \
  r 'test -x /usr/libexec/flowmesh-fw && [ "$(cat /tmp/owt-victim)" = keep ]'
r 'rm -f /var/lock/flowmesh-fw.lock /tmp/owt-victim' >/dev/null 2>&1

# Killed mid-run (SIGTERM, after the user's staged changes were set aside): they are put back. A
# slow uci in front of the real one keeps the run busy long enough.
r 'mkdir -p /tmp/owt-slow; real=$(command -v uci)
   printf "#!/bin/sh\ncase \"\$*\" in *\"show firewall\"*) sleep 4 ;; esac\nexec %s \"\$@\"\n" "$real" > /tmp/owt-slow/uci
   chmod +x /tmp/owt-slow/uci
   uci set firewall.@defaults[0].owt_staged=1
   PATH=/tmp/owt-slow:$PATH FLOWMESH_FW_NORELOAD=1 /usr/libexec/flowmesh-fw exitnode-off & p=$!
   sleep 2; kill -TERM $p; wait $p; rm -rf /tmp/owt-slow' >/dev/null 2>&1
check "flowmesh-fw killed with SIGTERM mid-run puts the user's staged firewall changes back" \
  r 'test -x /usr/libexec/flowmesh-fw && uci -q changes firewall | grep -q owt_staged'
r 'uci revert firewall' >/dev/null 2>&1

# A run stuck behind a held lock does not wait forever: it gives up after 60 s.
out=$(r 'mkfifo /tmp/owt-hold; (flock 9; read x < /tmp/owt-hold) 9<> /var/lock/flowmesh-fw.lock & sleep 1
   s=$(date +%s); FLOWMESH_FW_NORELOAD=1 /usr/libexec/flowmesh-fw exitnode-off > /tmp/owt-msg 2>&1 & p=$!
   (sleep 75; kill $p) < /dev/null > /dev/null 2>&1 & w=$!
   wait $p; rc=$?; t=$(( $(date +%s) - s )); kill $w
   echo release > /tmp/owt-hold; wait; echo "rc=$rc t=$t $(cat /tmp/owt-msg)"; rm -f /tmp/owt-hold /tmp/owt-msg' 2>&1)
sed 's/^/   | /' <<< "$out"
check "flowmesh-fw gives up on a held lock after about 60 s, with a message" eval '
  rc=$(sed -n "s/^rc=\([0-9]*\) .*/\1/p" <<< "$out"); t=$(sed -n "s/^rc=[0-9]* t=\([0-9]*\).*/\1/p" <<< "$out")
  [ -n "$rc" ] && [ "$rc" != 0 ] && [ "$t" -ge 55 ] && [ "$t" -le 70 ] && grep -qi lock <<< "$out"'

# Overlapping runs (the init's background apply, LuCI, a reload) must not interleave: from scratch,
# "add" and "exitnode-on" at the same time, five rounds, with a user change staged throughout.
race_ok=1
for _ in 1 2 3 4 5; do
  r 'uci set firewall.@defaults[0].owt_staged=1; F=/usr/libexec/flowmesh-fw; export FLOWMESH_FW_NORELOAD=1
     $F remove; $F add & $F exitnode-on & $F add & $F exitnode-on & wait' >/dev/null 2>&1
  inv=$(fw_inventory)
  [ "$(grep -cxF "zone flowmesh" <<< "$inv")" = 1 ] && [ "$(grep -cxF "fwd lan>flowmesh" <<< "$inv")" = 1 ] &&
    [ "$(grep -cxF "fwd flowmesh>lan" <<< "$inv")" = 1 ] && [ "$(grep -cxF "fwd flowmesh>wan" <<< "$inv")" = 1 ] &&
    [ "$(r 'uci -q changes firewall')" = "$(r 'uci -q changes firewall | grep owt_staged')" ] &&
    r 'uci -q changes firewall | grep -q owt_staged && ! grep -q owt_staged /etc/config/firewall' || { race_ok=0; echo "$inv" | sed 's/^/   | /'; r 'uci -q changes firewall' | sed 's/^/   | staged: /'; break; }
done
check "concurrent flowmesh-fw runs: one zone, each forwarding once, staged change kept" [ $race_ok = 1 ]
r 'uci revert firewall; F=/usr/libexec/flowmesh-fw; FLOWMESH_FW_NORELOAD=1 $F add; FLOWMESH_FW_NORELOAD=1 $F exitnode-off; /etc/init.d/firewall reload' >/dev/null 2>&1

# --- join, settings ---------------------------------------------------------------------------
host="owt-$(tr -c 'a-z0-9\n' '-' <<< "$label")"
check "daemon got accept-dns=false from the service" eventually 30 eval '[ "$(pref accept_dns)" = false ]'
# The command-line join of docs/install.md ("OpenWrt routers"), with LAN sharing switched on in the
# settings beforehand: up --reset starts from the defaults, the reload applies the settings.
r "uci set flowmesh.main.hostname=$host; uci set flowmesh.main.advertise_lan=1; uci commit flowmesh
   flowmesh up --reset --accept-dns=false --hostname=$host --login-server=$OWT_LOGIN_SERVER --auth-key=$OWT_AUTH_KEY --timeout=60s &&
   /etc/init.d/flowmesh reload" 2>&1 | sed 's/^/   | /' | tail -5
check "joined from the command line: BackendState Running" eventually 30 backend_running
check "command-line join: the reload applied the settings (LAN shared, accept-dns off)" eventually 20 eval '
  [ "$(pref hostname)" = "$host" ] && [ "$(pref "advertise_routes[0]")" = 192.168.1.0/24 ] && [ "$(pref accept_dns)" = false ]'
r "uci set flowmesh.main.advertise_lan=0; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1

pid1=$(r 'pidof flowmeshd')
r "uci set flowmesh.main.hostname=$host; uci set flowmesh.main.advertise_lan=1; uci set flowmesh.main.accept_routes=1; uci commit flowmesh; /etc/init.d/flowmesh reload" 2>&1 | sed 's/^/   | /'
check "reload does not restart the daemon" eval '[ -n "$pid1" ] && [ "$(r pidof flowmeshd)" = "$pid1" ]'
check "reload applied hostname, LAN route, accept-routes; accept-dns still off" eval '
  [ "$(pref hostname)" = "$host" ] && [ "$(pref "advertise_routes[0]")" = 192.168.1.0/24 ] &&
  [ "$(pref accept_routes)" = true ] && [ "$(pref accept_dns)" = false ]'

node_id=$($OWT_HS nodes list -o json 2>/dev/null | jq -r --arg h "$host" '.[] | select(.given_name == $h or .name == $h) | .id' | head -1)
[ -n "$node_id" ] && $OWT_HS nodes approve-routes -i "$node_id" -r 192.168.1.0/24 >/dev/null 2>&1
check "control server sees the router and its approved LAN route" \
  eventually 30 eval '[ -n "$node_id" ] && $OWT_PEER_CLI status --json | jq -e --arg h "$host" '\''(.Peer // {})[] | select(.HostName == $h) | (.PrimaryRoutes // []) | any(. == "192.168.1.0/24")'\'' >/dev/null'
check "the daemon's own forwarding rules are installed (subnet router)" eventually 20 own_rules_present
check "LAN host reaches another mesh node through the router ($fw)" eventually 45 lan_ping

r "uci set flowmesh.main.exit_node=1; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1
check "exit node on: forwarding flowmesh>wan, advertised" \
  eval 'has_line "$(fw_inventory)" "fwd flowmesh>wan" && [ "$(pref advertise_exit_node)" = true ]'
r "uci set flowmesh.main.exit_node=0; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1
check "exit node off: no forwarding flowmesh>wan" \
  eval '! has_line "$(fw_inventory)" "fwd flowmesh>wan" && [ "$(pref advertise_exit_node)" = false ]'

# --- persistence -----------------------------------------------------------------------------
sysupgrade_list=$(r 'sysupgrade -l')
check "sysupgrade -l keeps /etc/config/flowmesh" grep -qx /etc/config/flowmesh <<< "$sysupgrade_list"
check "sysupgrade -l keeps the files in /etc/flowmesh/" grep -q '^/etc/flowmesh/.' <<< "$sysupgrade_list"
echo "   sysupgrade -l (flowmesh):" $(grep flowmesh <<< "$sysupgrade_list")

r 'reboot' >/dev/null 2>&1
eventually 60 eval '! r true 2>/dev/null'
check "after reboot: back up" eventually 120 eval 'r true 2>/dev/null'
check "after reboot: Running again without the key" eventually 60 backend_running
check "after reboot: LAN host still reaches the mesh" eventually 45 lan_ping

# --- the Linux installer ---------------------------------------------------------------------
# The console's Linux install command run on the router must refuse and point to the feed, leaving
# the package's daemon alone (not replaced, no second one started).
sum_before=$(r 'md5sum /usr/sbin/flowmeshd /usr/bin/flowmesh')
pid_before=$(r 'pidof flowmeshd')
r 'cat > /tmp/install.sh' < "$(dirname "$0")/../../install.sh"
out=$(r "sh /tmp/install.sh --login-server=$OWT_LOGIN_SERVER --auth-key=$OWT_AUTH_KEY; echo \"exit=\$?\"" 2>&1)
sed 's/^/   | /' <<< "$out"
check "install.sh refuses on OpenWrt and points to add-feed.sh" \
  eval 'grep -q "^exit=1$" <<< "$out" && grep -q "add-feed.sh" <<< "$out"'
sleep 3
check "install.sh on OpenWrt: package binaries untouched, still one daemon (the service's)" eval '
  [ "$(r "md5sum /usr/sbin/flowmeshd /usr/bin/flowmesh")" = "$sum_before" ] && [ -n "$pid_before" ] &&
  [ "$(r "pidof flowmeshd")" = "$pid_before" ] && r "test ! -e /var/lib/flowmesh"'

# --- stop, removal ---------------------------------------------------------------------------
r '/etc/init.d/flowmesh stop' >/dev/null 2>&1
check "stop: daemon gone" eventually 20 no_daemon
check "stop: no inet flowmesh table, no fm-forward chain" own_rules_absent
r '/etc/init.d/flowmesh start' >/dev/null 2>&1
eventually 30 own_rules_present

ours="flowmesh"
[ -n "$feed" ] && ours="luci-app-flowmesh flowmesh"
if [ $pm = opkg ]; then r "opkg remove $ours"; else r "apk del $ours"; fi 2>&1 | sed 's/^/   | /' | tail -5
check "removed: no daemon" eventually 20 no_daemon
check "removed: no flowmesh zone or forwardings, other zones unchanged" eval '[ "$(fw_inventory)" = "$before" ]'
check "removed: no flowmesh rules in the running firewall ($fw)" eval '
  out=$(r "nft list ruleset 2>/dev/null; iptables -S 2>/dev/null; true") && ! grep -q flowmesh0 <<< "$out" && own_rules_absent'
check "removed: init script and binaries gone" r '! test -e /etc/init.d/flowmesh && ! test -e /usr/sbin/flowmeshd && ! test -e /etc/rc.d/S95flowmesh'
check "removed: /etc/flowmesh (identity) kept" r 'test -n "$(ls -A /etc/flowmesh)"'

[ -n "$node_id" ] && $OWT_HS nodes delete -i "$node_id" --force >/dev/null 2>&1
echo "== $label: $fails failed"
exit "$fails"
