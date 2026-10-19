#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the flowmesh package on a real OpenWrt (official x86-64 image, QEMU/KVM) and check it:
# service, persistence, sysupgrade keep list, firewall zone (fw3 and fw4), mesh traffic from the LAN,
# reboot, stop, removal. Exit status is the number of failed checks (0: all passed).
#
#   run.sh <openwrt-version | image.img[.gz]> <flowmesh .ipk or .apk>
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
cleanup() {
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

# --- install ---------------------------------------------------------------------------------
pkg_name=$(basename "$pkg")
if [ -f "$pkg" ] && r "cat > /tmp/$pkg_name" < "$pkg"; then
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

# --- join, settings ---------------------------------------------------------------------------
host="owt-$(tr -c 'a-z0-9\n' '-' <<< "$label")"
check "daemon got accept-dns=false from the service" eventually 30 eval '[ "$(pref accept_dns)" = false ]'
r "flowmesh up --reset --login-server=$OWT_LOGIN_SERVER --auth-key=$OWT_AUTH_KEY --hostname=$host --accept-dns=false --timeout=60s" 2>&1 | sed 's/^/   | /' | tail -5
check "joined: BackendState Running" eventually 30 backend_running

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

# --- stop, removal ---------------------------------------------------------------------------
r '/etc/init.d/flowmesh stop' >/dev/null 2>&1
check "stop: daemon gone" eventually 20 no_daemon
check "stop: no inet flowmesh table, no fm-forward chain" own_rules_absent
r '/etc/init.d/flowmesh start' >/dev/null 2>&1
eventually 30 own_rules_present

if [ $pm = opkg ]; then r 'opkg remove flowmesh'; else r 'apk del flowmesh'; fi 2>&1 | sed 's/^/   | /' | tail -5
check "removed: no daemon" eventually 20 no_daemon
check "removed: no flowmesh zone or forwardings, other zones unchanged" eval '[ "$(fw_inventory)" = "$before" ]'
check "removed: no flowmesh rules in the running firewall ($fw)" eval '
  out=$(r "nft list ruleset 2>/dev/null; iptables -S 2>/dev/null; true") && ! grep -q flowmesh0 <<< "$out" && own_rules_absent'
check "removed: init script and binaries gone" r '! test -e /etc/init.d/flowmesh && ! test -e /usr/sbin/flowmeshd && ! test -e /etc/rc.d/S95flowmesh'
check "removed: /etc/flowmesh (identity) kept" r 'test -n "$(ls -A /etc/flowmesh)"'

[ -n "$node_id" ] && $OWT_HS nodes delete -i "$node_id" --force >/dev/null 2>&1
echo "== $label: $fails failed"
exit "$fails"
