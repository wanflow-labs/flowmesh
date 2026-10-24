#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the flowmesh package on a real OpenWrt (official x86-64 image, QEMU/KVM) and check it:
# service, persistence, sysupgrade keep list, firewall zone (fw3 and fw4), mesh traffic from the LAN,
# the LAN using an exit node (and its IPv6 block), reboot, stop, removal. Exit status is the number of failed checks (0: all passed).
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
  sudo ip netns exec owt-lan ip -6 route del default 2>/dev/null
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
LAB="$(dirname "$0")/lab.sh"
# The watcher (second procd instance of the service): running, with respawn.
watcher_running() {
  local out
  out=$(r "ubus call service list '{\"name\":\"flowmesh\"}'") &&
    jq -e '.flowmesh.instances.watch | .running == true and .respawn != null and
      (.command | any(. == "/usr/libexec/flowmesh-watch"))' <<< "$out" >/dev/null
}
exit_state() { r 'jsonfilter -i /var/run/flowmesh/exit-state.json -e @.state 2>/dev/null'; }
# dnsmasq's UCI lists (first dnsmasq section), one value per line.
dns_list() { r "uci -q -d '
' get dhcp.@dnsmasq[0].$1"; }
dns_has() { dns_list "$1" | grep -qxF "$2"; }
dns_count() { dns_list "$1" | grep -cxF "$2"; }
# Ours: the suffix forwarded to FlowMesh's resolver, the split domain to its resolver, the owned
# list and the hosts file with the extra records.
ours_absent() {
  ! dns_list server | grep -qE "/100\.100\.100\.100\$|^/$OWT_SPLIT_DOMAIN/" && ! dns_has rebind_domain "$OWT_SPLIT_DOMAIN" &&
    r '! test -e /etc/flowmesh/lan-dns.owned && ! test -e /tmp/hosts/flowmesh'
}
# The user's own entries (set below): there, once each.
user_dns_kept() {
  [ "$(dns_count server /corp.example/10.0.0.53)" = 1 ] && [ "$(dns_count rebind_domain corp.example)" = 1 ]
}
# A LAN host asks the router (dnsmasq) for name $1 and gets address $2.
lan_resolves() { sudo ip netns exec owt-lan dig +short +time=2 +tries=1 @"$OWT_ROUTER_LAN_IP" "$1" A 2>/dev/null | grep -qxF "$2"; }
# The DNS status code the LAN host gets for name $1 (NOERROR, NXDOMAIN, SERVFAIL...).
lan_rcode() { sudo ip netns exec owt-lan dig +time=3 +tries=1 @"$OWT_ROUTER_LAN_IP" "$1" A 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p'; }

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

# --- upgrade (OWT_UPGRADE_FROM) -----------------------------------------------------------------
# OWT_UPGRADE_FROM="<feed 1> <feed 2>": older builds of the feed given as the package argument
# (feed 3), e.g. the same version with package releases 1, 2 and 3. The router installs
# luci-app-flowmesh from feed 1, joins through the LuCI helper and changes its settings, then:
# upgrades to feed 2 (settings, identity, firewall zone kept; daemon restarted on the new binary),
# is disabled and stopped by the user and upgraded to feed 3 (stays disabled and stopped), and finally
# goes through a sysupgrade with the same image and a reinstall from the feed (rejoins with its kept
# identity, no key).
if [ -n "${OWT_UPGRADE_FROM:-}" ]; then
  [ -n "$feed" ] || { echo "OWT_UPGRADE_FROM needs a feed as the package argument" >&2; exit 100; }
  if [ $pm = opkg ]; then fmt=ipk; else fmt=apk; fi
  www=$vm/www
  mkdir -p "$www"
  n=0
  for f in $OWT_UPGRADE_FROM "$feed"; do
    n=$((n + 1))
    case "$f" in
      *.tar.gz) mkdir -p "$vm/u$n"; tar -xzf "$f" -C "$vm/u$n" && mv "$vm/u$n/openwrt" "$www/feed$n" ;;
      *) cp -a "$f" "$www/feed$n" ;;
    esac
  done
  [ $n = 3 ] || { echo "OWT_UPGRADE_FROM must name two feeds" >&2; exit 100; }
  python3 -m http.server "$OWT_FEED_PORT" --bind "$OWT_LAN_HOST_IP" --directory "$www" > "$vm/http.log" 2>&1 &
  http_pid=$!
  eventually 10 curl -sf -o /dev/null "$furl/feed1/add-feed.sh"

  # What the package manager lists once feed $1's packages are installed, from their file names.
  want_installed() {
    local f b out=
    for f in "$www/$1/$fmt/x86_64"/*flowmesh*."$fmt"; do
      b=$(basename "$f" ".$fmt")
      if [ $fmt = ipk ]; then b=$(sed 's/^\([^_]*\)_\([^_]*\)_.*/\1 - \2/' <<< "$b"); fi
      out="$out$b"$'\n'
    done
    sort <<< "$out" | sed '/^$/d'
  }
  installed_versions() {
    if [ $pm = opkg ]; then r 'opkg list-installed' | grep -E '^(flowmesh|luci-app-flowmesh) '
    else r 'apk info -v 2>/dev/null' | grep -E '^(flowmesh|luci-app-flowmesh)-[0-9]'; fi | sort
  }
  feed_update() { add_feed "$1" > /dev/null 2>&1 && r "$pm update" > /dev/null 2>&1; }
  mesh_ip() { r 'flowmesh status --json 2>/dev/null | jsonfilter -e "@.Self.TailscaleIPs[0]"'; }
  nodes_named() { $OWT_HS nodes list -o json 2>/dev/null | jq --arg h "$1" '[.[] | select(.given_name == $h or .name == $h)] | length'; }
  enabled() { r '/etc/init.d/flowmesh enabled'; }
  on_new_binary() {
    local pid
    pid=$(r 'pidof flowmeshd') && [ -n "$pid" ] && [ "$pid" != "$1" ] &&
      ! r "readlink /proc/$pid/exe" | grep -q deleted
  }
  fw_once() {
    local inv
    inv=$(fw_inventory)
    [ "$(grep -cxF "zone flowmesh" <<< "$inv")" = 1 ] && [ "$(grep -cxF "fwd lan>flowmesh" <<< "$inv")" = 1 ] &&
      [ "$(grep -cxF "fwd flowmesh>lan" <<< "$inv")" = 1 ] && [ "$(grep -cxF "fwd flowmesh>wan" <<< "$inv")" = 1 ]
  }
  settings_kept() {
    [ "$(r 'cat /etc/config/flowmesh')" = "$cfg" ] && [ "$(pref hostname)" = "$host" ] &&
      [ "$(pref "advertise_routes[0]")" = 192.168.1.0/24 ] && [ "$(pref advertise_exit_node)" = true ] &&
      [ "$(pref accept_dns)" = false ]
  }
  same_node() { backend_running && [ "$(mesh_ip)" = "$ip0" ] && [ "$(nodes_named "$host")" = 1 ]; }

  # Release 1, joined and configured. (Dependencies come from the official feeds: WAN up first.)
  eventually 60 r 'wget -q -O /dev/null https://downloads.openwrt.org/' 2>/dev/null
  feed_update feed1
  r "$pm $([ $pm = opkg ] && echo install || echo add) luci-app-flowmesh" > "$vm/install.log" 2>&1
  check "upgrade: feed 1 installs ($(want_installed feed1 | tr '\n' ' '))" \
    eval '[ "$(installed_versions)" = "$(want_installed feed1)" ]'
  check "upgrade: service running" eventually 20 running
  host="owt-up-$(tr -c 'a-z0-9\n' '-' <<< "$label")"
  out=$(r "/usr/libexec/flowmesh-luci up $OWT_LOGIN_SERVER $OWT_AUTH_KEY $host" 2>&1)
  sed 's/^/   | /' <<< "$out"
  check "upgrade: joined with the LuCI helper (flowmesh-luci up <server> <key> <name>)" \
    eval 'grep -q "\"ok\": *true" <<< "$out" && eventually 30 backend_running'
  r "uci set flowmesh.main.advertise_lan=1; uci set flowmesh.main.exit_node=1; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1
  cfg=$(r 'cat /etc/config/flowmesh')
  ip0=$(mesh_ip)
  sed 's/^/   | /' <<< "$cfg"
  check "upgrade: settings applied (name $host, LAN shared, exit node), mesh address $ip0" \
    eval 'eventually 20 settings_kept && [ -n "$ip0" ] && fw_once'

  # Release 2, service enabled and running.
  pid1=$(r 'pidof flowmeshd')
  feed_update feed2
  if [ $pm = opkg ]; then up_cmd='opkg upgrade flowmesh luci-app-flowmesh'; else up_cmd='apk upgrade flowmesh luci-app-flowmesh'; fi
  r "$up_cmd" > "$vm/upgrade.log" 2>&1
  st=$?
  sed 's/^/   | /' "$vm/upgrade.log" | tail -8
  check "upgrade to feed 2: $up_cmd succeeds ($(want_installed feed2 | tr '\n' ' '))" \
    eval '[ $st -eq 0 ] && [ "$(installed_versions)" = "$(want_installed feed2)" ]'
  r 'ls /etc/config/ | grep flowmesh' | sed 's/^/   | \/etc\/config: /'
  check "upgrade to feed 2: /etc/config/flowmesh unchanged, settings in effect" eventually 20 settings_kept
  check "upgrade to feed 2: service still enabled and running" eval 'enabled && eventually 20 running'
  check "upgrade to feed 2: daemon restarted on the new binary" eventually 20 on_new_binary "$pid1"
  check "upgrade to feed 2: Running with the same mesh address, no second node" eventually 60 same_node
  check "upgrade to feed 2: firewall zone and forwardings once each" fw_once

  # Release 3, after the user disabled and stopped the service.
  r '/etc/init.d/flowmesh disable; /etc/init.d/flowmesh stop' >/dev/null 2>&1
  eventually 20 no_daemon
  feed_update feed3
  r "$up_cmd" > "$vm/upgrade.log" 2>&1
  st=$?
  sed 's/^/   | /' "$vm/upgrade.log" | tail -8
  check "upgrade to feed 3 (service disabled): succeeds ($(want_installed feed3 | tr '\n' ' '))" \
    eval '[ $st -eq 0 ] && [ "$(installed_versions)" = "$(want_installed feed3)" ]'
  check "upgrade to feed 3: the disabled service stays disabled and stopped" eval '! enabled && sleep 5 && no_daemon'
  check "upgrade to feed 3: /etc/config/flowmesh unchanged" eval '[ "$(r "cat /etc/config/flowmesh")" = "$cfg" ]'
  r '/etc/init.d/flowmesh enable; /etc/init.d/flowmesh start' >/dev/null 2>&1
  check "upgrade to feed 3: started again, Running with the same mesh address" eventually 60 same_node

  # Firmware sysupgrade with the same image (configuration kept): our packages are gone, the
  # settings and identity are not; reinstalling from the feed brings the node back without a key.
  img_name=fw.img
  case "$img" in *.gz) img_name=fw.img.gz ;; esac
  r "cat > /tmp/$img_name" < "$img"
  # (The router drops the session as it goes down; do not wait for ssh to notice.)
  timeout 60 ssh "${SSH_OPTS[@]}" "root@$OWT_ROUTER_LAN_IP" "sysupgrade /tmp/$img_name" > "$vm/sysupgrade.log" 2>&1
  tail -3 "$vm/sysupgrade.log" | sed 's/^/   | /'
  eventually 90 eval '! r true 2>/dev/null'
  check "sysupgrade: back up" eventually 180 eval 'r true 2>/dev/null'
  check "sysupgrade: our packages are gone, /etc/config/flowmesh and /etc/flowmesh/ kept" eval '
    [ -z "$(our_installed)" ] && [ "$(r "cat /etc/config/flowmesh")" = "$cfg" ] && r "test -n \"\$(ls -A /etc/flowmesh)\""'
  r 'grep -s flowmesh /etc/opkg/customfeeds.conf; cat /etc/apk/repositories.d/flowmesh.list 2>/dev/null; true' |
    sed 's/^/   | feed entry after sysupgrade: /'
  eventually 60 r 'wget -q -O /dev/null https://downloads.openwrt.org/' 2>/dev/null
  feed_update feed3
  r "$pm $([ $pm = opkg ] && echo install || echo add) luci-app-flowmesh" > "$vm/install.log" 2>&1
  check "sysupgrade: luci-app-flowmesh reinstalls from the feed" eval '[ "$(installed_versions)" = "$(want_installed feed3)" ]'
  check "sysupgrade: Running with the same mesh address, no key, no second node" eventually 60 same_node
  check "sysupgrade: settings in effect, firewall zone once, enabled" eval 'settings_kept && fw_once && enabled'

  node_id=$($OWT_HS nodes list -o json 2>/dev/null | jq -r --arg h "$host" '.[] | select(.given_name == $h or .name == $h) | .id' | head -1)
  [ -n "$node_id" ] && $OWT_HS nodes delete -i "$node_id" --force >/dev/null 2>&1
  echo "== $label (upgrade): $fails failed"
  exit "$fails"
fi

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
  # (Dependencies come from the official feeds: wait until the WAN is up after boot.)
  eventually 60 r 'wget -q -O /dev/null https://downloads.openwrt.org/' 2>/dev/null
  # (The feed index download now and then fails right after boot: retried.)
  if [ $pm = opkg ]; then
    r "for i in 1 2 3; do opkg update >/dev/null 2>&1 && break; sleep 5; done; opkg install /tmp/$pkg_name" > "$vm/install.log" 2>&1
  else
    r "for i in 1 2 3; do apk update >/dev/null 2>&1 && break; sleep 5; done; apk add --allow-untrusted /tmp/$pkg_name" > "$vm/install.log" 2>&1
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

# The watcher's own tests (a fake flowmesh), with this release's BusyBox, jsonfilter and uci.
tar -C "$(dirname "$0")/../flowmesh" -cf - files tests | r 'rm -rf /tmp/owt-watch; mkdir -p /tmp/owt-watch; tar -xf - -C /tmp/owt-watch'
out=$(r 'sh /tmp/owt-watch/tests/watch_test.sh 2>&1; echo "exit=$?"; rm -rf /tmp/owt-watch')
grep -E '^FAIL|^      ' <<< "$out" | sed 's/^/   | /'
check "flowmesh-watch unit tests (flowmesh/tests/watch_test.sh): $(grep -c '^PASS' <<< "$out") passed, none failed" \
  grep -qx 'exit=0' <<< "$out"

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
r 'F=/usr/libexec/flowmesh-fw; export FLOWMESH_FW_NORELOAD=1; $F exit-v6-block-on exit-kill-on exit-kill-on' >/dev/null 2>&1
check "flowmesh-fw exit-v6-block-on exit-kill-on: one rule each" eval '
  [ "$(r "uci -q -X show firewall" | grep -cE "\.name=.flowmesh_exit_(block_ipv6|kill_switch).$")" = 2 ]'
r 'FLOWMESH_FW_NORELOAD=1 /usr/libexec/flowmesh-fw remove' >/dev/null 2>&1
check "flowmesh-fw remove: the exit rules go with the zone" eval '! r "uci -q -X show firewall" | grep -q flowmesh_exit_'
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

# --- mesh names for the LAN (the watcher) -------------------------------------------------------
# lan_dns is on when unset. The router's client runs with --accept-dns=false, so FlowMesh's resolver
# answers only the mesh's own names: only the suffix is forwarded there (with a rebind_domain
# exception); the console's extra record (outside the suffix, lab.sh) goes into dnsmasq's hosts
# directory (/tmp/hosts/flowmesh); the split-DNS domain is forwarded to its own resolver (in
# owt-peer, lab.sh). The user's own entries (one forwarding and one exception, set here) must be left
# alone through all of it, and survive removal.
r "uci add_list dhcp.@dnsmasq[0].server=/corp.example/10.0.0.53; uci add_list dhcp.@dnsmasq[0].rebind_domain=corp.example
   uci commit dhcp; /etc/init.d/dnsmasq reload" >/dev/null 2>&1
suffix=$(r 'flowmesh dns status --json | jsonfilter -e @.suffix')
peer_name="owt-peer.$suffix"
check "watcher: a second instance of the service, with respawn" watcher_running
ours_present() {
  dns_has server "/$suffix/100.100.100.100" && dns_has rebind_domain "$suffix" &&
    dns_has server "/$OWT_SPLIT_DOMAIN/$OWT_PEER_IP" && dns_has rebind_domain "$OWT_SPLIT_DOMAIN" &&
    r "grep -qxF '$OWT_EXTRA_IP $OWT_EXTRA_NAME' /tmp/hosts/flowmesh"
}
check "dnsmasq reads the hosts directory /tmp/hosts (OpenWrt's default addn-hosts)" \
  r 'grep -qx "addn-hosts=/tmp/hosts" /var/etc/dnsmasq.conf*'
check "LAN names: $suffix to 100.100.100.100, $OWT_SPLIT_DOMAIN to its resolver $OWT_PEER_IP, both with rebind exceptions; $OWT_EXTRA_NAME in /tmp/hosts/flowmesh" \
  eventually 30 ours_present
dns_list server | sed 's/^/   | server: /'
dns_list rebind_domain | sed 's/^/   | rebind_domain: /'
r 'cat /tmp/hosts/flowmesh' | sed 's/^/   | \/tmp\/hosts\/flowmesh: /'
check "LAN names: nothing else forwarded to 100.100.100.100, no entry for the extra record (hosts file only), the user's entries untouched" eval '
  [ "$(dns_list server | grep -c "/100\.100\.100\.100$")" = 1 ] &&
  ! dns_has rebind_domain "$OWT_EXTRA_NAME" && ! dns_list server | grep -q "^/$OWT_EXTRA_NAME/" && user_dns_kept'
check "LAN host resolves $peer_name through the router: $OWT_PEER_MESH_IP" eventually 20 lan_resolves "$peer_name" "$OWT_PEER_MESH_IP"
check "LAN host resolves the console's extra record $OWT_EXTRA_NAME: $OWT_EXTRA_IP" eventually 20 lan_resolves "$OWT_EXTRA_NAME" "$OWT_EXTRA_IP"
rc=$(lan_rcode "sub.$OWT_EXTRA_NAME")
check "  ... a name under it is not failed by FlowMesh's resolver: it goes to the normal DNS ($rc)" eval '[ -n "$rc" ] && [ "$rc" != SERVFAIL ]'
check "LAN host resolves host.$OWT_SPLIT_DOMAIN through the split domain's resolver: $OWT_SPLIT_ANSWER (private: the exception works)" \
  eventually 20 lan_resolves "host.$OWT_SPLIT_DOMAIN" "$OWT_SPLIT_ANSWER"
# (dnsmasq 2.90 and later, OpenWrt 24.10 on, discard mesh addresses as a rebind without the
# rebind_domain exceptions, and log it.)
check "dnsmasq did not discard a mesh or split-domain answer as a DNS rebind" eval '! r "logread" | grep -q "DNS-rebind attack detected: .*\($suffix\|$OWT_EXTRA_NAME\|$OWT_SPLIT_DOMAIN\)"'
# Nothing changes: neither dnsmasq nor the settings are reloaded again.
logs_count() { r "logread | grep -c '$1'"; }
n_dns=$(logs_count 'LAN names updated'); n_apply=$(logs_count 're-applying the settings')
sleep 25
check "watcher, nothing changing for 25 s: no dnsmasq reload, nothing re-applied" eval '
  [ "$(logs_count "LAN names updated")" = "$n_dns" ] && [ "$(logs_count "re-applying the settings")" = "$n_apply" ]'
r 'uci set flowmesh.main.lan_dns=0; uci commit flowmesh; /etc/init.d/flowmesh reload' >/dev/null 2>&1
check "lan_dns=0: our entries and hosts file removed, the user's kept, the LAN no longer resolves $peer_name or $OWT_EXTRA_NAME" eventually 20 eval '
  ours_absent && user_dns_kept && ! lan_resolves "$peer_name" "$OWT_PEER_MESH_IP" && ! lan_resolves "$OWT_EXTRA_NAME" "$OWT_EXTRA_IP"'
r 'uci delete flowmesh.main.lan_dns; uci commit flowmesh; /etc/init.d/flowmesh reload' >/dev/null 2>&1
check "lan_dns unset again (on): entries back, resolves" eventually 30 eval 'ours_present && lan_resolves "$peer_name" "$OWT_PEER_MESH_IP"'
r 'flowmesh logout' >/dev/null 2>&1
check "logged out: our entries removed, the user's kept" eventually 20 eval 'ours_absent && user_dns_kept'
r "flowmesh up --reset --accept-dns=false --hostname=$host --login-server=$OWT_LOGIN_SERVER --auth-key=$OWT_AUTH_KEY --timeout=60s &&
   /etc/init.d/flowmesh reload" >/dev/null 2>&1
# (Should the control server have made it a new node, its LAN route is approved again.)
node_id=$($OWT_HS nodes list -o json 2>/dev/null | jq -r --arg h "$host" '[.[] | select(.given_name == $h or .name == $h)] | max_by(.id | tonumber) | .id')
[ -n "$node_id" ] && $OWT_HS nodes approve-routes -i "$node_id" -r 192.168.1.0/24 >/dev/null 2>&1
check "logged in again: Running, the LAN reaches the mesh, entries back" eventually 45 eval '
  backend_running && lan_ping && ours_present && user_dns_kept'

r "uci set flowmesh.main.exit_node=1; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1
check "exit node on: forwarding flowmesh>wan, advertised" \
  eval 'has_line "$(fw_inventory)" "fwd flowmesh>wan" && [ "$(pref advertise_exit_node)" = true ]'
r "uci set flowmesh.main.exit_node=0; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1
check "exit node off: no forwarding flowmesh>wan" \
  eval '! has_line "$(fw_inventory)" "fwd flowmesh>wan" && [ "$(pref advertise_exit_node)" = false ]'

# --- using an exit node ----------------------------------------------------------------------
# The peer is an approved exit node (lab.sh), with an "Internet" address behind it that answers with
# the source it sees. The LAN host goes there through the router; the router itself does not.
# IPv6: the lab's uplink (QEMU user networking, fec0::/64) answers only the router itself, so the
# LAN host's IPv6 to it never gets an answer; what shows the block is the router's reject.
# (CURL_T, LAN4_T: shorter timeouts where a switch-over is timed.)
inet_from_lan() { sudo ip netns exec owt-lan curl -s -m "${CURL_T:-4}" "http://$OWT_INET_IP:$OWT_INET_PORT/" 2>/dev/null; }
via_exit() { [ -n "$rip" ] && [ "$(inet_from_lan)" = "$rip" ]; }
not_via_exit() {
  local o
  o=$(inet_from_lan)
  [ -z "$o" ] && return 0
  echo "   | the Internet behind the peer saw the LAN host as $o; the router routes it:" \
    "$(r "ip route get $OWT_INET_IP from $OWT_LAN_CLIENT_IP iif br-lan" 2>&1 | head -1)"
  return 1
}
router_not_via_exit() {
  ! r "ip route get $OWT_INET_IP" | grep -q flowmesh0 &&
    ! r "wget -q -T 4 -O - http://$OWT_INET_IP:$OWT_INET_PORT/" >/dev/null 2>&1
}
policy() { r 'ip -4 rule; ip -6 rule; ip -4 route show table 52; ip -6 route show table 52; true' 2>/dev/null; }
exit_rules_in_place() {
  local out
  out=$(policy) && grep -qE '^5260:.*iif lo' <<< "$out" && grep -qE '^5270:' <<< "$out"
}
no_exit_rules() {
  local out
  out=$(policy) && ! grep -qE '^52[1-7]0:|flowmesh0|throw' <<< "$out"
}
snat_rules() { r 'nft list tables 2>/dev/null; iptables -t nat -S 2>/dev/null; true'; }
exit_snat_absent() {
  local out
  out=$(snat_rules) && ! grep -qE 'table ip flowmesh_exit|fm-exit-snat' <<< "$out"
}
v6_block_uci() { r 'uci -q -X show firewall' | grep -q "\.name='flowmesh_exit_block_ipv6'$"; }
v6_block_runtime() {
  local out
  if [ $fw = fw4 ]; then out=$(r 'nft list ruleset'); else out=$(r 'ip6tables -S'); fi &&
    grep -q flowmesh_exit_block_ipv6 <<< "$out"
}
v6_blocked() { v6_block_uci && v6_block_runtime; }
v6_open() { ! v6_block_uci && ! v6_block_runtime; }
# The router rejects the LAN host's IPv6 to the uplink (an ICMPv6 error at once, not a timeout).
# (Port unreachable is what fw3 and fw4 reject with; other ICMPv6 errors, e.g. "address
# unreachable" when the LAN host has no usable source address, are not the rule's.)
lan6_rejected() {
  local out
  out=$(sudo ip netns exec owt-lan ping -6 -c 1 -W 3 fec0::2 2>&1)
  grep -qi 'port unreachable' <<< "$out"
}
# The LAN host's IPv4 straight out of the uplink: QEMU user networking connects it, from this host,
# to this host's own SSH port on its public address (outside the router's WAN network, so not one
# of the networks that stay off table 52).
uplink_ip=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
lan4_direct() { sudo ip netns exec owt-lan timeout "${LAN4_T:-5}" bash -c "echo > /dev/tcp/$uplink_ip/22" 2>/dev/null; }
# The router's reject, for IPv4 (QEMU user networking answers pings to its gateway 10.0.2.2).
lan4_rejected() {
  local out
  out=$(sudo ip netns exec owt-lan ping -c 1 -W 3 10.0.2.2 2>&1)
  grep -qi 'port unreachable' <<< "$out"
}
kill_uci() { r 'uci -q -X show firewall' | grep -q "\.name='flowmesh_exit_kill_switch'$"; }
kill_runtime() {
  local out
  if [ $fw = fw4 ]; then out=$(r 'nft list ruleset'); else out=$(r 'iptables -S; ip6tables -S'); fi &&
    grep -q flowmesh_exit_kill_switch <<< "$out"
}
kill_on() { kill_uci && kill_runtime; }
kill_off() { ! kill_uci && ! kill_runtime; }
lan6_to_mesh() { sudo ip netns exec owt-lan ping -6 -c 2 -W 2 "$peer6" >/dev/null 2>&1; }
prefs_vars() {
  r ". /lib/functions.sh; . /usr/share/flowmesh/prefs.sh; flowmesh_load_prefs; echo \"\$FM_KILL_SWITCH \$FM_LAN_DNS\""
}
routes_shared() { r "flowmesh debug prefs 2>/dev/null | jsonfilter -e '@.advertise_routes[*]'" | sort | tr '\n' ' '; }

rip=$(r 'flowmesh status --json 2>/dev/null | jsonfilter -e "@.Self.TailscaleIPs[0]"')
peer6=$($OWT_PEER_CLI status --json | jq -r '.Self.TailscaleIPs[] | select(contains(":"))' | head -1)
# (Written as the kernel and the daemon print it: uci keeps it as entered, leading zeros and all.)
ula=$(python3 -c 'import ipaddress, sys; print(ipaddress.ip_network(sys.argv[1]))' "$(r 'uci -q get network.globals.ula_prefix')")
gw6=$(r 'ip -6 -o addr show dev br-lan scope global' | awk '{ sub("/.*", "", $4); print $4; exit }')
sudo ip netns exec owt-lan ip -6 route replace default via "$gw6"
# Addresses the LAN host took from an earlier run's router (another ULA prefix) are still valid for
# a while and may win source address selection: drop every global one outside this router's prefix.
for a in $(sudo ip netns exec owt-lan ip -6 -o addr show dev owt-lan1 scope global | awk '{ print $4 }'); do
  python3 -c 'import ipaddress, sys; sys.exit(ipaddress.ip_interface(sys.argv[1]).ip not in ipaddress.ip_network(sys.argv[2]))' "$a" "$ula" ||
    sudo ip netns exec owt-lan ip -6 addr del "$a" dev owt-lan1
done
echo "   router $rip, peer $OWT_PEER_MESH_IP / $peer6, LAN ULA $ula (LAN host's IPv6 default via $gw6)"

check "lab: the Internet address behind the peer is unreachable from this host (the router's uplink side)" \
  eval '! curl -s -m 3 -o /dev/null "http://$OWT_INET_IP:$OWT_INET_PORT/"'
check "lab: the LAN host reaches the uplink directly ($uplink_ip:22 through the router)" lan4_direct
check "kill_switch and lan_dns unset: uci get fails, both read as on" eval '
  ! r "uci -q get flowmesh.main.kill_switch" && ! r "uci -q get flowmesh.main.lan_dns" && [ "$(prefs_vars)" = "1 1" ]'
r 'uci set flowmesh.main.kill_switch=0; uci set flowmesh.main.lan_dns=0; uci commit flowmesh' >/dev/null 2>&1
check "kill_switch=0, lan_dns=0 are read as off" eval '[ "$(prefs_vars)" = "0 0" ]'
r 'uci delete flowmesh.main.kill_switch; uci delete flowmesh.main.lan_dns; uci commit flowmesh' >/dev/null 2>&1

check "no exit node: the LAN host does not reach the Internet behind the peer, IPv6 not blocked" \
  eval 'not_via_exit && v6_open && ! lan6_rejected && no_exit_rules'

# What flowmesh_cli sends, and which exit node the watcher's state file lets a reload apply: a
# fake `flowmesh` prints its arguments.
r "uci set flowmesh.main.use_exit_node=$OWT_PEER_MESH_IP; uci commit flowmesh" >/dev/null 2>&1
out=$(r "PEER=$OWT_PEER_MESH_IP sh -s" 2>&1 <<'EOF'
FLOWMESH_EXIT_STATE=/tmp/owt-exit-state.json
. /lib/functions.sh
. /usr/share/flowmesh/prefs.sh
flowmesh() { echo "$*"; }
try() {
  rm -f "$FM_EXIT_STATE_FILE"
  [ "$2" = - ] || printf '%s' "$2" > "$FM_EXIT_STATE_FILE"
  flowmesh_load_prefs
  echo "$1=$FM_EXIT_IP"
}
try missing -
try garbage 'not json {'
try fallback "{\"want\":\"$PEER\",\"state\":\"offline_fallback\",\"since\":1}"
try blocked "{\"want\":\"$PEER\",\"state\":\"offline_blocked\",\"since\":1}"
try active "{\"want\":\"$PEER\",\"state\":\"active\",\"since\":1}"
try other "{\"want\":\"100.64.0.250\",\"state\":\"offline_fallback\",\"since\":1}"
rm -f "$FM_EXIT_STATE_FILE"
flowmesh_load_prefs
echo "use: $(flowmesh_cli set)"
uci set flowmesh.main.exit_node=1
flowmesh_load_prefs
echo "both: $(flowmesh_cli set)"
uci revert flowmesh
# (A new shell: config_load does not unset what an earlier load set.)
uci delete flowmesh.main.use_exit_node
echo "none: $(sh -c '. /lib/functions.sh; . /usr/share/flowmesh/prefs.sh; flowmesh() { echo "$*"; }
  flowmesh_load_prefs; flowmesh_cli set')"
uci revert flowmesh
EOF
)
sed 's/^/   | /' <<< "$out"
P=$OWT_PEER_MESH_IP
check "exit-state.json: only offline_fallback for this exit node keeps it off (missing, unparsable, other states, another exit node: applied)" \
  eval '[ "$(grep -E "^[a-z]+=" <<< "$out" | tr "\n" " ")" = "missing=$P garbage=$P fallback= blocked=$P active=$P other=$P " ]'
check "flowmesh_cli: an exit node in use is sent with LAN access and router mode, no stateful filtering" eval '
  grep -q -- "^use: set .*--exit-node-allow-lan-access=true --exit-node-forwarded-only=true --exit-node=$P$" <<< "$out" &&
  ! grep -q stateful <<< "$out"'
check "flowmesh_cli: exit_node and use_exit_node both set: offers itself, uses none" \
  eval 'grep -q -- "^both: set .*--advertise-exit-node=1 --exit-node-allow-lan-access=false --exit-node-forwarded-only=false --exit-node=$" <<< "$out"'
check "flowmesh_cli: no exit node: --exit-node= with both exit flags off" \
  eval 'grep -q -- "^none: set .*--exit-node-allow-lan-access=false --exit-node-forwarded-only=false --exit-node=$" <<< "$out"'

# Use it, sharing the LAN's IPv4 network and its ULA prefix (so the peer can answer the LAN's IPv6).
r "uci delete flowmesh.main.lan_routes; uci add_list flowmesh.main.lan_routes=192.168.1.0/24
   uci add_list flowmesh.main.lan_routes=$ula; uci commit flowmesh; /etc/init.d/flowmesh reload" 2>&1 | sed 's/^/   | /'
$OWT_HS nodes approve-routes -i "$node_id" -r "192.168.1.0/24,$ula" >/dev/null 2>&1
check "use_exit_node: the daemon uses $P, LAN access and router mode on" eval '
  [ "$(pref exit_node)" = "$P" ] && [ "$(pref exit_node_allow_lan_access)" = true ] && [ "$(pref exit_node_forwarded_only)" = true ]'
check "lan_routes listed: exactly those are shared" eval '[ "$(routes_shared)" = "$(printf "%s\n" 192.168.1.0/24 "$ula" | sort | tr "\n" " ")" ]'
check "exit routing in place, with rule 5260 (the router's own traffic by the main table)" eventually 20 exit_rules_in_place
check "LAN host reaches the Internet through the exit node, seen from the router's mesh address $rip" eventually 30 via_exit
check "the router's own traffic does not use the exit node" router_not_via_exit
check "LAN IPv6 to the uplink is rejected (rule flowmesh_exit_block_ipv6 in UCI and $fw)" eval 'v6_blocked && lan6_rejected'
check "LAN IPv6 to a mesh node ($peer6) still works" eventually 30 lan6_to_mesh
check "the router's own IPv6 to the uplink is not blocked" r 'ping -6 -c 1 -W 3 fec0::2 >/dev/null'
if [ $fw = fw4 ]; then
  r 'nft list ruleset' | grep flowmesh_exit_block_ipv6 | sed 's/^ */   | /'
else
  r 'ip6tables -S' | grep flowmesh_exit_block_ipv6 | sed 's/^/   | /'
fi

# The daemon's SNAT and policy routing are not the firewall's, but fw3 flushes the whole nat table on
# every restart and reload (fw4 leaves other tables alone): the daemon checks every 5 s and puts its
# SNAT back, so the LAN is on the exit node again within that.
for act in restart reload; do
  r "/etc/init.d/firewall $act" >/dev/null 2>&1
  t0=$SECONDS
  if eventually 12 via_exit; then
    pass "firewall $act: LAN host through the exit node, translated, again after $((SECONDS - t0)) s (at most 12)"
  else
    fail "firewall $act: LAN host through the exit node, translated, within 12 s"
  fi
  check "firewall $act: IPv6 still blocked" eval 'v6_blocked && lan6_rejected'
done

# The watcher (exit-state.json) has fallen back to the uplink: a reload must not put the LAN back
# on the dead exit node, and IPv6 is open meanwhile.
r "printf '{\"want\":\"%s\",\"state\":\"offline_fallback\",\"since\":1}' $P > /var/run/flowmesh/exit-state.json
   /etc/init.d/flowmesh reload" >/dev/null 2>&1
check "exit-state offline_fallback: reload sends --exit-node=, IPv6 open, LAN on the uplink" eval '
  [ "$(pref exit_node)" = "" ] && v6_open && ! lan6_rejected && eventually 10 not_via_exit'
r "printf '{\"want\":\"%s\",\"state\":\"active\",\"since\":2}' $P > /var/run/flowmesh/exit-state.json
   /etc/init.d/flowmesh reload" >/dev/null 2>&1
check "exit-state active: reload uses the exit node again" eval '[ "$(pref exit_node)" = "$P" ] && v6_blocked && eventually 30 via_exit'
r 'rm -f /var/run/flowmesh/exit-state.json'

r "uci set flowmesh.main.exit_node=1; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1
check "exit_node and use_exit_node both set: offers itself, uses none, IPv6 open, a warning logged" eval '
  [ "$(pref advertise_exit_node)" = true ] && [ "$(pref exit_node)" = "" ] && v6_open &&
  r "logread | grep -q \"exit_node and use_exit_node are both set\""'
r "uci set flowmesh.main.exit_node=0; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1

# An exit node that is not in the mesh (any more): the other settings still apply, no exit node is
# used (not the previous one either). Kill switch on: the LAN gets no Internet at all (rule
# flowmesh_exit_kill_switch, both families) until an apply succeeds; off: the LAN uses the uplink.
check "with the exit node $P in use, the LAN's IPv4 is not sent out of the uplink" eval 'via_exit && ! lan4_direct'
# (b) after a working exit node.
r "uci set flowmesh.main.use_exit_node=100.64.0.250; uci set flowmesh.main.hostname=$host-x; uci commit flowmesh
   /etc/init.d/flowmesh reload" > "$vm/reload.log" 2>&1
st=$?
sed 's/^/   | /' "$vm/reload.log"
check "exit node not in the mesh (after $P), kill switch on: reload succeeds, the rest applied, $P dropped" eval '
  [ $st = 0 ] && [ "$(pref hostname)" = "$host-x" ] && [ "$(pref exit_node)" = "" ] && eventually 10 no_exit_rules'
check "  ... the LAN reaches neither the Internet behind $P nor the uplink (kill switch rule in UCI and $fw)" eval '
  kill_on && not_via_exit && lan4_rejected && lan6_rejected'
check "  ... the LAN still reaches the mesh" eventually 20 lan_ping
check "  ... the watcher reports it missing" eventually 20 eval '[ "$(exit_state)" = missing ]'
r '/etc/init.d/flowmesh stop' >/dev/null 2>&1
check "  ... stop lifts the kill switch rule (the LAN uses the uplink)" eval 'eventually 20 no_daemon && kill_off && v6_open && lan4_direct'
r '/etc/init.d/flowmesh start' >/dev/null 2>&1
# (Right after a start the CLI cannot check the exit node yet and the daemon takes it as given: it
# then drops the LAN's Internet traffic itself, "until it is found". Either way: no Internet.)
check "  ... start: the exit node is still unusable, the LAN still gets no Internet" eventually 45 eval '
  backend_running && not_via_exit && ! lan4_direct'
r "uci set flowmesh.main.kill_switch=0; uci set flowmesh.main.hostname=$host; uci commit flowmesh; /etc/init.d/flowmesh reload" > "$vm/reload.log" 2>&1
st=$?
check "exit node not in the mesh, kill switch off: reload succeeds, no exit node, no block, the LAN uses the uplink" eval '
  [ $st = 0 ] && [ "$(pref hostname)" = "$host" ] && [ "$(pref exit_node)" = "" ] && kill_off && v6_open &&
  lan4_direct && ! lan6_rejected && not_via_exit'
# (a) with no exit node before.
r 'uci delete flowmesh.main.kill_switch; uci delete flowmesh.main.use_exit_node; uci commit flowmesh; /etc/init.d/flowmesh reload' >/dev/null 2>&1
r "uci set flowmesh.main.use_exit_node=100.64.0.250; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1
check "exit node not in the mesh (no exit node before), kill switch on: no Internet for the LAN, IPv4 or IPv6" eval '
  [ "$(pref exit_node)" = "" ] && kill_on && not_via_exit && lan4_rejected && lan6_rejected'
r "uci set flowmesh.main.kill_switch=0; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1
check "exit node not in the mesh (no exit node before), kill switch off: the LAN uses the uplink" eval '
  kill_off && v6_open && lan4_direct && not_via_exit'
# Started like this, the daemon takes the exit node as given before it has the mesh map, and drops
# the LAN's Internet traffic; the watcher sees that and re-applies (no reload by hand).
r '/etc/init.d/flowmesh restart' >/dev/null 2>&1
t0=$SECONDS
if eventually 60 eval 'backend_running && [ "$(exit_state)" = missing ] && [ "$(pref exit_node)" = "" ] && lan4_direct && not_via_exit'; then
  pass "  ... restarted that way: the watcher puts the LAN on the uplink by itself, after $((SECONDS - t0)) s"
else
  fail "  ... restarted that way: the watcher puts the LAN on the uplink by itself (60 s)"
fi
r "uci delete flowmesh.main.kill_switch; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1
r 'uci delete flowmesh.main.use_exit_node; uci commit flowmesh; /etc/init.d/flowmesh reload' >/dev/null 2>&1
check "use_exit_node cleared after an unusable exit node (kill switch on): the kill switch rule is gone" eval 'kill_off && lan4_direct'

check "use_exit_node cleared: exit node off, no exit rules or SNAT, IPv6 open, LAN on the uplink" eval '
  [ "$(pref exit_node)" = "" ] && [ "$(pref exit_node_forwarded_only)" = false ] && eventually 10 no_exit_rules &&
  exit_snat_absent && v6_open && kill_off && ! lan6_rejected && lan4_direct && not_via_exit'

# On again, and left on: reboot, stop and removal below run with the exit node in use.
r "uci set flowmesh.main.use_exit_node=$P; uci commit flowmesh; /etc/init.d/flowmesh reload" >/dev/null 2>&1
check "use_exit_node set again: through the exit node" eventually 30 via_exit

# --- the exit node going offline (the watcher) ------------------------------------------------
# The peer's daemon is stopped (lab.sh peer-stop, by PID) and started again. Kill switch on: the LAN
# has no Internet while it is away and nothing is re-applied; the router itself keeps resolving
# names and its control connection. Kill switch off: the LAN moves to the uplink and back, each
# within 15 s (3 failed or answered probes, 3 s apart, and a re-apply).
check "watcher: exit-state.json says active for $P" eventually 15 eval '[ "$(exit_state)" = active ] &&
  [ "$(r "jsonfilter -i /var/run/flowmesh/exit-state.json -e @.want")" = "$P" ]'
# time_until <limit> <command...>: prints the seconds it took, fails after <limit> (polls every second).
time_until() {
  local lim=$1 t=$SECONDS
  shift
  while ! "$@"; do
    [ $((SECONDS - t)) -ge "$lim" ] && { echo "$((SECONDS - t))+"; return 1; }
    sleep 1
  done
  echo $((SECONDS - t))
}
state_is() { [ "$(exit_state)" = "$1" ]; }
fallback_now() { LAN4_T=1 lan4_direct; }
back_now() { [ "$(exit_state)" = active ] && CURL_T=1 via_exit; }
n_apply=$(logs_count 're-applying the settings')
"$LAB" peer-stop "$OWT_WORK" >/dev/null
dt=$(time_until 30 state_is offline_blocked)
check "exit node offline, kill switch on: offline_blocked after $dt s" [ "${dt%+}" = "$dt" ]
check "  ... the LAN reaches neither the Internet behind it nor the uplink" eval '! lan4_direct && not_via_exit'
check "  ... the router still resolves names and keeps its control connection" eval '
  r "nslookup downloads.openwrt.org 127.0.0.1 >/dev/null 2>&1" && sleep 5 && backend_running'
check "  ... nothing re-applied (the exit node is still set, the daemon drops the LAN's traffic)" eval '
  [ "$(pref exit_node)" = "$P" ] && [ "$(logs_count "re-applying the settings")" = "$n_apply" ]'
"$LAB" peer-start "$OWT_WORK" >/dev/null
dt=$(time_until 30 back_now)
check "  ... exit node back: active, the LAN through it again (after $dt s from the peer's Running)" [ "${dt%+}" = "$dt" ]

r 'uci set flowmesh.main.kill_switch=0; uci commit flowmesh; /etc/init.d/flowmesh reload' >/dev/null 2>&1
eventually 20 via_exit
"$LAB" peer-stop "$OWT_WORK" >/dev/null
dt=$(time_until 30 fallback_now)
check "exit node offline, kill switch off: the LAN on the uplink after $dt s (at most 15), offline_fallback" eval '
  [ "${dt%+}" = "$dt" ] && [ "$dt" -le 15 ] && state_is offline_fallback'
check "  ... exit node off in the daemon, IPv6 open, UCI unchanged (use_exit_node $P, kill_switch 0)" eval '
  [ "$(pref exit_node)" = "" ] && v6_open && ! lan6_rejected &&
  [ "$(r "uci -q get flowmesh.main.use_exit_node")" = "$P" ] && [ "$(r "uci -q get flowmesh.main.kill_switch")" = 0 ]'
r '/etc/init.d/flowmesh reload' >/dev/null 2>&1
check "  ... a reload keeps the fallback" eval '[ "$(pref exit_node)" = "" ] && lan4_direct'
"$LAB" peer-start "$OWT_WORK" >/dev/null
dt=$(time_until 30 back_now)
check "  ... exit node back: the LAN through it again after $dt s from the peer's Running (at most 15), IPv6 blocked" eval '
  [ "${dt%+}" = "$dt" ] && [ "$dt" -le 15 ] && v6_blocked'
r 'uci delete flowmesh.main.kill_switch; uci commit flowmesh; /etc/init.d/flowmesh reload' >/dev/null 2>&1
check "  ... kill switch back on (unset): still through the exit node" eventually 20 eval 'via_exit && [ "$(exit_state)" = active ]'

# Applies running while the watcher switches over (LuCI's apply is the service's reload): one apply
# at a time (/var/lock/flowmesh-apply.lock), so the end state agrees everywhere.
r 'uci set flowmesh.main.kill_switch=0; uci commit flowmesh; /etc/init.d/flowmesh reload' >/dev/null 2>&1
eventually 20 via_exit
r 'cat > /tmp/owt-reloads.sh' <<'EOF'
i=0; while [ $i -lt 20 ]; do /etc/init.d/flowmesh reload >/dev/null 2>&1; sleep 1; i=$((i + 1)); done
EOF
start_reloads() { r 'start-stop-daemon -S -b -m -p /tmp/owt-reloads.pid -x /bin/sh -- /tmp/owt-reloads.sh'; }
reloads_done() { ! r 'kill -0 $(cat /tmp/owt-reloads.pid) 2>/dev/null'; }
# agree <state> <daemon exit node> <v6: blocked|open>: exit-state.json, the daemon, the IPv6 block,
# and no kill switch rule (it is off).
agree() { [ "$(exit_state)" = "$1" ] && [ "$(pref exit_node)" = "$2" ] && kill_off && "v6_$3"; }
start_reloads
"$LAB" peer-stop "$OWT_WORK" >/dev/null
eventually 90 reloads_done
check "reloads every second while the watcher falls back: offline_fallback, no exit node in the daemon, IPv6 open, no kill rule, LAN on the uplink" \
  eventually 20 eval 'agree offline_fallback "" open && lan4_direct'
start_reloads
"$LAB" peer-start "$OWT_WORK" >/dev/null
eventually 90 reloads_done
check "  ... and while it comes back: active, exit node $P in the daemon, IPv6 blocked, no kill rule, LAN through it" \
  eventually 20 eval 'agree active "$P" blocked && via_exit'
r 'logread | grep -c "another apply has held"' | sed 's/^/   | lock waits given up: /'
r 'rm -f /tmp/owt-reloads.sh /tmp/owt-reloads.pid; uci delete flowmesh.main.kill_switch; uci commit flowmesh; /etc/init.d/flowmesh reload' >/dev/null 2>&1
eventually 20 via_exit

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
check "after reboot: LAN host through the exit node again, IPv6 blocked" eventually 60 eval 'via_exit && v6_blocked'

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
check "stop (exit node in use): no exit routing or SNAT left, IPv6 block lifted" eval 'no_exit_rules && exit_snat_absent && v6_open && kill_off'
check "stop: the watcher's dnsmasq entries and exit-state.json gone, the user's entries kept" eval '
  ours_absent && user_dns_kept && r "! test -e /var/run/flowmesh/exit-state.json"'
r '/etc/init.d/flowmesh start' >/dev/null 2>&1
eventually 30 own_rules_present
check "start: through the exit node again, IPv6 blocked" eventually 40 eval 'via_exit && v6_blocked'
check "start: the watcher's entries back" eventually 30 ours_present

ours="flowmesh"
[ -n "$feed" ] && ours="luci-app-flowmesh flowmesh"
if [ $pm = opkg ]; then r "opkg remove $ours"; else r "apk del $ours"; fi 2>&1 | sed 's/^/   | /' | tail -5
check "removed: no daemon" eventually 20 no_daemon
check "removed: no flowmesh zone or forwardings, other zones unchanged" eval '[ "$(fw_inventory)" = "$before" ]'
check "removed: no flowmesh rules in the running firewall ($fw)" eval '
  out=$(r "nft list ruleset 2>/dev/null; iptables -S 2>/dev/null; true") && ! grep -q flowmesh0 <<< "$out" && own_rules_absent'
check "removed while using an exit node: no exit routing, table 52 or SNAT, no IPv6 block rule (UCI or $fw)" \
  eval 'no_exit_rules && exit_snat_absent && v6_open && kill_off'
check "removed: init script and binaries gone" r '! test -e /etc/init.d/flowmesh && ! test -e /usr/sbin/flowmeshd && ! test -e /etc/rc.d/S95flowmesh'
check "removed: /etc/flowmesh (identity) kept" r 'test -n "$(ls -A /etc/flowmesh)"'
check "removed: no dnsmasq entries of ours left, the user's kept" eval 'ours_absent && user_dns_kept'
dns_list server | sed 's/^/   | server after removal: /'

[ -n "$node_id" ] && $OWT_HS nodes delete -i "$node_id" --force >/dev/null 2>&1
echo "== $label: $fails failed"
exit "$fails"
