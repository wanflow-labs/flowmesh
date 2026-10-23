#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Tests for flowmesh-watch (../files/flowmesh-watch.sh). Runs on OpenWrt (busybox ash, jsonfilter,
# uci, flock): `sh watch_test.sh` from this directory, as root. The watcher's functions are sourced
# with a fake `flowmesh` first on PATH (status, ping answers and the rest come from files), a clock
# the test sets, and the re-apply and dnsmasq reload replaced by recorders. /etc/config/flowmesh and
# /etc/config/dhcp are changed (without reloading anything) and restored afterwards; a running
# flowmesh service (whose own watcher would change dhcp meanwhile) is stopped for the duration and
# started again. Exit status: the number of failures.
# shellcheck disable=SC2015,SC2016,SC1090,SC1007,SC2034 # (the watcher reads the variables set here)

here=$(cd "$(dirname "$0")" && pwd)
src=$here/../files/flowmesh-watch.sh
work=$(mktemp -d /tmp/flowmesh-watch-test.XXXXXX)
mkdir -p "$work/bin"
was_running=
if /etc/init.d/flowmesh running; then
	was_running=1
	/etc/init.d/flowmesh stop
	sleep 2
fi
cp /etc/config/flowmesh "$work/flowmesh.uci"
cp /etc/config/dhcp "$work/dhcp.uci"
restore() {
	[ -n "$wpid" ] && kill "$wpid" 2> /dev/null
	uci -q revert flowmesh
	uci -q revert dhcp
	cp "$work/flowmesh.uci" /etc/config/flowmesh
	cp "$work/dhcp.uci" /etc/config/dhcp
	rm -rf "$work"
	[ -n "$was_running" ] && /etc/init.d/flowmesh start
}
trap restore EXIT

wpid=
fails=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
# expect <description> <want> <got>
expect() {
	if [ "$2" = "$3" ]; then pass "$1"; else fail "$1"; echo "      want: $2"; echo "      got:  $3"; fi
}

[ -f "$src" ] || { fail "flowmesh-watch.sh exists"; exit "$fails"; }

# Fake flowmesh. status --json: $work/status (exit status 1 unless Running, as the real CLI). ping: answers the first line of $work/ping ("ok" or
# "fail"), which it removes; no line left: fail. debug prefs: $work/prefs. dns status --json:
# $work/dns. Every call is appended to $work/calls.
cat > "$work/bin/flowmesh" << FAKE
#!/bin/sh
echo "\$*" >> $work/calls
case "\$1" in
status) cat $work/status; grep -q '"Running"' $work/status || exit 1 ;;   # (as the real one: 1 unless Running)
ping)
	a=\$(head -1 $work/ping 2>/dev/null); sed -i 1d $work/ping 2>/dev/null
	if [ "\$a" = ok ]; then echo "pong from peer (100.64.0.1) via 10.0.0.1:41641 in 2ms"; exit 0; fi
	echo "ping \"100.64.0.1\" timed out"; echo "no reply" >&2; exit 1 ;;
debug) cat $work/prefs 2>/dev/null || exit 1 ;;
dns) cat $work/dns ;;
esac
FAKE
chmod 0755 "$work/bin/flowmesh"
# The re-apply records the state file as it was when it ran; the dnsmasq reload counts.
cat > "$work/bin/reload" << FAKE
#!/bin/sh
echo "reload \$(jsonfilter -i $work/exit-state.json -e @.state 2>/dev/null)" >> $work/reloads
FAKE
cat > "$work/bin/dnsmasq-reload" << FAKE
#!/bin/sh
echo reload >> $work/dnsmasq-reloads
FAKE
# Fake ping (the tunnel warm-up): records its arguments.
cat > "$work/bin/ping" << FAKE
#!/bin/sh
echo "\$*" >> $work/icmp
FAKE
chmod 0755 "$work/bin/reload" "$work/bin/dnsmasq-reload" "$work/bin/ping"

PATH=$work/bin:$PATH
export FLOWMESH_EXIT_STATE=$work/exit-state.json FLOWMESH_DNS_OWNED=$work/lan-dns.owned \
	FLOWMESH_DNS_LOCK=$work/dns.lock FLOWMESH_WATCH_RELOAD=$work/bin/reload \
	FLOWMESH_WATCH_DNSMASQ_RELOAD=$work/bin/dnsmasq-reload FLOWMESH_WATCH_LIB=1
. "$src"
NOW=1000
now() { echo "$NOW"; }
logger() { :; }

EXIT=100.64.0.1
peer_status() {   # peer_status <exit node option true|false>
	printf '{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.2"]},"Peer":{"k1":{"HostName":"peer","TailscaleIPs":["%s","fd7a:115c:a1e0::1"],"ExitNodeOption":%s,"Online":true},"k2":{"HostName":"other","TailscaleIPs":["100.64.0.3"],"ExitNodeOption":false}}}\n' "$EXIT" "$1" > "$work/status"
}
no_peer_status() {
	printf '{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.2"]},"Peer":{"k2":{"HostName":"other","TailscaleIPs":["100.64.0.3"],"ExitNodeOption":false}}}\n' > "$work/status"
}
# fresh <kill_switch>: a watcher that has seen nothing yet, exit node $EXIT chosen.
fresh() {
	E_WANT= E_STATE= E_OK= E_FAIL= E_ABSENT= E_FIX_AT= E_SINCE=
	rm -f "$work/exit-state.json" "$work/reloads" "$work/ping" "$work/calls" "$work/icmp"
	uci set flowmesh.main.use_exit_node=$EXIT
	uci set flowmesh.main.exit_node=0
	if [ "$1" = - ]; then uci -q delete flowmesh.main.kill_switch; else uci set flowmesh.main.kill_switch="$1"; fi
	peer_status true
}
# ticks <answers...>: one exit_tick per answer (ok/fail/-, "-" when no probe is expected), 3 s apart;
# sets $got to the states after each. (Not in a subshell: the watcher's state carries over.)
ticks() {
	local a
	got=
	for a in "$@"; do
		[ "$a" = - ] || echo "$a" >> "$work/ping"
		STATUS_BACKEND=$(jsonfilter -i "$work/status" -e @.BackendState)
		exit_tick "$(cat "$work/status")"
		NOW=$((NOW + 3))
		got="$got${got:+ }$(jsonfilter -i "$work/exit-state.json" -e @.state 2>/dev/null)"
	done
}
pings() { cat "$work/calls" 2> /dev/null | grep -c '^ping '; }
reloads() { cat "$work/reloads" 2> /dev/null | tr '\n' ',' ; }

# --- the exit node ---
fresh 0
ticks ok ok ok fail fail fail ok ok ok
expect "kill switch off: up up up, down x3 (falls back on the 3rd), up x3 (back on the 3rd)" \
	"active active active active active offline_fallback offline_fallback offline_fallback active" "$got"
expect "  ... re-applied twice: state file offline_fallback before the first, active before the second" \
	"reload offline_fallback,reload active," "$(reloads)"
expect "  ... the state file: want exactly as in UCI, since the last change" \
	"$EXIT active $((NOW - 3))" \
	"$(jsonfilter -i "$work/exit-state.json" -e @.want) $(jsonfilter -i "$work/exit-state.json" -e @.state) $(jsonfilter -i "$work/exit-state.json" -e @.since)"
sleep 1   # (sent in the background)
expect "  ... coming back, each answer also sends one packet through the tunnel (WireGuard's session); none before" \
	"3 3" "$(cat "$work/icmp" 2>/dev/null | wc -l | tr -d ' ') $(cat "$work/icmp" 2>/dev/null | grep -c "^-c 1 -W 1 $EXIT\$")"
expect "  ... one probe per tick, of the chosen exit node, bounded to 2 s" \
	"9 9" "$(pings) $(cat "$work/calls" 2>/dev/null | grep -c "^ping -c 1 --until-direct=false --timeout=2s $EXIT\$")"

fresh 1
ticks ok fail fail fail fail ok ok ok
expect "kill switch on: offline_blocked on the 3rd failure, active on the 3rd answer" \
	"active active active offline_blocked offline_blocked offline_blocked offline_blocked active" "$got"
expect "  ... nothing re-applied (the daemon itself keeps the LAN off the uplink)" "" "$(reloads)"

fresh -
ticks fail fail fail
expect "kill switch unset counts as on" "active active offline_blocked" "$got"
uci set flowmesh.main.kill_switch=0
ticks fail
expect "  ... turned off while offline: falls back at once, re-applied" "offline_fallback reload offline_fallback," "$got $(reloads)"
uci set flowmesh.main.kill_switch=1
ticks fail
expect "  ... turned on again while offline: blocked, re-applied (the exit node goes back on)" \
	"offline_blocked reload offline_fallback,reload offline_blocked," "$got $(reloads)"

fresh 0
ticks fail ok fail ok fail ok fail fail ok fail fail ok
expect "alternating answers and failures (never 3 in a row): stays active" \
	"active active active active active active active active active active active active" "$got"
expect "  ... nothing re-applied" "" "$(reloads)"
fresh 0
ticks fail fail fail ok ok fail ok ok fail
expect "offline, then answers never 3 in a row: stays offline_fallback" \
	"active active offline_fallback offline_fallback offline_fallback offline_fallback offline_fallback offline_fallback offline_fallback" "$got"
expect "  ... re-applied once" "reload offline_fallback," "$(reloads)"

fresh 0
no_peer_status
ticks - - - -
expect "exit node not in the mesh map: missing after 3 checks, no probe" "active active missing missing" "$got"
expect "  ... no ping, nothing re-applied" "0 " "$(pings) $(reloads)"
peer_status false
ticks - -
expect "in the mesh but not offering itself as an exit node: still missing" "missing missing" "$got"
peer_status true
ticks - ok
expect "back in the mesh as an exit node: active at once, re-applied (lifts the kill switch rule)" \
	"active active reload active," "$got $(reloads)"

fresh 1
printf '{"BackendState":"NeedsLogin"}\n' > "$work/status"
ticks - - -
expect "logged out: the exit node is missing" "active active missing" "$got"
printf '{"BackendState":"Starting"}\n' > "$work/status"
ticks - - -
expect "  ... starting: no verdict either way" "missing missing missing" "$got"

# A restarted watcher takes over the recorded state for the same exit node.
fresh 0
printf '{"want":"%s","state":"offline_fallback","since":77}\n' $EXIT > "$work/exit-state.json"
ticks fail
expect "restarted watcher: keeps the recorded offline_fallback (and its since), nothing re-applied" \
	"offline_fallback offline_fallback 77 " "$got $E_STATE $(jsonfilter -i "$work/exit-state.json" -e @.since) $(reloads)"
printf '{"want":"100.64.0.250","state":"offline_fallback","since":77}\n' > "$work/exit-state.json"
E_WANT= E_STATE=
ticks ok
expect "  ... but not one recorded for another exit node" "active" "$got"

fresh 0
uci delete flowmesh.main.use_exit_node
ticks - -
expect "no exit node chosen: state none, want empty, no probe" "none none  0" \
	"$got $(jsonfilter -i "$work/exit-state.json" -e @.want) $(pings)"
uci set flowmesh.main.use_exit_node=$EXIT
uci set flowmesh.main.exit_node=1
ticks - -
expect "exit_node and use_exit_node both set: this router offers itself, uses none: none" "none none" "$got"
uci set flowmesh.main.exit_node=0

# The daemon's exit node, checked against the state.
fresh 0
ticks ok
STATUS_BACKEND=Running
printf '{"exit_node":"%s"}\n' $EXIT > "$work/prefs"
exit_consistency
expect "consistency: active and the daemon uses the exit node: nothing to do" "" "$(reloads)"
rm -f "$work/prefs"
exit_consistency
expect "  ... the daemon does not answer: no verdict, nothing re-applied" "" "$(reloads)"
printf '{"exit_node":""}\n' > "$work/prefs"
exit_consistency
expect "  ... active but the daemon uses none: re-applied" "reload active," "$(reloads)"
NOW=$((NOW + 10)); exit_consistency
expect "  ... still wrong 10 s later: not again (at most every 30 s)" "reload active," "$(reloads)"
NOW=$((NOW + 25)); exit_consistency
expect "  ... 35 s later: again" "reload active,reload active," "$(reloads)"
fresh 0
no_peer_status
ticks -
printf '{"exit_node":""}\n' > "$work/prefs"
STATUS_BACKEND=Running
exit_consistency
expect "  ... active, not in the map at the last check (not missing yet), the daemon uses none: not yet" "" "$(reloads)"
ticks - -
printf '{"exit_node":"%s"}\n' $EXIT > "$work/prefs"
STATUS_BACKEND=Running
exit_consistency
expect "  ... missing but the daemon took it (start before the map): re-applied" "reload missing," "$(reloads)"
fresh 0
ticks fail fail fail
rm -f "$work/reloads"
STATUS_BACKEND=Running
printf '{"exit_node":""}\n' > "$work/prefs"
NOW=$((NOW + 60)); exit_consistency
expect "  ... offline_fallback and the daemon uses none: nothing to do" "" "$(reloads)"

# --- the domain set ---
js='{"suffix":"Owt.Test.","extraRecords":[{"name":"app.owt-extra.test","type":"A","value":"100.64.0.200"},{"name":"APP.owt-extra.test.","type":"A","value":"100.64.0.200"},{"name":"svc.owt.test","type":"A","value":"100.64.0.201"},{"name":"*.wild.example","type":"A","value":"100.64.0.202"},{"name":"bad name","type":"A","value":"1.2.3.4"},{"name":"x/y","type":"A","value":"1.2.3.4"},{"name":"a#b","type":"A","value":"1.2.3.4"}],"routes":{"64.100.in-addr.arpa":[],"0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa":[],"corp.owt-split.test":["10.231.0.1"],"sub.corp.owt-split.test":["10.0.0.9","10.0.0.10"],"q\"uote.test":["1.1.1.1"]}}'
expect "domains: suffix, extra records and split domains; case, trailing dots, duplicates, covered names, wildcards, invalid names, reverse zones" \
	"app.owt-extra.test corp.owt-split.test owt.test wild.example" "$(dns_domains "$js" | tr '\n' ' ' | sed 's/ $//')"
js='{"suffix":"","extraRecords":[{"name":"svc.example.org","type":"A","value":"100.64.0.5"}],"routes":{"100.100.in-addr.arpa":[]}}'
expect "domains: no suffix (node name without a dot): only the extra records" "svc.example.org" "$(dns_domains "$js" | tr '\n' ' ' | sed 's/ $//')"
expect "domains: nothing at all" "" "$(dns_domains '{"suffix":"","extraRecords":[],"routes":{}}')"
expect "domains: not JSON" "" "$(dns_domains 'not json {')"

# --- dnsmasq entries ---
sec=$(dnsmasq_sections | head -1)
d=dhcp.$sec
count() { count_value "$sec" "$1" "$2"; }
dnsmasq_reloads() { cat "$work/dnsmasq-reloads" 2> /dev/null | wc -l | tr -d ' '; }
# The user's own entries, one of them the same as one of ours.
uci add_list $d.server=/corp.example/10.0.0.53
uci add_list $d.rebind_domain=corp.example
uci add_list $d.server=/owt.test/100.100.100.100
uci commit dhcp
uci set $d.owt_staged=1   # a user change staged, not applied
dns_reconcile "owt.test
app.owt-extra.test"
expect "added: server and rebind_domain for each domain (the user's same server entry not doubled)" "1 1 1 1" \
	"$(count server /owt.test/100.100.100.100) $(count rebind_domain owt.test) $(count server /app.owt-extra.test/100.100.100.100) $(count rebind_domain app.owt-extra.test)"
expect "  ... in /etc/config/dhcp (committed)" "1" "$(grep -c "list server '/app.owt-extra.test/100.100.100.100'" /etc/config/dhcp)"
expect "  ... recorded as ours: three entries (not the user's server /owt.test/)" \
	"$sec rebind_domain app.owt-extra.test,$sec rebind_domain owt.test,$sec server /app.owt-extra.test/100.100.100.100," \
	"$(sort "$work/lan-dns.owned" | tr '\n' ',')"
expect "  ... dnsmasq reloaded once" "1" "$(dnsmasq_reloads)"
expect "  ... the user's staged change still staged, not committed" "1 0" \
	"$(uci changes dhcp | grep -c owt_staged) $(grep -c owt_staged /etc/config/dhcp)"
dns_reconcile "app.owt-extra.test
owt.test"
expect "same set again: nothing changed, no reload" "1" "$(dnsmasq_reloads)"
dns_reconcile "owt.test"
expect "a domain gone: its entries removed, the rest kept, reloaded" "0 0 1 1 2" \
	"$(count server /app.owt-extra.test/100.100.100.100) $(count rebind_domain app.owt-extra.test) $(count rebind_domain owt.test) $(count server /owt.test/100.100.100.100) $(dnsmasq_reloads)"
uci -q revert dhcp
uci del_list $d.rebind_domain=owt.test; uci commit dhcp
uci set $d.owt_staged=1
dns_reconcile "owt.test"
expect "our entry removed by hand: put back" "1 3" "$(count rebind_domain owt.test) $(dnsmasq_reloads)"
dns_reconcile ""
expect "none wanted: ours removed; the user's server /owt.test/, /corp.example/ and rebind corp.example kept" \
	"0 1 1 1 4" \
	"$(count rebind_domain owt.test) $(count server /owt.test/100.100.100.100) $(count server /corp.example/10.0.0.53) $(count rebind_domain corp.example) $(dnsmasq_reloads)"
expect "  ... the owned list is gone" "no" "$([ -e "$work/lan-dns.owned" ] && echo yes || echo no)"
expect "  ... the user's staged change still staged" "1 0" "$(uci changes dhcp | grep -c owt_staged) $(grep -c owt_staged /etc/config/dhcp)"
uci -q revert dhcp
# An entry of ours that the user adds as well later: removing ours leaves theirs.
dns_reconcile "dup.test"
uci add_list $d.rebind_domain=dup.test; uci commit dhcp
dns_reconcile ""
expect "the user added the same entry as ours later: one is left (theirs)" "1" "$(count rebind_domain dup.test)"

# --- the whole loop: lan_dns, logout, SIGTERM ---
uci set flowmesh.main.lan_dns=1
uci -q delete flowmesh.main.use_exit_node
uci commit flowmesh
peer_status true
printf '%s\n' '{"suffix":"owt.test","extraRecords":[{"name":"app.owt-extra.test","type":"A","value":"100.64.0.200"}],"routes":{}}' > "$work/dns"
DNS_AT=0 NOW=5000
watch_tick
expect "loop, logged in, lan_dns on: entries for the suffix and the extra record" "1 1" \
	"$(count server /app.owt-extra.test/100.100.100.100) $(count rebind_domain owt.test)"
uci set flowmesh.main.lan_dns=0
NOW=5003; watch_tick
expect "  ... lan_dns=0: not before the next name check (10 s)" "1" "$(count server /app.owt-extra.test/100.100.100.100)"
NOW=5010; watch_tick
expect "  ... lan_dns=0: removed at the next name check" "0 0" "$(count server /app.owt-extra.test/100.100.100.100) $(count rebind_domain owt.test)"
uci set flowmesh.main.lan_dns=1
NOW=5020; watch_tick
printf '{"BackendState":"Starting"}\n' > "$work/status"
NOW=5030; watch_tick
expect "  ... starting: left as it was" "1" "$(count server /app.owt-extra.test/100.100.100.100)"
printf '{"BackendState":"NeedsLogin"}\n' > "$work/status"
NOW=5040; watch_tick
expect "  ... logged out: removed" "0 0" "$(count server /app.owt-extra.test/100.100.100.100) $(count rebind_domain owt.test)"
uci commit flowmesh

# The real process: SIGTERM removes its entries and the state file.
peer_status true
uci set flowmesh.main.use_exit_node=$EXIT; uci commit flowmesh
i=0; while [ "$i" -lt 50 ]; do echo ok; i=$((i + 1)); done > "$work/ping"
FLOWMESH_WATCH_LIB= sh "$src" &
wpid=$!
i=0
while [ "$i" -lt 10 ] && [ "$(count server /app.owt-extra.test/100.100.100.100)" != 1 ]; do sleep 1; i=$((i + 1)); done
expect "process: entries added, state file written" "1 active" \
	"$(count server /app.owt-extra.test/100.100.100.100) $(jsonfilter -i "$work/exit-state.json" -e @.state 2>/dev/null)"
t0=$(date +%s)
kill -TERM "$wpid"
wait "$wpid"
expect "  ... SIGTERM: exits within 5 s, entries removed, state file deleted" "yes 0 0 no" \
	"$([ $(($(date +%s) - t0)) -le 5 ] && echo yes || echo no) $(count server /app.owt-extra.test/100.100.100.100) $(count rebind_domain owt.test) $([ -e "$work/exit-state.json" ] && echo yes || echo no)"
wpid=
dns_reconcile "again.test"
FLOWMESH_WATCH_LIB= sh "$src" cleanup
expect "cleanup command: removes them too (watcher not running)" "0" "$(count rebind_domain again.test)"

echo "watch_test: $fails failed"
exit "$fails"
