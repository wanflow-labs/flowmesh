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

# Fake flowmesh. status --json: $work/status (exit status 1 unless Running, as the real CLI). ping
# (discovery level): answers the first line of $work/disco ("ok" or "fail"), which it removes; no
# line left: answers (it keeps answering while IP through the tunnel is dead, so the IP ping
# decides). debug prefs: $work/prefs. dns status --json: $work/dns. Every call is appended to
# $work/calls.
cat > "$work/bin/flowmesh" << FAKE
#!/bin/sh
echo "\$*" >> $work/calls
case "\$1" in
status) cat $work/status; grep -q '"Running"' $work/status || exit 1 ;;   # (as the real one: 1 unless Running)
ping)
	a=\$(head -1 $work/disco 2>/dev/null); sed -i 1d $work/disco 2>/dev/null
	[ "\$a" = fail ] && { echo "ping \"100.64.0.1\" timed out"; echo "no reply" >&2; exit 1; }
	echo "pong from peer (100.64.0.1) via 10.0.0.1:41641 in 2ms"; exit 0 ;;
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
# Fake ping (the probe, an ICMP echo through the tunnel): records its arguments in $work/icmp and
# answers the first line of $work/ping ("ok" or "fail"), which it removes; no line left: fail.
cat > "$work/bin/ping" << FAKE
#!/bin/sh
echo "\$*" >> $work/icmp
a=\$(head -1 $work/ping 2>/dev/null); sed -i 1d $work/ping 2>/dev/null
[ "\$a" = ok ] && { echo "64 bytes from 100.64.0.1: seq=0 ttl=64 time=1.0 ms"; exit 0; }
exit 1
FAKE
# Fake flowmesh-fw: records its arguments in $work/fwcalls and keeps the rule names it has put in
# place in $work/fwstate (read by the fw_has below).
cat > "$work/bin/fw" << FAKE
#!/bin/sh
echo "\$*" >> $work/fwcalls
touch $work/fwstate
for a in "\$@"; do
	case "\$a" in
	exit-kill-on) grep -qx flowmesh_exit_kill_switch $work/fwstate || echo flowmesh_exit_kill_switch >> $work/fwstate ;;
	exit-kill-off) sed -i '/^flowmesh_exit_kill_switch\$/d' $work/fwstate ;;
	exit-v6-block-on) grep -qx flowmesh_exit_block_ipv6 $work/fwstate || echo flowmesh_exit_block_ipv6 >> $work/fwstate ;;
	exit-v6-block-off) sed -i '/^flowmesh_exit_block_ipv6\$/d' $work/fwstate ;;
	esac
done
FAKE
chmod 0755 "$work/bin/reload" "$work/bin/dnsmasq-reload" "$work/bin/ping" "$work/bin/fw"

PATH=$work/bin:$PATH
export FLOWMESH_EXIT_STATE=$work/exit-state.json FLOWMESH_DNS_OWNED=$work/lan-dns.owned \
	FLOWMESH_DNS_LOCK=$work/dns.lock FLOWMESH_WATCH_RELOAD=$work/bin/reload FLOWMESH_HOSTS_FILE=$work/hosts/flowmesh \
	FLOWMESH_WATCH_DNSMASQ_RELOAD=$work/bin/dnsmasq-reload FLOWMESH_WATCH_LIB=1 \
	FLOWMESH_USER_STOPPED=$work/user-stopped FLOWMESH_APPLY_LOCK=$work/apply.lock FLOWMESH_WATCH_FW=$work/bin/fw
. "$src"
fw_has() { grep -qxF "$1" "$work/fwstate" 2> /dev/null; }
NOW=1000
now() { echo "$NOW"; }
logger() { echo "$*" >> "$work/log"; }   # (the watcher's log, for the notes it must write once)

EXIT=100.64.0.1
peer_status() {   # peer_status <exit node option true|false>
	printf '{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.2"]},"Peer":{"k1":{"HostName":"peer","TailscaleIPs":["%s","fd7a:115c:a1e0::1"],"ExitNodeOption":%s,"Online":true,"PrimaryRoutes":["10.0.0.0/24"]},"k2":{"HostName":"other","TailscaleIPs":["100.64.0.3"],"ExitNodeOption":false}}}\n' "$EXIT" "$1" > "$work/status"
}
no_peer_status() {
	printf '{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.2"]},"Peer":{"k2":{"HostName":"other","TailscaleIPs":["100.64.0.3"],"ExitNodeOption":false}}}\n' > "$work/status"
}
# fresh <kill_switch>: a watcher that has seen nothing yet, exit node $EXIT chosen.
fresh() {
	E_WANT= E_STATE= E_OK= E_FAIL= E_ABSENT= E_FIX_AT= E_SINCE= E_ICMP= E_ICMP_NOTED= E_DOWN=
	rm -f "$work/exit-state.json" "$work/reloads" "$work/ping" "$work/disco" "$work/calls" "$work/icmp" "$work/log" \
		"$work/fwcalls" "$work/user-stopped"
	: > "$work/fwstate"
	uci set flowmesh.main.use_exit_node=$EXIT
	uci set flowmesh.main.exit_node=0
	if [ "$1" = - ]; then uci -q delete flowmesh.main.kill_switch; else uci set flowmesh.main.kill_switch="$1"; fi
	peer_status true
}
# ticks <answers...>: one exit_tick per answer, 3 s apart: ok (discovery and the ICMP echo
# answer), fail (the exit node away: discovery does not answer, so no echo), nodata (discovery
# answers, the echo does not), "-" (no probe expected); sets $got to the states after each. (Not in a
# subshell: the watcher's state carries over.)
ticks() {
	local a
	got=
	for a in "$@"; do
		case "$a" in
		ok) echo ok >> "$work/disco"; echo ok >> "$work/ping" ;;
		fail) echo fail >> "$work/disco" ;;
		nodata) echo ok >> "$work/disco"; echo fail >> "$work/ping" ;;
		esac
		STATUS_BACKEND=$(jsonfilter -i "$work/status" -e @.BackendState 2> /dev/null)
		T_STATUS=$NOW
		exit_tick "$(cat "$work/status")"
		NOW=$((NOW + 3))
		got="$got${got:+ }$(jsonfilter -i "$work/exit-state.json" -e @.state 2>/dev/null)"
	done
}
pings() { cat "$work/icmp" 2> /dev/null | wc -l | tr -d ' '; }
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
expect "  ... one probe per tick: a discovery ping, then an ICMP echo through the tunnel, each 2 s, to the chosen exit node" \
	"6 6 9" "$(pings) $(cat "$work/icmp" 2>/dev/null | grep -c "^-c 1 -W 2 $EXIT\$") $(cat "$work/calls" 2>/dev/null | grep -c "^ping -c 1 --until-direct=false --timeout=2s $EXIT\$")"

# (b) The data plane dead while the exit node is in the map, online and answering discovery pings,
# after an echo has been answered: only the echo notices.
fresh 1
ticks ok nodata nodata nodata
expect "IP through the tunnel dead (echo answered before), discovery still answering: offline_blocked on the 3rd failed echo" \
	"active active active offline_blocked" "$got"
ticks ok ok ok
expect "  ... echoes answered again: active on the 3rd" "offline_blocked offline_blocked active" "$got"
fresh 0
ticks ok nodata nodata nodata
expect "  ... kill switch off: falls back" "active active active offline_fallback reload offline_fallback," "$got $(reloads)"

# (c) Another exit node chosen after (b): its ICMP history starts empty.
EXIT2=100.64.0.7
printf '{"BackendState":"Running","Self":{"TailscaleIPs":["100.64.0.2"]},"Peer":{"k1":{"HostName":"peer","TailscaleIPs":["%s"],"ExitNodeOption":true,"Online":true},"k3":{"HostName":"peer2","TailscaleIPs":["%s"],"ExitNodeOption":true,"Online":true}}}\n' "$EXIT" "$EXIT2" > "$work/status"
uci set flowmesh.main.use_exit_node=$EXIT2
: > "$work/log"
ticks nodata nodata nodata nodata
expect "a new exit node chosen: no echo answered for it yet, discovery alone keeps it active" \
	"active active active active" "$got"
expect "  ... and the note is logged once for it" "1" "$(grep -c 'not ICMP through the tunnel' "$work/log")"
uci set flowmesh.main.use_exit_node=$EXIT

# (a) ICMP to the exit node filtered from the start (a mesh ACL), discovery fine: it stays active,
# and that is logged once, not on every probe.
fresh 1
: > "$work/log"
ticks nodata nodata nodata nodata nodata nodata
expect "echo never answered, discovery fine: stays active (a filter must not keep the LAN off for good)" \
	"active active active active active active" "$got"
expect "  ... logged once" "1" "$(grep -c 'not ICMP through the tunnel' "$work/log")"
ticks fail fail fail
expect "  ... discovery failing still counts: offline_blocked on the 3rd" "active active offline_blocked" "$got"

# The exit node away: discovery fails, and no IP packet is sent to it (they would make the tunnel
# back off its handshakes and come back late).
fresh 1
ticks fail fail fail
expect "discovery not answering: a failed probe, no ICMP echo sent; offline_blocked on the 3rd" \
	"active active offline_blocked 0" "$got $(pings)"
ticks ok ok ok
expect "  ... discovery answering again: the echoes decide, back on the 3rd answer" "offline_blocked offline_blocked active 3" "$got $(pings)"

# next <answers...>: like ticks, also collecting the delay the loop would wait before the next probe
# ($nx) and the states ($sts).
next() {
	local a
	nx= sts=
	for a in "$@"; do
		E_NEXT=$PERIOD
		ticks "$a"
		nx="$nx${nx:+ }$E_NEXT"
		sts="$sts${sts:+ }$got"
	done
}
fresh 1
next fail fail fail fail ok ok ok fail
expect "probe period 3 s, but 1 s between the probes that confirm an offline exit node is back" \
	"3 3 3 3 1 1 1 3" "$nx"
expect "  ... still 3 answers in a row to come back" \
	"active active offline_blocked offline_blocked offline_blocked offline_blocked active active" "$sts"

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

# --- FlowMesh itself not running (the daemon not Running) ---
backend() { if [ -n "$1" ]; then printf '{"BackendState":"%s"}\n' "$1" > "$work/status"; else : > "$work/status"; fi; }
fwcalls() { cat "$work/fwcalls" 2> /dev/null | tr '\n' ','; }
fwstate() { sort "$work/fwstate" 2> /dev/null | tr '\n' ','; }
V6=flowmesh_exit_block_ipv6 KS=flowmesh_exit_kill_switch

fresh 1
echo $V6 > "$work/fwstate"
ticks ok
backend Starting
ticks - - - -
expect "kill switch on, the daemon starting (the control server cannot be reached): down_blocked on the 3rd check" \
	"active active down_blocked down_blocked" "$got"
expect "  ... the kill switch rule put in place once, the IPv6 block kept, nothing re-applied, no probe" \
	"exit-kill-on, $V6,$KS, [] 1" "$(fwcalls) $(fwstate) [$(reloads)] $(pings)"
sed -i "/^$KS\$/d" "$work/fwstate"
ticks -
expect "  ... the rule removed meanwhile (a reload): put back at the next check" "down_blocked exit-kill-on,exit-kill-on," "$got $(fwcalls)"
peer_status true
ticks ok
expect "  ... Running again: active, re-applied (that lifts the rule once the exit node is accepted)" \
	"active reload active," "$got $(reloads)"
expect "  ... the state file says active" "active" "$(jsonfilter -i "$work/exit-state.json" -e @.state)"

# Every way of not running, without and with the user's stop.
for b in Starting NeedsLogin NeedsMachineAuth Stopped NoState ""; do
	fresh 1
	echo $V6 > "$work/fwstate"
	ticks ok
	backend "$b"
	ticks - - -
	expect "daemon ${b:-not answering}, kill switch on: down_blocked on the 3rd check, kill switch rule in place" \
		"active active down_blocked exit-kill-on, $V6,$KS," "$got $(fwcalls) $(fwstate)"
	fresh 1
	printf '%s\n' $V6 $KS > "$work/fwstate"
	ticks ok
	echo "$NOW" > "$work/user-stopped"
	backend "$b"
	ticks -
	expect "  ... after the user's Disconnect or Log out (marker): stopped at once, kill switch rule and IPv6 block lifted" \
		"stopped exit-kill-off exit-v6-block-off, " "$got $(fwcalls) $(fwstate)"
	ticks - - -
	expect "  ... and it stays so (nothing more to change)" "stopped stopped stopped exit-kill-off exit-v6-block-off," "$got $(fwcalls)"
done

fresh 0
echo $V6 > "$work/fwstate"
ticks ok
backend Starting
ticks - - -
expect "kill switch off, the daemon starting: down_fallback on the 3rd check, the IPv6 block lifted (the LAN uses the uplink)" \
	"active active down_fallback exit-v6-block-off, " "$got $(fwcalls) $(fwstate)"
uci set flowmesh.main.kill_switch=1
ticks -
expect "  ... kill switch turned on meanwhile: down_blocked, rule in place" "down_blocked exit-v6-block-off,exit-kill-on, $KS," "$got $(fwcalls) $(fwstate)"
uci set flowmesh.main.kill_switch=0
ticks -
expect "  ... and off again: down_fallback, rule lifted" "down_fallback exit-v6-block-off,exit-kill-on,exit-kill-off, " "$got $(fwcalls) $(fwstate)"
peer_status true
ticks ok
expect "  ... Running again: active, re-applied" "active reload active," "$got $(reloads)"

fresh 1
ticks ok
backend Starting
ticks - - -
uci delete flowmesh.main.use_exit_node
ticks -
expect "exit node unset while down_blocked: none, the watcher's kill switch rule lifted" "none exit-kill-on,exit-kill-off, " "$got $(fwcalls) $(fwstate)"
uci set flowmesh.main.use_exit_node=$EXIT

fresh 1
ticks ok
backend Starting
STOP=1
ticks - - -
STOP=
expect "being stopped (SIGTERM): the state is recorded, the firewall left alone" "active active down_blocked " "$got $(fwcalls)"

# The marker against a Running daemon.
fresh 1
echo $((NOW - 10)) > "$work/user-stopped"
ticks ok
expect "Running, marker from before the status was read: removed (FlowMesh was brought up again)" "active no" \
	"$got $([ -e "$work/user-stopped" ] && echo yes || echo no)"
fresh 1
echo garbage > "$work/user-stopped"
ticks ok
expect "  ... an unreadable marker too" "no" "$([ -e "$work/user-stopped" ] && echo yes || echo no)"
fresh 1
echo "$NOW" > "$work/user-stopped"
ticks ok
expect "  ... one from the same second is kept (the status may predate the stop), the exit node handled as usual" \
	"active yes" "$got $([ -e "$work/user-stopped" ] && echo yes || echo no)"
# Disconnect, Reconnect.
fresh 1
echo $V6 > "$work/fwstate"
ticks ok
echo "$NOW" > "$work/user-stopped"
backend Stopped
ticks - -
rm -f "$work/user-stopped"   # (the helper's reconnect)
peer_status true
ticks ok
expect "Disconnect then Reconnect: stopped, then active and re-applied (the IPv6 block comes back with it)" \
	"active reload active," "$got $(reloads)"

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
fresh 1
printf '{"want":"%s","state":"down_blocked","since":77}\n' $EXIT > "$work/exit-state.json"
ticks ok
expect "  ... a recorded down_blocked, the daemon Running now: active, re-applied" "active reload active," "$got $(reloads)"

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

# --- what the names become ---
js='{"suffix":"Owt.Test.","extraRecords":[{"name":"app.owt-extra.test","type":"A","value":"100.64.0.200"},{"name":"APP.owt-extra.test.","type":"A","value":"100.64.0.200"},{"name":"app.owt-extra.test","type":"AAAA","value":"FD7A:115C:A1E0::C8"},{"name":"svc.owt.test","type":"a","value":"100.64.0.201"},{"name":"*.wild.example","type":"A","value":"100.64.0.202"},{"name":"bad name","type":"A","value":"1.2.3.4"},{"name":"x/y","type":"A","value":"1.2.3.4"},{"name":"v6inA.example","type":"A","value":"fd00::1"},{"name":"txt.example","type":"TXT","value":"hello"},{"name":"cname.example","type":"CNAME","value":"app.owt-extra.test"},{"name":"inj.example","type":"A","value":"1.2.3.4 evil.example"}],"routes":{"64.100.in-addr.arpa":[],"0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa":[],"Corp.Example.":["10.0.0.53","10.0.0.54:5353","[fd00::53]:53","fd00::54","https://dns.example/dns-query","1.2.3.4; rm -rf /"],"q\"uote.test":["1.1.1.1"]}}'
expect "suffix: lower-cased, without the trailing dot" "owt.test" "$(dns_suffix "$js")"
expect "suffix: none (a node name without a dot)" "" "$(dns_suffix '{"suffix":"","extraRecords":[],"routes":{}}')"
expect "hosts: A and AAAA records only, valid names and addresses, case and trailing dots, no duplicates, no wildcards" \
	"100.64.0.200 app.owt-extra.test,100.64.0.201 svc.owt.test,fd7a:115c:a1e0::c8 app.owt-extra.test," \
	"$(dns_hosts "$js" | tr '\n' ',')"
expect "splits: each resolver as dnsmasq takes it (port as #port), reverse zones and invalid names left out, URLs and garbage skipped and listed" \
	"- corp.example 1.2.3.4;,- corp.example https://dns.example/dns-query,corp.example 10.0.0.53,corp.example 10.0.0.54#5353,corp.example fd00::53#53,corp.example fd00::54," \
	"$(dns_splits "$js" | tr '\n' ',')"
# Resolver addresses are checked strictly: a server= dnsmasq cannot parse must never reach it.
js2='{"suffix":"","extraRecords":[],"routes":{"a.example":["999.1.1.1","1.2.3.4:99999",":::","fe80::1::2","01.2.3.4","1.2.3","1.2.3.4:0","::","1:2:3:4:5:6:7:8:9","12345::1","[fe80::1::2]:53","[fd00::1]:65536","1.2.3.4:65535","10.0.0.53","10.0.0.54:5353","255.255.255.255","fd00::53","FD00:0:0:0:0:0:0:54","::1","fd00::","[fd00::1]:53","1:2:3:4:5:6:7::"]}}'
got=$(dns_splits "$js2")
expect "splits: invalid resolvers skipped and listed (999.1.1.1, port 99999, :::, two ::, leading zero, 3 octets, port 0, :: alone, 9 groups, 5-digit group, bracketed bad v6, port 65536)" \
	"- a.example 01.2.3.4,- a.example 1.2.3,- a.example 1.2.3.4:0,- a.example 1.2.3.4:99999,- a.example 12345::1,- a.example 1:2:3:4:5:6:7:8:9,- a.example 999.1.1.1,- a.example ::,- a.example :::,- a.example [fd00::1]:65536,- a.example [fe80::1::2]:53,- a.example fe80::1::2," \
	"$(printf '%s\n' "$got" | grep '^- ' | tr '\n' ',')"
expect "splits: valid v4, v4:port (max port), v6 (compressed, full, lower-cased, ::1, trailing ::, 7 groups + ::), [v6]:port kept" \
	"a.example 1.2.3.4#65535,a.example 10.0.0.53,a.example 10.0.0.54#5353,a.example 1:2:3:4:5:6:7::,a.example 255.255.255.255,a.example ::1,a.example fd00:0:0:0:0:0:0:54,a.example fd00::,a.example fd00::1#53,a.example fd00::53," \
	"$(printf '%s\n' "$got" | grep -v '^- ' | tr '\n' ',')"
expect "entries: the suffix to FlowMesh's resolver, split domains to their own resolvers; one rebind exception per domain" \
	"server /owt.test/100.100.100.100,rebind_domain owt.test,server /corp.example/10.0.0.53,rebind_domain corp.example,server /corp.example/10.0.0.54#5353,server /lab.example/10.0.0.9,rebind_domain lab.example," \
	"$(dns_wanted owt.test "corp.example 10.0.0.53
corp.example 10.0.0.54#5353
lab.example 10.0.0.9" | tr '\n' ',')"
expect "entries: no suffix, no splits: none" "" "$(dns_wanted "" "")"
# Which resolvers the router reaches through the mesh: mesh addresses, or inside a peer's primary
# subnet route (passed only with accept_routes on); default routes do not count.
expect "reachable: mesh addresses (v4, v6, with a port) always; others only inside a route given; /0 never" \
	"a.example 10.0.0.53,~ a.example 10.0.1.53,b.example 100.100.100.100#53,c.example fd7a:115c:a1e0::35,d.example fd00:1::53#53,~ d.example fd00:2::53,~ e.example 8.8.8.8,f.example 192.168.7.200,~ f.example 192.168.7.100,~ g.example 100.128.0.1," \
	"$(dns_reachable "10.0.0.0/24 fd00:1::/64 0.0.0.0/0 ::/0 192.168.7.128/25" "a.example 10.0.0.53
a.example 10.0.1.53
b.example 100.100.100.100#53
c.example fd7a:115c:a1e0::35
d.example fd00:1::53#53
d.example fd00:2::53
e.example 8.8.8.8
f.example 192.168.7.200
f.example 192.168.7.100
g.example 100.128.0.1" | tr '\n' ',')"
expect "reachable: no routes (accept_routes off): only mesh addresses" "~ a.example 10.0.0.53,b.example 100.64.0.53," \
	"$(dns_reachable "" "a.example 10.0.0.53
b.example 100.64.0.53" | tr '\n' ',')"
expect "not JSON: nothing" "||" "$(dns_suffix 'not json {')|$(dns_hosts 'not json {')|$(dns_splits 'not json {')"

# --- dnsmasq entries and the hosts file ---
sec=$(dnsmasq_sections | head -1)
d=dhcp.$sec
count() { count_value "$sec" "$1" "$2"; }
dnsmasq_reloads() { cat "$work/dnsmasq-reloads" 2> /dev/null | wc -l | tr -d ' '; }
hosts() { cat "$work/hosts/flowmesh" 2> /dev/null | grep -v '^#' | tr '\n' ','; }
E_SUF='server /owt.test/100.100.100.100
rebind_domain owt.test'
E_SPLIT='server /corp.owt-split.test/10.0.0.53
rebind_domain corp.owt-split.test'
H1='100.64.0.200 app.owt-extra.test'
# The user's own entries, one of them the same as one of ours.
uci add_list $d.server=/corp.example/10.0.0.53
uci add_list $d.rebind_domain=corp.example
uci add_list $d.server=/owt.test/100.100.100.100
uci commit dhcp
uci set $d.owt_staged=1   # a user change staged, not applied
dns_reconcile "$E_SUF
$E_SPLIT" "$H1"
expect "added: the suffix's and the split domain's server and rebind_domain (the user's same server entry not doubled)" "1 1 1 1" \
	"$(count server /owt.test/100.100.100.100) $(count rebind_domain owt.test) $(count server /corp.owt-split.test/10.0.0.53) $(count rebind_domain corp.owt-split.test)"
expect "  ... in /etc/config/dhcp (committed)" "1" "$(grep -c "list server '/corp.owt-split.test/10.0.0.53'" /etc/config/dhcp)"
expect "  ... recorded as ours: three entries (not the user's server /owt.test/)" \
	"$sec rebind_domain corp.owt-split.test,$sec rebind_domain owt.test,$sec server /corp.owt-split.test/10.0.0.53," \
	"$(sort "$work/lan-dns.owned" | tr '\n' ',')"
expect "  ... the hosts file has the extra record" "$H1," "$(hosts)"
expect "  ... dnsmasq reloaded once (for both)" "1" "$(dnsmasq_reloads)"
expect "  ... the user's staged change still staged, not committed" "1 0" \
	"$(uci changes dhcp | grep -c owt_staged) $(grep -c owt_staged /etc/config/dhcp)"
dns_reconcile "$E_SPLIT
$E_SUF" "$H1"
expect "same again: nothing changed, no reload" "1" "$(dnsmasq_reloads)"
dns_reconcile "$E_SUF" "$H1"
expect "a split domain gone: its server and exception removed, the rest kept, reloaded" "0 0 1 1 2" \
	"$(count server /corp.owt-split.test/10.0.0.53) $(count rebind_domain corp.owt-split.test) $(count rebind_domain owt.test) $(count server /owt.test/100.100.100.100) $(dnsmasq_reloads)"
dns_reconcile "$E_SUF" "$H1
fd7a:115c:a1e0::c8 app.owt-extra.test"
expect "hosts content changed (UCI not): file replaced, reloaded" "$H1,fd7a:115c:a1e0::c8 app.owt-extra.test, 3" "$(hosts) $(dnsmasq_reloads)"
expect "  ... no temporary file left beside it" "flowmesh" "$(ls -A "$work/hosts")"
uci -q revert dhcp
uci del_list $d.rebind_domain=owt.test; uci commit dhcp
uci set $d.owt_staged=1
dns_reconcile "$E_SUF" "$H1
fd7a:115c:a1e0::c8 app.owt-extra.test"
expect "our entry removed by hand: put back" "1 4" "$(count rebind_domain owt.test) $(dnsmasq_reloads)"
dns_reconcile "" ""
expect "none wanted: ours removed and the hosts file deleted; the user's server /owt.test/, /corp.example/ and rebind corp.example kept" \
	"0 no 1 1 1 5" \
	"$(count rebind_domain owt.test) $([ -e "$work/hosts/flowmesh" ] && echo yes || echo no) $(count server /owt.test/100.100.100.100) $(count server /corp.example/10.0.0.53) $(count rebind_domain corp.example) $(dnsmasq_reloads)"
expect "  ... the owned list is gone" "no" "$([ -e "$work/lan-dns.owned" ] && echo yes || echo no)"
expect "  ... the user's staged change still staged" "1 0" "$(uci changes dhcp | grep -c owt_staged) $(grep -c owt_staged /etc/config/dhcp)"
uci -q revert dhcp
dns_reconcile "" ""
expect "nothing to remove: no reload" "5" "$(dnsmasq_reloads)"
# An entry of ours that the user adds as well later: removing ours leaves theirs.
dns_reconcile "rebind_domain dup.test" ""
uci add_list $d.rebind_domain=dup.test; uci commit dhcp
dns_reconcile "" ""
expect "the user added the same entry as ours later: one is left (theirs)" "1" "$(count rebind_domain dup.test)"

# --- the whole loop: lan_dns, accept_routes, logout, SIGTERM ---
uci set flowmesh.main.lan_dns=1
uci set flowmesh.main.accept_routes=1   # (the split domain's resolver is in the peer's subnet route)
uci -q delete flowmesh.main.use_exit_node
uci commit flowmesh
peer_status true
printf '%s\n' '{"suffix":"owt.test","extraRecords":[{"name":"app.owt-extra.test","type":"A","value":"100.64.0.200"}],"routes":{"corp.owt-split.test":["10.0.0.53"],"64.100.in-addr.arpa":[]}}' > "$work/dns"
present() { echo "$(count rebind_domain owt.test) $(count server /corp.owt-split.test/10.0.0.53)$(count rebind_domain corp.owt-split.test) $(hosts)"; }
DNS_AT=0 NOW=5000
watch_tick
expect "loop, logged in, lan_dns on: the suffix, the split domain, the hosts file" "1 11 $H1," "$(present)"
expect "  ... nothing forwarded to FlowMesh's resolver but the suffix" "1" \
	"$(uci -q -X show "$d.server" | tr ' ' '\n' | grep -c '/100\.100\.100\.100')"
uci set flowmesh.main.lan_dns=0
NOW=5003; watch_tick
expect "  ... lan_dns=0: not before the next name check (10 s)" "1 11 $H1," "$(present)"
NOW=5010; watch_tick
expect "  ... lan_dns=0: removed at the next name check" "0 00 " "$(present)"
uci set flowmesh.main.lan_dns=1
NOW=5020; watch_tick
expect "  ... lan_dns on again: back" "1 11 $H1," "$(present)"
: > "$work/log"
uci set flowmesh.main.accept_routes=0
NOW=5030; watch_tick
expect "  ... accept_routes=0: the split domain's resolver (in a peer's subnet route) is not reachable: its server and exception removed, the rest kept" \
	"1 00 $H1," "$(present)"
expect "  ... logged, once" "1" "$(grep -c 'not reachable through the mesh.*corp.owt-split.test 10.0.0.53' "$work/log")"
NOW=5040; watch_tick
expect "  ... (not logged again)" "1" "$(grep -c 'not reachable through the mesh' "$work/log")"
uci set flowmesh.main.accept_routes=1
NOW=5050; watch_tick
expect "  ... accept_routes=1: forwarded again" "1 11 $H1," "$(present)"
no_peer_status
NOW=5060; watch_tick
expect "  ... no peer routes it any more: removed" "1 00 $H1," "$(present)"
peer_status true
NOW=5070; watch_tick
printf '{"BackendState":"Starting"}\n' > "$work/status"
NOW=5080; watch_tick
expect "  ... starting: left as it was" "1 11 $H1," "$(present)"
printf '{"BackendState":"NeedsLogin"}\n' > "$work/status"
NOW=5090; watch_tick
expect "  ... logged out: removed" "0 00 " "$(present)"
uci commit flowmesh

# The real process: SIGTERM removes its entries, the hosts file and the state file.
peer_status true
uci set flowmesh.main.use_exit_node=$EXIT; uci commit flowmesh
i=0; while [ "$i" -lt 50 ]; do echo ok; i=$((i + 1)); done > "$work/ping"
FLOWMESH_WATCH_LIB= sh "$src" &
wpid=$!
i=0
while [ "$i" -lt 10 ] && [ "$(present)" != "1 11 $H1," ]; do sleep 1; i=$((i + 1)); done
sleep 1
expect "process: entries and hosts file added, state file written" "1 11 $H1, active" \
	"$(present) $(jsonfilter -i "$work/exit-state.json" -e @.state 2>/dev/null)"
t0=$(date +%s)
kill -TERM "$wpid"
wait "$wpid"
expect "  ... SIGTERM: exits within 5 s, entries and hosts file removed, state file deleted" "yes 0 00  no" \
	"$([ $(($(date +%s) - t0)) -le 5 ] && echo yes || echo no) $(present) $([ -e "$work/exit-state.json" ] && echo yes || echo no)"
wpid=
dns_reconcile "rebind_domain again.test" "$H1"
FLOWMESH_WATCH_LIB= sh "$src" cleanup
expect "cleanup command: removes them too (watcher not running)" "0 no" \
	"$(count rebind_domain again.test) $([ -e "$work/hosts/flowmesh" ] && echo yes || echo no)"

echo "watch_test: $fails failed"
exit "$fails"
