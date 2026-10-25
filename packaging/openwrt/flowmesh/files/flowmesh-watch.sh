#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# flowmesh-watch (installed as /usr/libexec/flowmesh-watch): runs with the flowmesh service, as its
# second procd instance.
#
#   flowmesh-watch           watch until SIGTERM, then undo what it set up (below)
#   flowmesh-watch cleanup   only the undoing (the service's stop and the package's removal call it, in
#                            case the watcher is not running)
#
# 1. The exit node chosen in /etc/config/flowmesh (use_exit_node). Every 3 s it pings that node over
#    the mesh (one ICMP echo through the tunnel, 2 s); 3 failures in a row: offline, 3 answers in a
#    row: back (once an offline exit node answers, the two confirming probes follow 1 s apart: its
#    tunnel needs some seconds before the first answer, and 2 x 3 s more on top would keep the LAN
#    waiting past 15 s). A probe answers only when both the discovery-level `flowmesh ping` and then an IP
#    ping through the tunnel do: the first alone keeps answering while IP traffic through the
#    tunnel is dead (a stale endpoint, a broken WireGuard session), which is exactly when the LAN
#    has lost its exit node. The IP ping is sent only once discovery answers: IP packets sent to an
#    exit node that is away make the tunnel back off its handshakes, and it then comes back about
#    10 s late. (The IP ping goes from the router itself, so through the mesh route of the main
#    table, not the exit node's table.) A mesh ACL may refuse the router ICMP to the exit node: until
#    an echo has been answered once for the chosen exit node (since it was chosen, or since the
#    watcher started), a discovery answer alone counts, and that is logged once. Otherwise a filter
#    would keep the exit node "offline" for good (with the kill switch on: the LAN without Internet).
#    With the kill switch on, offline only changes the state (the daemon itself drops the LAN's
#    Internet traffic while its exit node is away). With it off, it falls back to the local uplink:
#    it writes the state "offline_fallback" first and then re-applies the settings
#    (`/etc/init.d/flowmesh reload`), which leave the exit node out for as long as the state file
#    says so (flowmesh_load_prefs); back online, it writes "active" and re-applies again. UCI is the
#    user's intent and is never changed here. An exit node that is not in the mesh map, or does not
#    offer itself as one, is "missing"; once it is back the settings are re-applied (which lifts the
#    kill switch rule and uses it). If the daemon's exit node is not what the state calls for (e.g.
#    right after a start it took one that turned out not to be in the mesh), the settings are
#    re-applied, at most every 30 s. Otherwise settings are re-applied only on a change of state.
#    FlowMesh itself not running (the daemon not Running for 3 checks in a row: not answering, still
#    starting because the control server cannot be reached, its login refused or expired) means no
#    exit node either, and the LAN would go straight out of the uplink: with the kill switch on the
#    state is "down_blocked" and the watcher puts the kill switch rule in place itself
#    (flowmesh-fw exit-kill-on; the IPv6 block stays); off, "down_fallback" and both rules are lifted.
#    Not so after the user's own Disconnect or Log out (the LuCI helper's down/logout leave the
#    marker /etc/flowmesh/user-stopped, which its up/reconnect remove): then the state is "stopped",
#    and the kill switch rule and the IPv6 block are lifted (the LAN uses the local uplink). A marker
#    is also removed once the daemon is Running again after the stop was seen (it was brought up
#    some other way, e.g. `flowmesh up`): the watcher notes in the marker that it saw the daemon not
#    Running in a check that began after the marker was written, and only a noted marker expires on
#    Running (a check that reads Running just before the stop takes effect leaves it alone). Running
#    again after down_*: the state goes back to "active" and the settings are re-applied (which
#    lifts the rule once the exit node is usable).
#    The state, for the LuCI page: /var/run/flowmesh/exit-state.json,
#    {"want":"<use_exit_node>","state":"none|active|offline_blocked|offline_fallback|missing|
#    down_blocked|down_fallback|stopped","since":N} ("want" exactly as in UCI).
# 2. Mesh names for the LAN (lan_dns, on when unset). While the node is logged in, every 10 s it reads
#    `flowmesh dns status --json`. The router runs the client with --accept-dns=false, so FlowMesh's
#    resolver (100.100.100.100) answers only the mesh's own names and fails everything else; so
#    only the mesh suffix goes there:
#    - the suffix: UCI dhcp list server '/<suffix>/100.100.100.100' and list rebind_domain
#      '<suffix>' (dnsmasq 2.90 and later discard mesh addresses as a rebind otherwise);
#    - the console's extra records (A and AAAA): a hosts file, /tmp/hosts/flowmesh (dnsmasq's
#      additional hosts directory), so a record's own name resolves and its subdomains still go to
#      the normal DNS;
#    - split-DNS domains: list server '/<domain>/<resolver>' straight to the resolvers the mesh
#      names for them (IPv4/IPv6 addresses, optionally with a port; other kinds are skipped and
#      logged), and list rebind_domain '<domain>' (intranet answers are usually private). Only
#      resolvers the router reaches through the mesh right now: a mesh address, or (with
#      accept_routes on) an address inside a peer's primary subnet route. Any other is skipped and
#      logged, and a domain left without one stays with the normal DNS (dnsmasq would otherwise send
#      its queries out of the uplink to an intranet address and lose the domain). Re-checked at
#      every name check, so turning accept_routes on, or a route appearing, adds it.
#    In every dnsmasq section. Only the UCI entries it added are ever changed or removed: they are
#    listed in /etc/flowmesh/lan-dns.owned ("<section> <option> <value>" lines; on flash like
#    /etc/config/dhcp, and both survive a sysupgrade). An entry the user already has stays the
#    user's. dnsmasq is reloaded only when something changed. lan_dns=0, logging out, stopping the
#    service and removing the package remove the entries and the hosts file.

RESOLVER=100.100.100.100
PERIOD=3          # seconds between exit node probes
CONFIRM_PERIOD=1  # seconds between the probes that confirm an offline exit node is back
DNS_PERIOD=10     # seconds between name checks (and the daemon consistency check)
DEBOUNCE=3        # probes in a row that change the verdict
FIX_INTERVAL=30   # minimum seconds between consistency re-applies
EXIT_STATE=${FLOWMESH_EXIT_STATE:-/var/run/flowmesh/exit-state.json}
USER_STOPPED=${FLOWMESH_USER_STOPPED:-/etc/flowmesh/user-stopped}   # see 1. above (the LuCI helper)
APPLY_LOCK=${FLOWMESH_APPLY_LOCK:-/var/lock/flowmesh-apply.lock}   # prefs.sh's FM_APPLY_LOCK
FW_CMD=${FLOWMESH_WATCH_FW:-/usr/libexec/flowmesh-fw}
DNS_OWNED=${FLOWMESH_DNS_OWNED:-/etc/flowmesh/lan-dns.owned}
DNS_LOCK=${FLOWMESH_DNS_LOCK:-/var/lock/flowmesh-dns.lock}
HOSTS_FILE=${FLOWMESH_HOSTS_FILE:-/tmp/hosts/flowmesh}
# (Overridable for the tests.)
RELOAD_CMD=${FLOWMESH_WATCH_RELOAD:-/etc/init.d/flowmesh reload}
DNSMASQ_RELOAD_CMD=${FLOWMESH_WATCH_DNSMASQ_RELOAD:-/etc/init.d/dnsmasq reload}

log() { logger -t flowmesh-watch "$*"; }
now() { date +%s; }

# bounded <seconds> <command...>: the command (its stdout is ours), killed after <seconds>. (Not every
# BusyBox has `timeout`.) The watchdog keeps no descriptor of ours open, so $(bounded ...) does not
# wait for it, and it takes its sleep with it when it is cancelled.
bounded() {
	local secs=$1 pid w rc
	shift
	"$@" &
	pid=$!
	(
		sleep "$secs" &
		s=$!
		trap 'kill $s 2>/dev/null; exit 0' TERM
		wait $s
		kill "$pid" 2>/dev/null
	) < /dev/null > /dev/null 2>&1 &
	w=$!
	wait "$pid"
	rc=$?
	kill "$w" 2>/dev/null
	wait "$w" 2>/dev/null
	return $rc
}

# opt_bool <option> <default>: flowmesh.main.<option> read as config_get_bool does.
opt_bool() {
	case "$(uci -q get "flowmesh.main.$1")" in
	1 | on | true | yes | enabled) echo 1 ;;
	0 | off | false | no | disabled) echo 0 ;;
	*) echo "$2" ;;
	esac
}

# --- the exit node --------------------------------------------------------------------------------

# The exit node the LAN should use (as flowmesh_load_prefs decides it, before any fallback).
wanted_exit() {
	local w
	w=$(uci -q get flowmesh.main.use_exit_node)
	# Offering this router as an exit node wins (flowmesh_load_prefs).
	[ -n "$w" ] && [ "$(opt_bool exit_node 0)" = 1 ] && w=
	echo "$w"
}

write_state() {
	local tmp
	mkdir -p "$(dirname "$EXIT_STATE")"
	tmp=$EXIT_STATE.tmp.$$
	printf '{"want":"%s","state":"%s","since":%s}\n' "$E_WANT" "$E_STATE" "$E_SINCE" > "$tmp" &&
		mv -f "$tmp" "$EXIT_STATE"
}

# set_state <state>: record a change of state (and log it).
set_state() {
	[ "$1" = "$E_STATE" ] && return 0
	log "exit node ${E_WANT:-(none)}: ${E_STATE:-(start)} -> $1"
	E_STATE=$1
	E_SINCE=$(now)
	write_state
}

reapply() {
	log "re-applying the settings: $1"
	$RELOAD_CMD 2>&1 | logger -t flowmesh-watch
	E_FIX_AT=$(($(now) + FIX_INTERVAL))
}

# One probe of the exit node: true when it answers discovery and then an ICMP echo through the
# tunnel; discovery alone while no echo has been answered yet for this exit node (see 1. above).
# E_ICMP: an echo was answered; E_ICMP_NOTED: the "filtered" note was logged.
probe() {
	bounded $((PERIOD + 2)) flowmesh ping -c 1 --until-direct=false --timeout=2s "$E_WANT" > /dev/null 2>&1 ||
		return 1
	if bounded $((PERIOD + 2)) ping -c 1 -W 2 "$E_WANT" > /dev/null 2>&1; then
		E_ICMP=1
		return 0
	fi
	[ -n "$E_ICMP" ] && return 1
	if [ -z "$E_ICMP_NOTED" ]; then
		E_ICMP_NOTED=1
		log "exit node $E_WANT answers, but not ICMP through the tunnel (filtered?): checking it without the data-plane probe until it does"
	fi
	return 0
}

# adopt_recorded <want>: take over the state an earlier run of the watcher recorded for <want> (it
# was restarted); false when there is none.
adopt_recorded() {
	local want state since
	[ -r "$EXIT_STATE" ] || return 1
	want=$(jsonfilter -i "$EXIT_STATE" -e '@.want' 2>/dev/null) || return 1
	state=$(jsonfilter -i "$EXIT_STATE" -e '@.state' 2>/dev/null) || return 1
	since=$(jsonfilter -i "$EXIT_STATE" -e '@.since' 2>/dev/null) || return 1
	[ "$want" = "$1" ] || return 1
	case "$state" in active | offline_blocked | offline_fallback | missing | down_blocked | down_fallback | stopped) ;;
	*) return 1 ;; esac
	case "$since" in '' | *[!0-9]*) return 1 ;; esac
	E_STATE=$state E_SINCE=$since
}

# The user stopped FlowMesh (Disconnect or Log out in LuCI): the marker exists.
user_stopped() { [ -e "$USER_STOPPED" ]; }

# The marker: "<time written>" (the helper, just before its down/logout), then "<time> seen" once a
# check that began after that second has read a state other than Running: the stop has taken
# effect (the helper writes the marker immediately before the CLI call, so a status read that began
# in a later second sees its result, or the CLI failed and the helper removed the marker again).
user_stop_seen() {
	local t rest
	read -r t rest < "$USER_STOPPED" 2> /dev/null
	[ "$rest" = seen ] && return 0
	case "$t" in '' | *[!0-9]*) t=0 ;; esac
	[ "${T_STATUS:-0}" -gt "$t" ] || return 0
	printf '%s seen\n' "$t" > "$USER_STOPPED.tmp" && mv -f "$USER_STOPPED.tmp" "$USER_STOPPED"
}

# The daemon is Running: a marker whose stop was seen belongs to a stop that is over (FlowMesh was
# brought up again, maybe not through LuCI). One not seen yet stays: this check may have read the
# status just before the stop took effect. (An unreadable marker is not the helper's: removed.)
user_stop_expire() {
	local t rest
	user_stopped || return 0
	read -r t rest < "$USER_STOPPED" 2> /dev/null
	case "$t" in [0-9]*) [ "$rest" = seen ] || return 0 ;; esac
	rm -f "$USER_STOPPED"
	log "FlowMesh is running again: the user's stop is over"
}

# fw_has <rule name>: the firewall has that rule (UCI; flowmesh-fw is its only writer).
fw_has() { uci -q -X show firewall | grep -q "\.name='$1'\$"; }

# exit_fw block|open: block, the kill switch rule in place (the IPv6 block left as it is); open,
# neither the kill switch rule nor the IPv6 block. Through flowmesh-fw, holding the apply lock (an
# apply in progress decides the firewall too), and only when something is to change; not done when
# the lock stays taken for 10 s (the next check tries again) or the watcher is being stopped.
exit_fw() {
	local args=
	case "$1" in
	block) fw_has flowmesh_exit_kill_switch || args="exit-kill-on" ;;
	open)
		fw_has flowmesh_exit_kill_switch && args="exit-kill-off"
		fw_has flowmesh_exit_block_ipv6 && args="$args exit-v6-block-off"
		;;
	esac
	[ -n "$args" ] && [ -z "$STOP" ] || return 0
	mkdir -p "$(dirname "$APPLY_LOCK")"
	(
		w=0
		until flock -n 7; do
			[ "$w" -ge 10 ] && { log "the apply lock stays taken: firewall ($args) left for the next check"; exit 1; }
			sleep 1
			w=$((w + 1))
		done
		log "firewall: $args (exit node ${E_WANT}, $E_STATE)"
		# shellcheck disable=SC2086 # the actions, one word each
		$FW_CMD $args 2>&1 | logger -t flowmesh-watch
	) 7<> "$APPLY_LOCK"
}

# Every check, exit node chosen or not ($STATUS_BACKEND read, its read begun at $T_STATUS).
user_stop_track() {
	user_stopped || return 0
	if [ "$STATUS_BACKEND" = Running ]; then
		user_stop_expire
	else
		user_stop_seen
	fi
}

# down_tick <kill switch>: the daemon is not Running ($STATUS_BACKEND, empty when it does not answer).
down_tick() {
	E_OK=0 E_FAIL=0 E_ABSENT=0
	if user_stopped; then
		E_DOWN=0
		set_state stopped
		exit_fw open
		return 0
	fi
	E_DOWN=$((E_DOWN + 1))
	[ "$E_DOWN" -ge "$DEBOUNCE" ] || return 0
	if [ "$1" = 1 ]; then
		set_state down_blocked
		exit_fw block
	else
		set_state down_fallback
		exit_fw open
	fi
}

# exit_tick <status json>: one step, once the daemon's status was read ($STATUS_BACKEND: its state).
exit_tick() {
	local status=$1 want kill present prev
	want=$(wanted_exit)
	if [ "$want" != "$E_WANT" ] || [ -z "$E_STATE" ]; then
		prev=$E_STATE
		E_WANT=$want
		E_OK=0 E_FAIL=0 E_ABSENT=0 E_DOWN=0
		E_ICMP= E_ICMP_NOTED=
		E_STATE=
		if [ -z "$want" ]; then
			set_state none
			# (A kill switch rule this watcher put in place has no exit node to stand for now.)
			[ "$prev" = down_blocked ] && exit_fw open
		elif ! adopt_recorded "$want"; then
			set_state active
		fi
	fi
	[ -n "$want" ] || return 0
	kill=$(opt_bool kill_switch 1)

	if [ "$STATUS_BACKEND" != Running ]; then
		down_tick "$kill"
		return 0
	fi
	E_DOWN=0
	case "$E_STATE" in
	down_* | stopped)
		# FlowMesh is running again: the exit node (if it is in the mesh) is back in the daemon's
		# routing; the re-apply lifts the kill switch rule, or keeps it when the exit node is refused.
		E_OK=0 E_FAIL=0 E_ABSENT=0
		set_state active
		reapply "FlowMesh is running again"
		return 0
		;;
	esac
	present=0
	echo "$status" | jsonfilter -e '@.Peer[@.ExitNodeOption=true].TailscaleIPs[*]' 2>/dev/null |
		grep -qxF "$want" && present=1

	if [ "$present" = 0 ]; then
		E_OK=0 E_FAIL=0
		E_ABSENT=$((E_ABSENT + 1))
		[ "$E_ABSENT" -ge "$DEBOUNCE" ] && set_state missing
		return 0
	fi
	E_ABSENT=0
	if [ "$E_STATE" = missing ]; then
		E_OK=0 E_FAIL=0
		set_state active
		reapply "exit node $want is in the mesh again"
		return 0
	fi

	if probe; then
		# (The probe itself goes through the tunnel: by the time the LAN is moved back, WireGuard
		# has its session.)
		E_OK=$((E_OK + 1)) E_FAIL=0
	else
		[ -n "$STOP" ] && return 0   # (interrupted by SIGTERM: not an answer either way)
		E_FAIL=$((E_FAIL + 1)) E_OK=0
	fi

	# (the next probe: sooner while an offline exit node is being confirmed back)
	case "$E_STATE" in offline_*) [ "$E_OK" -ge 1 ] && E_NEXT=$CONFIRM_PERIOD ;; esac

	case "$E_STATE" in
	active)
		if [ "$E_FAIL" -ge "$DEBOUNCE" ]; then
			if [ "$kill" = 1 ]; then
				set_state offline_blocked
			else
				# The state file first: the reload reads it.
				set_state offline_fallback
				reapply "exit node $want is offline: falling back to the local uplink"
			fi
		fi
		;;
	offline_blocked)
		if [ "$E_OK" -ge "$DEBOUNCE" ]; then
			set_state active
		elif [ "$kill" = 0 ]; then
			set_state offline_fallback
			reapply "kill switch off while exit node $want is offline: falling back to the local uplink"
		fi
		;;
	offline_fallback)
		if [ "$E_OK" -ge "$DEBOUNCE" ]; then
			set_state active
			reapply "exit node $want is back"
		elif [ "$kill" = 1 ]; then
			set_state offline_blocked
			reapply "kill switch on while exit node $want is offline"
		fi
		;;
	esac
}

# The daemon's exit node must be what the state calls for: the chosen one while active or blocked,
# none otherwise. A mismatch (e.g. right after a start the CLI cannot check the exit node yet and the
# daemon takes one that is not in the mesh; or an apply failed) is fixed by re-applying.
exit_consistency() {
	local expect have prefs
	[ -n "$E_WANT" ] && [ "$STATUS_BACKEND" = Running ] || return 0
	case "$E_STATE" in
	active | offline_blocked)
		# (Not in the mesh map at the last check: a reload has just dropped it, and the verdict
		# "missing" is a few checks away.)
		[ "$E_ABSENT" -gt 0 ] && return 0
		expect=$E_WANT
		;;
	*) expect= ;;
	esac
	# (No answer: no verdict.)
	prefs=$(bounded 5 flowmesh debug prefs 2> /dev/null) && [ -n "$prefs" ] || return 0
	have=$(echo "$prefs" | jsonfilter -e '@.exit_node' 2> /dev/null)
	[ "$have" = "$expect" ] && return 0
	[ "$(now)" -ge "${E_FIX_AT:-0}" ] || return 0
	reapply "the daemon's exit node is '$have', expected '$expect' ($E_STATE)"
}

# --- mesh names for the LAN -----------------------------------------------------------------------

# Every string in a JSON object of arrays (jsonfilter's rendering of `routes`), as "<key> <string>"
# lines (keys of empty arrays do not appear). (jsonfilter cannot list keys, and jshn mangles them.)
route_pairs() {
	awk '
		{ s = s $0 "\n" }
		END {
			n = length(s); depth = 0; instr = 0
			for (i = 1; i <= n; i++) {
				c = substr(s, i, 1)
				if (instr) {
					# (jsonfilter writes "/" as "\/"; other escapes are kept, and make the value invalid.)
					if (c == "\\") { e = substr(s, i + 1, 1); if (e == "/") tok = tok "/"; else tok = tok "\\" e; i++; continue }
					if (c == "\"") { instr = 0; if (depth == 1) key = tok; else if (depth == 2) print key " " tok; continue }
					tok = tok c
					continue
				}
				if (c == "\"") { instr = 1; tok = ""; continue }
				if (c == "{" || c == "[") { depth++; continue }
				if (c == "}" || c == "]") { depth--; continue }
			}
		}'
}

# (awk) name(d): d lower-cased without trailing dots, or "" when it is not a valid DNS name.
NAME_AWK='function name(d) {
	d = tolower(d); sub(/\.+$/, "", d)
	if (d == "" || length(d) > 253 || d !~ /^[a-z0-9_][a-z0-9_-]*(\.[a-z0-9_][a-z0-9_-]*)*$/) return ""
	return d
}'

# dns_suffix <`dns status --json`>: the mesh suffix; nothing when there is none (a node name without
# a dot).
dns_suffix() {
	jsonfilter -s "$1" -e '@.suffix' 2> /dev/null | awk "$NAME_AWK"' { d = name($0); if (d != "") print d; exit }'
}

# dns_hosts <`dns status --json`>: "<address> <name>" lines, sorted and unique, for the extra records
# of type A (IPv4 value) and AAAA (IPv6 value); other types, wildcards and invalid names or
# addresses are skipped.
dns_hosts() {
	local i=0 n t v
	while [ "$i" -lt 1000 ]; do
		n=$(jsonfilter -s "$1" -e "@.extraRecords[$i].name" 2> /dev/null) || break
		t=$(jsonfilter -s "$1" -e "@.extraRecords[$i].type" 2> /dev/null)
		v=$(jsonfilter -s "$1" -e "@.extraRecords[$i].value" 2> /dev/null)
		printf '%s\t%s\t%s\n' "$t" "$v" "$n"
		i=$((i + 1))
	done | awk -F '\t' "$NAME_AWK"'
		{
			d = name($3); t = toupper($1); v = $2
			if (d == "") next
			if (t == "A" && v ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print v " " d
			else if (t == "AAAA" && v ~ /^[0-9a-fA-F:.]+$/ && v ~ /:/) print tolower(v) " " d
		}' | sort -u
}

# (awk) Strict address checks for resolvers (dnsmasq may refuse to start on a server= it cannot
# parse, which would take all LAN DNS down): v4(a) four decimal octets 0-255 without leading zeros;
# v6(a) hex groups of 1-4 digits, at most one "::", 8 groups without it and at most 7 with it, not
# "::" alone (embedded IPv4 forms are not accepted); port(p) 1-65535.
ADDR_AWK='function v4(a,   p, i) {
	if (split(a, p, ".") != 4) return 0
	for (i = 1; i <= 4; i++)
		if (p[i] !~ /^(0|[1-9][0-9]?[0-9]?)$/ || p[i] + 0 > 255) return 0
	return 1
}
function v6(a,   t, n, g, i, c, dc) {
	if (a !~ /^[0-9a-fA-F:]+$/ || a ~ /:::/) return 0
	t = a; dc = gsub(/::/, "", t)
	if (dc > 1) return 0
	# A single ":" may not start or end the address (only "::" may).
	if (a ~ /^:[^:]/ || a ~ /[^:]:$/) return 0
	n = split(a, g, ":"); c = 0
	for (i = 1; i <= n; i++) {
		if (g[i] == "") continue
		if (length(g[i]) > 4) return 0
		c++
	}
	if (dc == 0) return c == 8
	return c >= 1 && c <= 7
}
function port(p) { return p ~ /^[1-9][0-9]?[0-9]?[0-9]?[0-9]?$/ && p + 0 <= 65535 }'

# dns_splits <`dns status --json`>: the split-DNS domains and their resolvers as dnsmasq takes them,
# "<domain> <address>[#<port>]" lines (sorted, unique), from "<IPv4>", "<IPv4>:<port>", "<IPv6>" or
# "[<IPv6>]:<port>" (strictly checked: ADDR_AWK); a resolver given any other way (a DNS-over-HTTPS
# URL, an invalid address or port) is listed as "- <domain> <resolver>" (skipped, and logged).
# Reverse zones (empty arrays) do not appear.
dns_splits() {
	jsonfilter -s "$1" -e '@.routes' 2> /dev/null | route_pairs | awk "$NAME_AWK
$ADDR_AWK"'
		{
			d = name($1); r = $2; out = ""
			if (d == "") next
			if (v4(r)) out = r
			else if (r ~ /^[0-9.]+:[0-9]+$/) {
				i = index(r, ":"); a = substr(r, 1, i - 1); p = substr(r, i + 1)
				if (v4(a) && port(p)) out = a "#" p
			} else if (r ~ /^\[[0-9a-fA-F:]+\]:[0-9]+$/) {
				i = index(r, "]"); a = substr(r, 2, i - 2); p = substr(r, i + 2)
				if (v6(a) && port(p)) out = tolower(a) "#" p
			} else if (v6(r)) out = tolower(r)
			if (out == "") { print "- " d " " r; next }
			print d " " out
		}' | sort -u
}

# (awk) Address ranges: in_net(a, net) is 1 when address a (IPv4 or IPv6, as ADDR_AWK accepts it)
# is inside net ("<address>/<length>"; a network of the other family, or not understood: 0).
NET_AWK='function hexval(h,   i, v) {
	h = tolower(h); v = 0
	for (i = 1; i <= length(h); i++) v = v * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1
	return v
}
# v6 groups of a into g[1..8] (as numbers); 0 when it is not an IPv6 address of that form.
function groups6(a, g,   n, p, i, j, k, head, tail, nh, nt) {
	if (a !~ /:/ || a !~ /^[0-9a-fA-F:]+$/) return 0
	if (index(a, "::")) {
		head = substr(a, 1, index(a, "::") - 1); tail = substr(a, index(a, "::") + 2)
		nh = head == "" ? 0 : split(head, p, ":")
		for (i = 1; i <= nh; i++) g[i] = hexval(p[i])
		nt = tail == "" ? 0 : split(tail, p, ":")
		if (nh + nt > 7) return 0
		for (i = nh + 1; i <= 8 - nt; i++) g[i] = 0
		for (j = 1; j <= nt; j++) g[8 - nt + j] = hexval(p[j])
		return 1
	}
	if (split(a, p, ":") != 8) return 0
	for (i = 1; i <= 8; i++) g[i] = hexval(p[i])
	return 1
}
function num4(a,   p) {
	if (split(a, p, ".") != 4) return -1
	return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4]
}
function in_net(a, net,   n, len, x, y, ga, gn, i, r) {
	n = index(net, "/"); if (!n) return 0
	len = substr(net, n + 1) + 0; net = substr(net, 1, n - 1)
	if (a ~ /^[0-9.]+$/) {
		if (net !~ /^[0-9.]+$/ || len < 0 || len > 32) return 0
		x = num4(a); y = num4(net)
		if (x < 0 || y < 0) return 0
		r = 2 ^ (32 - len)
		return int(x / r) == int(y / r)
	}
	if (len < 0 || len > 128 || !groups6(a, ga) || !groups6(net, gn)) return 0
	for (i = 1; i <= 8 && len > 0; i++) {
		if (len >= 16) { if (ga[i] != gn[i]) return 0 }
		else { r = 2 ^ (16 - len); if (int(ga[i] / r) != int(gn[i] / r)) return 0 }
		len -= 16
	}
	return 1
}'

# dns_reachable <routes> <splits ("<domain> <resolver>" lines)>: the splits whose resolver the router
# reaches through the mesh: a mesh address (100.64.0.0/10, fd7a:115c:a1e0::/48), or one inside
# <routes> (space-separated networks: the peers' primary subnet routes when accept_routes is on,
# else empty; default routes do not count). The others are listed as "~ <domain> <resolver>".
dns_reachable() {
	printf '%s\n' "$2" | awk -v routes="$1" "$NET_AWK"'
		BEGIN { nr = split(routes, rt, " ") }
		NF < 2 { next }
		{
			a = $2; sub(/#.*/, "", a); ok = 0
			if (in_net(a, "100.64.0.0/10") || in_net(a, "fd7a:115c:a1e0::/48")) ok = 1
			for (i = 1; !ok && i <= nr; i++)
				if (rt[i] !~ /\/0$/ && in_net(a, rt[i])) ok = 1
			print (ok ? "" : "~ ") $1 " " $2
		}'
}

# dns_wanted <suffix> <splits ("<domain> <resolver>" lines)>: the UCI entries, "<option> <value>"
# lines: the suffix to FlowMesh's resolver with a rebind exception (the answers are mesh addresses);
# each split domain to its own resolvers, also with a rebind exception (configured by the operator in
# the console; intranet split DNS typically answers private addresses, which dnsmasq would drop).
dns_wanted() {
	local d r last=
	if [ -n "$1" ]; then
		echo "server /$1/$RESOLVER"
		echo "rebind_domain $1"
	fi
	# (Sorted by domain: one exception per domain.)
	printf '%s\n' "$2" | while read -r d r; do
		[ -n "$r" ] || continue
		echo "server /$d/$r"
		[ "$d" = "$last" ] || echo "rebind_domain $d"
		last=$d
	done
}

dnsmasq_sections() {
	uci -q -X show dhcp | sed -n 's/^dhcp\.\([^.=]*\)=dnsmasq$/\1/p'
}

# The "<section> <option> <value>" lines for entries $1 ("<option> <value>" lines), in every dnsmasq
# section.
dns_entries() {
	local sec
	for sec in $(dnsmasq_sections); do
		printf '%s\n' "$1" | sed -n "s/^./$sec &/p"
	done
}

# count_value <section> <option> <value>: how many times that list has that value.
count_value() {
	uci -q -X show "dhcp.$1.$2" | sed -n "s/^dhcp\.$1\.$2=//p" | tr ' ' '\n' | sed "s/^'//; s/'\$//" | grep -cxF "$3"
}

# remove_one <section> <option> <value>: one occurrence (uci del_list removes them all).
remove_one() {
	local n
	n=$(count_value "$1" "$2" "$3")
	[ "$n" -gt 0 ] || return 1
	uci -q del_list "dhcp.$1.$2=$3"
	while [ "$n" -gt 1 ]; do
		uci -q add_list "dhcp.$1.$2=$3"
		n=$((n - 1))
	done
	return 0
}

# dns_reconcile <entries> <hosts>: make the UCI entries we own exactly <entries> ("<option> <value>"
# lines; empty: none), leaving the user's alone, and the hosts file exactly <hosts> ("<address>
# <name>" lines; empty: no file); dnsmasq is reloaded once if anything changed. Serialized with a
# cleanup run by another process.
dns_reconcile() {
	mkdir -p "$(dirname "$DNS_LOCK")"
	(
		flock 8 || exit 1
		DNS_CHANGED=
		dns_reconcile_locked "$1"
		hosts_sync "$2"
		if [ -n "$DNS_CHANGED" ]; then
			log "LAN names updated:$DNS_CHANGED"
			$DNSMASQ_RELOAD_CMD > /dev/null 2>&1
		fi
		true
	) 8<> "$DNS_LOCK"
}

# The extra records, for dnsmasq's additional hosts directory (/tmp/hosts, read by OpenWrt's dnsmasq
# at start and on SIGHUP, which `/etc/init.d/dnsmasq reload` sends). The file is entirely ours.
hosts_sync() {
	local new tmp
	if [ -z "$1" ]; then
		[ -e "$HOSTS_FILE" ] || return 0
		rm -f "$HOSTS_FILE"
		DNS_CHANGED="$DNS_CHANGED hosts file removed"
		return 0
	fi
	new="# FlowMesh: the mesh's extra DNS records (written by flowmesh-watch)
$1"
	[ "$(cat "$HOSTS_FILE" 2> /dev/null)" = "$new" ] && return 0
	mkdir -p "$(dirname "$HOSTS_FILE")"
	# (Written beside it on the same file system, then renamed: dnsmasq never reads half a file.)
	tmp=$(dirname "$HOSTS_FILE")/.flowmesh-hosts.$$
	printf '%s\n' "$new" > "$tmp" && mv -f "$tmp" "$HOSTS_FILE"
	DNS_CHANGED="$DNS_CHANGED hosts file ($(printf '%s\n' "$1" | wc -l | tr -d ' ') records)"
}

dns_reconcile_locked() {
	local entries=$1 want owned keep="" add="" drop="" fix="" line changed=0 staged=/tmp/.uci/dhcp aside
	want=$(dns_entries "$entries")
	owned=$(cat "$DNS_OWNED" 2> /dev/null)
	[ -z "$want" ] && [ -z "$owned" ] && return 0
	# Ours and still wanted (keep; put back if removed by hand: fix), ours and not wanted (drop).
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		if printf '%s\n' "$want" | grep -qxF "$line"; then
			keep="$keep$line
"
			set -- $line
			[ "$(count_value "$1" "$2" "$3")" -gt 0 ] || fix="$fix$line
"
		else
			drop="$drop$line
"
		fi
	done << EOF
$owned
EOF
	# Wanted and not ours: added, unless the user has that entry already (then it stays theirs).
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		printf '%s' "$keep" | grep -qxF "$line" && continue
		set -- $line
		[ "$(count_value "$1" "$2" "$3")" -gt 0 ] && continue
		add="$add$line
"
	done << EOF
$want
EOF
	if [ -z "$add$drop$fix" ]; then
		return 0
	fi

	# The user's staged dhcp changes are set aside while we commit (as flowmesh-fw does with the
	# firewall's), so they are neither committed with ours nor lost.
	aside=$(mktemp -d /tmp/flowmesh-dns.XXXXXX) || return 1
	[ -s "$staged" ] && mv -f "$staged" "$aside/dhcp"
	# Recorded as ours before UCI has them: a crash in between leaves no entry we do not know about.
	mkdir -p "$(dirname "$DNS_OWNED")"
	printf '%s%s%s' "$keep" "$add" "$drop" | sed '/^$/d' > "$DNS_OWNED.tmp" && mv -f "$DNS_OWNED.tmp" "$DNS_OWNED"
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		set -- $line
		remove_one "$1" "$2" "$3" && changed=1
	done << EOF
$drop
EOF
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		set -- $line
		uci -q add_list "dhcp.$1.$2=$3" && changed=1
	done << EOF
$add$fix
EOF
	[ "$changed" = 1 ] && uci -q commit dhcp
	printf '%s%s' "$keep" "$add" | sed '/^$/d' > "$DNS_OWNED.tmp" && mv -f "$DNS_OWNED.tmp" "$DNS_OWNED"
	[ -s "$DNS_OWNED" ] || rm -f "$DNS_OWNED"
	[ -f "$aside/dhcp" ] && mv -f "$aside/dhcp" "$staged"
	rm -rf "$aside"
	[ "$changed" = 1 ] && DNS_CHANGED="$DNS_CHANGED dhcp:$(printf '%s\n' "$entries" | sed 's/^./ &/' | tr '\n' ';')"
	return 0
}

# dns_tick <status json>
dns_tick() {
	local js suffix splits skipped unreach routes='' entries='' hosts=''
	case "$STATUS_BACKEND" in
	Running)
		if [ "$(opt_bool lan_dns 1)" = 1 ]; then
			js=$(bounded 5 flowmesh dns status --json 2> /dev/null) || return 0
			suffix=$(dns_suffix "$js")
			splits=$(dns_splits "$js")
			skipped=$(printf '%s\n' "$splits" | sed -n 's/^- //p')
			if [ "$skipped" != "$DNS_SKIPPED" ]; then
				DNS_SKIPPED=$skipped
				# shellcheck disable=SC2086 # one line
				[ -n "$skipped" ] && log "split DNS: resolvers dnsmasq cannot use, skipped: $(echo $skipped)"
			fi
			if [ "$(opt_bool accept_routes 0)" = 1 ]; then
				# shellcheck disable=SC2046 # one network per word
				routes=$(echo $(jsonfilter -s "$1" -e '@.Peer[*].PrimaryRoutes[*]' 2> /dev/null))
			fi
			splits=$(dns_reachable "$routes" "$(printf '%s\n' "$splits" | grep -v '^- ')")
			unreach=$(printf '%s\n' "$splits" | sed -n 's/^~ //p')
			if [ "$unreach" != "$DNS_UNREACH" ]; then
				DNS_UNREACH=$unreach
				# shellcheck disable=SC2086 # one line
				[ -n "$unreach" ] && log "split DNS: resolvers not reachable through the mesh (a peer's subnet route needs accept_routes), left to the normal DNS: $(echo $unreach)"
			fi
			entries=$(dns_wanted "$suffix" "$(printf '%s\n' "$splits" | grep -v '^~ ')")
			hosts=$(dns_hosts "$js")
		fi
		;;
	NeedsLogin | NeedsMachineAuth | Stopped) ;;
	*) return 0 ;;   # starting: leave things as they are
	esac
	dns_reconcile "$entries" "$hosts"
}

# --- the loop -------------------------------------------------------------------------------------

watch_tick() {
	local status t
	# (`status` exits 1 unless the node is Running, so its output decides. The daemon not answering,
	# e.g. restarting: an empty state, which only the exit node part acts on.)
	T_STATUS=$(now)
	status=$(bounded 5 flowmesh status --json 2> /dev/null)
	STATUS_BACKEND=$(echo "$status" | jsonfilter -e '@.BackendState' 2> /dev/null)
	user_stop_track
	exit_tick "$status"
	[ -n "$STOP" ] && return 0
	[ -n "$STATUS_BACKEND" ] || return 0
	t=$(now)
	if [ "$t" -ge "${DNS_AT:-0}" ]; then
		DNS_AT=$((t + DNS_PERIOD))
		dns_tick "$status"
		exit_consistency
	fi
}

cleanup() {
	dns_reconcile "" ""
	rm -f "$EXIT_STATE"
}

main() {
	local t d
	STOP=
	SLEEPER=
	trap 'STOP=1; [ -n "$SLEEPER" ] && kill $SLEEPER 2>/dev/null' TERM INT HUP
	while [ -z "$STOP" ]; do
		t=$(now)
		E_NEXT=$PERIOD
		watch_tick
		[ -n "$STOP" ] && break
		d=$((E_NEXT - ($(now) - t)))
		[ "$d" -ge 1 ] || d=1
		sleep "$d" &
		SLEEPER=$!
		wait "$SLEEPER"
		SLEEPER=
	done
	cleanup
	log "stopped"
}

# (FLOWMESH_WATCH_LIB=1 and sourced: only the functions, for the tests.)
if [ "$FLOWMESH_WATCH_LIB" != 1 ]; then
	case "$1" in
	"") main ;;
	cleanup) cleanup ;;
	*) echo "usage: $0 [cleanup]" >&2; exit 2 ;;
	esac
fi
