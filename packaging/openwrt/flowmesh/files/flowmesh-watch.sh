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
#    the mesh (one `flowmesh ping`, 2 s); 3 failures in a row: offline, 3 answers in a row: back.
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
#    The state, for the LuCI page: /var/run/flowmesh/exit-state.json,
#    {"want":"<use_exit_node>","state":"none|active|offline_blocked|offline_fallback|missing","since":N}
#    ("want" exactly as in UCI).
# 2. Mesh names for the LAN (lan_dns, on when unset). While the node is logged in, every 10 s it reads
#    `flowmesh dns status --json` and has dnsmasq forward the mesh's domains to FlowMesh's resolver
#    (100.100.100.100): the mesh suffix, the names of the console's extra records and the split-DNS
#    domains. UCI dhcp, in every dnsmasq section: list server '/<domain>/100.100.100.100' and list
#    rebind_domain '<domain>' (newer dnsmasq releases discard 100.64.0.0/10 answers as a rebind).
#    Only the entries it added are ever changed or removed: they are listed in
#    /etc/flowmesh/lan-dns.owned ("<section> <option> <value>" lines; on flash like /etc/config/dhcp,
#    and both survive a sysupgrade). An entry the user already has stays the user's. dnsmasq is
#    reloaded only when an entry was added or removed. lan_dns=0, logging out, stopping the service
#    and removing the package remove them all.

RESOLVER=100.100.100.100
PERIOD=3          # seconds between exit node probes
DNS_PERIOD=10     # seconds between name checks (and the daemon consistency check)
DEBOUNCE=3        # probes in a row that change the verdict
FIX_INTERVAL=30   # minimum seconds between consistency re-applies
EXIT_STATE=${FLOWMESH_EXIT_STATE:-/var/run/flowmesh/exit-state.json}
DNS_OWNED=${FLOWMESH_DNS_OWNED:-/etc/flowmesh/lan-dns.owned}
DNS_LOCK=${FLOWMESH_DNS_LOCK:-/var/lock/flowmesh-dns.lock}
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

# One probe of the exit node: true when it answered.
probe() {
	bounded $((PERIOD + 2)) flowmesh ping -c 1 --until-direct=false --timeout=2s "$E_WANT" > /dev/null 2>&1
}

warm_tunnel() {
	ping -c 1 -W 1 "$E_WANT" > /dev/null 2>&1 &
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
	case "$state" in active | offline_blocked | offline_fallback | missing) ;; *) return 1 ;; esac
	case "$since" in '' | *[!0-9]*) return 1 ;; esac
	E_STATE=$state E_SINCE=$since
}

# exit_tick <status json>: one step, once the daemon's status was read ($STATUS_BACKEND: its state).
exit_tick() {
	local status=$1 want kill present
	want=$(wanted_exit)
	if [ "$want" != "$E_WANT" ] || [ -z "$E_STATE" ]; then
		E_WANT=$want
		E_OK=0 E_FAIL=0 E_ABSENT=0
		E_STATE=
		if [ -z "$want" ]; then
			set_state none
		elif ! adopt_recorded "$want"; then
			set_state active
		fi
	fi
	[ -n "$want" ] || return 0
	kill=$(opt_bool kill_switch 1)

	case "$STATUS_BACKEND" in
	Running)
		present=0
		echo "$status" | jsonfilter -e '@.Peer[@.ExitNodeOption=true].TailscaleIPs[*]' 2>/dev/null |
			grep -qxF "$want" && present=1
		;;
	NeedsLogin | NeedsMachineAuth | Stopped) present=0 ;;
	*) return 0 ;;   # starting: wait
	esac

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
		E_OK=$((E_OK + 1)) E_FAIL=0
		# Coming back: one packet through the tunnel (its answer does not matter; the mesh's ACL may
		# not even allow it), so that WireGuard has its session by the time the LAN is moved back.
		# (The probe above does not need one, and a restarted exit node drops the first handshake:
		# without this the LAN would wait another 5 s for WireGuard's retry.)
		case "$E_STATE" in offline_*) warm_tunnel ;; esac
	else
		[ -n "$STOP" ] && return 0   # (interrupted by SIGTERM: not an answer either way)
		E_FAIL=$((E_FAIL + 1)) E_OK=0
	fi

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

# The keys of a JSON object of arrays (jsonfilter's rendering of `routes`) whose array is not empty.
# (jsonfilter cannot list keys, and jshn mangles them.)
nonempty_keys() {
	awk '
		{ s = s $0 "\n" }
		END {
			n = length(s); depth = 0; instr = 0
			for (i = 1; i <= n; i++) {
				c = substr(s, i, 1)
				if (instr) {
					if (c == "\\") { tok = tok substr(s, i, 2); i++; continue }
					if (c == "\"") { instr = 0; if (depth == 1) key = tok; else if (depth == 2) cnt++; continue }
					tok = tok c
					continue
				}
				if (c == "\"") { instr = 1; tok = ""; continue }
				if (c == "{" || c == "[") { depth++; if (depth == 2) cnt = 0; continue }
				if (c == "}" || c == "]") { if (depth == 2 && cnt > 0) print key; depth--; continue }
			}
		}'
}

# dns_domains <`dns status --json`>: the domains to forward, one per line, sorted: the suffix, the
# extra records' names and the split-DNS domains, lower-cased, without trailing dots or a leading
# "*.", invalid names dropped, and none that is under another one in the list (that one covers it).
dns_domains() {
	{
		jsonfilter -s "$1" -e '@.suffix'
		jsonfilter -s "$1" -e '@.extraRecords[*].name'
		jsonfilter -s "$1" -e '@.routes' | nonempty_keys
	} 2> /dev/null | awk '
		{
			d = tolower($0)
			sub(/\.+$/, "", d)
			sub(/^\*\./, "", d)
			if (d == "" || length(d) > 253 || d !~ /^[a-z0-9_][a-z0-9_-]*(\.[a-z0-9_][a-z0-9_-]*)*$/) next
			if (!(d in seen)) { seen[d] = 1; print split(d, x, ".") " " d }
		}' | sort -n | awk '
		{
			d = $2
			for (i = 1; i <= k; i++) {
				p = kept[i]
				if (d == p || (length(d) > length(p) && substr(d, length(d) - length(p)) == "." p)) next
			}
			kept[++k] = d
		}
		END { for (i = 1; i <= k; i++) print kept[i] }' | sort
}

dnsmasq_sections() {
	uci -q -X show dhcp | sed -n 's/^dhcp\.\([^.=]*\)=dnsmasq$/\1/p'
}

# The "<section> <option> <value>" entries for domains $1 (newline-separated) in every dnsmasq section.
dns_entries() {
	local sec d
	for sec in $(dnsmasq_sections); do
		for d in $1; do
			echo "$sec server /$d/$RESOLVER"
			echo "$sec rebind_domain $d"
		done
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

# dns_reconcile <domains>: make the entries we own exactly those for <domains> (newline-separated;
# empty: none), leaving the user's alone. Serialized with the cleanup run by another process.
dns_reconcile() {
	mkdir -p "$(dirname "$DNS_LOCK")"
	(
		flock 8 || exit 1
		dns_reconcile_locked "$1"
	) 8<> "$DNS_LOCK"
}

dns_reconcile_locked() {
	local domains=$1 want owned keep="" add="" drop="" fix="" line changed=0 staged=/tmp/.uci/dhcp aside
	want=$(dns_entries "$domains")
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
	if [ "$changed" = 1 ]; then
		# shellcheck disable=SC2086 # one line
		log "LAN names: forwarding to $RESOLVER: $(echo ${domains:-none})"
		$DNSMASQ_RELOAD_CMD > /dev/null 2>&1
	fi
	return 0
}

dns_tick() {
	local js domains=
	case "$STATUS_BACKEND" in
	Running)
		if [ "$(opt_bool lan_dns 1)" = 1 ]; then
			js=$(bounded 5 flowmesh dns status --json 2> /dev/null) || return 0
			domains=$(dns_domains "$js")
		fi
		;;
	NeedsLogin | NeedsMachineAuth | Stopped) ;;
	*) return 0 ;;   # starting: leave things as they are
	esac
	dns_reconcile "$domains"
}

# --- the loop -------------------------------------------------------------------------------------

watch_tick() {
	local status t
	# (`status` exits 1 unless the node is Running, so its output decides. The daemon not answering,
	# e.g. restarting: nothing is changed.)
	status=$(bounded 5 flowmesh status --json 2> /dev/null)
	STATUS_BACKEND=$(echo "$status" | jsonfilter -e '@.BackendState' 2> /dev/null)
	[ -n "$STATUS_BACKEND" ] || return 0
	exit_tick "$status"
	[ -n "$STOP" ] && return 0
	t=$(now)
	if [ "$t" -ge "${DNS_AT:-0}" ]; then
		DNS_AT=$((t + DNS_PERIOD))
		dns_tick
		exit_consistency
	fi
}

cleanup() {
	dns_reconcile ""
	rm -f "$EXIT_STATE"
}

main() {
	local t d
	STOP=
	SLEEPER=
	trap 'STOP=1; [ -n "$SLEEPER" ] && kill $SLEEPER 2>/dev/null' TERM INT HUP
	while [ -z "$STOP" ]; do
		t=$(now)
		watch_tick
		[ -n "$STOP" ] && break
		d=$((PERIOD - ($(now) - t)))
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
