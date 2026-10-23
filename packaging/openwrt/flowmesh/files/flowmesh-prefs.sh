# SPDX-License-Identifier: Apache-2.0
# Sourced (installed as /usr/share/flowmesh/prefs.sh): turns the UCI intent in /etc/config/flowmesh
# into `flowmesh` flags. Shared by the init script (`flowmesh set` on reload) and the LuCI helper
# (`flowmesh up --reset`, which must repeat every setting), so both always send the same set.
# Needs /lib/functions.sh (config_load and friends) to be sourced first.

# IPv4 networks of the lan interface (e.g. 192.168.1.0/24), from netifd.
flowmesh_lan_networks() {
	local status i=0 addr mask n a b c d
	status=$(ubus call network.interface.lan status 2>/dev/null) || return 0
	while :; do
		addr=$(echo "$status" | jsonfilter -e "@['ipv4-address'][$i].address" 2>/dev/null)
		mask=$(echo "$status" | jsonfilter -e "@['ipv4-address'][$i].mask" 2>/dev/null)
		[ -n "$addr" ] && [ -n "$mask" ] || break
		local IFS=.
		# shellcheck disable=SC2086 # split on the dots
		set -- $addr
		unset IFS
		a=$1 b=$2 c=$3 d=$4
		n=$(( ((a << 24) | (b << 16) | (c << 8) | d) & ((0xffffffff << (32 - mask)) & 0xffffffff) ))
		echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))/$mask"
		i=$((i + 1))
	done
}

flowmesh_append_route() {
	FM_ROUTES="${FM_ROUTES:+$FM_ROUTES,}$1"
}

# Where the exit node watcher records what it sees: {"want":"<ip>","state":"none|active|
# offline_blocked|offline_fallback|missing","since":N}. (FLOWMESH_EXIT_STATE: for tests.)
FM_EXIT_STATE_FILE=${FLOWMESH_EXIT_STATE:-/var/run/flowmesh/exit-state.json}

# True when the watcher has fallen back to the local uplink for exit node $1 (kill switch off, the
# exit node offline). A missing or unreadable file, or one about another exit node, is not.
flowmesh_exit_fell_back() {
	local want state
	[ -r "$FM_EXIT_STATE_FILE" ] || return 1
	want=$(jsonfilter -i "$FM_EXIT_STATE_FILE" -e '@.want' 2>/dev/null) || return 1
	state=$(jsonfilter -i "$FM_EXIT_STATE_FILE" -e '@.state' 2>/dev/null) || return 1
	[ "$want" = "$1" ] && [ "$state" = offline_fallback ]
}

# Read the intent into FM_HOSTNAME, FM_ROUTES, FM_EXIT_NODE (offer this router as an exit node),
# FM_ACCEPT_ROUTES, FM_USE_EXIT_NODE (the exit node chosen, empty: none), FM_EXIT_IP (the exit
# node to send the LAN through now: FM_USE_EXIT_NODE unless that is overruled or has fallen
# back), FM_KILL_SWITCH and FM_LAN_DNS.
flowmesh_load_prefs() {
	local advertise_lan n
	FM_ROUTES=
	FM_EXIT_BLOCK=
	config_load flowmesh
	config_get FM_HOSTNAME main hostname
	config_get_bool advertise_lan main advertise_lan 0
	config_get_bool FM_EXIT_NODE main exit_node 0
	config_get_bool FM_ACCEPT_ROUTES main accept_routes 0
	config_get FM_USE_EXIT_NODE main use_exit_node
	# Both default to on when absent (an older /etc/config/flowmesh has neither).
	config_get_bool FM_KILL_SWITCH main kill_switch 1
	config_get_bool FM_LAN_DNS main lan_dns 1
	FM_EXIT_IP=$FM_USE_EXIT_NODE
	if [ -n "$FM_EXIT_IP" ] && [ "$FM_EXIT_NODE" = 1 ]; then
		# The page offers one or the other; a hand-edited config may have both.
		logger -t flowmesh "exit_node and use_exit_node are both set: offering this router as an exit node, not using $FM_EXIT_IP"
		FM_EXIT_IP=
	fi
	# The watcher has moved the LAN to the local uplink while this exit node is offline: a reload
	# must not put it back on the dead exit node (the watcher switches back when it returns).
	if [ -n "$FM_EXIT_IP" ] && flowmesh_exit_fell_back "$FM_EXIT_IP"; then
		FM_EXIT_IP=
	fi
	# The daemon does not fall back to the system hostname itself, and a node without a name is
	# refused by the control server.
	[ -n "$FM_HOSTNAME" ] || FM_HOSTNAME=$(cat /proc/sys/kernel/hostname)
	if [ "$advertise_lan" = 1 ]; then
		config_list_foreach main lan_routes flowmesh_append_route
		if [ -z "$FM_ROUTES" ]; then
			for n in $(flowmesh_lan_networks); do flowmesh_append_route "$n"; done
		fi
	fi
}

# flowmesh_cli [exec] <subcommand> [args...]: `flowmesh <subcommand> <args>` plus every preference
# flag, from the FM_* variables; with "exec" the CLI replaces the calling (sub)shell, so a background
# job's PID is the CLI's own. The router's DNS belongs to dnsmasq: the daemon never rewrites
# resolv.conf.
# Using an exit node, the router sends only what it forwards for the LAN through it, translated to
# its mesh address (--exit-node-forwarded-only), and always lets the LAN through to its own networks
# (without that, the replies to the LAN would go to the exit node too). --stateful-filtering stays
# at the client's default: on, it would drop the LAN's traffic to the exit node.
flowmesh_cli() {
	local run="" sub via=false
	[ "$1" = exec ] && { run="exec"; shift; }
	sub=$1
	shift
	[ -n "$FM_EXIT_IP" ] && via=true
	set -- "$@" --accept-dns=false --hostname="$FM_HOSTNAME" \
		--accept-routes="$FM_ACCEPT_ROUTES" --advertise-routes="$FM_ROUTES" \
		--advertise-exit-node="$FM_EXIT_NODE" \
		--exit-node-allow-lan-access="$via" --exit-node-forwarded-only="$via"
	$run flowmesh "$sub" "$@" --exit-node="$FM_EXIT_IP"
}

# The firewall side of FM_EXIT_NODE (the forwarding flowmesh -> wan), of FM_EXIT_IP (the LAN's
# IPv6 kept off the local uplink while its IPv4 goes through the exit node; no NAT66) and of
# FM_EXIT_BLOCK (set by the init when the chosen exit node could not be used and the kill switch is
# on: the LAN kept off the local uplink entirely). Every successful apply sets all three.
# flowmesh_apply_fw early: the first two only, before the CLI has answered (the kill switch rule
# depends on its answer and is left as it is).
flowmesh_apply_fw() {
	local exit=exitnode-off v6="exit-v6-block-off" kill="exit-kill-off"
	[ "$FM_EXIT_NODE" = 1 ] && exit=exitnode-on
	[ -n "$FM_EXIT_IP" ] && v6="exit-v6-block-on"
	[ "$FM_EXIT_BLOCK" = 1 ] && kill="exit-kill-on"
	if [ "$1" = early ]; then
		/usr/libexec/flowmesh-fw "$exit" "$v6"
	else
		/usr/libexec/flowmesh-fw "$exit" "$v6" "$kill"
	fi
}
