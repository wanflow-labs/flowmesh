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

# Read the intent into FM_HOSTNAME, FM_ROUTES, FM_EXIT_NODE and FM_ACCEPT_ROUTES.
flowmesh_load_prefs() {
	local advertise_lan n
	FM_ROUTES=
	config_load flowmesh
	config_get FM_HOSTNAME main hostname
	config_get_bool advertise_lan main advertise_lan 0
	config_get_bool FM_EXIT_NODE main exit_node 0
	config_get_bool FM_ACCEPT_ROUTES main accept_routes 0
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
flowmesh_cli() {
	local run="" sub
	[ "$1" = exec ] && { run="exec"; shift; }
	sub=$1
	shift
	$run flowmesh "$sub" "$@" --accept-dns=false --hostname="$FM_HOSTNAME" \
		--accept-routes="$FM_ACCEPT_ROUTES" --advertise-routes="$FM_ROUTES" \
		--advertise-exit-node="$FM_EXIT_NODE"
}

# The firewall side of FM_EXIT_NODE (the forwarding flowmesh -> wan).
flowmesh_apply_fw() {
	if [ "$FM_EXIT_NODE" = 1 ]; then
		/usr/libexec/flowmesh-fw exitnode-on
	else
		/usr/libexec/flowmesh-fw exitnode-off
	fi
}
