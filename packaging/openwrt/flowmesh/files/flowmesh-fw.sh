#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The flowmesh firewall zone, through UCI only (fw3 or fw4 turns it into iptables or nftables rules):
#   add           zone "flowmesh" (device flowmesh0, accept all, no masquerading) and the
#                 forwardings lan -> flowmesh and flowmesh -> lan
#   remove        every zone named "flowmesh" and every forwarding from or to it
#   exitnode-on   forwarding flowmesh -> wan (this router offers itself as an exit node)
#   exitnode-off  the forwardings flowmesh -> wan
#   exit-v6-block-on   rule "flowmesh_exit_block_ipv6": IPv6 forwarded from lan to wan is
#                      rejected (this router sends its LAN through an exit node; lan -> flowmesh
#                      and the router's own traffic are not affected)
#   exit-v6-block-off  every rule of that name
#   exit-kill-on       rule "flowmesh_exit_kill_switch": everything forwarded from lan to wan is
#                      rejected, IPv4 and IPv6 (the chosen exit node cannot be used and the kill
#                      switch is on; lan -> flowmesh and the router's own traffic are not affected)
#   exit-kill-off      every rule of that name
# Several actions may be given; they are applied in one commit and one firewall reload. `remove`
# also removes both rules. Nothing else in /etc/config/firewall is touched. Access control is the
# mesh's ACL, which also decides what the device list shows. Firewall changes the user has staged with the uci command but
# not applied are set aside while we commit, so they are neither committed with ours nor lost.
# The firewall is reloaded when something changed, unless FLOWMESH_FW_NORELOAD=1 (first boot, where
# the firewall starts later on its own).

ZONE=flowmesh
DEVICE=flowmesh0
V6_BLOCK=flowmesh_exit_block_ipv6
KILL_BLOCK=flowmesh_exit_kill_switch

usage() {
	echo "usage: $0 add|remove|exitnode-on|exitnode-off|exit-v6-block-on|exit-v6-block-off|exit-kill-on|exit-kill-off..." >&2
	exit 2
}
[ $# -gt 0 ] || usage
for a in "$@"; do
	case "$a" in
	add | remove | exitnode-on | exitnode-off | exit-v6-block-on | exit-v6-block-off | exit-kill-on | exit-kill-off) ;;
	*) usage ;;
	esac
done

# One run at a time: the init's background apply, a reload and LuCI can overlap, and the staged-change
# shuffle below (and uci's own add-then-set) is not safe against a concurrent run.
# Opened without truncating (<>): we run as root, and the path may be a symlink to anything. A run
# that holds the lock for a minute is stuck (a hung firewall reload): give up rather than queue
# every later run behind it. (BusyBox flock has no -w.)
mkdir -p /var/lock
exec 9<> /var/lock/flowmesh-fw.lock || exit 1
waited=0
until flock -n 9; do
	if [ "$waited" -ge 60 ]; then
		echo "flowmesh-fw: another run has held /var/lock/flowmesh-fw.lock for 60 s; giving up" >&2
		exit 1
	fi
	sleep 1
	waited=$((waited + 1))
done

# uci always reads the default delta directory (-t only moves where new changes are written), so the
# user's staged firewall changes are moved out of the way for the duration.
STAGED=/tmp/.uci/firewall
ASIDE=$(mktemp -d /tmp/flowmesh-fw.XXXXXX) || exit 1
restore() {
	[ -f "$ASIDE/firewall" ] && mv -f "$ASIDE/firewall" "$STAGED"
	rm -rf "$ASIDE"
}
trap restore EXIT
# (A signal would otherwise end the shell without running the EXIT trap.)
trap 'exit 1' INT TERM HUP
if [ -s "$STAGED" ]; then
	mv -f "$STAGED" "$ASIDE/firewall" || exit 1
fi
changed=0

u() {
	uci -q "$@"
}

# One line per firewall section: "<id> <type> <name> <src> <dest>" ("-" for unset options).
sections() {
	u -X show firewall | awk '
		{
			i = index($0, "=")
			key = substr($0, 1, i - 1)
			val = substr($0, i + 1)
			gsub("\047", "", val)
			n = split(key, p, ".")
		}
		n == 2 { type[p[2]] = val; order[++c] = p[2]; next }
		n == 3 { opt[p[2] "." p[3]] = val }
		function get(s, o) { return ((s "." o) in opt) && opt[s "." o] != "" ? opt[s "." o] : "-" }
		END { for (j = 1; j <= c; j++) { s = order[j]; print s, type[s], get(s, "name"), get(s, "src"), get(s, "dest") } }'
}

zones() {
	sections | awk -v z="$ZONE" '$2 == "zone" && $3 == z { print $1 }'
}

# Rules named $1.
rules() {
	sections | awk -v n="$1" '$2 == "rule" && $3 == n { print $1 }'
}

# Forwardings from $1 to $2 ("*" matches any zone).
forwardings() {
	sections | awk -v s="$1" -v d="$2" '$2 == "forwarding" && (s == "*" || $4 == s) && (d == "*" || $5 == d) { print $1 }'
}

delete() {
	local id
	for id in "$@"; do
		u delete "firewall.$id"
		changed=1
	done
}

add_forwarding() {
	local id
	[ -n "$(forwardings "$1" "$2")" ] && return 0
	id=$(u add firewall forwarding)
	u set "firewall.$id.src=$1"
	u set "firewall.$id.dest=$2"
	changed=1
}

add_zone() {
	local id
	if [ -z "$(zones)" ]; then
		id=$(u add firewall zone)
		u set "firewall.$id.name=$ZONE"
		u add_list "firewall.$id.device=$DEVICE"
		u set "firewall.$id.input=ACCEPT"
		u set "firewall.$id.output=ACCEPT"
		u set "firewall.$id.forward=ACCEPT"
		u set "firewall.$id.masq=0"
		changed=1
	fi
	add_forwarding lan "$ZONE"
	add_forwarding "$ZONE" lan
}

# add_block <name> <family>: rule <name> rejecting lan -> wan forwarding of <family> (ipv6, or any).
# REJECT, not DROP: the LAN's dual-stack hosts give up on IPv6 at once and use IPv4 (through the
# exit node) instead of waiting for timeouts. proto all: a rule's default is tcp and udp only.
add_block() {
	local id
	[ -n "$(rules "$1")" ] && return 0
	id=$(u add firewall rule)
	u set "firewall.$id.name=$1"
	u set "firewall.$id.family=$2"
	u set "firewall.$id.src=lan"
	u set "firewall.$id.dest=wan"
	u set "firewall.$id.proto=all"
	u set "firewall.$id.target=REJECT"
	changed=1
}

for a in "$@"; do
	case "$a" in
	add) add_zone ;;
	remove)
		delete $(forwardings "$ZONE" "*") $(forwardings "*" "$ZONE")
		delete $(zones)
		delete $(rules "$V6_BLOCK") $(rules "$KILL_BLOCK")
		;;
	exitnode-on) add_forwarding "$ZONE" wan ;;
	exitnode-off) delete $(forwardings "$ZONE" wan) ;;
	exit-v6-block-on) add_block "$V6_BLOCK" ipv6 ;;
	exit-v6-block-off) delete $(rules "$V6_BLOCK") ;;
	exit-kill-on) add_block "$KILL_BLOCK" any ;;
	exit-kill-off) delete $(rules "$KILL_BLOCK") ;;
	esac
done

[ "$changed" = 1 ] || exit 0
u commit firewall || exit 1
# (Lock fd closed for the reload: nothing it starts may hold the lock.)
[ "$FLOWMESH_FW_NORELOAD" = 1 ] || /etc/init.d/firewall reload >/dev/null 2>&1 9>&-
exit 0
