#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# NAT router: the lab-side interface (172.29.0.x) faces the "internet", the LAN side faces the private network.
# NAT_MODE=easy : full cone (endpoint-independent mapping + filtering). MASQUERADE keeps the port, inbound UDP is DNATed to the internal client per FULLCONE.
#                 FULLCONE="41641:10.10.1.31 *:10.10.1.21": port 41641 to .31, all other ports to .21.
# NAT_MODE=pr   : Linux default MASQUERADE (port-restricted cone; when punch packets cross, the mapping port can change, a common case on real home routers)
# NAT_MODE=hard : MASQUERADE --random-fully (new external port per destination; symmetric NAT)
set -eu
WAN_IF=$(ip -o -4 addr show | awk '$4 ~ /^172\.29\./ {print $2; exit}')
iptables -t nat -F
case "${NAT_MODE:-pr}" in
  hard) iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE --random-fully ;;
  easy)
    iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
    for m in ${FULLCONE:-}; do
      port=${m%%:*}; host=${m#*:}
      if [ "$port" = "*" ]; then
        iptables -t nat -A PREROUTING -i "$WAN_IF" -p udp -j DNAT --to-destination "$host"
      else
        iptables -t nat -I PREROUTING -i "$WAN_IF" -p udp --dport "$port" -j DNAT --to-destination "$host"
      fi
    done ;;
  *) iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE ;;
esac
# Packets to another LAN's private address must not leave via the WAN (the Docker host would route them there directly, bypassing NAT).
# On the real internet private addresses are not routable; the only way in is the address mapped by NAT.
iptables -F FORWARD
iptables -A FORWARD -o "$WAN_IF" -d 10.10.0.0/16 -j DROP
iptables -P FORWARD ACCEPT
# Flush conntrack entries created before the rules existed (their NAT decision is fixed at the first packet).
conntrack -F >/dev/null 2>&1 || true
echo "router up: wan=$WAN_IF mode=${NAT_MODE:-pr} fullcone=${FULLCONE:-}"
exec sleep infinity
