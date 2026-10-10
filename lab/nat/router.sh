#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# NAT router: lab-side interface (172.29.0.x) faces the "internet", LAN side faces the private network.
# NAT_MODE=easy : plain MASQUERADE (keeps the source port where possible; endpoint-independent mapping, hole punching can succeed)
# NAT_MODE=hard : MASQUERADE --random-fully (new external port per destination; symmetric NAT)
set -eu
WAN_IF=$(ip -o -4 addr show | awk '$4 ~ /^172\.29\./ {print $2; exit}')
iptables -t nat -F POSTROUTING
if [ "${NAT_MODE:-easy}" = hard ]; then
  iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE --random-fully
else
  iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
fi
iptables -P FORWARD ACCEPT
echo "router up: wan=$WAN_IF mode=${NAT_MODE:-easy}"
exec sleep infinity
