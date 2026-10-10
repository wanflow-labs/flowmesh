# Packet filtering semantics

Source: `OBS-20261010-acl-diff/cases.json`. Each entry in that file is a set of policies (case) plus a group of probes; `delivered` records whether the official client 1.94.2 (ts2) received the probe on `tailscale0` under that policy. Probes are sent from ts1 to ts2 and cover both IPv4 and IPv6. Probe IDs below are `case/probe`.

All judgments below are about **inbound** packets (sent to this node by a peer). The stateful part (letting return traffic through) is covered in §2a.

## 1. Rule input

| Fact | Source |
|---|---|
| headscale filters rules per destination node: if the rule's destination is not this node, the node never receives it at all | dst-other: ts2 receives only the CapGrant rule |
| A rule matches on `SrcIPs` (CIDR, or `*` for any), `DstPorts[].IP` (CIDR), `DstPorts[].Ports` (closed interval `First..=Last`), and `IPProto` (a list of protocol numbers) | rules field of each case |
| Port lists such as `22,443` are expanded into multiple `DstPorts` entries | list-22-443 rules |
| `proto: icmp` is expanded to `IPProto: [1, 58]`; `udp` → `[17]`; `gre` → `[47]` | rules of proto-icmp / proto-udp / proto-gre |
| Rules that carry only a `CapGrant` and no `DstPorts` do not allow any packets | deny-all: ts2 still holds the CapGrant rule, yet tcp-syn-*, udp-* are not delivered |

## 2. Judgment

| # | Semantics | Evidence (counterexample / positive example) |
|---|---|---|
| F1 | **Only a "pure SYN" (SYN set, ACK not set) counts as a new connection and needs a rule; every other TCP packet is always allowed** (ACK, FIN, RST, no flags, SYN-ACK) | deny-all/tcp-ack-*, tcp-fin-9001, tcp-rst-9001, tcp-null-9001, tcp-synack-9001 are all delivered; deny-all/tcp-synfin-9001 (SYN+FIN, no ACK) is not delivered, allow-all/tcp-synfin-9001 is delivered; acl-stateful: an unprompted SYN-ACK is also delivered |
| F2 | A TCP SYN is allowed only if some rule matches all of: source address, destination address, destination port in range, and TCP in the protocol set | tcp-80: only tcp-syn-80 delivered; range-8000-8100: 8000 and 8100 delivered, 8101 not (closed interval) |
| F3 | UDP uses the same matching as F2 (protocol must be UDP) | proto-udp: all udp-* delivered and no tcp-syn-*; proto-tcp-all-ports: no udp-* |
| F4 | When `IPProto` is empty, the protocol set includes TCP and UDP; **GRE is not included** | allow-all: tcp/udp delivered, gre not; proto-gre: gre delivered |
| F5 | **ICMP request types (echo 8, timestamp 13, timestamp reply 14, ICMPv6 echo 128)**: allowed as long as some rule's source and destination addresses match, **ignoring ports and the rule's `IPProto`** | tcp-80, proto-udp, proto-gre: icmp-echo is delivered under all three; other-src, deny-all: not delivered |
| F6 | **ICMP echo reply (0) and ICMPv6 echo reply (129) are always allowed** | deny-all/icmp-echo-reply, v6-icmp6-echo-reply delivered |
| F7 | **ICMPv4 errors (3 destination unreachable, 4 source quench, 5 redirect, 11 time exceeded, 12 parameter problem) are always dropped**, even under allow-all | allow-all/icmp-unreachable, icmp-time-exceeded, icmp-source-quench, icmp-redirect, icmp-param-problem are all not delivered. An error with a valid embedded original packet is dropped too, see F12 |
| F7b | **ICMPv6 errors (1 destination unreachable, 2 packet too big, 3 time exceeded) are always allowed**, even under deny-all; this is asymmetric with ICMPv4 | deny-all/v6-icmp6-unreachable, v6-icmp6-too-big, v6-icmp6-time-exceeded delivered. Note: the first implementation inferred "drop" from the RFC, mutation testing exposed that this logic had no observational basis, and the added observation showed the opposite |
| F8 | Non-TCP/UDP/ICMP protocols (e.g. GRE) are allowed only when `IPProto` explicitly includes them and the addresses match | proto-gre/gre |
| F9 | Packets from a source not covered by any rule are dropped (subject to the unconditional exceptions F1, F6, F7b, F10) | other-src, tcp-80-from-other-only |

## 2a. Stateful part

Source: `OBS-20261010-acl-stateful/cases.json`. Policy allows only ts2 → ts1; observation is at the receiving end, ts2.

| # | Semantics | Evidence |
|---|---|---|
| F10 | Replies to UDP flows this node initiated (exact 4-tuple match: the reply's source address/port = the outbound packet's destination address/port, and vice versa) are allowed even if the rules don't allow that direction | s2-udp-reply-after-outbound delivered; s2-control-other-sport (same destination port, different source port) not delivered |
| F11 | TCP needs no state: replies (SYN-ACK etc.) are already allowed under F1 | s1-synack-after-outbound and s1-control-unsolicited-synack are both delivered |
| F12 | ICMPv4 errors (port unreachable) are dropped even when they answer this node's own outbound flow | s3-icmp-port-unreachable-for-outbound not delivered; the control confirms ts1 did send it |

## 3. Security notes

- F1 (non-SYN TCP passes unconditionally) and F6 (echo reply passes unconditionally) are official behavior. flowmesh keeps them for consistency. These packets cannot establish a new connection on their own: a TCP stack replies RST to an ACK that belongs to no connection. But they can be used for scanning (e.g. ACK scans to probe whether a host is alive). This is recorded here and is **not** listed as a deviation; reconsider if there is a security requirement later.

## 4. Pending

| Question | Plan |
|---|---|
| **Lifetime of a UDP flow record**: not observed; flowmesh provisionally uses 120 seconds (`UDP_FLOW_TTL`) | Observe once there is a long-running test environment (M8 soak test) |
| **Attribution**: every probe passes through the sender ts1's outbound filter and then the receiver ts2's inbound filter, so the observations are the result of both combined. When every node runs flowmesh, consistency is unaffected; in mixed deployments, which side drops a packet matters (e.g. F7/F12 could be dropped at the sender's outbound) | In M4, once flowmesh can inject packets directly over WireGuard (bypassing the sender's filter), observe again and attribute |
| Packets whose destination is a subnet route (not this node's address) | M6 (subnet routes) |
| IP fragments | M5 (once the data plane can carry fragments) |
