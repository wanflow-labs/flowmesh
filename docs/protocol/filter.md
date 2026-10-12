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
| F5 | **Other ICMP types (echo 8, timestamp 13/14, source quench 4, redirect 5, parameter problem 12, ICMPv6 echo 128)**: allowed as long as some rule's source and destination addresses match, **ignoring ports and the rule's `IPProto`** | tcp-80, proto-udp, proto-gre: these types are all delivered; deny-all, other-src: not delivered |
| F6 | **ICMP echo reply (v4 type 0, v6 type 129) is always allowed** | deny-all/icmp-echo-reply, v6-icmp6-echo-reply delivered |
| F7 | **The error messages path discovery depends on are always allowed: ICMPv4 destination unreachable 3 and time exceeded 11; ICMPv6 destination unreachable 1, packet too big 2, time exceeded 3**, regardless of rules and of the embedded original packet | deny-all and other-src: these types are all delivered; OBS-20261010-icmp-errors-receiver: errors with garbage or valid embedded packets, related or unrelated, are all delivered under both allow-all and deny-all. ICMPv6 parameter problem (4) is not observed and is handled per F5 |
| F8 | Non-TCP/UDP/ICMP protocols (e.g. GRE) are allowed only when `IPProto` explicitly includes them and the addresses match | proto-gre/gre |
| F9 | Packets from a source not covered by any rule are dropped (subject to the unconditional exceptions F1, F6, F7, F10) | other-src, tcp-80-from-other-only |

## 2a. Stateful part

Source: `OBS-20261010-acl-stateful/cases.json`. Policy allows only ts2 → ts1; observation is at the receiving end, ts2.

| # | Semantics | Evidence |
|---|---|---|
| F10 | Replies to UDP flows this node initiated (exact 4-tuple match: the reply's source address/port = the outbound packet's destination address/port, and vice versa) are allowed even if the rules don't allow that direction | s2-udp-reply-after-outbound delivered; s2-control-other-sport (same destination port, different source port) not delivered |
| F11 | TCP needs no state: replies (SYN-ACK etc.) are already allowed under F1 | s1-synack-after-outbound and s1-control-unsolicited-synack are both delivered |
| F12 | An ICMP error for this node's outbound flow is delivered (consistent with F7; no flow state needed) | s3-icmp-port-unreachable-for-outbound delivered |

## 3. Security notes

- F1 (non-SYN TCP passes unconditionally) and F6 (echo reply passes unconditionally) are official behavior. flowmesh keeps them for consistency. These packets cannot establish a new connection on their own: a TCP stack replies RST to an ACK that belongs to no connection. But they can be used for scanning (e.g. ACK scans to probe whether a host is alive). This is recorded here and is **not** listed as a deviation; reconsider if there is a security requirement later.

## 4. Pending

| Question | Plan |
|---|---|
| **Lifetime of a UDP flow record**: not observed; flowmesh provisionally uses 120 seconds (`UDP_FLOW_TTL`) | Observe once there is a long-running test environment (soak test) |
| ~~Attribution~~ **Resolved**: with flowmesh as the sender (no outbound filtering) and the official ts1 as the receiver, the full matrix (OBS-20261010-acl-diff-receiver) is **exactly identical** to the combined result above, so every semantic above belongs to the receiver's inbound filtering, which is consistent with flowmesh's implementation | — |
| Packets whose destination is a subnet route (not this node's address) | Open (relevant to subnet routers) |
| IP fragments | Open |

## 5. Measurement error record

The first version of F7 read "ICMPv4 errors are always dropped", and F12 read "dropped even when they answer this node's own outbound flow". **Both were wrong**: they came from a bug in the collection script, not from official behavior.

- **Cause**: tshark parses the payload of an ICMPv4 error as an embedded packet. The text payload starts with `i` (0x69), so it was read as an IPv6 header and `ipv6.nxt` was filled with a garbage value. The classification code checked for IPv6 fields first, so these IPv4 packets were treated as IPv6 and discarded, i.e. counted as "not delivered". The stateful script did not handle multi-valued fields such as `ip.proto` = `1,17`.
- **Consequence**: the first implementation dropped ICMPv4 destination unreachable / time exceeded. That would break path MTU discovery (fragmentation needed is type 3 code 4).
- **How it was found**: an attribution experiment hand-built an ICMP error that was delivered, which contradicted the record. Inspecting the raw pcaps showed these packets had in fact arrived.
- **Fix**: classify by the outer IP version and take only the first value of multi-valued fields. All the original pcaps were saved, so `run.py --reparse` re-derived the results without rerunning the lab. The "v4/v6 asymmetry" finding that mutation testing had prompted was likewise an artifact of this bug.
- **Lesson**: "not delivered" observations need control evidence of the same kind. When an observation contradicts intuition, first check the measurement pipeline (raw pcap), then build an explanation.
