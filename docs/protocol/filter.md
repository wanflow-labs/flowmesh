# Packet filtering semantics

Source: `OBS-20261010-acl-diff/cases.json`. Each entry in that file is a set of policies (case) plus a group of probes; `delivered` records whether the official client 1.94.2 (ts2) received the probe on `tailscale0` under that policy. Probes are sent from ts1 to ts2 and cover both IPv4 and IPv6. Probe IDs below are `case/probe`.

All judgments below are about **inbound** packets (sent to this node by a peer). Outbound packets and the stateful part (letting return traffic through) are covered in §4.

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
| F1 | **TCP packets that are not SYN are always allowed**, regardless of rules | deny-all/tcp-ack-80, tcp-ack-9999, v6-tcp-ack-9999 are all delivered |
| F2 | A TCP SYN is allowed only if some rule matches all of: source address, destination address, destination port in range, and TCP in the protocol set | tcp-80: only tcp-syn-80 delivered; range-8000-8100: 8000 and 8100 delivered, 8101 not (closed interval) |
| F3 | UDP uses the same matching as F2 (protocol must be UDP) | proto-udp: all udp-* delivered and no tcp-syn-*; proto-tcp-all-ports: no udp-* |
| F4 | When `IPProto` is empty, the protocol set includes TCP and UDP; **GRE is not included** | allow-all: tcp/udp delivered, gre not; proto-gre: gre delivered |
| F5 | **ICMP request types (echo 8, timestamp 13, timestamp reply 14, ICMPv6 echo 128)**: allowed as long as some rule's source and destination addresses match, **ignoring ports and the rule's `IPProto`** | tcp-80, proto-udp, proto-gre: icmp-echo is delivered under all three; other-src, deny-all: not delivered |
| F6 | **ICMP echo reply (0) and ICMPv6 echo reply (129) are always allowed** | deny-all/icmp-echo-reply, v6-icmp6-echo-reply delivered |
| F7 | ICMP errors (destination unreachable 3, time exceeded 11) **with no embedded original packet** are always dropped, even under allow-all | allow-all/icmp-unreachable, icmp-time-exceeded not delivered. Whether an error with a valid embedded original packet is allowed is still pending (§4) |
| F8 | Non-TCP/UDP/ICMP protocols (e.g. GRE) are allowed only when `IPProto` explicitly includes them and the addresses match | proto-gre/gre |
| F9 | Packets from a source not covered by any rule are dropped (subject to the unconditional exceptions F1 and F6) | other-src, tcp-80-from-other-only |

## 3. Security notes

- F1 (non-SYN TCP passes unconditionally) and F6 (echo reply passes unconditionally) are official behavior. flowmesh keeps them for consistency. These packets cannot establish a new connection on their own: a TCP stack replies RST to an ACK that belongs to no connection. But they can be used for scanning (e.g. ACK scans to probe whether a host is alive). This is recorded here and is **not** listed as a deviation; reconsider if there is a security requirement later.

## 4. Pending

| Question | Plan |
|---|---|
| Whether return traffic for connections this node initiated (UDP replies, SYN-ACK) is allowed, and the timeout | M3 Task 3 |
| Whether ICMP errors with a valid embedded original packet are allowed (related to F7) | M3 Task 3 |
| Packets whose destination is a subnet route (not this node's address) | M6 (subnet routes) |
| IP fragments | M5 (once the data plane can carry fragments) |
