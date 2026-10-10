# Peer relay data path between two official clients (ts1, ts2) through tsr

Capture: `tcpdump udp port 40000` in tsr's network namespace while ts1 reaches ts2 through the peer
relay (`peer-relay(172.29.0.23:40000:vni:4)`), with one disco ping per second (`tailscale ping`) and an
ICMP ping per second through the tunnel for 50 s. `tsr-pcap.txt` is `lab/scripts/peer_relay_pcap.py`
over `tsr.pcap` with ts1's netmap (`b5d72284` = the relay server's key from
OBS-20261010-peer-relay-alloc-response; it is in no netmap).

## The 8-byte header on every relayed packet

Every UDP payload to and from port 40000 (except STUN) starts with 8 bytes, then a disco envelope or a
WireGuard message. The layout is the Geneve header of RFC 8926 (PUB: https://www.rfc-editor.org/rfc/rfc8926):

| Byte(s) | Seen | Meaning | Status |
|---|---|---|---|
| 0 | `00` | version 0, no options | Observed + RFC 8926 |
| 1 | `00`, or `80` | `80` is the O (control) bit: set only on the 160-byte messages exchanged between a client and the relay server itself | Observed |
| 2–3 | `7a11` before a disco envelope, `7a12` before a WireGuard message | protocol type | Observed |
| 4–6 | `000004` | the VNI of the allocation (the client shows `vni:4`; the allocation response carries it as a u32) | Observed |
| 7 | `00` | reserved | Observed |

Counts over the capture (header → packets): disco `00007a11…` 179 to the relay / 176 from it; disco with
the O bit `00807a11…` 4 / 2; WireGuard `00007a12…` 102 / 102 (types 1, 2 once each, then type 4).

## Sequence

| Time | Packets | Reading | Status |
|---|---|---|---|
| 0.000 | relay → both DERP servers, 40 bytes, STUN binding request (cookie `2112a442`); replies 44 bytes | the relay server learns its own address with STUN against the DERP servers' STUN ports | Observed |
| 1.372 | ts1 → relay and ts2 → relay: 160-byte disco with the O bit, sealed by each client; relay → each client: 160-byte disco with the O bit, sealed by the server key; each client → relay: another 160-byte O-bit message | a three-message handshake between each client and the server, the third message from the client; contents sealed between client and server (not observable from a capture) | Observed (sizes, order, keys); contents Pending |
| 1.373 | 132-byte (Ping) and 118-byte (Pong) disco both ways, without the O bit, forwarded by the relay (sealed by ts1 or ts2) | after the handshake, ordinary disco ping/pong between the two clients runs through the relay | Observed (sizes match disco.md: 8 + 62 + 46 + 16 and 8 + 62 + 32 + 16) |
| 1.373 | ts1 → ts2 through the relay: one 250-byte disco message | larger than any known disco type; sealed between ts1 and ts2 | Observed (size); contents Pending |
| 1.4 on | WireGuard handshake (type 1, 156 bytes = 8 + 148; type 2, 100 = 8 + 92), then transport data (type 4) | WireGuard runs unchanged inside the header | Observed |
| steady | disco ping every second from `tailscale ping`; no other periodic messages within 50 s | keepalive interval not visible at this traffic level | Observed |

- One relay → client WireGuard type-1 packet is 288 bytes (156 expected): unexplained, Pending.
- The relay server does not rewrite payloads: a disco message keeps its sealer's key and size from one
  leg to the other.
