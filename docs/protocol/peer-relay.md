# Peer relay

How two clients that cannot reach each other directly talk through a third node acting as a UDP relay
server, as the official 1.94.2 client does it. Status notation as in disco.md: **Observed** /
**Inferred** / **Pending**. Every fact cites its evidence (`OBS-…` = `fixtures/observed/<date>-…`).

flowmesh implements the client side only (v2); relay servers are the official client with
`--relay-server-port` in the lab and the WanFlow high-performance relay in production.

## 1. Roles and when a relay is used

| Fact | Status | Source |
|---|---|---|
| Any peer the control server grants `cap/relay` is a candidate relay server; the WanFlow control server grants it to every node (control.md, `PacketFilters`) | Observed | OBS-20261010-peer-relay-alloc-request |
| A client asks candidates for an allocation only while it has traffic for a peer, no direct path and no working relay path; requests stop once the pair is idle (~45 s), goes direct, or has a relay | Observed | OBS-20261010-peer-relay-alloc-request (conditions A/B/C) |
| A relayed path is reported as `peer-relay(<ip>:<port>:vni:<n>)` by `ping` and as the same string in `status --json` `PeerRelay` (with `CurAddr` empty) | Observed | OBS-20261010-peer-relay-official |
| The relay is used in auto, prefer and strict modes alike: those modes forbid direct paths, not the relay server | Observed | OBS-20261010-peer-relay-behavior |

## 2. Disco messages (over DERP)

All are disco messages (disco.md §1 envelope), type byte + version byte (0) + body.

### 0x08 allocation request (client → candidate server)

| Bytes | Content | Status | Source |
|---|---|---|---|
| 0–31, 32–63 | the disco public keys of the pair that wants to talk (not the server's) | Observed | OBS-20261010-peer-relay-alloc-request |
| 64–67 | u32 BE counter, per sender, shared across its requests | Observed (sharing across servers Inferred) | same |

- Official clients send the smaller key first; the server accepts either order and normalises it (Observed, OBS-20261010-peer-relay-alloc-response run B).
- Each request is sent twice, 3 s apart, with the same counter; rounds every 30 s (Observed).

### 0x09 allocation response (server → requester)

Body: the request's counter (u32 BE), then the allocation (below). Arrives 2–5 ms after the request (Observed, OBS-20261010-peer-relay-alloc-response).

### 0x07 allocation forward (requester → other member of the pair)

Body: the allocation alone. Sent twice after an allocation (Observed, OBS-20261010-peer-relay-forward).

### Allocation layout (142 bytes with one address)

| Bytes | Content | Status |
|---|---|---|
| 0–31 | the relay server's key for this role: the same for every allocation while the server runs, regenerated when it restarts; not the node's DiscoKey | Observed (OBS-20261010-peer-relay-handshake) |
| 32–95 | the pair, smaller key first | Observed |
| 96–103 | u64 BE generation, increments per new allocation | Observed (name Inferred) |
| 104–107 | u32 BE VNI; restarts at 1 when the server restarts | Observed |
| 108–115, 116–123 | u64 BE durations, 30 s and 300 s, in nanoseconds | Observed (unit and meaning Inferred) |
| 124– | one or more 18-byte addresses (disco.md §2 encoding): the relay endpoint | Observed (one address seen) |

- A repeated request for the same pair returns the existing allocation; a new pair gets a new VNI (Observed).
- The server allocates even when the other key belongs to no node (Observed): an allocation proves nothing about the peer.

## 3. Data path (UDP to the relay endpoint)

| Fact | Status | Source |
|---|---|---|
| Every packet starts with an 8-byte Geneve header (RFC 8926): byte 0 `00`; byte 1 `80` (O bit) for messages to the server itself, else `00`; bytes 2–3 protocol `7a11` (disco) or `7a12` (WireGuard); bytes 4–6 the VNI; byte 7 `00` | Observed (layout per RFC 8926) | OBS-20261010-peer-relay-datapath |
| Before using the path, each client completes a three-message handshake with the server, all O-bit disco messages of 74 bytes of plaintext sealed between the client and the server key: Bind (0x04, client), Challenge (0x05, server), Answer (0x06, client). Layout below | Observed | OBS-20261010-peer-relay-datapath, OBS-20261010-peer-relay-handshake |
| Then ordinary disco ping/pong and WireGuard between the clients run through the relay unchanged; the server does not rewrite payloads | Observed | same |
| One 250-byte disco message goes from one client to the other through the relay after the handshake | Observed (size) | same |
| The relay server learns its own address with STUN to the DERP servers | Observed | same |

### Handshake messages (0x04 Bind, 0x05 Challenge, 0x06 Answer)

Same 72-byte body for all three (Observed: a probe completed the handshake and its disco ping was forwarded, OBS-20261010-peer-relay-handshake):

| Bytes | Field |
|---|---|
| 0–3 | VNI (u32 BE), must equal the Geneve header's VNI |
| 4–7 | handshake generation (u32 BE): chosen by the client, nonzero, new for each handshake |
| 8–39 | the other member's disco public key |
| 40–71 | challenge: zero in Bind (padding: all three messages are the same size, so the server never answers with more than it received), set by the server in Challenge, echoed unchanged in Answer |

- Each client of a pair binds separately and gets its own challenge (Observed).
- After both members have answered, disco messages sealed to the other member and sent without the O bit are forwarded by the relay (Observed).

**Pending:** the 250-byte message one official client sends the other after the handshake.

## 4. Behavior

| Fact | Status | Source |
|---|---|---|
| Relay server gone: the client falls back to DERP after 7 s | Observed | OBS-20261010-peer-relay-behavior |
| Relay server back: the client is on the relay again 20–23 s later | Observed | same |
| An idle pair stops all relay traffic after about a minute; the next packet goes via DERP while both clients redo the handshake | Observed | same |

## 5. Open questions

| Question | What would settle it |
|---|---|
| The 250-byte client-to-client message | An official client paired with a probe through the relay (the message is then sealed to the probe) |
| Meaning of the 30 s and 300 s durations | Observing re-handshakes over longer active sessions |
| Several relay addresses in one allocation | A relay server with more than one interface |
