# disco path discovery

Status notation as in control.md: **Observed** / **Interop-verified** / **Pending** / **Provisional** (no way to observe yet; a conservative value is used).
Source: `OBS-20261010-disco`. flowmesh-dev decrypts the disco messages that official clients send it via DERP using its own disco private key.

## 1. Envelope

| Fact | Status |
|---|---|
| 6-byte magic `54 53 f0 9f 92 ac` (ASCII "TS" + UTF-8 💬) | Observed |
| Then the sender's 32-byte disco public key; it equals `DiscoKey` for that node in the netmap | Observed |
| Then a 24-byte nonce + NaCl box (Curve25519 + XSalsa20-Poly1305); the box key pair is (receiver's disco private key, sender's disco public key) | Observed (decrypts successfully) |
| Over DERP, a disco message is the payload of a SendPacket/RecvPacket; peers tell it apart from WireGuard by the magic | Observed |

## 2. Payload

1-byte type + 1-byte version (observed as 0) + body.

| Type | Name | Body | Status |
|---|---|---|---|
| 0x01 | Ping | 12-byte transaction ID + 32-byte **sender node key** (46 bytes total) | Observed |
| 0x02 | Pong | 12-byte transaction ID (same as the ping) + the source address the replier saw: 16-byte IPv6 form (IPv4 as `::ffff:a.b.c.d`) + 2-byte big-endian port (32 bytes total) | Observed |
| 0x03 | CallMeMaybe | Zero or more 18-byte addresses (same encoding as Pong): the sender's endpoints, asking the receiver to ping them. Sent via DERP | Observed (OBS-20261010-disco/decrypted-callmemaybe.tsv, sent by wanflow-mesh) |
| 0x04–0x09 | peer relay: Bind, Challenge, Answer (handshake with a relay server), CallMeMaybeVia (allocation forwarded to the peer), allocation request and response | see peer-relay.md §2–3. flowmesh (a client only) does not answer allocation requests sent to it; the official client keeps working | Observed (OBS-20261010-peer-relay-*) |

## 3. Behavior

| Fact | Status |
|---|---|
| The source address in a pong over DERP is `127.3.3.40:<DERP region number>`, the same format as the legacy `DERP` field in the netmap | Observed |
| Official clients send pings to a peer with no endpoints via DERP about every 5 seconds (tap timestamps 1.4s, 6.4s, 11.4s) | Observed (interval) → `DISCOVERY_INTERVAL = 5s` |
| While a direct path is active, **both ends ping each other every 3.0 seconds** (heartbeat). UDP length 132 for a ping (8+62+46+16) and 118 for a pong (8+62+32+16) | Observed (packet capture between ts1 and ts2) → `HEARTBEAT = 3s` |
| After the direct path stops responding (drops on the receive side only), the official client falls back to DERP about **6.2 seconds** later; since the heartbeat is 3 s, the trust window measured from the last pong is 6.2–9.2 s | Observed → `TRUST = 6.5s` (provisional) |
| **When the send itself fails** (e.g. a local firewall DROP makes sendto return an error), the official client falls back to DERP within about 1 second | Observed → `on_send_error` falls back immediately |
| A pong over UDP carries the source address this end saw (the address the ping came from) | flowmesh behavior, matching the Pong format |
| The peer counts as active if data was sent within 45 seconds; idle peers get no heartbeat | Provisional (`ACTIVE_WINDOW`) |

## 4. STUN (used together with disco)

Source: `OBS-20261010-stun`. STUN is unencrypted, so the official client's requests can be captured directly.

| Fact | Status |
|---|---|
| A Binding request is sent to the DERP node's `STUNPort` (default 3478) | Observed |
| The request carries **SOFTWARE `tailnode`** and **FINGERPRINT** (RFC 5389 §15.5) attributes, 40 bytes total. The derper does not answer a plain request missing these two attributes | Observed (flowmesh generates a request byte-identical to the official client's) |
| The response has only XOR-MAPPED-ADDRESS, and an IPv4 address is given as an IPv4-mapped IPv6 address (family 0x02, `::ffff:a.b.c.d`) | Observed (flowmesh normalizes it to IPv4) |
| Docker Desktop on macOS does not reliably forward UDP published ports; STUN interop tests must run inside a lab container | Lab note |

## 5. Disco key lifetime

| Fact | Status |
|---|---|
| **Official clients and wanflow-mesh generate a new disco key on every process start** (the peer's DiscoKey in the netmap changes after a restart) | Observed |
| Peers use the key change to detect "the other side restarted" and reset the WireGuard session right away: after wanflow-mesh restarts, peer pings recover within about 1.0 s | Observed (lab/scripts/restart_recovery.sh) |
| flowmesh originally persisted the disco key, so peers did not notice the restart and kept sending on the stale session until it timed out and re-handshook: recovery took **15.4 s**. After switching to a per-run key it takes **0.6 s** | Fixed |

## 6. Relay modes (WanFlow tag semantics)

Tag combinations used in production: prefer = `relay-force`; strict = `relay-force` + `relay-strict`.
What a node sees under each combination (observed via wanflow-mesh's netmap):

| Mode | DERP STUN port | Peer endpoints this node sees |
|---|---|---|
| auto | 3478 | visible |
| prefer | **-1** from older control servers (wanflow-mesh relay-only triggers); the real port from current ones | visible |
| strict | **3478 (back on)** | **cleared** |

How flowmesh picks the mode: `tag:relay-strict` on the self node → strict; otherwise `tag:relay-force`
on the self node, **or** every DERP node with STUNPort -1 (an older control server's only signal) →
prefer; otherwise auto.

### Prefer: relays first, direct only on the LAN or when the relays go silent

Since 0.1.9 prefer is decided **per peer** (crates/flowmesh-pathsock `prefer.rs` + `lib.rs`):

- **Normally**: traffic goes through the peer relay if one answers, otherwise the cloud relay. Direct
  paths are used, pinged and answered only for LAN addresses (10/8, 172.16/12, 192.168/16, 169.254/16,
  fc00::/7, fe80::/10; not 100.64/10 or the mesh's fd7a:115c:a1e0::/48). A ping from a public address
  is dropped unanswered. A CallMeMaybe's endpoints are recorded, but only LAN ones are pinged.
  CallMeMaybe is sent as in auto. Endpoints reported = local + STUN (as auto), so a peer has public
  candidates ready for a fallback.
- **Active** = data sent to or received from the peer, or disco received from it over the direct
  path (pings, CallMeMaybe, including ones that are dropped), within the last 15 s. Pongs never
  count, and neither does disco that arrives over a relay: that answers our own probes and would
  keep an idle peer active forever.
- **Relay probe**: while active, a disco ping every 5 s over the cloud relay and through a bound peer
  relay. Any pong that comes back over a relay counts as "the relays answer".
- **Fallback**: an active peer that the control server does not mark offline, with no relay pong
  for 15 s (counted from the start of the active period, from coming back online, or from the last
  pong, whichever is latest) falls back to auto behaviour for direct paths: all candidates, public
  ones too, are pinged and answered.
- **Back to relay**: after at least 30 s in fallback, once relay pongs have kept coming for 30 s
  with no gap over 10 s, decided only while active. A public direct path is dropped; a LAN one stays.
  An idle peer keeps its fallback state.
- A node that only receives becomes active from the peer's direct pings, so both ends fall back
  without coordination (the second at most 15 s after the first).
- Status: `prefer_fallback` per peer in `status --json`; one log line per transition.

Behavior differential before 0.1.9 (OBS-20261010-relay-modes, peer is official ts1, same LAN; the
prefer row is the old definition: "never initiates, answers UDP pings"):

| Mode | wanflow-mesh (wm1) | flowmesh (fm1) | Note |
|---|---|---|---|
| auto | direct | direct | same |
| prefer | direct (ts1→wm1 direct; wm1 only replies with pongs over UDP and never initiates) | direct (same pattern) | same; matches the product comment "LAN still P2P" |
| strict | **direct (leak)** | relay | **intentional deviation**, see deviation list #6 |

Strict-mode leak mechanism (lab/scripts/strict_leak.sh): with flowmesh (which sends no CallMeMaybe) as the peer, strict wm1 stays on relay; with official ts1 as the peer, it goes direct. So the leak comes from **the strict node accepting CallMeMaybe from the non-strict peer and pinging back**. In production, a strict CPE and an auto-mode CPE will therefore go P2P, which contradicts the product promise of "always relay, no P2P".

## 7. NAT matrix (OBS-20261010-nat-matrix)

| NAT A (subject side) : NAT B (observer side) | flowmesh | official | |
|---|---|---|---|
| easy : easy (full cone) | direct | direct | same |
| easy : pr | relay | relay | same |
| pr : pr (Linux default MASQUERADE) | relay | relay | same |
| easy : hard | relay | relay | same |
| pr : hard | relay | relay | same |
| hard : hard (symmetric) | relay | relay | same |

Lab notes (each one was a source of misleading results):
- Routers must have NAT tools baked into the image: if installed at startup, the client sends traffic before the rules exist, conntrack pins those flows to "no NAT", and NAT never takes effect.
- Packets toward another LAN's private address must be dropped on the router's WAN side, or the Docker host routes them straight there and bypasses NAT.
- Linux default MASQUERADE: crossing punch packets create a reverse conntrack entry that occupies the mapped port, so the outbound mapping changes port. Official and flowmesh both stay on relay.
- The subject and the reference must log in at the same relative time to the observer. Observed once: the observer's netmap kept the subject's old disco key (subject started within 1 s of the observer logging in, with many stale nodes in headscale). Not reproduced in the simplified test (lab/nat/disco_staleness.sh, official and flowmesh both FRESH); kept as an open item.
