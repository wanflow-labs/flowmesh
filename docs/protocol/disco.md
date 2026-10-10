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
| 0x03 | CallMeMaybe | Pending (will be observed once endpoints are reported in M5 Task 4) | Pending |
| 0x08 | (peer relay) endpoint allocation request | sender disco key (32) + another disco key (32) + 4-byte incrementing counter. Official clients send this to peers granted `cap/relay` (wanflow headscale grants it to all nodes unconditionally). v1 ignores it and does not reply; the official client keeps working normally | Observed (semantics inferred) |

## 3. Behavior

| Fact | Status |
|---|---|
| The source address in a pong over DERP is `127.3.3.40:<DERP region number>`, the same format as the legacy `DERP` field in the netmap | Observed |
| Official clients send pings to a peer with no endpoints via DERP about every 5 seconds (tap timestamps 1.4s, 6.4s, 11.4s) | Observed (interval) |
