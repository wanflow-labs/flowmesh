# DERP relay

Status notation is the same as control.md: **observed** / **interop-verified** / **pending**.
Evidence for "interop-verified": `crates/flowmesh-derp/tests/lab_relay.rs` passes against the lab lab-relay (OBS-20261010-derp-handshake), and in M4 Task 3 traffic is exchanged end to end with the official client.

## 1. Connection

| Fact | Status |
|---|---|
| TLS to the node's `HostName`. SNI is `HostName`. The connect address prefers `IPv4` if present. Port `DERPPort`; 0 means 443 | Interop-verified |
| When the node has `InsecureForTests: true`, skip certificate verification (lab self-signed only); otherwise use system root certificates | Interop-verified (lab) |
| `GET /derp HTTP/1.1`, headers `Connection: Upgrade`, `Upgrade: DERP`. The server responds `101` and from then on carries binary frames | Interop-verified |

## 2. Frames

1-byte type + 4-byte big-endian length + payload (interop-verified).

| Type | Name | Payload |
|---|---|---|
| 0x01 | ServerKey | 8-byte magic `DERP🔑` + 32-byte server public key |
| 0x02 | ClientInfo | 32-byte client node public key + 24-byte nonce + NaCl box(JSON) |
| 0x03 | ServerInfo | 24-byte nonce + NaCl box(JSON); the lab server returns `{"version":2}` |
| 0x04 | SendPacket | 32-byte destination node public key + data |
| 0x05 | RecvPacket | 32-byte source node public key + data |
| 0x06 | KeepAlive | empty |
| 0x07 | NotePreferred | 1 byte; 1 means this is the client's home relay |
| 0x08 | PeerGone | 32-byte node public key (+ reason byte) |
| 0x12 / 0x13 | Ping / Pong | 8 bytes; the client returns the payload unchanged |
| 0x14 | Health | UTF-8 text |
| 0x15 | Restarting | — |

All entries above are interop-verified for 0x01–0x05 (handshake and relay round trip). 0x06–0x15 are pending: they are sent by the server or depend on server-side scenarios, and will be recorded when they show up in the long-running M4 Task 3 connection.

## 3. Handshake

| Fact | Status |
|---|---|
| The server first sends ServerKey; the client replies with ClientInfo; the server sends ServerInfo | Interop-verified |
| NaCl box (Curve25519 + XSalsa20-Poly1305). The client uses its own **node private key** and the server public key | Interop-verified |
| ClientInfo JSON: `{"version":2,"canAckPings":true}` | Interop-verified (server accepted it) |
| The identity key on DERP is the node key: when A sends to B's node key, B sees src = A's node key | Interop-verified |
