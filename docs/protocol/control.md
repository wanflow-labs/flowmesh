# Control channel

Status legend:
- **Observed**: confirmed directly by black-box captures.
- **Interoperates**: implemented from prior knowledge, and flowmesh interoperates with headscale; the successful interop is the evidence that the fact holds.
- **Unverified**: not yet confirmed.

## 1. Fetching the server public key

| Fact | Status | Source |
|---|---|---|
| `GET /key?v=<capability version>`; official 1.94.2 sends `v=131` | Observed | OBS-20261010-control-handshake/ts1-register.pcap |
| The response JSON contains `legacyPublicKey` and `publicKey`, each `mkey:` followed by 64 hex digits; headscale 0.26 sends an all-zero `legacyPublicKey` | Observed | OBS-20261010-control-handshake/key-response.json |

## 2. Protocol upgrade

| Fact | Status | Source |
|---|---|---|
| `POST /ts2021 HTTP/1.1` with request headers `Connection: upgrade`, `Upgrade: tailscale-control-protocol`, `X-Tailscale-Handshake: <base64>`, `Content-Length: 0` | Observed | OBS-20261010-control-handshake/framing-summary.json |
| The server answers `101 Switching Protocols`; after that, binary frames flow in both directions on the same connection | Observed | Same as above |
| The official client uses plaintext only on port 80; flowmesh uses plaintext on any port for `http://` (deviation #2), and port 18080 works in practice | Observed / Interoperates | OBS-20261010-official-http-control; OBS-20261010-flowmesh-probe |
| Once a Noise connection fails (for example, the server restarts), the official client switches to a "force 443 TLS" mode and can no longer reconnect over plaintext port 80; only a client restart recovers. flowmesh does not inherit this behavior | Observed | lab log 2026-10-09T23:21:45Z (see lab/README.md) |
| `https://` addresses: TLS runs over TCP first (default 443); `/key` and the upgrade request are sent as HTTP/1.1 inside TLS, and after the upgrade the Noise record layer is carried over TLS. The official client and flowmesh both join and interoperate through the same TLS terminator (socat, self-signed CA); an untrusted certificate is rejected (flowmesh reports `invalid peer certificate: UnknownIssuer`) | Interoperates | `lab/scripts/https_control.sh` |

## 3. Frame format

The frame header is 3 bytes: a 1-byte type and a 2-byte big-endian length, followed by the payload.

| Type | Direction | Payload | Status | Source |
|---|---|---|---|---|
| 1 initiation | Client, carried in the `X-Tailscale-Handshake` header | Preceded by a 2-byte big-endian protocol version (= capability version 131); payload is 96 bytes | Observed | framing-summary.json |
| 2 response | Server, first frame after the 101 | 48 bytes | Observed | Same as above |
| 4 record | Both | Ciphertext (plaintext + 16-byte tag) | Observed | Same as above |

## 4. Handshake and record layer

| Fact | Status | Source |
|---|---|---|
| Noise `IK`, `25519`, `ChaChaPoly`, `BLAKE2s`; initiation 96 = 32 + 48 + 16, response 48 = 32 + 16 | Observed (lengths) / Interoperates (algorithms) | framing-summary.json; OBS-20261010-flowmesh-probe |
| The initiator static key is the machine key; the responder static public key is the `publicKey` from §1 | Interoperates | OBS-20261010-flowmesh-probe |
| The prologue is `Tailscale Control Protocol v<version>` | Interoperates | Same as above (a wrong prologue always fails the handshake) |
| Record-layer keys come from the Noise split (initiator: the first key sends, the second receives); the cipher is ChaCha20-Poly1305 | Interoperates | Same as above |
| **Record-layer nonce = 4 zero bytes + 8-byte big-endian counter**, unlike the little-endian encoding in the Noise spec | Observed | With the little-endian encoding from the Noise spec, the second consecutive record from the server failed to decrypt (both encodings agree for nonce 0 and differ from 1 on); switching to big-endian interoperates |
| The server first sends an early payload: 5-byte magic `ff ff ff 54 53` + 4-byte big-endian length + JSON; the plaintext lengths are 5, 4 and 95 bytes in that order; the JSON has a single key, `nodeKeyChallenge` | Observed | framing-summary.json (lengths); OBS-20261010-flowmesh-probe/early.json |

## 5. Over the encrypted channel (HTTP/2)

| Fact | Status | Source |
|---|---|---|
| HTTP/2 runs over the encrypted channel; the client sends the connection preface directly | Interoperates | OBS-20261010-flowmesh-probe |
| `POST /machine/register`: request as in register-request.json; response keys are `AuthURL`, `Error`, `Login`, `MachineAuthorized`, `NodeKeyExpired`, `NodeKeySignature`, `User`. **The user name is in `Login.LoginName`**, not in `User` | Observed | register-response.json |
| `POST /machine/map` (`Stream: true`): the response is a sequence of messages, each prefixed with a 4-byte little-endian length; when the request sets `Compress: "zstd"`, message bodies are zstd-compressed | Interoperates | map-0000.json … map-0004.json |
| The first message contains `Node`, `Peers` (full list), `DERPMap`, `DNSConfig`, `PacketFilters`, `UserProfiles`, `Domain`, `Debug`, `CollectServices`, `ControlTime` | Observed | map-0000.json |
| Later messages are incremental: `PeersChangedPatch` (e.g. `{"NodeID":3,"Online":true}`), `PeersChanged`, `DERPMap`, `DNSConfig`, `Node`, and so on | Observed | map-0001.json … map-0004.json |
| **A node that only sends a streaming `MapRequest` has no `DiscoKey` and `Online` false in other nodes' netmaps**, so other nodes drop its disco messages. After it also sends a non-streaming update (`Stream:false`, `OmitPeers:true`, with the same Hostinfo and DiscoKey), peers see its DiscoKey and `Online` true. flowmeshd always does this (the engine's lite update); flowmesh-probe did not at first | Observed | OBS-20261010-probe-disco-mode |
| Peer nodes carry both `HomeDERP` (integer region ID) and the legacy `DERP` (`127.3.3.40:<region ID>`); the self node's `DERP` is `127.3.3.40:0` while it has no home region yet | Observed | map-0000.json |
| headscale sends `PacketFilters` (`{"base":[...]}`), not `PacketFilter`. Besides the ACL rules, the `base` group also holds peer relay `CapGrant` rules that the lab's control server appends unconditionally | Observed | map-0000.json |

## 6. Open questions

| Question | Status |
|---|---|
| Merge semantics of `PacketFilters` across messages: whole replacement or per-key update, and what null means | Open; to be confirmed by differential tests |
| How each `DNSConfig` field is applied (empty `Routes` lists, `FallbackResolvers`, etc.) | Partly answered; see dns.md |
| What `nodeKeyChallenge` is for | Open; needs differential observation of when the official client uses it |

## 7. Observed but not yet modeled fields

`Debug` (headscale sends `{"DisableLogTail":true}`), `CollectServices`, `UserProfiles[].ProfilePicURL`, `NetInfo`, `Services`, `GoArch` and others in `Node.Hostinfo`, and `RegisterResponse.NodeKeySignature`. Lenient parsing ignores these fields; model and test them when a later feature needs them.

## 8. Node key expiry and the stream lifecycle

Source: OBS-20261010-key-expiry (`lab/scripts/fault_key_expiry.sh`; map messages tapped with `flowmesh-dev --tap-dir`) and OBS-20261010-control-outage (`lab/scripts/fault_control.sh`).

- **Expiry is pushed, not enforced by closing the stream.** After `headscale nodes expire`, the node receives a map message with a full `Node` whose `KeyExpiry` is in the past (with `ControlTime` alongside); the stream stays open and further messages keep arriving. The official client switches to `NeedsLogin` on that message (Health empty, no `AuthURL`). flowmesh does the same and puts `node key expired` in Health.
- Expiry is judged against the message's `ControlTime` (server clock) when present, otherwise the local clock. The zero time `0001-01-01T00:00:00Z` means "never expires".
- **An expired key cannot be renewed.** Registering again with the same node key and an auth key is accepted (`MachineAuthorized`) but the node stays expired, with `NodeKeyExpired: true` in the register response. Registering a **new** node key with `OldNodeKey` set to the expired one (same machine key, same auth key) moves the node to the new key: it keeps its node ID and addresses.
- **Control server restart closes the stream** (EOF). The client must reopen it on a new Noise connection; the first message after reopening is a full netmap. Tunnels are unaffected meanwhile (0% loss over a 15 s outage).
- **Expired peers** stay in the netmap with `KeyExpiry` in the past. The official client lists them (`"Expired": true` in `status --json`) and refuses to ping them (`peer's node key has expired`, exit 1). flowmesh does the same and also leaves them out of WireGuard and path selection. Limitation: a key that reaches its expiry time without any new map message takes effect at the next message; `headscale nodes expire` always pushes one.
- **A server can vanish without closing the stream.** After `docker restart` of the lab control server the client's TCP connection sometimes stayed ESTABLISHED with no counterpart on the server (the container's network namespace was replaced, no FIN or RST was sent; a crashed server or an expired NAT mapping looks the same). The map stream is a read-only long poll, so nothing ever fails. flowmesh presumes a stream dead after **120 s without any message** and redials, with each dial bounded to **30 s** (a server that accepts TCP but never answers would otherwise hang the redial). In the lab the stream carries a message at least every 30 s (DERP map refreshes), so the server's own keepalive interval is still to be observed against a server with a longer refresh. Test: `fault_control.sh` scenario B freezes the server with `docker pause`.
