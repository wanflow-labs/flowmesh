# Client–server handshake with a probe as the client

A probe gets an allocation from tsr over DERP (0x09, as in OBS-20261010-peer-relay-alloc-response), then
sends the relay address UDP packets laid out like the official clients' first handshake message
(OBS-20261010-peer-relay-datapath): Geneve header with the O bit, protocol 0x7a11, the allocation's VNI,
then a disco envelope sealed by the probe to the allocation's server key, 74 bytes of plaintext (type,
version, 72-byte body). Every packet is 160 bytes, the size of the official handshake messages.

| Run | Types tried | 72-byte body | Server replies over UDP |
|---|---|---|---|
| h1 | 0x04, 0x05, 0x06, 0x0a, 0x0b, 0x0c | the allocation's pair (64) + generation (u64) | none |
| h2 | same six | generation + 64 zero bytes, and 64 zero bytes + generation | none |

Still open: the message types and body layout of the handshake (Pending). The equal size of all three
handshake messages (client, server, client) fits a design where the client pads its first message to
the size of the server's reply, but no layout tried so far gets an answer.

## Handshake completed (runs h3, h4)

Message layout used (all three messages share a 72-byte body after type and version 0):

| Bytes | Field |
|---|---|
| 0–3 | VNI (u32 BE), equal to the Geneve header's VNI |
| 4–7 | handshake generation (u32 BE), chosen by the client, nonzero, new for each handshake |
| 8–39 | the other member's disco public key |
| 40–71 | challenge: zero in Bind (padding, so all three messages are equal in size), set by the server in Challenge, echoed by the client in Answer |

| Run | What happened | Status |
|---|---|---|
| h3 | Bind (0x04) from probe A over UDP, O bit set, sealed to the server key → the server answers within 3 ms with Challenge (0x05): the same VNI, generation and remote key, and a 32-byte challenge | Observed (`run-h3.tsv`) |
| h4 | A and B, one allocation (VNI 4, both got the identical 0x09). Each sends Bind, gets its own Challenge (the two challenges differ), answers with Answer (0x06, the Challenge body echoed). One second later A sends B a disco Ping sealed to B's key through the relay without the O bit; B receives it over UDP from the relay with header `00007a1100000400` | Observed (`run-h4-A.tsv`, `run-h4-B.tsv`): the relay forwards between two bound clients |

- The server key in the allocation changed (`b5d72284…` → `30395198…`) after tsr was restarted for OBS-20261010-peer-relay-behavior: it lasts for the server's lifetime, not across restarts.
