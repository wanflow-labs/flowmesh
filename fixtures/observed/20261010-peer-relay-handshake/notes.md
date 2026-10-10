# Client–server handshake: attempts with a probe as the client (no reply yet)

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
