# Allocation forwarded to the peer (disco type 0x07)

Setup: the official client ts1 pings a probe node (100.64.0.15) that has no UDP endpoints, so ts1 cannot
go direct; tsr (official relay server) is up. The probe listens over DERP (`disco.tsv`).

ts1 sent the probe: Pings (0x01, 26), allocation requests (0x08, 4: the probe is a candidate relay
server too), and two identical **0x07** messages of 144 bytes.

## Body of 0x07 (142 bytes after `07 00`)

| Bytes | Content | Status |
|---|---|---|
| 0–31 | the relay server's key (`b5d72284…`, as in the 0x09 reply) | Observed |
| 32–95 | the pair {ts1, probe}, smaller first | Observed |
| 96–103 | u64 generation (5 here) | Observed |
| 104–107 | u32 VNI (5) | Observed |
| 108–115, 116–123 | u64 durations, 30 s and 300 s in ns | Observed |
| 124–141 | the relay endpoint `172.29.0.23:40000`, 18-byte address encoding | Observed |

It is the 0x09 reply's body without the 4-byte counter: after an allocation, the requesting client
forwards it to the other member of the pair over DERP (twice, like other one-shot disco messages), so
that member can bind to the same allocation.

## A hypothesis rejected

The 250-byte message ts1 sends ts2 through the relay (OBS-20261010-peer-relay-datapath) has 164 bytes of
plaintext. A CallMeMaybe would need 9 addresses (2 + 9 × 18), but ts1 has one endpoint: it is not a
CallMeMaybe. It travels only on the relay leg, after the handshake, so it is observable only by a probe
that binds to the relay itself.
