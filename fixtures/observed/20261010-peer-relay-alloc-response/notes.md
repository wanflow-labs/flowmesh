# Peer relay allocation response (disco type 0x09) from an official relay server

Setup: `tsr` (official 1.94.2, `RelayServerPort: 40000`, tailnet 100.64.0.14, lab 172.29.0.23).
Two probes, A (`probe1`, 100.64.0.15) and B (`probe2`, 100.64.0.16), send tsr an allocation request
(type 0x08, layout from OBS-20261010-peer-relay-alloc-request) over DERP and record the replies.
Each probe's own disco key for the run: `run-*-own-discokey.txt`; tsr's node DiscoKey: `map-0000.json`.

| Run | Request (after `08 00`) | Reply |
|---|---|---|
| A | A's key, B's key, counter 1 (A < B bytewise: sorted) | 0x09, 148 bytes |
| B | B's key, A's key, counter 1 (unsorted) | 0x09, byte-identical to run A's reply |
| V1 | A (new run, new key), B, counters 7 then 8 | two replies, same allocation |
| V2 | A, a key of 32 × `ee` that no node has, counter 9 | a reply with a new allocation |

## Reply body (146 bytes after `09 00`)

| Bytes | Content | How identified | Status |
|---|---|---|---|
| 0–3 | the request's counter, echoed (u32 BE) | 1/1/7/8/9 match the requests one to one | Observed |
| 4–35 | a 32-byte key, the same in every reply (`b5d72284…`), **not** tsr's node DiscoKey | constant across pairs and allocations | Observed; its role (the server's key for relay handshakes) is Inferred, to be settled by the data path |
| 36–67, 68–99 | the pair's two disco keys, smaller first bytewise | equal to A's and B's keys; run B's unsorted request got the same sorted reply | Observed: the server normalises the order |
| 100–107 | u64 BE, 1, 2, 3 for the three allocations | increments per new allocation | Observed; meaning (allocation generation?) Inferred |
| 108–111 | u32 BE, 1, 2, 3: the **VNI** | equals `vni:1` of the official client's `peer-relay(…:vni:1)` (OBS-20261010-peer-relay-official) | Observed |
| 112–119 | u64 BE, 30 000 000 000: **30 s** in nanoseconds | value | Observed (unit Inferred: ns) |
| 120–127 | u64 BE, 300 000 000 000: **300 s** in nanoseconds | value | Observed (unit Inferred: ns) |
| 128–145 | one 18-byte address (disco address encoding): `::ffff:172.29.0.23` port 40000 | tsr's lab address and relay port | Observed; one address per reply here (tsr has one interface) |

## Behaviour

| Fact | Status |
|---|---|
| A repeated request for the same pair returns the existing allocation (same VNI), whichever member asks and in whichever key order | Observed (A/B, V1) |
| A new pair (here: A after restarting with a new disco key) gets a new allocation: VNI and the u64 both increment | Observed (V1) |
| The server allocates for any pair: the other key need not belong to any node (V2) | Observed |
| Replies arrive about 2–5 ms after the request, over DERP through the requester's home region | Observed |
