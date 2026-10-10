# Peer relay allocation request (disco type 0x08), as official clients send it

Setup: ts1 and ts2 (official 1.94.2) with direct UDP between them dropped; the lab relay server `tsr`
stopped, so the pair has no working relay; a probe node (`flowmesh-probe --derp-region 1000`) listens.
Every node is granted `cap/relay` by the control server, so ts1 and ts2 treat the probe as a candidate
relay server and send it allocation requests. Decoding by correlation with the DiscoKeys in
`map-0000.json` (the probe's netmap at start).

## Body (68 bytes after type 0x08, version 0)

| Bytes | Content | Status |
|---|---|---|
| 0–31 | disco public key of one member of the pair (ts2 here) | Observed: equals ts2's DiscoKey |
| 32–63 | disco public key of the other member (ts1) | Observed: equals ts1's DiscoKey |
| 64–67 | big-endian counter | Observed |

- The two keys are the pair that wants to talk, **not** the relay server's key, and the order is the
  same whichever member sends: in every request, from ts1 and from ts2, the key that is smaller
  bytewise comes first. Only one pair has been seen: "sorted ascending" is **Inferred** until a second
  pair (Task 4) confirms it.
- The sender is not in the body; it is the envelope's sender key (one of the two).

## Timing and the counter (`disco.tsv`, `cond-*.tsv`)

| Fact | Status |
|---|---|
| Each request is sent twice, 3.0 s apart, with the same counter (a retransmission) | Observed (every row) |
| Rounds repeat every 30 s while the pair needs a relay and has traffic | Observed (cond-A: 8, 38, 68, 98 s) |
| The counter grows between rounds by varying amounts (+12, +19, +18, +31), never within a retransmission: one counter per sender shared by all requests it sends, presumably to all candidate servers | Inferred (per-server distribution not observable from one candidate) |
| ts1 and ts2 each run their own counter (29 vs 37 at the same moment) | Observed |

## When requests are sent (`conditions.sh`, 100 s probe runs)

| Condition | Rounds received | Reading | Status |
|---|---|---|---|
| A: direct dropped, ts1 pings ts2 every second | 8, 38, 68, 98 s | requests continue every 30 s | Observed |
| B: direct dropped, a single ping at the start | 9, 39 s; none at 69 s | requests stop once the pair is idle; consistent with the ~45 s activity window of disco.md §3 | Observed |
| C: pings every second, drops removed at ~48 s (ts1 then pongs `via 172.29.0.22:42776`) | 8, 38, 68 s; none at 98 s | requests stop after a direct path exists (one more round came 19 s after it) | Observed |
| An established peer relay path (tsr running): no requests to other candidates in 120 s | none | a client with a working relay does not shop for another | Observed (first listen run) |

The strict-tagged candidate condition (does an official client still ask a `tag:relay-strict` node?) moves to the relay-mode runs of the behavior task.
