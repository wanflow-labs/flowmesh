# Probe disco mode against an official client (ts1)

`flowmesh-probe --derp-region 1000 --disco-to <ts1> --disco-payload <Ping>` in the lab.

| Run | Probe's map requests | ts1's netmap entry for the probe | Ping over DERP |
|---|---|---|---|
| 1 | streaming MapRequest only | `DiscoKey` absent, `Online` false | no reply |
| 2 | streaming MapRequest, then a non-streaming one (`Stream:false`, `OmitPeers:true`, same Hostinfo and DiscoKey) | `DiscoKey` = the probe's key for this run, `Online` true | Pong 1 ms after the Ping (`disco.tsv`) |

- Sending through the probe's own home region (1000) while ts1's home is 1001 got `PeerGone` for ts1's node key from the relay: disco over DERP has to go through the receiver's home region.
- The Pong carries the source address `::ffff:127.3.3.40` port 1001 (`03e9`): ts1 saw the Ping arrive through region 1001, matching disco.md §3.
