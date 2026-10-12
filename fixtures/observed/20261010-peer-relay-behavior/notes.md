# Peer relay behavior: failure, recovery, idleness

Official 1.94.2 clients ts1 and ts2, direct UDP between them dropped, tsr as relay server.

## Relay server stops and comes back (`failover.sh`, three runs)

| Event | Run 1 | Run 2 | Run 3 | Status |
|---|---|---|---|---|
| tsr stopped → ts1's ping to ts2 goes via DERP | 7 s | 7 s | 7 s | Observed (1 s ping granularity); consistent with the ~6.5 s trust window of disco.md §3 |
| tsr started → back to the peer relay | 20 s | 23 s | 21 s | Observed |
| VNI after tsr restarts | 1 | 1 | 1 | Observed: the server keeps no allocations across restarts |

## Idle pair (`idle.pcap`, `idle-pcap.txt`: 10 minutes with no traffic)

| Fact | Status |
|---|---|
| Disco ping/pong through the relay continues for about a minute after the last traffic, then the relay port is silent: no periodic re-allocation or re-handshake while idle | Observed |
| The first ping after 10 idle minutes goes via DERP; both clients then repeat the handshake with the server (160-byte O-bit messages) and ping/pong resumes through the relay | Observed |

## WanFlow relay modes (`relay-modes.sh`: ts1 tagged prefer, strict, then auto)

| ts1's mode | ts1 → ts2 | ts2 → ts1 | Status |
|---|---|---|---|
| prefer (`relay-force`) | peer relay (vni 2); isolated single pings reported DERP and the next one the relay again (1 s ping timeout) | peer relay | Observed |
| strict (`relay-force` + `relay-strict`; the server clears the node's endpoints) | DERP for the first pings, the peer relay from t+6 s | peer relay | Observed |
| auto | peer relay | peer relay | Observed |

The peer relay is used in every mode: prefer and strict rule out direct paths, not the relay server.
flowmesh must keep the peer relay available to flowmesh in its prefer and strict modes.
