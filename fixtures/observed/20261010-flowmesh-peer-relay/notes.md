# flowmesh through the official peer relay (M10 Task 4)

flowmesh-dev (commit a4dcee9) as node `fmr` (172.29.0.61, tailnet 100.64.0.17) in a temporary lab
container; ts2 (official 1.94.2) drops all UDP to and from 172.29.0.61, so the pair has no direct path;
tsr serves as relay. fmr pings ts2 every second.

| Check | Result |
|---|---|
| `tailscale ping 100.64.0.17` on ts2 | `pong from fmr (100.64.0.17) via peer-relay(172.29.0.23:40000:vni:5) in 1ms`, 3 s after traffic started |
| `tsr-fmr.pcap`, 8 s on tsr's relay port, host 172.29.0.61 | fmr → relay: 7 WireGuard (`00007a12000005..`) and 4 disco (`00007a11000005..`); relay → fmr: the same counts |

flowmesh requested or accepted the allocation, completed the handshake, and carries both disco
(3 s heartbeats) and WireGuard through the relay with the Geneve header.
