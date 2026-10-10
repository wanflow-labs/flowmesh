# CLI and status semantics

Source: `OBS-20261010-cli` (official 1.94.2, ts2) and wanflow-mesh (wm1). Field names stay compatible with the official client (for the WanFlow gateway agent and similar consumers): these are interoperability facts, not product naming.

## 1. State transitions

| Action | BackendState | exit code of `status` |
|---|---|---|
| Running normally | `Running` | 0 |
| `down` | `Stopped` | 1 |
| A bare `up` after `down` (no flags given) | still `Stopped`: `up` fails with "changing settings requires mentioning all non-default flags" and exit 1 | 1 |
| `logout` | `NeedsLogin` | 1 |
| `up` again with full flags + authkey | `Running` | 0 |

**The "must mention all non-default flags" rule for `up`**: when the current preferences contain non-default values and an `up` call does not explicitly give all of them (and does not pass `--reset`), it is refused, so a flag isn't reset by accident. wanflow-mesh behaves the same way. (The CPE agent's WebUI reconnect runs a bare `up` and is broken by this; tracked as a separate issue.)

## 2. `status --json` fields

Top level (official): `AuthURL BackendState CertDomains ClientVersion CurrentTailnet HaveNodeKey Health MagicDNSSuffix Peer Self TUN TailscaleIPs User Version`.
Self/Peer (official): `Active Addrs AllowedIPs CapMap Created CurAddr DNSName ExitNode ExitNodeOption HostName ID InEngine InMagicSock InNetworkMap LastHandshake LastSeen LastWrite OS Online PeerAPIURL PeerRelay PrimaryRoutes PublicKey Relay RxBytes Tags TailscaleIPs TxBytes UserID` and others.

Fields **the WanFlow gateway agent actually reads** (inventory): top level `BackendState`, `Self.PublicKey`, `Health`, `MagicDNSSuffix`, `CurrentTailnet`; `Peer[]` items `HostName DNSName TailscaleIPs Online LastSeen OS Relay RxBytes TxBytes CurAddr Active PublicKey ExitNodeOption`. flowmesh outputs at least these fields, with the same names and meanings; fields that are not implemented are omitted rather than faked.
