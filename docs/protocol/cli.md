# CLI and status semantics

Source: `OBS-20261010-cli` (official 1.94.2, ts2) and wanflow-mesh (wm1). Field names stay compatible with the official client (for the WanFlow gateway agent and similar consumers): these are interoperability facts, not product naming.

## 1. State transitions

Source: `OBS-20261010-cli-diff` (`lab/scripts/cli_diff.sh`, official 1.94.2 on ts2 vs flowmeshd on fm1; every row matches). Non-zero exit codes are compared as 1.

| Step | Command | cmd exit | BackendState | exit of `status` |
|---|---|---|---|---|
| logout0 | `logout` (start from a clean, logged-out state) | 0 | `NeedsLogin` | 1 |
| join | `up` with flags + auth key | 0 | `Running` | 0 |
| routes | `up` with the same flags + `--accept-routes` | 0 | `Running` | 0 |
| omit | `up` with the original flags, omitting `--accept-routes` | 1 (refused) | `Running` (unchanged) | 0 |
| down | `down` | 0 | `Stopped` | 1 |
| bare-up | `up` with no flags | 1 (refused) | `Stopped` | 1 |
| full-up | `up` mentioning every non-default flag | 0 | `Running` | 0 |
| logout-cut | `logout` while the control server is unreachable | 1 | `Stopped` | 1 |
| logout | `logout` (server reachable) | 0 | `NeedsLogin` | 1 |
| relogin | `up` with fewer flags than before + auth key | 0 | `Running` | 0 |

Facts behind the table:

- **The "must mention all non-default flags" rule for `up`**: when the current preferences contain non-default values and an `up` call does not explicitly give all of them (and does not pass `--reset`), it is refused, so a flag isn't reset by accident. The refusal prints a complete suggested command line. wanflow-mesh behaves the same way. (The CPE agent's WebUI reconnect runs a bare `up` and is broken by this; tracked as a separate issue.)
- **`logout` resets every preference to its default** (official `debug prefs` after logout: empty ControlURL and Hostname, CorpDNS back to true, AdvertiseRoutes cleared, WantRunning false). That is why `relogin` with fewer flags is accepted: there is nothing non-default left to mention.
- **`logout` needs the control server.** It stops the network first, then asks the server to expire the node key. If the server cannot be told, nothing else changes: Stopped, still logged in (`HaveNodeKey`), preferences kept. The official client waits indefinitely (until killed); flowmesh gives up after 15 s with exit 1 (deviation #7). A successful logout replaces the node key and keeps the machine key.
- **No default control server in flowmesh** (deviation #8). A bare official `up` while logged out falls back to the vendor's control server; the differential never runs it.
- `up` waits until `Running` (exit 0) or until the control server refuses the node (exit 1, the login URL is printed if the server gave one). `--timeout` bounds the wait; `0s` (default) waits forever.
- `--advertise-routes` is accepted by the preference model but refused by the daemon ("not supported yet") until the engine advertises subnet routes; silently ignoring it would be worse.

## 2. `status --json` fields

Top level (official): `AuthURL BackendState CertDomains ClientVersion CurrentTailnet HaveNodeKey Health MagicDNSSuffix Peer Self TUN TailscaleIPs User Version`.
Self/Peer (official): `Active Addrs AllowedIPs CapMap Created CurAddr DNSName ExitNode ExitNodeOption HostName ID InEngine InMagicSock InNetworkMap LastHandshake LastSeen LastWrite OS Online PeerAPIURL PeerRelay PrimaryRoutes PublicKey Relay RxBytes Tags TailscaleIPs TxBytes UserID` and others.

Fields **the WanFlow gateway agent actually reads** (inventory): top level `BackendState`, `Self.PublicKey`, `Health`, `MagicDNSSuffix`, `CurrentTailnet`; `Peer[]` items `HostName DNSName TailscaleIPs Online LastSeen OS Relay RxBytes TxBytes CurAddr Active PublicKey ExitNodeOption`. flowmesh outputs at least these fields, with the same names and meanings; fields that are not implemented are omitted rather than faked.

flowmesh-specific details of the output:

- Logged out, the shape follows the official client: `Self.ID` is `""`, `Self.PublicKey` is the all-zero node key, `Self.HostName` is the configured hostname, `TailscaleIPs`/`Peer`/`CurrentTailnet` are `null`, and `HaveNodeKey` is omitted.
- After `down`, the last netmap stays visible (`Peer` is still populated), as on the official client.
- `Health` carries `"flowmesh is stopped."` while Stopped or NeedsLogin (the official text names its own product; the WanFlow gateway agent does not parse it), plus the latest engine error while one is pending.
- `Version` is the flowmesh version. `User`, `CertDomains`, `Addrs`, `CapMap` and the other fields no consumer reads are omitted, not faked.

## 3. Lab notes

- **Official client and a plain-HTTP control server.** After a noise dial has succeeded, the official client remembers it and insists on port 443 for later control dials ("forcing port 443 dial due to recent noise dial"); the memory does not expire on its own. The lab headscale serves plain HTTP on port 80, so a logout, or the login right after it, fails on the official side for this reason alone. `cli_diff.sh` restarts ts2 around each logout (state is persisted, so this clears only the in-memory heuristic). flowmesh has no such heuristic (deviation #2).
- The official client also queries bootstrap DNS on vendor DERP hosts when the control name does not resolve; flowmesh never contacts built-in third-party addresses (deviation #3).
- An unreachable control server is simulated with `ip route add blackhole 172.29.0.10/32` on the client side (fm1 has no iptables).
