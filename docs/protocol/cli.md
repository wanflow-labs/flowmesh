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
- **Subnet router** (`--advertise-routes`, `--snat-subnet-routes`, OBS-20261011-subnet-router-official): routes go to the control server as `Hostinfo.RoutableIPs`; the control server still has to approve them. Entries are checked like the official client does, with its messages (`10.0.0.1/24 has non-address bits set; expected 10.0.0.0/24`, `"x" is not a valid IP address or CIDR prefix`); a bare address is a /32 or /128. Both default routes (`0.0.0.0/0,::/0`) mean `--advertise-exit-node`; one without the other is refused with the official message (`0.0.0.0/0 advertised without its IPv6 counterpart, please also advertise ::/0`, and the reverse). Neither client changes sysctls: when routes are advertised and the kernel does not forward, `up`/`set` print the official warning (`Warning: IP forwarding is disabled, subnet routing/exit nodes will not work.`, or the IPv6 one when only IPv6 forwarding is off); health stays empty, as in the official client. Forwarding is accepted and, with `--snat-subnet-routes` (default true), traffic from the mesh into other interfaces is masqueraded (deviation #10 for how). `lab/scripts/subnet_router_check.sh` verifies it end to end with both backends.
- **Inbound destinations** are limited to the node's own addresses, the subnets it advertises, and for an exit node the default routes shrunk as the official client shrinks them (minus this host's interface networks, plus its own addresses, minus private, link-local, multicast and mesh ranges): an exit node is "guest Wi-Fi", its LAN needs a subnet route (OBS-20261011-exit-node-official; the official exit node answers such packets with a TSMP reject).
- **Offering an exit node** (`--advertise-exit-node`, `--stateful-filtering`): Hostinfo.RoutableIPs gains both default routes (approved on the control server); forwarding/SNAT rules as for a subnet router; `--stateful-filtering` drops new connections forwarded into the mesh (conntrack, like the official rule). The exit node serves peers' DNS on its peerapi (`/dns-query`, RFC 8484 GET `?dns=` and POST `application/dns-message`), advertised as `peerapi4`/`peerapi6`/`peerapi-dns-proxy` in Hostinfo.Services: official clients send their DNS there for any exit node of capability version 26 or more, so without it their MagicDNS fails. Like the official handler it bypasses the packet filter and answers only peers whose ACL reaches the internet's port 53 (deviation #11).
- **Using an exit node** (`--exit-node`, `--exit-node-allow-lan-access`): the CLI resolves the value against the current status like the official CLI and stores an address: an address (not our own — `cannot use X as an exit node as it is a local IP address to this machine`; once running a peer that offers one — `no node found in netmap with IP X`, `node X is not advertising an exit node`) or a DNS name with or without the MagicDNS suffix, case-insensitive, unique (`ambiguous exit node name "x"`, `invalid value "x" for --exit-node; must be IP or unique node name`). `auto:any` is refused (not supported yet). Routing is the official layout: rules 5210/5230/5250 send packets with fwmark 0x80000/0xff0000 (flowmesh's own sockets: control, DERP, UDP, DNS forwarding) to the main table and never through the mesh, rule 5270 sends the rest to table 52 (default via flowmesh0, `throw` for loopback, and with LAN access for the host's networks). Only the exit node in use gets the default routes in its AllowedIPs (subnet routes only with `--accept-routes`). While the exit node is unknown or offline, internet traffic is dropped, not leaked (health message). MagicDNS forwards through the exit node's DNS proxy when it has one. `status --json` shows `ExitNodeStatus` (ID, Online, TailscaleIPs as prefixes) and each peer's `ExitNode`. `--exit-node-forwarded-only` (flowmesh only, deviations.md #19) is router mode: rule 5260 `iif lo table main` keeps the host's own traffic off table 52, forwarded IPv4 to the internet is masqueraded to the mesh address, and the throw routes follow the host's networks.
- **`--shields-up`**: the control server's filter rules are ignored, so only replies to this node's connections come in; Hostinfo.ShieldsUp is reported. **`--advertise-tags`** sends Hostinfo.RequestTags, checked with the official messages (`tag: "x": tags must start with 'tag:'`, `tag names must not be empty`, `tag names must start with a letter, after 'tag:'`, `tag names can only contain numbers, letters, or dashes`); granting is the control server's decision.
- `lab/scripts/exit_node_check.sh` covers these end to end against the official client in both roles.
- **Settings change without a restart** (OBS-20261011-set-live, `lab/scripts/set_live_observe.sh`): the official client changes every setting above in place — its disco key stays the same and a 0.2 s ping across the change loses nothing (shields-up loses exactly the pings it refuses). flowmesh does the same: `set` and `up` hand the new settings to the running engine, which re-sends Hostinfo, re-applies the network map, reinstalls only the rules whose inputs changed, starts or stops the DNS proxy and takes over or restores resolv.conf; WireGuard sessions and the disco key are untouched. Only a change of control server (or of the daemon's own TUN/port/state options) restarts the engine, and so does a change the engine reports it cannot apply. A later automatic restart uses the current preferences.

## 2. `status --json` fields

Top level (official): `AuthURL BackendState CertDomains ClientVersion CurrentTailnet HaveNodeKey Health MagicDNSSuffix Peer Self TUN TailscaleIPs User Version`.
Self/Peer (official): `Active Addrs AllowedIPs CapMap Created CurAddr DNSName ExitNode ExitNodeOption HostName ID InEngine InMagicSock InNetworkMap LastHandshake LastSeen LastWrite OS Online PeerAPIURL PeerRelay PrimaryRoutes PublicKey Relay RxBytes Tags TailscaleIPs TxBytes UserID` and others.

Fields **the WanFlow gateway agent actually reads** (inventory): top level `BackendState`, `Self.PublicKey`, `Health`, `MagicDNSSuffix`, `CurrentTailnet`; `Peer[]` items `HostName DNSName TailscaleIPs Online LastSeen OS Relay RxBytes TxBytes CurAddr Active PublicKey ExitNodeOption`. flowmesh outputs at least these fields, with the same names and meanings; fields that are not implemented are omitted rather than faked.

flowmesh-specific details of the output:

- flowmesh additions, camelCase to set them apart from the official PascalCase fields: `backend` (`userspace`) and `relayMode` (`auto`, `prefer`, `strict`; `null` before the first netmap).
- Logged out, the shape follows the official client: `Self.ID` is `""`, `Self.PublicKey` is the all-zero node key, `Self.HostName` is the configured hostname, `TailscaleIPs`/`Peer`/`CurrentTailnet` are `null`, and `HaveNodeKey` is omitted.
- After `down`, the last netmap stays visible (`Peer` is still populated), as on the official client.
- `Health` carries `"flowmesh is stopped."` while Stopped or NeedsLogin (the official text names its own product; the WanFlow gateway agent does not parse it), plus the latest engine error while one is pending.
- `Version` is the flowmesh version. `User`, `CertDomains`, `Addrs`, `CapMap` and the other fields no consumer reads are omitted, not faked.

## 3. `ping`

Source: `OBS-20261010-ping` (`lab/scripts/ping_diff.sh`; stdout, stderr and exit code match the official client in every case, latency and endpoints normalized).

| Case | stdout | stderr | exit |
|---|---|---|---|
| direct path available | `pong from ts1 (100.64.0.1) via 172.29.0.21:59419 in 2ms` (stops at the first direct pong) | — | 0 |
| relay only, `-c 3` | three `pong from … via DERP(wanflow-relay-1000) in 6ms` | `direct connection not established` | 1 |
| peer offline, `-c 2` | `ping "100.64.0.10" timed out` per attempt | `no reply` | 1 |
| IP not in the netmap | — | `no matching peer` | 1 |
| peer whose node key has expired | — | `peer's node key has expired` (immediately, nothing is sent) | 1 |

- One attempt is a disco ping over every path the relay mode allows (DERP always; candidate endpoints in Auto mode), answered by the first pong; an attempt times out after 5 s. A direct pong also establishes the direct path, so pinging is itself a way to trigger hole punching (seen on the official client: the second `ping` to a NATed peer went direct).
- Defaults: `-c 10`, `--until-direct=true`, `--timeout 5s` per attempt (clamped to 1–60 s by the daemon). Without `--until-direct`, relay pongs count as success. `-c 2 --timeout 2s` to an offline peer takes 4 s on both clients.
- The name shown is the first label of the peer's DNS name. Targets may be an IP, that short name, the host name, or the full DNS name; flowmesh resolves names from the netmap only (the official client also asks the system resolver).
- Local API: `POST /localapi/v0/ping` with `{"ip": …}` returns the official field names (`IP NodeIP NodeName Err LatencySeconds Endpoint DERPRegionID DERPRegionCode`); open to every local user, 503 when not Running.

## 4. `debug prefs` and `bugreport`

- `debug prefs` prints the daemon's preferences (flowmesh's own field names; there is no compatibility requirement here).
- `bugreport` writes a local JSON bundle (mode 0600, refuses to overwrite) with the status and preferences from the daemon, `uname -a`, `ip -o addr`, `ip route show table all`, `ip rule`, `/etc/resolv.conf` and the last 300 journal lines of `flowmeshd`. Each item records its own failure instead of aborting (e.g. no journalctl). Every `nodekey:`/`discokey:`/`mkey:`/`privkey:` value is shortened to 8 hex digits. **Deviation from the official client**, which uploads logs and prints an ID: flowmesh never uploads anything (deviation #3); the user decides whether to share the file.

- `debug netmap|paths|filter|derp` print engine views as JSON (root or the daemon's user only; they carry peers' keys and endpoints): the merged netmap; per peer the path in use and why (`direct: pong from … 2.8s ago`, `relay: no direct attempt yet`, `relay: no pong yet from any of N candidate endpoint(s)`, `relay: strict mode …`, `node key expired: not reachable`); the filter groups and whether they compile; the relay regions with the reconnect/home plan.

## 5. `whois` and mesh services

Source: `OBS-20261010-whois` (`lab/scripts/whois_diff.sh`; text, stderr and exit codes match the official client for IPv4, `ip:port`, IPv6, this node itself, a NATed peer, an unknown address and a malformed one; the JSON `CapMap`, `UserProfile` and node ID/Name/Addresses/Tags match).

```
Machine:
  Name:          ts1.mesh.lab.internal
  ID:            1
  Addresses:     [100.64.0.1/32 fd7a:115c:a1e0::1/128]
  Tags:          tag:relay-enabled
Capabilities:
  - tailscale.com/cap/relay
  - tailscale.com/cap/relay-target
```

- `CapMap` is **not** the node's own capability map: it is what the packet filter's `CapGrant` rules grant from that address to this node (rules whose `SrcIPs` match the address and whose `Dsts` contain one of this node's addresses). A name listed in `Caps` has the value `null`; `CapMap` values are concatenated. With WanFlow's control server this is where the high-performance relay grants (`tailscale.com/cap/relay`, `…/relay-target`) show up.
- Failures go to stderr with exit 1: `peer not found`; `400 Bad Request: invalid 'addr' parameter`; `missing argument, expected one peer`.
- Tagged nodes show `Tags` and no user. For untagged nodes flowmesh prints a `User:` section (`Name`/`ID`); every lab node is tagged, so that layout is **not yet verified** against the official client.
- Local API: `GET /localapi/v0/whois?addr=<ip | ip:port | [v6]:port>` → `{"Node", "UserProfile", "CapMap"}`; 404 `peer not found`, 400 for a bad address, 503 when not Running; open to every local user.
- `flowmesh-meshsvc` uses the same lookup: a mesh service gets a `Caller` (node, tags, user, caps) for each connection and never sees a connection whose source the netmap cannot name. Access control stays in the packet filter.

## 6. Query and operations commands

Source: `OBS-20261012-cli-more-official` (`lab/scripts/cli_more_observe.sh`); flowmesh checked against a live mesh with an official exit node by `lab/scripts/cli_more_check.sh`. Machine-readable output (JSON, metric names and labels, messages scripts match on) keeps the official form so existing tools read it; human-facing prose is flowmesh's own wording.

- `ip [-4|-6|-1] [peer]`: this node's mesh addresses, or a peer's (by address, short name, host name or full DNS name; a name the netmap does not know is looked up with the system resolver and must lead to a peer's address). `-1` prints one address, IPv4 when there is one. Messages as official: `flowmesh ip -1, -4, and -6 are mutually exclusive`, `too many arguments, expected at most one peer`, `error looking up IP of "x": …`, and when stopped `no current flowmesh IPs; state: NeedsLogin` (all exit 1).
- `exit-node list [--filter=country]`: the official table (tabwriter layout, minimum column width 10, padding 5, blank line before and after) followed by two `#` hint lines; `STATUS` is `selected`, `offline` or `-`. Headscale sends no locations, so `COUNTRY`/`CITY` are `-`. `no exit nodes found for "x"` (exit 1). `exit-node suggest` is not offered.
- `dns status [--all]`: the official sections in the official order (use-DNS state, MagicDNS configuration, resolvers, split DNS routes, search domains; with `--all` also fallback resolvers, nameserver addresses, certificate domains, additional records, exit-node filtered suffixes, match domains; then the system configuration). Routes without resolvers (headscale sends one per mesh reverse zone) are left out, as official. The system configuration is the host's resolv.conf from before MagicDNS took it over. Local API `GET /localapi/v0/dns`, open to every local user.
- `dns query <name> [a|aaaa|cname|mx|ns|opt|ptr|srv|txt]` (OBS-20261012-dns-query-official): one query to 100.100.100.100, sent over the mesh interface like any program's, shown in the official layout (`Response code: RCodeSuccess`, a tabwriter table with `ClassINET`/`TypeA` names, `No answers were returned.` on failure codes, `(no answers found)` on an empty success). The resolver line names the upstreams the resolver would forward this name to — `Forwarding to resolver: X` for one (with `--accept-dns` and no configured resolvers: the host's nameserver, shown for local names too), `Multiple resolvers available:` otherwise (empty without `--accept-dns`). Errors are printed with exit 0, as official (`failed to query DNS: 400 Bad Request: unknown DNS message type: BOGUS`); words after the type are ignored; no name prints the usage. `lab/scripts/dns_query_observe.sh` runs 14 cases on both clients with and without `--accept-dns`: response code and resolver line agree in all 28.
- `netcheck [--format=json]`: probes run in the CLI process, as official: STUN binding requests (three tries, 300 ms apart) to every relay node of every measured region, IPv4 and IPv6; latency is the fastest answer, rounded to 100 µs in the text report; `MappingVariesByDestIP` is true when servers saw different external addresses; regions STUN does not reach are timed by a TCP connect to the relay. Text and JSON layouts match the official ones byte for byte for the same measurements (JSON: official field order, tab indent, nanoseconds; the warning line goes to stderr). `unknown output format "xml"` (exit 1). PortMapping is always empty (no UPnP/NAT-PMP/PCP). The relay map comes from flowmeshd (`GET /localapi/v0/derpmap`, open to every local user); when it has none, netcheck refuses (deviation #13).
- `metrics print` / `metrics write <file>`: Prometheus text with the official metric names, types and labels (the help texts are flowmesh's own) (`tailscaled_advertised_routes`, `…_approved_routes`, `…_health_messages{type="warning"}`, `…_home_derp_region_id`, `…_{inbound,outbound}_{bytes,packets}_total{path=derp|direct_ipv4|direct_ipv6|peer_relay_ipv4|peer_relay_ipv6}`, `…_outbound_dropped_packets_total{reason=error|multicast}`). flowmesh also fills `…_inbound_dropped_packets_total{reason="acl"|"error"}` (filter refusals; packets not for this node or from outside the peer's AllowedIPs), which the official client declares without samples. Byte counts are WireGuard datagram sizes. `write` replaces the file atomically (for node_exporter's textfile collector). Local API `GET /localapi/v0/metrics`, open to every local user.
- `--operator=<user>` (`up`/`set`): that local user may change settings and read the debug views without root; anyone else is read-only (the socket is 0666). The name is accepted as given (an unknown user matches nobody) and looked up on each request. Only root (or the daemon's own user) may name a different operator; repeating the current one, as `up` requires for non-default settings, is allowed. A refused change prints, like the official client:

```
Access denied: changing flowmesh requires root or the operator

Use 'sudo flowmesh set --shields-up'.
To not require root, use 'sudo flowmesh set --operator=$USER' once.
```

- `--ssh` (`up`/`set`): run the SSH server; `flowmesh ssh` and `flowmesh nc` are the client side. See docs/protocol/ssh.md.
- `serve [--bg] [--http=<port> | --tcp=<port>] [--set-path=…] [--proxy-protocol=1|2] <target> | off`, `serve status [--json]`, `serve reset`, `serve --help`: see docs/protocol/serve.md.

## 7. Lab notes

- **Official client and a plain-HTTP control server.** After a noise dial has succeeded, the official client remembers it and insists on port 443 for later control dials ("forcing port 443 dial due to recent noise dial"); the memory does not expire on its own. The lab headscale serves plain HTTP on port 80, so a logout, or the login right after it, fails on the official side for this reason alone. `cli_diff.sh` restarts ts2 around each logout (state is persisted, so this clears only the in-memory heuristic). flowmesh has no such heuristic (deviation #2).
- The official client also queries bootstrap DNS on vendor DERP hosts when the control name does not resolve; flowmesh never contacts built-in third-party addresses (deviation #3).
- An unreachable control server is simulated with `ip route add blackhole 172.29.0.10/32` on the client side (fm1 has no iptables).
