# MagicDNS

Source: `OBS-20261010-magicdns` (as seen by official 1.94.2 on ts2, with accept-dns enabled). Status labels are the same as in control.md.

## 1. System configuration

| Fact | Status |
|---|---|
| With accept-dns on, the official client takes over `/etc/resolv.conf` (direct mode): `nameserver 100.100.100.100`, `search <mesh domain>` | Observed (ts2-resolv.conf) |
| The mesh domain comes from `DNSConfig.Domains` (the lab's `mesh.lab.internal`); `MapResponse.Domain` is the control server's domain (`headscale.lab`), not the DNS suffix | Observed |
| `DNSConfig.Routes` lists 65 reverse zones (`100.100.in-addr.arpa` … and the ip6.arpa zone for `fd7a:115c:a1e0::/48`); an empty value means "answered locally" | Observed |
| Upstream for forwarding: `DNSConfig.Resolvers` takes priority; when absent, use the host's original resolver (the lab only sends `FallbackResolvers`: 223.5.5.5) | Observed (fields); forwarding target inferred |

## 2. Answers (100.100.100.100)

| Query | Answer | Status |
|---|---|---|
| `<node FQDN> A` | that node's IPv4, TTL 600, flags `qr aa rd ra ad` | Observed |
| Case-insensitive name; the answer echoes the query's original case | Observed (`TS1.MESH.LAB.INTERNAL`) |
| `<node FQDN> AAAA` | **NOERROR, empty** (even though the node has an IPv6 address). Inferred cause: the host has no IPv6 connectivity (official log `v6=false`). flowmesh answers AAAA only when the host has a global IPv6 address | Observed (result); condition pending verification (needs an IPv6 lab) |
| `<node FQDN> TXT/MX/other types` | NOERROR, empty | Observed |
| `ExtraRecords` (`svc.mesh.lab.internal A`) | the configured value, TTL 600; querying AAAA on it returns NOERROR, empty | Observed |
| Nonexistent name under the mesh domain, including the domain apex itself | NXDOMAIN, no authority section | Observed |
| `PTR` for a mesh address | that node's FQDN; an unassigned address in the zone → NXDOMAIN | Observed |
| A bare name (`ts1`), an external domain, a name in another private domain (`headscale.lab`) | forwarded upstream (in the lab, the bare name was resolved by Docker DNS to the container IP) | Observed |
