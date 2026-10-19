// SPDX-License-Identifier: Apache-2.0
//! The engine's pure decisions (home relay, relay mode, endpoints, DNS view, subnet routes, status,
//! applying a netmap), kept out of the Linux event loop so they are unit- and mutation-tested.
// Called from the Linux event loop; the tests run everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::status::{EngineStatus, PeerStatus};
use flowmesh_control::netmap::NetMap;
use flowmesh_dataplane::plane::{Dataplane, PeerConfig};
use flowmesh_pathsock::{Mode, PathSock, PeerInfo, Route};
use flowmesh_proto::control::Node;
use flowmesh_proto::derp::{DerpMap, DerpNode};
use flowmesh_proto::key::NodePublic;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Regions that may be home, in ID order, each with the node to use (the first that is not
/// STUN-only, in the order the server sent: that order is the server's site steering).
pub(crate) fn home_candidates(dm: &DerpMap) -> Vec<(u32, DerpNode)> {
    dm.regions
        .iter()
        .filter(|(_, r)| !r.no_measure_no_home)
        .filter_map(|(id, r)| {
            r.nodes
                .iter()
                .find(|n| !n.stun_only)
                .map(|n| (*id, n.clone()))
        })
        .collect()
}

/// Choose the home relay from measured latencies: the fastest region that answered; if none
/// answered, the first candidate (the lowest ID). Ties keep the lower ID.
pub(crate) fn pick_by_latency(measured: &[(u32, Option<Duration>)]) -> Option<u32> {
    measured
        .iter()
        .filter_map(|(id, rtt)| rtt.map(|r| (r, *id)))
        .min()
        .map(|(_, id)| id)
        .or_else(|| measured.first().map(|(id, _)| *id))
}

/// relay-only (deviation #1): every DERP node has STUNPort == -1.
pub(crate) fn relay_only(dm: &DerpMap) -> bool {
    let mut nodes = dm.regions.values().flat_map(|r| r.nodes.iter()).peekable();
    nodes.peek().is_some() && nodes.all(|n| n.stun_port == -1)
}

/// Relay mode: strict if the self node carries `tag:relay-strict`; prefer if every DERP node has STUNPort == -1; otherwise auto.
pub(crate) fn mode_of(nm: &NetMap) -> Mode {
    let strict = nm
        .self_node
        .as_ref()
        .is_some_and(|n| n.tags.iter().any(|t| t == "tag:relay-strict"));
    if strict {
        Mode::Strict
    } else if relay_only(&nm.derp_map) {
        Mode::Prefer
    } else {
        Mode::Auto
    }
}

/// Endpoints to report in each mode: auto = local + STUN; prefer = local only (no STUN); strict = none.
pub(crate) fn endpoints_for(
    mode: Mode,
    local: &[SocketAddr],
    stun: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut v = match mode {
        Mode::Strict => return Vec::new(),
        Mode::Prefer | Mode::Auto => local.to_vec(),
    };
    if mode == Mode::Auto {
        if let Some(s) = stun.filter(|s| !v.contains(s)) {
            v.push(s);
        }
    }
    v
}

/// A peer's home relay: prefer `HomeDERP`, otherwise parse the legacy `127.3.3.40:<region>`.
pub(crate) fn peer_home(n: &Node) -> Option<u32> {
    if n.home_derp != 0 {
        return Some(n.home_derp);
    }
    n.legacy_derp
        .strip_prefix("127.3.3.40:")
        .and_then(|r| r.parse().ok())
        .filter(|r| *r != 0)
}

/// A WireGuard message starts with a type byte 1–4 followed by three zero bytes (WireGuard whitepaper §5.4, PUB-2).
pub(crate) fn looks_like_wireguard(b: &[u8]) -> bool {
    b.len() >= 4 && (1..=4).contains(&b[0]) && b[1..4] == [0, 0, 0]
}

pub(crate) fn dns_view(nm: &NetMap, answer_aaaa: bool) -> flowmesh_dns::DnsView {
    let Some(dns) = &nm.dns else {
        return flowmesh_dns::DnsView::default();
    };
    let routes: Vec<(String, bool)> = dns
        .routes
        .iter()
        .map(|(k, v)| (k.clone(), v.is_empty()))
        .collect();
    let nodes: Vec<flowmesh_dns::HostEntry> = nm
        .peers
        .values()
        .chain(nm.self_node.iter())
        .map(|n| flowmesh_dns::HostEntry {
            fqdn: n.name.clone(),
            addrs: n.addresses.iter().map(|a| a.addr()).collect(),
        })
        .collect();
    flowmesh_dns::DnsView::new(
        &dns.domains,
        &routes,
        &nodes,
        &dns.extra_records,
        answer_aaaa,
    )
}

/// Forwarding upstreams: `DNSConfig.Resolvers` first, otherwise the host's original nameservers.
/// Where to send forwarded DNS while using `exit_node`: its peerapi DNS proxy, when it has one
/// (capability version 26 or more, or a `peerapi-dns-proxy` service, as the official client
/// decides) and advertises a peerapi port for one of its addresses (IPv4 first).
pub(crate) fn exit_dns_target(nm: &NetMap, exit_node: NodePublic) -> Option<SocketAddr> {
    use flowmesh_proto::control::{PEERAPI_DNS, PEERAPI4, PEERAPI6};
    let n = nm.peers.values().find(|n| n.key == exit_node)?;
    let services = &n.hostinfo.services;
    let proxies = n.cap >= 26
        || services
            .iter()
            .any(|s| s.proto == PEERAPI_DNS && s.port >= 1);
    if !proxies {
        return None;
    }
    let port = |proto: &str| services.iter().find(|s| s.proto == proto).map(|s| s.port);
    let addr = |v4: bool| {
        n.addresses
            .iter()
            .map(|a| a.addr())
            .find(|a| a.is_ipv4() == v4)
    };
    port(PEERAPI4)
        .zip(addr(true))
        .or_else(|| port(PEERAPI6).zip(addr(false)))
        .map(|(p, ip)| SocketAddr::new(ip, p))
}

pub(crate) fn dns_upstreams(nm: &NetMap, host: &[IpAddr]) -> Vec<IpAddr> {
    let from_config: Vec<IpAddr> = nm
        .dns
        .iter()
        .flat_map(|d| d.resolvers.iter())
        .filter_map(|r| r.addr.parse().ok())
        .collect();
    if from_config.is_empty() {
        host.to_vec()
    } else {
        from_config
    }
}

/// Subnet routes advertised by peers: prefixes in AllowedIPs outside the mesh address ranges, excluding default routes (exit nodes are a separate feature).
pub(crate) fn subnet_routes(nm: &NetMap) -> std::collections::BTreeSet<ipnet::IpNet> {
    let mesh4: ipnet::IpNet = "100.64.0.0/10".parse().unwrap_or_default();
    let mesh6: ipnet::IpNet = "fd7a:115c:a1e0::/48".parse().unwrap_or_default();
    nm.peers
        .values()
        .flat_map(|n| n.allowed_ips.iter().copied())
        .filter(|p| p.prefix_len() != 0 && !mesh4.contains(p) && !mesh6.contains(p))
        .collect()
}

pub(crate) fn peer_status(n: &Node, nm: &NetMap) -> PeerStatus {
    let relay = peer_home(n)
        .and_then(|r| nm.derp_map.regions.get(&r))
        .map(|r| r.region_code.clone())
        .unwrap_or_default();
    PeerStatus {
        id: n.id,
        public_key: n.key.to_string(),
        host_name: n.hostinfo.hostname.clone(),
        dns_name: n.name.clone(),
        os: n.hostinfo.os.clone(),
        tailscale_ips: n.addresses.iter().map(|a| a.addr()).collect(),
        online: n.online.unwrap_or(false),
        last_seen: n.last_seen.clone(),
        relay,
        exit_node_option: n.allowed_ips.iter().any(|p| p.prefix_len() == 0),
        tags: n.tags.clone(),
        ssh_host_keys: n.hostinfo.ssh_host_keys.clone(),
        key_expiry: n
            .key_expiry
            .clone()
            .filter(|e| parse_rfc3339_utc(e) > parse_rfc3339_utc("0001-01-01T00:00:00Z")),
        expired: key_expired(n, nm.control_time.as_deref(), unix_now()),
        primary_routes: n.primary_routes.clone(),
        ..Default::default()
    }
}

pub(crate) fn snapshot(
    nm: &NetMap,
    ps: &PathSock,
    dp: &Dataplane,
    now: Duration,
    health: &[String],
) -> EngineStatus {
    let stats: HashMap<NodePublic, (u64, u64)> = dp
        .stats()
        .into_iter()
        .map(|(k, tx, rx)| (k, (tx, rx)))
        .collect();
    let peers = nm
        .peers
        .values()
        .map(|n| {
            let mut s = peer_status(n, nm);
            match ps.current_route(n.key, now) {
                Route::Direct(addr) => s.cur_addr = Some(addr),
                Route::PeerRelay { server, vni } => s.peer_relay = format!("{server}:vni:{vni}"),
                _ => {}
            }
            if let Some((tx, rx)) = stats.get(&n.key) {
                s.tx_bytes = *tx;
                s.rx_bytes = *rx;
                s.active = *tx + *rx > 0;
            }
            s
        })
        .collect();
    let suffix = nm
        .dns
        .as_ref()
        .and_then(|d| d.domains.first().cloned())
        .unwrap_or_default();
    EngineStatus {
        self_node: nm.self_node.as_ref().map(|n| peer_status(n, nm)),
        peers,
        magic_dns_suffix: suffix.clone(),
        tailnet_name: suffix,
        health: health.to_vec(),
        relay_mode: mode_name(mode_of(nm)).to_string(),
    }
}

/// The name of a relay mode in `status --json` (`relayMode`).
pub(crate) fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Auto => "auto",
        Mode::Prefer => "prefer",
        Mode::Strict => "strict",
    }
}

/// Seconds since the Unix epoch by the local clock (0 if the clock is before 1970).
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Peers the data plane may talk to: an expired node key is shown in status but not reached, as on
/// the official client (control.md §8).
/// Peers that may serve this node as a peer relay server: the packet filter grants this node
/// `cap/relay-target` from them, i.e. the right to allocate relay endpoints on them (peer-relay.md §1).
/// Only peers we can ask: online, not expired, and with a home region present in our DERP map (the
/// map is per node, so a peer's region may be missing from ours).
pub(crate) fn relay_candidates(nm: &NetMap, now_unix: i64) -> Vec<flowmesh_udprelay::Candidate> {
    const RELAY_TARGET: &str = "tailscale.com/cap/relay-target";
    let mine: Vec<IpAddr> = nm
        .self_node
        .iter()
        .flat_map(|n| n.addresses.iter().map(|a| a.addr()))
        .collect();
    let rules = nm.filter_rules();
    let mut out: Vec<flowmesh_udprelay::Candidate> = live_peers(nm, now_unix)
        .filter(|n| n.online == Some(true))
        .filter(|n| {
            n.addresses.iter().any(|a| {
                flowmesh_filter::caps::peer_caps(&rules, a.addr(), &mine).contains_key(RELAY_TARGET)
            })
        })
        .filter_map(|n| {
            let region = peer_home(n).filter(|r| nm.derp_map.regions.contains_key(r))?;
            Some(flowmesh_udprelay::Candidate {
                node: n.key,
                disco: n.disco_key,
                home_region: Some(region),
            })
        })
        .collect();
    out.sort_by_key(|c| c.node.0);
    out
}

pub(crate) fn live_peers(nm: &NetMap, now_unix: i64) -> impl Iterator<Item = &Node> {
    nm.peers
        .values()
        .filter(move |n| !key_expired(n, nm.control_time.as_deref(), now_unix))
}

/// This host's interface networks and addresses (the mesh interface excluded), which an exit node
/// keeps out of the default route it offers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Interfaces {
    pub nets: Vec<ipnet::IpNet>,
    pub hosts: Vec<IpAddr>,
}

/// Destinations inbound packets may have: this node's own addresses, the subnets it advertises,
/// and when it offers an exit node, the default routes shrunk as the official client does.
pub(crate) fn local_nets(
    nm: &NetMap,
    advertised: &[ipnet::IpNet],
    exit_node: Option<&Interfaces>,
) -> flowmesh_dataplane::netset::LocalNets {
    use flowmesh_dataplane::netset::shrink_default_route;
    let own = nm
        .self_node
        .iter()
        .flat_map(|n| n.addresses.iter().copied());
    let routes = advertised.iter().copied().filter(|r| r.prefix_len() != 0);
    let exits = exit_node.into_iter().flat_map(|ifs| {
        ["0.0.0.0/0", "::/0"]
            .into_iter()
            .filter_map(|r| r.parse().ok())
            .flat_map(|r| shrink_default_route(r, &ifs.nets, &ifs.hosts))
            .collect::<Vec<_>>()
    });
    flowmesh_dataplane::netset::LocalNets::new(own.chain(routes).chain(exits))
}

/// Local choices that shape how a network map is applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Policy {
    /// `--shields-up`: no inbound connections at all, whatever the control server's filter says.
    pub shields_up: bool,
    /// `--accept-routes`: peers' subnet routes go into their AllowedIPs (and the kernel table).
    pub accept_routes: bool,
    /// The exit node in use: the only peer whose default routes go into its AllowedIPs.
    pub exit_node: Option<NodePublic>,
}

/// The AllowedIPs this node gives a peer: its own addresses, its subnet routes when routes are
/// accepted, its default routes only when it is the exit node in use (the official client builds
/// its WireGuard configuration the same way).
pub(crate) fn peer_allowed_ips(n: &Node, policy: &Policy) -> Vec<ipnet::IpNet> {
    n.allowed_ips
        .iter()
        .copied()
        .filter(|p| {
            if n.addresses.contains(p) {
                true
            } else if p.prefix_len() == 0 {
                policy.exit_node == Some(n.key)
            } else {
                policy.accept_routes
            }
        })
        .collect()
}

/// The peer `--exit-node` names. The CLI resolves names to an address (as the official CLI does),
/// so the engine looks the address up.
pub(crate) fn resolve_exit_node(nm: &NetMap, spec: &str) -> Result<NodePublic, String> {
    let bad = || format!("exit node {spec} is not in the network map");
    let ip: IpAddr = spec.parse().map_err(|_| bad())?;
    nm.peers
        .values()
        .find(|n| n.addresses.iter().any(|a| a.addr() == ip))
        .map(|n| n.key)
        .ok_or_else(bad)
}

pub(crate) fn apply_netmap(
    dp: &mut Dataplane,
    ps: &mut PathSock,
    nm: &NetMap,
    now_unix: i64,
    policy: &Policy,
) -> Result<(), String> {
    dp.set_peers(
        live_peers(nm, now_unix)
            .map(|n| PeerConfig {
                key: n.key,
                allowed_ips: peer_allowed_ips(n, policy),
                disco: n.disco_key,
            })
            .collect(),
    );
    ps.set_peers(
        live_peers(nm, now_unix)
            .map(|n| PeerInfo {
                node: n.key,
                disco: n.disco_key,
                home_region: peer_home(n),
                endpoints: n.endpoints.clone(),
            })
            .collect(),
    );
    ps.set_mode(mode_of(nm));
    // Shields up: no rules, so only replies to this node's own connections come in (the filter
    // tracks outbound flows), as the official client does.
    if policy.shields_up {
        dp.set_filter_rules(Vec::new());
        return Ok(());
    }
    // fail-closed: on a compile error the previous valid rules stay.
    let rules = flowmesh_filter::compile::compile(&nm.filter_rules())
        .map_err(|e| format!("filter rules rejected, keeping previous: {e}"))?;
    dp.set_filter_rules(rules);
    Ok(())
}

/// RFC 3339 time in UTC (`YYYY-MM-DDTHH:MM:SS[.fraction]Z`) as Unix seconds; `None` for any other
/// shape. Control servers send UTC; offsets other than `Z` are not accepted rather than misread.
pub(crate) fn parse_rfc3339_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let rest = &s[19..];
    let frac_ok = match rest.strip_suffix('Z') {
        Some("") => true,
        Some(f) => f
            .strip_prefix('.')
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit())),
        None => false,
    };
    if !frac_ok {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    // Days from 1970-01-01 (civil-from-days inverse, proleptic Gregorian).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se)
}

/// Whether this node's key has expired: `KeyExpiry` is set (not the zero time) and not later than
/// the reference time, which is the message's `ControlTime` when present (the server's clock, so a
/// skewed local clock cannot cause it) and otherwise `now_unix`.
pub(crate) fn key_expired(self_node: &Node, control_time: Option<&str>, now_unix: i64) -> bool {
    let Some(expiry) = self_node.key_expiry.as_deref().and_then(parse_rfc3339_utc) else {
        return false;
    };
    // Go's zero time, which means "never expires".
    if expiry <= parse_rfc3339_utc("0001-01-01T00:00:00Z").unwrap_or(i64::MIN) {
        return false;
    }
    let reference = control_time.and_then(parse_rfc3339_utc).unwrap_or(now_unix);
    expiry <= reference
}

/// `ID`, `VERSION_ID` and `VERSION_CODENAME` from an os-release file (os-release(5)): the Distro,
/// DistroVersion and DistroCodeName the official client reports. Values may be quoted; missing
/// keys are empty.
pub fn os_release_fields(text: &str) -> (String, String, String) {
    let mut id = String::new();
    let mut version = String::new();
    let mut codename = String::new();
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value)
            .to_string();
        match key.trim() {
            "ID" => id = value,
            "VERSION_ID" => version = value,
            "VERSION_CODENAME" => codename = value,
            _ => {}
        }
    }
    (id, version, codename)
}

/// Whether adding an IPv6 address failed because the host has IPv6 turned off, rather than for a
/// reason that should stop the engine. With `net.ipv6.conf.*.disable_ipv6=1` (common on servers) the
/// kernel refuses the address with EACCES; with the `ipv6.disable=1` boot option there is no IPv6
/// socket family at all (EAFNOSUPPORT). The mesh then runs IPv4-only instead of failing to bring the
/// interface up and restarting forever. Linux errno values.
pub fn ipv6_unavailable(e: &std::io::Error) -> bool {
    const EACCES: i32 = 13;
    const EAFNOSUPPORT: i32 = 97;
    matches!(e.raw_os_error(), Some(EACCES | EAFNOSUPPORT))
}

#[cfg(test)]
mod tests {

    #[test]
    fn os_release_gives_distro_fields() {
        let ubuntu = "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\n";
        assert_eq!(
            super::os_release_fields(ubuntu),
            ("ubuntu".into(), "22.04".into(), "jammy".into())
        );
        // Alpine has no codename; single quotes and stray blanks are tolerated.
        assert_eq!(
            super::os_release_fields("ID=alpine\nVERSION_ID='3.22.3'\n# comment\n\n  BAD LINE\n"),
            ("alpine".into(), "3.22.3".into(), String::new())
        );
        assert_eq!(
            super::os_release_fields(""),
            (String::new(), String::new(), String::new())
        );
    }

    #[test]
    fn ipv6_turned_off_is_not_an_engine_error() {
        use std::io::Error;
        assert!(super::ipv6_unavailable(&Error::from_raw_os_error(13)));
        assert!(super::ipv6_unavailable(&Error::from_raw_os_error(97)));
        // Anything else (no such device, address in use, out of memory) still stops the engine.
        for errno in [1, 12, 17, 19] {
            assert!(
                !super::ipv6_unavailable(&Error::from_raw_os_error(errno)),
                "errno {errno}"
            );
        }
        assert!(!super::ipv6_unavailable(&Error::other("not an OS error")));
    }

    #[test]
    fn exit_dns_goes_to_the_exit_nodes_peerapi_proxy() {
        use flowmesh_proto::control::Service;
        let svc = |proto: &str, port: u16| Service {
            proto: proto.into(),
            port,
            description: String::new(),
        };
        let mut n = exit_peer(1, 1, "tse", "tsE", "100.64.0.9/32");
        n.addresses.push("fd7a:115c:a1e0::9/128".parse().unwrap());
        n.cap = 131;
        n.hostinfo.services = vec![svc("peerapi4", 38210), svc("peerapi6", 39042)];
        let mut nm = NetMap::default();
        nm.peers.insert(1, n.clone());
        assert_eq!(
            exit_dns_target(&nm, n.key),
            Some("100.64.0.9:38210".parse().unwrap())
        );
        // An old peer (capability below 26) needs the explicit service.
        nm.peers.get_mut(&1).unwrap().cap = 20;
        assert_eq!(exit_dns_target(&nm, n.key), None);
        nm.peers
            .get_mut(&1)
            .unwrap()
            .hostinfo
            .services
            .push(svc("peerapi-dns-proxy", 1));
        assert!(exit_dns_target(&nm, n.key).is_some());
        // No peerapi4 port: the IPv6 one.
        nm.peers
            .get_mut(&1)
            .unwrap()
            .hostinfo
            .services
            .retain(|s| s.proto != "peerapi4");
        assert_eq!(
            exit_dns_target(&nm, n.key),
            Some("[fd7a:115c:a1e0::9]:39042".parse().unwrap())
        );
        nm.peers.get_mut(&1).unwrap().hostinfo.services.clear();
        assert_eq!(exit_dns_target(&nm, n.key), None, "no port advertised");
        assert_eq!(exit_dns_target(&nm, NodePublic([9; 32])), None);
    }

    fn exit_peer(id: i64, key: u8, name: &str, host: &str, addr: &str) -> Node {
        Node {
            id,
            key: NodePublic([key; 32]),
            name: format!("{name}.mesh.lab.internal."),
            hostinfo: flowmesh_proto::control::Hostinfo {
                hostname: host.into(),
                ..Default::default()
            },
            addresses: vec![addr.parse().unwrap()],
            allowed_ips: vec![
                addr.parse().unwrap(),
                "0.0.0.0/0".parse().unwrap(),
                "::/0".parse().unwrap(),
                "10.9.0.0/24".parse().unwrap(),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn allowed_ips_carry_default_routes_only_for_the_exit_node_in_use() {
        let n = exit_peer(1, 1, "tse", "tsE", "100.64.0.9/32");
        let none = peer_allowed_ips(&n, &Policy::default());
        assert_eq!(
            none,
            vec!["100.64.0.9/32".parse::<ipnet::IpNet>().unwrap()],
            "no routes accepted, not the exit node"
        );
        let routes = peer_allowed_ips(
            &n,
            &Policy {
                accept_routes: true,
                ..Default::default()
            },
        );
        assert!(
            routes.contains(&"10.9.0.0/24".parse().unwrap())
                && routes.iter().all(|p| p.prefix_len() != 0)
        );
        let exit = peer_allowed_ips(
            &n,
            &Policy {
                exit_node: Some(n.key),
                ..Default::default()
            },
        );
        assert!(
            exit.contains(&"0.0.0.0/0".parse().unwrap()) && exit.contains(&"::/0".parse().unwrap())
        );
        assert!(
            !exit.contains(&"10.9.0.0/24".parse().unwrap()),
            "using an exit node does not accept subnet routes"
        );
    }

    #[test]
    fn exit_node_is_looked_up_by_address() {
        let mut nm = NetMap::default();
        let n = exit_peer(1, 1, "tse", "tsE", "100.64.0.9/32");
        nm.peers.insert(n.id, n);
        assert_eq!(
            resolve_exit_node(&nm, "100.64.0.9"),
            Ok(NodePublic([1; 32]))
        );
        assert_eq!(
            resolve_exit_node(&nm, "100.64.0.99"),
            Err("exit node 100.64.0.99 is not in the network map".into())
        );
        assert!(
            resolve_exit_node(&nm, "tse").is_err(),
            "names are resolved by the CLI"
        );
    }

    #[test]
    fn local_nets_cover_own_addresses_routes_and_a_shrunk_exit() {
        let nm = NetMap {
            self_node: Some(Node {
                addresses: vec![
                    "100.64.0.7/32".parse().unwrap(),
                    "fd7a:115c:a1e0::7/128".parse().unwrap(),
                ],
                ..Default::default()
            }),
            ..Default::default()
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let plain = local_nets(&nm, &[], None);
        assert!(plain.contains(&ip("100.64.0.7")) && plain.contains(&ip("fd7a:115c:a1e0::7")));
        assert!(!plain.contains(&ip("100.64.0.8")) && !plain.contains(&ip("1.1.1.1")));
        let router = local_nets(&nm, &["10.99.0.0/24".parse().unwrap()], None);
        assert!(router.contains(&ip("10.99.0.10")) && !router.contains(&ip("10.98.0.10")));
        let ifs = Interfaces {
            nets: vec!["172.29.0.0/24".parse().unwrap()],
            hosts: vec![ip("172.29.0.88")],
        };
        let exit = local_nets(&nm, &[], Some(&ifs));
        assert!(exit.contains(&ip("1.1.1.1")) && exit.contains(&ip("2606:4700::1111")));
        assert!(!exit.contains(&ip("172.29.0.10")) && !exit.contains(&ip("10.98.0.10")));
        assert!(exit.contains(&ip("100.64.0.7")), "own addresses stay");
    }

    use super::*;

    fn first_home(dm: &DerpMap) -> Option<(u32, DerpNode)> {
        home_candidates(dm).into_iter().next()
    }
    use flowmesh_dataplane::plane::Output;
    use flowmesh_disco::{envelope, message};
    use flowmesh_proto::control::{DnsConfig, DnsResolver};
    use flowmesh_proto::derp::DerpRegion;
    use flowmesh_proto::key::{DiscoPrivate, NodePrivate};
    use std::net::SocketAddrV4;

    fn node(name: &str, stun_port: i32, stun_only: bool) -> DerpNode {
        DerpNode {
            name: name.into(),
            host_name: format!("{name}.lab"),
            stun_port,
            stun_only,
            ..Default::default()
        }
    }

    fn region(id: u32, code: &str, no_home: bool, nodes: Vec<DerpNode>) -> (u32, DerpRegion) {
        (
            id,
            DerpRegion {
                region_id: id,
                region_code: code.into(),
                no_measure_no_home: no_home,
                nodes,
                ..Default::default()
            },
        )
    }

    fn map(regions: Vec<(u32, DerpRegion)>) -> DerpMap {
        DerpMap {
            regions: regions.into_iter().collect(),
            ..Default::default()
        }
    }

    #[test]
    fn rfc3339_utc() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_utc("2026-10-10T06:18:17.53902463Z"),
            Some(1_791_613_097)
        );
        assert_eq!(parse_rfc3339_utc("2000-02-29T12:00:00Z"), Some(951_825_600));
        assert_eq!(parse_rfc3339_utc("1969-12-31T23:59:59Z"), Some(-1));
        assert_eq!(
            parse_rfc3339_utc("0001-01-01T00:00:00Z"),
            Some(-62_135_596_800)
        );
        for bad in [
            "",
            "2026-10-10",
            "2026-10-10T06:18:17",
            "2026-10-10T06:18:17+08:00",
            "2026-10-10 06:18:17Z",
            "2026-13-10T06:18:17Z",
            "2026-10-32T06:18:17Z",
            "2026-10-10T24:00:00Z",
            "2026-10-10T06:60:00Z",
            "2026-10-10T06:18:61Z",
            "2026-10-10T06:18:17.Z",
            "2026-10-10T06:18:17.5xZ",
            "+026-10-10T06:18:17Z",
            "2026-1a-10T06:18:17Z",
            "2026/10-10T06:18:17Z",
            "2026-10/10T06:18:17Z",
            "2026-10-10T06.18:17Z",
            "2026-10-10T06:18.17Z",
            "2026-00-10T06:18:17Z",
            "2026-10-00T06:18:17Z",
        ] {
            assert_eq!(parse_rfc3339_utc(bad), None, "{bad}");
        }
        assert_eq!(
            parse_rfc3339_utc("2026-10-10T06:18:60Z"),
            Some(1_791_613_140),
            "leap second accepted"
        );
    }

    #[test]
    fn key_expiry_against_server_time() {
        let n = |e: Option<&str>| Node {
            key_expiry: e.map(str::to_string),
            ..Default::default()
        };
        let t = parse_rfc3339_utc("2026-10-10T06:18:17Z").unwrap();
        // Expired according to the server, even though the local clock lags.
        assert!(key_expired(
            &n(Some("2026-10-10T06:18:17Z")),
            Some("2026-10-10T06:18:20Z"),
            t - 3600
        ));
        assert!(
            key_expired(
                &n(Some("2026-10-10T06:18:17Z")),
                Some("2026-10-10T06:18:17Z"),
                0
            ),
            "at the instant"
        );
        // Not yet expired according to the server, even though the local clock runs ahead.
        assert!(!key_expired(
            &n(Some("2026-10-10T06:18:17Z")),
            Some("2026-10-10T06:18:16Z"),
            t + 3600
        ));
        // No server time: the local clock decides.
        assert!(key_expired(&n(Some("2026-10-10T06:18:17Z")), None, t + 1));
        assert!(!key_expired(&n(Some("2026-10-10T06:18:17Z")), None, t - 1));
        assert!(
            !key_expired(&n(Some("2026-10-10T06:18:17Z")), Some("garbage"), t - 1),
            "unparsable server time: local"
        );
        // Never expires.
        assert!(!key_expired(
            &n(Some("0001-01-01T00:00:00Z")),
            Some("2026-10-10T06:18:17Z"),
            t
        ));
        assert!(!key_expired(&n(None), None, t));
        assert!(!key_expired(&n(Some("not a time")), None, t));
    }

    #[test]
    fn home_skips_no_home_regions_and_stun_only_nodes_and_keeps_site_order() {
        let dm = map(vec![
            region(900, "a", true, vec![node("a1", 3478, false)]),
            region(
                1000,
                "b",
                false,
                vec![
                    node("b-stun", 3478, true),
                    node("b-site2", 3478, false),
                    node("b-site1", 3478, false),
                ],
            ),
            region(1100, "c", false, vec![node("c1", 3478, false)]),
        ]);
        let (id, n) = first_home(&dm).unwrap();
        assert_eq!(
            (id, n.name.as_str()),
            (1000, "b-site2"),
            "first eligible node, in the order the server sent"
        );
        assert_eq!(
            first_home(&map(vec![region(
                900,
                "a",
                true,
                vec![node("a1", 1, false)]
            )])),
            None
        );
        assert_eq!(
            first_home(&map(vec![region(1, "x", false, vec![node("s", 1, true)])])),
            None
        );
        assert_eq!(first_home(&DerpMap::default()), None);
    }

    #[test]
    fn latency_picks_the_fastest_answering_region() {
        let ms = Duration::from_millis;
        assert_eq!(
            pick_by_latency(&[(1000, Some(ms(40))), (1001, Some(ms(5))), (1002, None)]),
            Some(1001)
        );
        assert_eq!(
            pick_by_latency(&[(1000, Some(ms(5))), (1001, Some(ms(5)))]),
            Some(1000),
            "tie: lower ID"
        );
        assert_eq!(
            pick_by_latency(&[(1000, None), (1001, Some(ms(90)))]),
            Some(1001),
            "only one answered"
        );
        assert_eq!(
            pick_by_latency(&[(1000, None), (1001, None)]),
            Some(1000),
            "nobody answered: lowest ID"
        );
        assert_eq!(pick_by_latency(&[]), None);
    }

    #[test]
    fn candidates_follow_region_order() {
        let dm = map(vec![
            region(1002, "c", false, vec![node("c1", 1, false)]),
            region(
                1000,
                "a",
                false,
                vec![node("a-stun", 1, true), node("a1", 1, false)],
            ),
            region(1001, "b", true, vec![node("b1", 1, false)]),
        ]);
        let got: Vec<(u32, String)> = home_candidates(&dm)
            .into_iter()
            .map(|(id, n)| (id, n.name))
            .collect();
        assert_eq!(got, [(1000, "a1".to_string()), (1002, "c1".to_string())]);
    }

    #[test]
    fn relay_only_needs_every_node_without_stun() {
        assert!(
            !relay_only(&DerpMap::default()),
            "an empty map is not relay-only"
        );
        assert!(relay_only(&map(vec![region(
            1,
            "a",
            false,
            vec![node("n", -1, false), node("m", -1, false)]
        )])));
        assert!(!relay_only(&map(vec![
            region(1, "a", false, vec![node("n", -1, false)]),
            region(2, "b", false, vec![node("m", 3478, false)]),
        ])));
    }

    fn netmap_with(tags: &[&str], stun_port: i32) -> NetMap {
        NetMap {
            self_node: Some(Node {
                tags: tags.iter().map(|t| t.to_string()).collect(),
                ..Default::default()
            }),
            derp_map: map(vec![region(
                1000,
                "r",
                false,
                vec![node("n", stun_port, false)],
            )]),
            ..Default::default()
        }
    }

    #[test]
    fn relay_mode_from_tags_and_derp_map() {
        assert_eq!(
            mode_of(&netmap_with(&["tag:relay-strict"], 3478)),
            Mode::Strict
        );
        assert_eq!(
            mode_of(&netmap_with(&["tag:relay-strict"], -1)),
            Mode::Strict,
            "strict wins"
        );
        assert_eq!(
            mode_of(&netmap_with(&["tag:relay-enabled"], -1)),
            Mode::Prefer
        );
        assert_eq!(mode_of(&netmap_with(&[], 3478)), Mode::Auto);
        assert_eq!(mode_of(&NetMap::default()), Mode::Auto);
    }

    #[test]
    fn mode_names_and_snapshot_field() {
        assert_eq!(
            [Mode::Auto, Mode::Prefer, Mode::Strict].map(mode_name),
            ["auto", "prefer", "strict"]
        );
        let ps = PathSock::new(DiscoPrivate::generate().unwrap(), NodePublic([1; 32]));
        let dp = Dataplane::new(NodePrivate::generate().unwrap());
        let s = snapshot(
            &netmap_with(&["tag:relay-strict"], 3478),
            &ps,
            &dp,
            Duration::ZERO,
            &[],
        );
        assert_eq!(s.relay_mode, "strict");
    }

    #[test]
    fn endpoints_per_mode() {
        let local: Vec<SocketAddr> = vec!["172.29.0.31:41641".parse().unwrap()];
        let stun: SocketAddr = "203.0.113.5:41641".parse().unwrap();
        assert!(endpoints_for(Mode::Strict, &local, Some(stun)).is_empty());
        assert_eq!(endpoints_for(Mode::Prefer, &local, Some(stun)), local);
        assert_eq!(
            endpoints_for(Mode::Auto, &local, Some(stun)),
            vec![local[0], stun]
        );
        assert_eq!(
            endpoints_for(Mode::Auto, &local, Some(local[0])),
            local,
            "no duplicate"
        );
        assert_eq!(endpoints_for(Mode::Auto, &local, None), local);
    }

    #[test]
    fn peer_home_prefers_home_derp_then_legacy() {
        let n = |home, legacy: &str| Node {
            home_derp: home,
            legacy_derp: legacy.into(),
            ..Default::default()
        };
        assert_eq!(peer_home(&n(1000, "127.3.3.40:5")), Some(1000));
        assert_eq!(peer_home(&n(0, "127.3.3.40:1001")), Some(1001));
        assert_eq!(peer_home(&n(0, "127.3.3.40:0")), None);
        assert_eq!(peer_home(&n(0, "127.3.3.40:x")), None);
        assert_eq!(peer_home(&n(0, "10.0.0.1:1001")), None);
        assert_eq!(peer_home(&n(0, "")), None);
    }

    #[test]
    fn wireguard_message_shape() {
        for t in 1..=4u8 {
            assert!(looks_like_wireguard(&[t, 0, 0, 0, 9]), "{t}");
        }
        assert!(!looks_like_wireguard(&[0, 0, 0, 0]));
        assert!(!looks_like_wireguard(&[5, 0, 0, 0]));
        assert!(!looks_like_wireguard(&[1, 0, 1, 0]));
        assert!(!looks_like_wireguard(&[1, 0, 0]));
    }

    fn dns_netmap(resolvers: &[&str]) -> NetMap {
        let mut nm = NetMap {
            dns: Some(DnsConfig {
                resolvers: resolvers
                    .iter()
                    .map(|r| DnsResolver {
                        addr: r.to_string(),
                    })
                    .collect(),
                domains: vec!["mesh.lab.internal".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        nm.peers.insert(
            1,
            Node {
                id: 1,
                name: "ts1.mesh.lab.internal.".into(),
                addresses: vec!["100.64.0.1/32".parse().unwrap()],
                allowed_ips: vec![
                    "100.64.0.1/32".parse().unwrap(),
                    "10.99.0.0/24".parse().unwrap(),
                    "0.0.0.0/0".parse().unwrap(),
                ],
                ..Default::default()
            },
        );
        nm.peers.insert(
            2,
            Node {
                id: 2,
                allowed_ips: vec![
                    "fd7a:115c:a1e0::2/128".parse().unwrap(),
                    "fd00:1::/64".parse().unwrap(),
                    "::/0".parse().unwrap(),
                ],
                ..Default::default()
            },
        );
        nm
    }

    #[test]
    fn dns_upstreams_prefer_the_server_config() {
        let host: Vec<IpAddr> = vec!["127.0.0.11".parse().unwrap()];
        assert_eq!(
            dns_upstreams(&dns_netmap(&["1.1.1.1", "not-an-ip"]), &host),
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            dns_upstreams(&dns_netmap(&["https://doh.example/"]), &host),
            host,
            "nothing usable: host upstreams"
        );
        assert_eq!(dns_upstreams(&NetMap::default(), &host), host);
    }

    #[test]
    fn dns_view_answers_for_netmap_nodes() {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        let mut q = Message::query();
        q.add_query(Query::query(
            Name::from_ascii("ts1.mesh.lab.internal.").unwrap(),
            RecordType::A,
        ));
        let bytes = q.to_vec().unwrap();
        assert!(matches!(
            flowmesh_dns::handle(&dns_view(&dns_netmap(&[]), false), &bytes),
            flowmesh_dns::Decision::Local(_)
        ));
        assert_eq!(
            flowmesh_dns::handle(&dns_view(&NetMap::default(), false), &bytes),
            flowmesh_dns::Decision::Forward
        );
    }

    #[test]
    fn subnet_routes_exclude_mesh_ranges_and_default_routes() {
        let got: Vec<String> = subnet_routes(&dns_netmap(&[]))
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(got, ["10.99.0.0/24", "fd00:1::/64"]);
    }

    #[test]
    fn peer_status_fields() {
        let mut nm = dns_netmap(&[]);
        nm.derp_map = map(vec![region(
            1000,
            "wanflow-relay-1000",
            false,
            vec![node("n", 1, false)],
        )]);
        let mut n = nm.peers[&1].clone();
        n.home_derp = 1000;
        n.online = Some(true);
        n.key = NodePublic([5; 32]);
        n.hostinfo.hostname = "ts1".into();
        n.hostinfo.os = "linux".into();
        n.last_seen = Some("2026-10-10T02:26:22Z".into());
        n.addresses.push("fd7a:115c:a1e0::1/128".parse().unwrap());
        n.primary_routes = vec!["192.168.1.0/24".parse().unwrap()];
        assert_eq!(
            peer_status(&n, &nm),
            PeerStatus {
                id: 1,
                public_key: NodePublic([5; 32]).to_string(),
                host_name: "ts1".into(),
                dns_name: "ts1.mesh.lab.internal.".into(),
                os: "linux".into(),
                tailscale_ips: vec![
                    "100.64.0.1".parse().unwrap(),
                    "fd7a:115c:a1e0::1".parse().unwrap()
                ],
                online: true,
                last_seen: Some("2026-10-10T02:26:22Z".into()),
                relay: "wanflow-relay-1000".into(),
                exit_node_option: true,
                primary_routes: vec!["192.168.1.0/24".parse().unwrap()],
                ..Default::default()
            }
        );
        let mut unknown = nm.peers[&2].clone();
        unknown.allowed_ips.retain(|p| p.prefix_len() != 0);
        let s = peer_status(&unknown, &nm);
        assert_eq!(
            (s.relay.as_str(), s.online, s.exit_node_option),
            ("", false, false)
        );
    }

    /// Two data planes that complete a WireGuard handshake and send one packet a → b, and with
    /// `reply` one packet back.
    fn handshake(reply: bool) -> (Dataplane, NodePublic, Dataplane, NodePublic) {
        let (ka, kb) = (
            NodePrivate::generate().unwrap(),
            NodePrivate::generate().unwrap(),
        );
        let (pa, pb) = (ka.public(), kb.public());
        let mut a = Dataplane::new(ka);
        let mut b = Dataplane::new(kb);
        a.set_peers(vec![PeerConfig {
            key: pb,
            allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
            ..Default::default()
        }]);
        b.set_peers(vec![PeerConfig {
            key: pa,
            allowed_ips: vec!["100.64.0.1/32".parse().unwrap()],
            ..Default::default()
        }]);
        let pkt = flowmesh_dataplane::ippkt::build_udp4(
            SocketAddrV4::new([100, 64, 0, 1].into(), 1000),
            SocketAddrV4::new([100, 64, 0, 2].into(), 2000),
            b"hello",
        );
        let mut to_b: Vec<Vec<u8>> = a
            .outbound(&pkt, Duration::ZERO)
            .into_iter()
            .filter_map(|o| match o {
                Output::ToPeer(_, d) => Some(d),
                _ => None,
            })
            .collect();
        for _ in 0..4 {
            let mut to_a = Vec::new();
            for d in to_b.drain(..) {
                for o in b.inbound(pa, &d, Duration::ZERO) {
                    if let Output::ToPeer(_, r) = o {
                        to_a.push(r)
                    }
                }
            }
            for d in to_a {
                for o in a.inbound(pb, &d, Duration::ZERO) {
                    if let Output::ToPeer(_, r) = o {
                        to_b.push(r)
                    }
                }
            }
        }
        // And one data packet back, b → a.
        let back = flowmesh_dataplane::ippkt::build_udp4(
            SocketAddrV4::new([100, 64, 0, 2].into(), 2000),
            SocketAddrV4::new([100, 64, 0, 1].into(), 1000),
            b"world",
        );
        for o in b
            .outbound(&back, Duration::ZERO)
            .into_iter()
            .filter(|_| reply)
        {
            if let Output::ToPeer(_, d) = o {
                let _ = a.inbound(pb, &d, Duration::ZERO);
            }
        }
        (a, pa, b, pb)
    }

    #[test]
    fn snapshot_counts_traffic_and_reports_direct_paths() {
        let (a, _pa, _b, pb) = handshake(true);
        let me = DiscoPrivate::generate().unwrap();
        let peer_disco = DiscoPrivate::generate().unwrap();
        let mut ps = PathSock::new(me.clone(), NodePublic([1; 32]));
        let ep: SocketAddr = "172.29.0.21:41641".parse().unwrap();
        ps.set_peers(vec![PeerInfo {
            node: pb,
            disco: peer_disco.public(),
            home_region: Some(1000),
            endpoints: vec![ep],
        }]);
        // Answer the direct probe so the path to the peer is direct.
        struct R(u8);
        impl flowmesh_pathsock::Random for R {
            fn fill(&mut self, buf: &mut [u8]) {
                for b in buf {
                    self.0 = self.0.wrapping_add(1);
                    *b = self.0;
                }
            }
        }
        let mut rng = R(0);
        for act in ps.probe(pb, Duration::from_secs(1), &mut rng) {
            if let flowmesh_pathsock::Action::Udp { to, data } = act {
                let (_, plain) = envelope::open(&peer_disco, &data).unwrap();
                let message::Message::Ping { tx_id, .. } = message::decode(&plain).unwrap() else {
                    continue;
                };
                let pong = envelope::seal(
                    &peer_disco,
                    &me.public(),
                    &message::encode(&message::Message::Pong { tx_id, src: ep }),
                    [3; 24],
                )
                .unwrap();
                ps.on_disco(
                    flowmesh_pathsock::Source::Udp(to),
                    &pong,
                    Duration::from_secs(1),
                    &mut rng,
                );
            }
        }
        let mut nm = NetMap {
            dns: Some(DnsConfig {
                domains: vec!["mesh.lab.internal".into(), "other".into()],
                ..Default::default()
            }),
            self_node: Some(Node {
                id: 9,
                ..Default::default()
            }),
            ..Default::default()
        };
        nm.peers.insert(
            2,
            Node {
                id: 2,
                key: pb,
                ..Default::default()
            },
        );
        nm.peers.insert(
            3,
            Node {
                id: 3,
                key: NodePublic([7; 32]),
                ..Default::default()
            },
        );
        let s = snapshot(&nm, &ps, &a, Duration::from_secs(2), &["h".into()]);
        assert_eq!(
            (s.magic_dns_suffix.as_str(), s.tailnet_name.as_str()),
            ("mesh.lab.internal", "mesh.lab.internal")
        );
        assert_eq!(s.health, ["h"]);
        assert_eq!(s.self_node.unwrap().id, 9);
        let p2 = s.peers.iter().find(|p| p.id == 2).unwrap();
        assert_eq!(p2.cur_addr, Some(ep));
        assert!(p2.tx_bytes > 0 && p2.rx_bytes > 0 && p2.active, "{p2:?}");
        let p3 = s.peers.iter().find(|p| p.id == 3).unwrap();
        assert_eq!(
            (p3.cur_addr, p3.tx_bytes, p3.rx_bytes, p3.active),
            (None, 0, 0, false)
        );
        // Past the trust window the path is no longer direct.
        let later = snapshot(&nm, &ps, &a, Duration::from_secs(30), &[]);
        assert_eq!(
            later.peers.iter().find(|p| p.id == 2).unwrap().cur_addr,
            None
        );
        assert_eq!(
            snapshot(&NetMap::default(), &ps, &a, Duration::ZERO, &[]).magic_dns_suffix,
            ""
        );
    }

    #[test]
    fn active_means_any_traffic_either_way() {
        let ps = PathSock::new(DiscoPrivate::generate().unwrap(), NodePublic([1; 32]));
        let status_of = |dp: &Dataplane, key: NodePublic| {
            let mut nm = NetMap::default();
            nm.peers.insert(
                2,
                Node {
                    id: 2,
                    key,
                    ..Default::default()
                },
            );
            snapshot(&nm, &ps, dp, Duration::ZERO, &[]).peers.remove(0)
        };
        // Sent but nothing received yet.
        let (a, _, _, pb) = handshake(false);
        let s = status_of(&a, pb);
        assert!(s.tx_bytes > 0 && s.rx_bytes == 0 && s.active, "{s:?}");
        // Configured, no traffic at all.
        let mut idle = Dataplane::new(NodePrivate::generate().unwrap());
        let quiet = NodePrivate::generate().unwrap().public();
        idle.set_peers(vec![PeerConfig {
            key: quiet,
            allowed_ips: vec![],
            ..Default::default()
        }]);
        let s = status_of(&idle, quiet);
        assert_eq!((s.tx_bytes, s.rx_bytes, s.active), (0, 0, false));
    }

    #[test]
    fn apply_netmap_is_fail_closed_on_bad_rules() {
        let (mut dp, _, _, pb) = handshake(true);
        let mut ps = PathSock::new(DiscoPrivate::generate().unwrap(), NodePublic([1; 32]));
        let mut nm = netmap_with(&["tag:relay-strict"], 3478);
        nm.peers.insert(
            2,
            Node {
                id: 2,
                key: pb,
                home_derp: 1000,
                allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
                ..Default::default()
            },
        );
        assert_eq!(
            apply_netmap(&mut dp, &mut ps, &nm, 0, &Policy::default()),
            Ok(())
        );
        assert_eq!(
            ps.current_route(pb, Duration::ZERO),
            Route::Derp(1000),
            "peers handed to path selection"
        );
        let bad: flowmesh_proto::filter::FilterRule = serde_json::from_value(serde_json::json!({
            "SrcIPs": ["not-an-address"], "DstPorts": [{ "IP": "*", "Ports": { "First": 0, "Last": 65535 } }]
        })).unwrap();
        nm.packet_filters.insert("g".into(), vec![bad]);
        let err = apply_netmap(&mut dp, &mut ps, &nm, 0, &Policy::default()).unwrap_err();
        assert!(err.contains("keeping previous"), "{err}");
    }

    /// Candidates: granted `cap/relay-target` towards this node, with a home region, not expired.
    #[test]
    fn relay_candidates_follow_the_relay_target_grant() {
        let mut nm = NetMap {
            control_time: Some("2026-10-10T07:00:00Z".into()),
            self_node: Some(Node {
                id: 6,
                addresses: vec!["100.64.0.6/32".parse().unwrap()],
                ..Default::default()
            }),
            ..Default::default()
        };
        for r in [1000, 1001] {
            nm.derp_map.regions.insert(r, Default::default());
        }
        let peer = |id: i64, home: u32, expiry: &str| Node {
            id,
            key: NodePublic([id as u8; 32]),
            disco_key: flowmesh_proto::key::DiscoPublic([id as u8 + 100; 32]),
            addresses: vec![format!("100.64.0.{id}/32").parse().unwrap()],
            home_derp: home,
            key_expiry: (!expiry.is_empty()).then(|| expiry.to_string()),
            online: Some(true),
            ..Default::default()
        };
        nm.peers.insert(1, peer(1, 1000, ""));
        nm.peers.insert(
            7,
            Node {
                online: Some(false),
                ..peer(7, 1000, "")
            },
        ); // offline
        nm.peers.insert(8, peer(8, 1002, "")); // home region not in our DERP map
        nm.peers.insert(2, peer(2, 0, "")); // granted, but no home region
        nm.peers.insert(3, peer(3, 1001, "")); // not granted
        nm.peers.insert(4, peer(4, 1001, "")); // granted cap/relay only: it may use us, not we it
        nm.peers.insert(5, peer(5, 1000, "2026-10-10T06:00:00Z")); // expired
        let rules: Vec<flowmesh_proto::filter::FilterRule> = serde_json::from_value(serde_json::json!([
            { "SrcIPs": ["100.64.0.1", "100.64.0.2", "100.64.0.5", "100.64.0.7", "100.64.0.8"], "DstPorts": [],
              "CapGrant": [{ "Caps": ["tailscale.com/cap/relay-target"], "Dsts": ["100.64.0.6/32"] }] },
            { "SrcIPs": ["100.64.0.4"], "DstPorts": [],
              "CapGrant": [{ "Caps": ["tailscale.com/cap/relay"], "Dsts": ["100.64.0.6/32"] }] }
        ]))
        .unwrap();
        nm.packet_filters.insert("base".into(), rules);
        let now = parse_rfc3339_utc("2026-10-10T07:00:00Z").unwrap();
        let got = relay_candidates(&nm, now);
        assert_eq!(
            got,
            vec![flowmesh_udprelay::Candidate {
                node: NodePublic([1; 32]),
                disco: flowmesh_proto::key::DiscoPublic([101; 32]),
                home_region: Some(1000),
            }]
        );
    }

    #[test]
    fn expired_peers_are_left_out_of_the_data_plane() {
        let (mut dp, _, _, pb) = handshake(true);
        let mut ps = PathSock::new(DiscoPrivate::generate().unwrap(), NodePublic([1; 32]));
        let gone = NodePublic([9; 32]);
        let mut nm = NetMap {
            control_time: Some("2026-10-10T07:00:00Z".into()),
            ..Default::default()
        };
        nm.peers.insert(
            2,
            Node {
                id: 2,
                key: pb,
                home_derp: 1000,
                ..Default::default()
            },
        );
        nm.peers.insert(
            3,
            Node {
                id: 3,
                key: gone,
                home_derp: 1000,
                key_expiry: Some("2026-10-10T06:00:00Z".into()),
                ..Default::default()
            },
        );
        let ids: Vec<i64> = live_peers(&nm, 0).map(|n| n.id).collect();
        assert_eq!(ids, [2], "judged by the server's clock, not the local 0");
        apply_netmap(&mut dp, &mut ps, &nm, 0, &Policy::default()).unwrap();
        assert_eq!(ps.current_route(pb, Duration::ZERO), Route::Derp(1000));
        assert_eq!(
            ps.current_route(gone, Duration::ZERO),
            Route::None,
            "not given to path selection"
        );
        assert!(
            dp.stats().iter().all(|(k, _, _)| *k != gone),
            "not given to WireGuard"
        );
    }

    #[test]
    fn peer_status_expiry_fields() {
        let mut nm = NetMap {
            control_time: Some("2026-10-10T07:00:00Z".into()),
            ..Default::default()
        };
        let mut n = Node {
            id: 4,
            ..Default::default()
        };
        n.key_expiry = Some("2026-10-10T06:26:42Z".into());
        let s = peer_status(&n, &nm);
        assert_eq!(
            (s.key_expiry.as_deref(), s.expired),
            (Some("2026-10-10T06:26:42Z"), true)
        );
        n.key_expiry = Some("2026-10-10T08:00:00Z".into());
        let s = peer_status(&n, &nm);
        assert_eq!(
            (s.key_expiry.as_deref(), s.expired),
            (Some("2026-10-10T08:00:00Z"), false)
        );
        // The zero time means "never": not shown, like the official output.
        n.key_expiry = Some("0001-01-01T00:00:00Z".into());
        assert_eq!(peer_status(&n, &nm).key_expiry, None);
        n.key_expiry = Some("0001-01-01T00:00:01Z".into());
        nm.control_time = None;
        assert_eq!(
            peer_status(&n, &nm).key_expiry.as_deref(),
            Some("0001-01-01T00:00:01Z")
        );
    }

    #[test]
    fn unix_now_is_plausible() {
        let t = unix_now();
        assert!((1_700_000_000..4_000_000_000).contains(&t), "{t}");
    }
}
