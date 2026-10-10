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

/// Choose the home relay: the lowest-numbered region that may be home and has a non-STUN-only node.
pub(crate) fn pick_home(dm: &DerpMap) -> Option<(u32, DerpNode)> {
    dm.regions
        .iter()
        .filter(|(_, r)| !r.no_measure_no_home)
        .find_map(|(id, r)| {
            r.nodes
                .iter()
                .find(|n| !n.stun_only)
                .map(|n| (*id, n.clone()))
        })
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
            if let Route::Direct(addr) = ps.current_route(n.key, now) {
                s.cur_addr = Some(addr);
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
    }
}

pub(crate) fn apply_netmap(
    dp: &mut Dataplane,
    ps: &mut PathSock,
    nm: &NetMap,
) -> Result<(), String> {
    dp.set_peers(
        nm.peers
            .values()
            .map(|n| PeerConfig {
                key: n.key,
                allowed_ips: n.allowed_ips.clone(),
            })
            .collect(),
    );
    ps.set_peers(
        nm.peers
            .values()
            .map(|n| PeerInfo {
                node: n.key,
                disco: n.disco_key,
                home_region: peer_home(n),
                endpoints: n.endpoints.clone(),
            })
            .collect(),
    );
    ps.set_mode(mode_of(nm));
    // fail-closed: on a compile error the previous valid rules stay (design doc §7.2).
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

#[cfg(test)]
mod tests {
    use super::*;
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
        let (id, n) = pick_home(&dm).unwrap();
        assert_eq!(
            (id, n.name.as_str()),
            (1000, "b-site2"),
            "first eligible node, in the order the server sent"
        );
        assert_eq!(
            pick_home(&map(vec![region(
                900,
                "a",
                true,
                vec![node("a1", 1, false)]
            )])),
            None
        );
        assert_eq!(
            pick_home(&map(vec![region(1, "x", false, vec![node("s", 1, true)])])),
            None
        );
        assert_eq!(pick_home(&DerpMap::default()), None);
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
        }]);
        b.set_peers(vec![PeerConfig {
            key: pa,
            allowed_ips: vec!["100.64.0.1/32".parse().unwrap()],
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
        assert_eq!(apply_netmap(&mut dp, &mut ps, &nm), Ok(()));
        assert_eq!(
            ps.current_route(pb, Duration::ZERO),
            Route::Derp(1000),
            "peers handed to path selection"
        );
        let bad: flowmesh_proto::filter::FilterRule = serde_json::from_value(serde_json::json!({
            "SrcIPs": ["not-an-address"], "DstPorts": [{ "IP": "*", "Ports": { "First": 0, "Last": 65535 } }]
        })).unwrap();
        nm.packet_filters.insert("g".into(), vec![bad]);
        let err = apply_netmap(&mut dp, &mut ps, &nm).unwrap_err();
        assert!(err.contains("keeping previous"), "{err}");
    }
}
