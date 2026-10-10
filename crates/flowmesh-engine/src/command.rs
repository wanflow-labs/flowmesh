// SPDX-License-Identifier: Apache-2.0
//! Requests the daemon sends into a running engine.

use flowmesh_control::netmap::NetMap;
use flowmesh_pathsock::{ProbeResult, Route};
use flowmesh_proto::key::NodePublic;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::sync::oneshot;

pub enum EngineCommand {
    /// Disco-ping the peer that owns `ip` once over every allowed path; answered by the first pong.
    Ping {
        ip: IpAddr,
        reply: oneshot::Sender<Result<PingReply, PingError>>,
    },
    /// Who owns `ip` (this node or a peer), for `whois` and mesh services.
    Whois {
        ip: IpAddr,
        reply: oneshot::Sender<Option<WhoisReply>>,
    },
}

/// The node owning an address, its user, and the capabilities the packet filter grants it towards
/// this node (cli.md §5).
#[derive(Debug, Clone, PartialEq)]
pub struct WhoisReply {
    pub node: flowmesh_proto::control::Node,
    pub user_profile: Option<flowmesh_proto::control::UserProfile>,
    pub cap_map: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Look up `ip` among this node and its peers.
pub fn whois(nm: &NetMap, ip: IpAddr) -> Option<WhoisReply> {
    let node = nm
        .self_node
        .iter()
        .chain(nm.peers.values())
        .find(|n| n.addresses.iter().any(|a| a.addr() == ip))?;
    let mine: Vec<IpAddr> = nm
        .self_node
        .iter()
        .flat_map(|n| n.addresses.iter().map(|a| a.addr()))
        .collect();
    Some(WhoisReply {
        node: node.clone(),
        user_profile: nm.user_profiles.get(&node.user).cloned(),
        cap_map: flowmesh_filter::caps::peer_caps(&nm.filter_rules(), ip, &mine),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PingPath {
    Direct(SocketAddr),
    Derp { region: u32, code: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingReply {
    /// The peer's first mesh address.
    pub node_ip: IpAddr,
    /// Short name (first label of the peer's DNS name).
    pub node_name: String,
    pub via: PingPath,
    pub latency: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PingError {
    #[error("no matching peer")]
    NoPeer,
    #[error("timed out")]
    Timeout,
}

/// A `flowmesh ping` waiting for its pong.
// Used by the Linux engine loop; the unit tests run everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct PendingPing {
    pub(crate) peer: NodePublic,
    pub(crate) node_ip: IpAddr,
    pub(crate) node_name: String,
    pub(crate) deadline: Duration,
    pub(crate) reply: oneshot::Sender<Result<PingReply, PingError>>,
}

// Used by the Linux engine loop; the unit tests run everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn short_name(n: &flowmesh_proto::control::Node) -> String {
    n.name
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(&n.hostinfo.hostname)
        .to_string()
}

/// Answer waiting pings with the first pong from their peer.
// Used by the Linux engine loop; the unit tests run everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn deliver_pings(pings: &mut Vec<PendingPing>, results: Vec<ProbeResult>, nm: &NetMap) {
    for r in results {
        let Some(i) = pings.iter().position(|p| p.peer == r.peer) else {
            continue;
        };
        let via = match r.via {
            Route::Direct(addr) => PingPath::Direct(addr),
            Route::Derp(region) => PingPath::Derp {
                region,
                code: nm
                    .derp_map
                    .regions
                    .get(&region)
                    .map(|reg| reg.region_code.clone())
                    .unwrap_or_default(),
            },
            Route::None => continue,
        };
        let p = pings.remove(i);
        let _ = p.reply.send(Ok(PingReply {
            node_ip: p.node_ip,
            node_name: p.node_name,
            via,
            latency: r.latency,
        }));
    }
}

// Used by the Linux engine loop; the unit tests run everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn expire_pings(pings: &mut Vec<PendingPing>, now: Duration) {
    let (expired, live): (Vec<_>, Vec<_>) = pings.drain(..).partition(|p| now >= p.deadline);
    *pings = live;
    for p in expired {
        let _ = p.reply.send(Err(PingError::Timeout));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmesh_proto::control::Node;
    use flowmesh_proto::derp::DerpRegion;

    fn pending(
        peer: u8,
        deadline_s: u64,
    ) -> (PendingPing, oneshot::Receiver<Result<PingReply, PingError>>) {
        let (tx, rx) = oneshot::channel();
        (
            PendingPing {
                peer: NodePublic([peer; 32]),
                node_ip: "100.64.0.1".parse().unwrap(),
                node_name: "ts1".into(),
                deadline: Duration::from_secs(deadline_s),
                reply: tx,
            },
            rx,
        )
    }

    fn netmap() -> NetMap {
        let mut nm = NetMap::default();
        nm.derp_map.regions.insert(
            1000,
            DerpRegion {
                region_id: 1000,
                region_code: "wanflow-relay-1000".into(),
                ..Default::default()
            },
        );
        nm
    }

    fn result(peer: u8, via: Route) -> ProbeResult {
        ProbeResult {
            peer: NodePublic([peer; 32]),
            via,
            latency: Duration::from_millis(7),
        }
    }

    #[test]
    fn first_pong_answers_and_names_the_relay_region() {
        let (p, mut rx) = pending(2, 10);
        let mut pings = vec![p];
        deliver_pings(&mut pings, vec![result(2, Route::Derp(1000))], &netmap());
        assert!(pings.is_empty());
        let r = rx.try_recv().unwrap().unwrap();
        assert_eq!(
            r.via,
            PingPath::Derp {
                region: 1000,
                code: "wanflow-relay-1000".into()
            }
        );
        assert_eq!(
            (r.node_name.as_str(), r.latency),
            ("ts1", Duration::from_millis(7))
        );
    }

    #[test]
    fn direct_pong_and_unknown_region() {
        let (a, mut rx_a) = pending(2, 10);
        let (b, mut rx_b) = pending(3, 10);
        let mut pings = vec![a, b];
        let addr: SocketAddr = "172.29.0.21:41641".parse().unwrap();
        deliver_pings(
            &mut pings,
            vec![result(3, Route::Derp(1999)), result(2, Route::Direct(addr))],
            &netmap(),
        );
        assert_eq!(
            rx_a.try_recv().unwrap().unwrap().via,
            PingPath::Direct(addr)
        );
        assert_eq!(
            rx_b.try_recv().unwrap().unwrap().via,
            PingPath::Derp {
                region: 1999,
                code: String::new()
            }
        );
    }

    #[test]
    fn results_for_other_peers_leave_pings_waiting() {
        let (p, mut rx) = pending(2, 10);
        let mut pings = vec![p];
        deliver_pings(
            &mut pings,
            vec![result(9, Route::Derp(1000)), result(2, Route::None)],
            &netmap(),
        );
        assert_eq!(pings.len(), 1);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn expiry_at_the_deadline() {
        let (a, mut rx_a) = pending(2, 5);
        let (b, mut rx_b) = pending(3, 6);
        let mut pings = vec![a, b];
        expire_pings(&mut pings, Duration::from_secs(5));
        assert_eq!(rx_a.try_recv().unwrap(), Err(PingError::Timeout));
        assert!(rx_b.try_recv().is_err());
        assert_eq!(pings.len(), 1);
    }

    fn node(id: i64, user: i64, addrs: &[&str]) -> Node {
        Node {
            id,
            user,
            name: format!("n{id}.mesh.lab.internal."),
            addresses: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            ..Default::default()
        }
    }

    fn whois_netmap() -> NetMap {
        let mut nm = NetMap {
            self_node: Some(node(2, 1, &["100.64.0.2/32", "fd7a:115c:a1e0::2/128"])),
            ..Default::default()
        };
        nm.peers
            .insert(1, node(1, 1, &["100.64.0.1/32", "fd7a:115c:a1e0::1/128"]));
        nm.peers.insert(7, node(7, 9, &["100.64.0.7/32"]));
        nm.user_profiles.insert(
            1,
            flowmesh_proto::control::UserProfile {
                id: 1,
                login_name: "lab".into(),
                display_name: "lab".into(),
            },
        );
        nm.packet_filters.insert(
            "base".into(),
            vec![
                serde_json::from_value(serde_json::json!({
                    "SrcIPs": ["100.64.0.1"],
                    "CapGrant": [{ "Caps": ["tailscale.com/cap/relay"], "Dsts": ["100.64.0.2/32"] }]
                }))
                .unwrap(),
            ],
        );
        nm
    }

    #[test]
    fn whois_finds_peers_by_any_address() {
        let nm = whois_netmap();
        for ip in ["100.64.0.1", "fd7a:115c:a1e0::1"] {
            let w = whois(&nm, ip.parse().unwrap()).unwrap();
            assert_eq!(w.node.id, 1, "{ip}");
            assert_eq!(w.user_profile.as_ref().unwrap().login_name, "lab");
        }
        let w = whois(&nm, "100.64.0.1".parse().unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&w.cap_map).unwrap(),
            serde_json::json!({ "tailscale.com/cap/relay": null })
        );
    }

    #[test]
    fn whois_self_unknown_user_and_missing() {
        let nm = whois_netmap();
        let me = whois(&nm, "100.64.0.2".parse().unwrap()).unwrap();
        assert_eq!(me.node.id, 2);
        assert!(me.cap_map.is_empty(), "the grant is only for 100.64.0.1");
        let other = whois(&nm, "100.64.0.7".parse().unwrap()).unwrap();
        assert_eq!(other.user_profile, None, "profile not in the netmap");
        assert_eq!(whois(&nm, "100.64.99.99".parse().unwrap()), None);
        assert_eq!(
            whois(&NetMap::default(), "100.64.0.1".parse().unwrap()),
            None
        );
    }

    #[test]
    fn short_name_prefers_the_dns_label() {
        let mut n = Node {
            name: "ts-a-e2zlhu95.mesh.lab.internal.".into(),
            ..Default::default()
        };
        n.hostinfo.hostname = "ts-a".into();
        assert_eq!(short_name(&n), "ts-a-e2zlhu95");
        n.name.clear();
        assert_eq!(short_name(&n), "ts-a");
    }
}
