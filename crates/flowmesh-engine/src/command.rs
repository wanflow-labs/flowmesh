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
