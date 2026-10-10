// SPDX-License-Identifier: Apache-2.0
//! Per-peer path selection (sans-IO): discover direct paths with disco ping/pong, and route traffic
//! either directly or via DERP. All time and randomness come from the caller, so tests can replay
//! sequences with simulated time.
//!
//! Timing parameters and message semantics are in docs/protocol/disco.md §3.

use flowmesh_disco::envelope;
use flowmesh_disco::message::{self, Message, TX_ID_LEN};
use flowmesh_proto::key::{DiscoPrivate, DiscoPublic, NodePublic};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// While a direct path is active, ping it every 3 seconds (observed: official clients send a heartbeat every 3.0 s).
pub const HEARTBEAT: Duration = Duration::from_secs(3);
/// How long a direct path is trusted after its last pong. Observed fallback was 6.2 s after blocking; with a 3 s
/// heartbeat the true value lies between 6.2 and 9.2 s. Provisionally 6.5 s.
pub const TRUST: Duration = Duration::from_millis(6_500);
/// Interval between discovery rounds when there is no direct path (observed: pings over DERP to a peer without endpoints every 5 s).
pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);
/// A ping with no pong after this long is forgotten.
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// A peer counts as active if data was sent to it within this window; heartbeats stop for idle peers. Provisional.
pub const ACTIVE_WINDOW: Duration = Duration::from_secs(45);
/// Source address used in a pong sent over DERP: 127.3.3.40:<region> (observed).
pub const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);

/// Randomness supplied by the caller (OS random in production, deterministic in tests).
pub trait Random {
    fn fill(&mut self, buf: &mut [u8]);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Udp {
        to: SocketAddr,
        data: Vec<u8>,
    },
    Derp {
        to: NodePublic,
        region: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Direct(SocketAddr),
    Derp(u32),
    /// Peer unknown or has no home relay.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Udp(SocketAddr),
    Derp { node: NodePublic, region: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub node: NodePublic,
    pub disco: DiscoPublic,
    pub home_region: Option<u32>,
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Debug, Clone)]
struct PeerPath {
    info: PeerInfo,
    best: Option<(SocketAddr, Duration)>,
    last_discovery: Option<Duration>,
    last_heartbeat: Option<Duration>,
    last_active: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    peer: NodePublic,
    to: SocketAddr,
    sent: Duration,
}

pub struct PathSock {
    me: DiscoPrivate,
    my_node: NodePublic,
    relay_only: bool,
    peers: HashMap<NodePublic, PeerPath>,
    by_disco: HashMap<DiscoPublic, NodePublic>,
    pending: HashMap<[u8; TX_ID_LEN], Pending>,
}

impl PathSock {
    pub fn new(me: DiscoPrivate, my_node: NodePublic) -> Self {
        Self {
            me,
            my_node,
            relay_only: false,
            peers: HashMap::new(),
            by_disco: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// relay-only (deviation #1): no direct traffic of any kind.
    pub fn set_relay_only(&mut self, on: bool) {
        self.relay_only = on;
        if on {
            for p in self.peers.values_mut() {
                p.best = None;
            }
        }
    }

    /// Replace the peer set; peers whose node key is unchanged keep their established path state.
    pub fn set_peers(&mut self, peers: Vec<PeerInfo>) {
        let mut next = HashMap::with_capacity(peers.len());
        self.by_disco.clear();
        for info in peers {
            self.by_disco.insert(info.disco, info.node);
            let path = match self.peers.remove(&info.node) {
                Some(mut existing) => {
                    existing.info = info;
                    existing
                }
                None => PeerPath {
                    info,
                    best: None,
                    last_discovery: None,
                    last_heartbeat: None,
                    last_active: None,
                },
            };
            next.insert(path.info.node, path);
        }
        self.peers = next;
        self.pending.retain(|_, p| self.peers.contains_key(&p.peer));
    }

    /// Called when there is data to send to `peer`: returns the route to use, plus any disco traffic this triggers.
    pub fn route(
        &mut self,
        peer: NodePublic,
        now: Duration,
        rng: &mut dyn Random,
    ) -> (Route, Vec<Action>) {
        let relay_only = self.relay_only;
        let Some(p) = self.peers.get_mut(&peer) else {
            return (Route::None, Vec::new());
        };
        p.last_active = Some(now);
        if let Some((addr, confirmed)) = p.best {
            if !relay_only && now < confirmed + TRUST {
                return (Route::Direct(addr), Vec::new());
            }
            p.best = None;
        }
        let route = p.info.home_region.map_or(Route::None, Route::Derp);
        let due = p
            .last_discovery
            .is_none_or(|last| now.saturating_sub(last) >= DISCOVERY_INTERVAL);
        if !due {
            return (route, Vec::new());
        }
        p.last_discovery = Some(now);
        let info = p.info.clone();
        let mut actions = Vec::new();
        if !relay_only {
            for ep in &info.endpoints {
                if let Some(a) = self.ping(&info, Some(*ep), now, rng) {
                    actions.push(a);
                }
            }
        }
        if let Some(a) = self.ping(&info, None, now, rng) {
            actions.push(a);
        }
        (route, actions)
    }

    /// Build a ping: `to` = Some(endpoint) means directly over UDP, None means via the home DERP.
    fn ping(
        &mut self,
        info: &PeerInfo,
        to: Option<SocketAddr>,
        now: Duration,
        rng: &mut dyn Random,
    ) -> Option<Action> {
        let mut tx_id = [0u8; TX_ID_LEN];
        rng.fill(&mut tx_id);
        let plain = message::encode(&Message::Ping {
            tx_id,
            node_key: self.my_node,
        });
        let data = self.seal(&info.disco, &plain, rng)?;
        match to {
            Some(addr) => {
                self.pending.insert(
                    tx_id,
                    Pending {
                        peer: info.node,
                        to: addr,
                        sent: now,
                    },
                );
                Some(Action::Udp { to: addr, data })
            }
            None => info.home_region.map(|region| Action::Derp {
                to: info.node,
                region,
                data,
            }),
        }
    }

    fn seal(&self, to: &DiscoPublic, plain: &[u8], rng: &mut dyn Random) -> Option<Vec<u8>> {
        let mut nonce = [0u8; envelope::NONCE_LEN];
        rng.fill(&mut nonce);
        envelope::seal(&self.me, to, plain, nonce).ok()
    }

    /// Handle a received disco message.
    pub fn on_disco(
        &mut self,
        from: Source,
        bytes: &[u8],
        now: Duration,
        rng: &mut dyn Random,
    ) -> Vec<Action> {
        if self.relay_only && matches!(from, Source::Udp(_)) {
            return Vec::new();
        }
        let Ok((sender, plain)) = envelope::open(&self.me, bytes) else {
            return Vec::new();
        };
        let Some(&peer) = self.by_disco.get(&sender) else {
            return Vec::new();
        };
        match message::decode(&plain) {
            Ok(Message::Ping { tx_id, .. }) => {
                let src = match from {
                    Source::Udp(a) => a,
                    Source::Derp { region, .. } => {
                        SocketAddr::new(IpAddr::V4(DERP_MAGIC_IP), clamp_port(region))
                    }
                };
                let pong = message::encode(&Message::Pong { tx_id, src });
                let Some(data) = self.seal(&sender, &pong, rng) else {
                    return Vec::new();
                };
                match from {
                    Source::Udp(a) => vec![Action::Udp { to: a, data }],
                    Source::Derp { node, region } => vec![Action::Derp {
                        to: node,
                        region,
                        data,
                    }],
                }
            }
            Ok(Message::Pong { tx_id, .. }) => {
                if let (Source::Udp(a), Some(pend)) = (from, self.pending.get(&tx_id).copied()) {
                    let fresh = now.saturating_sub(pend.sent) <= PING_TIMEOUT;
                    if pend.peer == peer && pend.to == a && fresh {
                        self.pending.remove(&tx_id);
                        if let Some(p) = self.peers.get_mut(&peer) {
                            p.best = Some((a, now));
                            p.last_heartbeat = Some(now);
                        }
                    }
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// Periodic driver: heartbeats and expiry.
    pub fn tick(&mut self, now: Duration, rng: &mut dyn Random) -> Vec<Action> {
        self.pending
            .retain(|_, p| now.saturating_sub(p.sent) <= PING_TIMEOUT);
        if self.relay_only {
            return Vec::new();
        }
        let mut due = Vec::new();
        for p in self.peers.values_mut() {
            let Some((addr, confirmed)) = p.best else {
                continue;
            };
            if now >= confirmed + TRUST {
                p.best = None;
                continue;
            }
            let active = p
                .last_active
                .is_some_and(|t| now.saturating_sub(t) < ACTIVE_WINDOW);
            let hb_due = p
                .last_heartbeat
                .is_none_or(|t| now.saturating_sub(t) >= HEARTBEAT);
            if active && hb_due {
                p.last_heartbeat = Some(now);
                due.push((p.info.clone(), addr));
            }
        }
        due.into_iter()
            .filter_map(|(info, addr)| self.ping(&info, Some(addr), now, rng))
            .collect()
    }

    /// Which peer a packet arriving over UDP from `addr` belongs to: the established direct path takes precedence, then the candidate endpoints.
    pub fn peer_for_addr(&self, addr: SocketAddr) -> Option<NodePublic> {
        self.peers
            .values()
            .find(|p| p.best.is_some_and(|(a, _)| a == addr))
            .or_else(|| {
                self.peers
                    .values()
                    .find(|p| p.info.endpoints.contains(&addr))
            })
            .map(|p| p.info.node)
    }

    /// A direct send failed (e.g. the socket returned an error): fall back to DERP immediately (observed).
    pub fn on_send_error(&mut self, peer: NodePublic) {
        if let Some(p) = self.peers.get_mut(&peer) {
            p.best = None;
        }
    }
}

/// The "port" in the DERP magic address is the region number; region numbers in WanFlow all fit in u16 (1000+).
fn clamp_port(region: u32) -> u16 {
    u16::try_from(region).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic random source: incrementing bytes.
    struct Counter(u8);
    impl Random for Counter {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
        }
    }

    const S: Duration = Duration::from_secs(1);
    const E: &str = "172.29.0.21:41641";

    struct World {
        a: PathSock,
        a_disco: DiscoPrivate,
        b_node: NodePublic,
        b_disco: DiscoPrivate,
        rng: Counter,
    }

    fn world(endpoints: Vec<SocketAddr>) -> World {
        let a_disco = DiscoPrivate::generate().unwrap();
        let a_node = NodePublic([1; 32]);
        let b_disco = DiscoPrivate::generate().unwrap();
        let b_node = NodePublic([2; 32]);
        let mut a = PathSock::new(a_disco.clone(), a_node);
        a.set_peers(vec![PeerInfo {
            node: b_node,
            disco: b_disco.public(),
            home_region: Some(1000),
            endpoints,
        }]);
        World {
            a,
            a_disco,
            b_node,
            b_disco,
            rng: Counter(0),
        }
    }

    /// The peer (b) opens a disco message a sent and returns the decoded payload.
    fn b_reads(w: &World, data: &[u8]) -> Message {
        let (from, plain) = envelope::open(&w.b_disco, data).unwrap();
        assert_eq!(from, w.a_disco.public());
        message::decode(&plain).unwrap()
    }

    /// The peer (b) seals a disco message for a.
    fn b_says(w: &World, m: &Message) -> Vec<u8> {
        envelope::seal(
            &w.b_disco,
            &w.a_disco.public(),
            &message::encode(m),
            [7; 24],
        )
        .unwrap()
    }

    fn udp_pings(w: &World, acts: &[Action]) -> Vec<(SocketAddr, [u8; TX_ID_LEN])> {
        acts.iter()
            .filter_map(|a| match a {
                Action::Udp { to, data } => match b_reads(w, data) {
                    Message::Ping { tx_id, .. } => Some((*to, tx_id)),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    #[test]
    fn no_endpoints_routes_via_home_derp_and_pings_over_derp_every_5s() {
        let mut w = world(vec![]);
        let (r, acts) = w.a.route(w.b_node, 10 * S, &mut w.rng);
        assert_eq!(r, Route::Derp(1000));
        assert!(
            matches!(acts.as_slice(), [Action::Derp { region: 1000, .. }]),
            "{acts:?}"
        );
        let Action::Derp { data, to, .. } = &acts[0] else {
            unreachable!()
        };
        assert_eq!(*to, w.b_node);
        assert!(
            matches!(b_reads(&w, data), Message::Ping { node_key, .. } if node_key == NodePublic([1; 32]))
        );
        // A second send within 5 s does not start a new discovery round.
        assert!(w.a.route(w.b_node, 12 * S, &mut w.rng).1.is_empty());
        assert_eq!(w.a.route(w.b_node, 15 * S, &mut w.rng).1.len(), 1);
    }

    #[test]
    fn pong_from_endpoint_upgrades_to_direct() {
        let mut w = world(vec![E.parse().unwrap()]);
        let (r, acts) = w.a.route(w.b_node, 10 * S, &mut w.rng);
        assert_eq!(r, Route::Derp(1000));
        let pings = udp_pings(&w, &acts);
        assert_eq!(pings.len(), 1);
        let (to, tx_id) = pings[0];
        assert_eq!(to, E.parse().unwrap());
        let pong = b_says(
            &w,
            &Message::Pong {
                tx_id,
                src: "172.29.0.31:41641".parse().unwrap(),
            },
        );
        w.a.on_disco(
            Source::Udp(to),
            &pong,
            10 * S + Duration::from_millis(3),
            &mut w.rng,
        );
        assert_eq!(w.a.route(w.b_node, 11 * S, &mut w.rng).0, Route::Direct(to));
    }

    #[test]
    fn pong_with_unknown_tx_or_wrong_source_is_ignored() {
        let mut w = world(vec![E.parse().unwrap()]);
        let (_, acts) = w.a.route(w.b_node, 10 * S, &mut w.rng);
        let (to, tx_id) = udp_pings(&w, &acts)[0];
        let bogus = b_says(
            &w,
            &Message::Pong {
                tx_id: [0xee; TX_ID_LEN],
                src: to,
            },
        );
        w.a.on_disco(Source::Udp(to), &bogus, 10 * S, &mut w.rng);
        let wrong_src = b_says(&w, &Message::Pong { tx_id, src: to });
        w.a.on_disco(
            Source::Udp("10.9.9.9:1".parse().unwrap()),
            &wrong_src,
            10 * S,
            &mut w.rng,
        );
        assert_eq!(w.a.route(w.b_node, 11 * S, &mut w.rng).0, Route::Derp(1000));
    }

    fn establish(w: &mut World, t: Duration) -> SocketAddr {
        let (_, acts) = w.a.route(w.b_node, t, &mut w.rng);
        let (to, tx_id) = udp_pings(w, &acts)[0];
        let pong = b_says(w, &Message::Pong { tx_id, src: to });
        w.a.on_disco(Source::Udp(to), &pong, t, &mut w.rng);
        to
    }

    #[test]
    fn heartbeat_every_3s_keeps_direct_and_silence_falls_back_after_trust() {
        let mut w = world(vec![E.parse().unwrap()]);
        let to = establish(&mut w, 10 * S);
        // Active and direct: tick at +3 s sends a heartbeat ping.
        let hb = w.a.tick(13 * S, &mut w.rng);
        let pings = udp_pings(&w, &hb);
        assert_eq!(pings.len(), 1);
        assert_eq!(pings[0].0, to);
        // No reply: still direct before the trust window ends, DERP once it has passed.
        assert_eq!(
            w.a.route(
                w.b_node,
                10 * S + TRUST - Duration::from_millis(1),
                &mut w.rng
            )
            .0,
            Route::Direct(to)
        );
        assert_eq!(
            w.a.route(w.b_node, 10 * S + TRUST, &mut w.rng).0,
            Route::Derp(1000)
        );
    }

    #[test]
    fn heartbeat_pong_extends_trust() {
        let mut w = world(vec![E.parse().unwrap()]);
        let to = establish(&mut w, 10 * S);
        let hb = w.a.tick(13 * S, &mut w.rng);
        let (_, tx_id) = udp_pings(&w, &hb)[0];
        let pong = b_says(&w, &Message::Pong { tx_id, src: to });
        w.a.on_disco(Source::Udp(to), &pong, 13 * S, &mut w.rng);
        assert_eq!(
            w.a.route(w.b_node, 10 * S + TRUST + S, &mut w.rng).0,
            Route::Direct(to)
        );
    }

    /// Keep the direct path alive with heartbeats but send no data: heartbeats stop once the idle time reaches ACTIVE_WINDOW (boundary inclusive).
    #[test]
    fn heartbeats_stop_exactly_when_peer_becomes_idle() {
        let mut w = world(vec![E.parse().unwrap()]);
        let t0 = 10 * S;
        let to = establish(&mut w, t0);
        let mut t = t0;
        loop {
            t += HEARTBEAT;
            let hb = w.a.tick(t, &mut w.rng);
            let pings = udp_pings(&w, &hb);
            if t - t0 >= ACTIVE_WINDOW {
                assert!(pings.is_empty(), "heartbeat after idle at +{:?}", t - t0);
                break;
            }
            assert_eq!(pings.len(), 1, "heartbeat expected at +{:?}", t - t0);
            let pong = b_says(
                &w,
                &Message::Pong {
                    tx_id: pings[0].1,
                    src: to,
                },
            );
            w.a.on_disco(Source::Udp(to), &pong, t, &mut w.rng);
        }
    }

    /// Pending-ping cleanup keeps unexpired pings: a pong arriving after a tick must still be recognized.
    #[test]
    fn tick_keeps_fresh_pending_pings() {
        let mut w = world(vec![E.parse().unwrap()]);
        let (_, acts) = w.a.route(w.b_node, 10 * S, &mut w.rng);
        let (to, tx_id) = udp_pings(&w, &acts)[0];
        w.a.tick(10 * S + Duration::from_millis(500), &mut w.rng);
        let pong = b_says(&w, &Message::Pong { tx_id, src: to });
        w.a.on_disco(
            Source::Udp(to),
            &pong,
            10 * S + Duration::from_millis(600),
            &mut w.rng,
        );
        assert_eq!(w.a.route(w.b_node, 11 * S, &mut w.rng).0, Route::Direct(to));
    }

    #[test]
    fn send_error_falls_back_immediately() {
        let mut w = world(vec![E.parse().unwrap()]);
        establish(&mut w, 10 * S);
        w.a.on_send_error(w.b_node);
        assert_eq!(w.a.route(w.b_node, 10 * S, &mut w.rng).0, Route::Derp(1000));
    }

    #[test]
    fn udp_ping_from_known_peer_gets_udp_pong_with_observed_source() {
        let mut w = world(vec![E.parse().unwrap()]);
        let from: SocketAddr = "172.29.0.21:5555".parse().unwrap();
        let ping = b_says(
            &w,
            &Message::Ping {
                tx_id: [3; TX_ID_LEN],
                node_key: w.b_node,
            },
        );
        let acts = w.a.on_disco(Source::Udp(from), &ping, 10 * S, &mut w.rng);
        let [Action::Udp { to, data }] = acts.as_slice() else {
            panic!("{acts:?}")
        };
        assert_eq!(*to, from);
        assert_eq!(
            b_reads(&w, data),
            Message::Pong {
                tx_id: [3; TX_ID_LEN],
                src: from
            }
        );
    }

    #[test]
    fn derp_ping_gets_derp_pong_with_magic_source() {
        let mut w = world(vec![]);
        let ping = b_says(
            &w,
            &Message::Ping {
                tx_id: [4; TX_ID_LEN],
                node_key: w.b_node,
            },
        );
        let acts = w.a.on_disco(
            Source::Derp {
                node: w.b_node,
                region: 1000,
            },
            &ping,
            10 * S,
            &mut w.rng,
        );
        let [Action::Derp { to, region, data }] = acts.as_slice() else {
            panic!("{acts:?}")
        };
        assert_eq!((*to, *region), (w.b_node, 1000));
        assert_eq!(
            b_reads(&w, data),
            Message::Pong {
                tx_id: [4; TX_ID_LEN],
                src: "127.3.3.40:1000".parse().unwrap()
            }
        );
    }

    #[test]
    fn ping_from_unknown_disco_key_is_ignored() {
        let mut w = world(vec![]);
        let stranger = DiscoPrivate::generate().unwrap();
        let ping = envelope::seal(
            &stranger,
            &w.a_disco.public(),
            &message::encode(&Message::Ping {
                tx_id: [5; TX_ID_LEN],
                node_key: NodePublic([9; 32]),
            }),
            [1; 24],
        )
        .unwrap();
        assert!(
            w.a.on_disco(
                Source::Udp("1.2.3.4:5".parse().unwrap()),
                &ping,
                S,
                &mut w.rng
            )
            .is_empty()
        );
    }

    #[test]
    fn relay_only_never_produces_udp() {
        let mut w = world(vec![E.parse().unwrap()]);
        w.a.set_relay_only(true);
        let (r, acts) = w.a.route(w.b_node, 10 * S, &mut w.rng);
        assert_eq!(r, Route::Derp(1000));
        assert!(
            acts.iter().all(|a| matches!(a, Action::Derp { .. })),
            "{acts:?}"
        );
        let ping = b_says(
            &w,
            &Message::Ping {
                tx_id: [6; TX_ID_LEN],
                node_key: w.b_node,
            },
        );
        assert!(
            w.a.on_disco(Source::Udp(E.parse().unwrap()), &ping, 11 * S, &mut w.rng)
                .is_empty()
        );
        assert!(
            w.a.tick(20 * S, &mut w.rng)
                .iter()
                .all(|a| matches!(a, Action::Derp { .. }))
        );
    }

    #[test]
    fn peer_for_addr_prefers_established_path_then_endpoints() {
        let mut w = world(vec![E.parse().unwrap()]);
        assert_eq!(w.a.peer_for_addr(E.parse().unwrap()), Some(w.b_node));
        assert_eq!(w.a.peer_for_addr("9.9.9.9:9".parse().unwrap()), None);
        // After the direct path is established, the netmap no longer carries that endpoint: it is still recognized via the established path.
        let to = establish(&mut w, S);
        w.a.set_peers(vec![PeerInfo {
            node: w.b_node,
            disco: w.b_disco.public(),
            home_region: Some(1000),
            endpoints: vec![],
        }]);
        assert_eq!(w.a.peer_for_addr(to), Some(w.b_node));
    }

    #[test]
    fn unknown_peer_has_no_route() {
        let mut w = world(vec![]);
        assert_eq!(
            w.a.route(NodePublic([77; 32]), S, &mut w.rng),
            (Route::None, vec![])
        );
    }

    #[test]
    fn set_peers_keeps_established_direct_path() {
        let mut w = world(vec![E.parse().unwrap()]);
        let to = establish(&mut w, 10 * S);
        let info = PeerInfo {
            node: w.b_node,
            disco: w.b_disco.public(),
            home_region: Some(1001),
            endpoints: vec![E.parse().unwrap()],
        };
        w.a.set_peers(vec![info]);
        assert_eq!(w.a.route(w.b_node, 11 * S, &mut w.rng).0, Route::Direct(to));
    }
}
