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
/// Upper bound on endpoints accepted from CallMeMaybe per peer, so a peer cannot make us ping many addresses.
pub const MAX_CMM_ENDPOINTS: usize = 16;
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

/// Relay mode (disco.md §5; WanFlow tag semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Discover direct paths normally, sending and accepting CallMeMaybe.
    #[default]
    Auto,
    /// prefer (`relay-force`; all DERP STUNPort == -1, deviation #1): never initiates direct traffic and ignores CallMeMaybe,
    /// but still answers UDP pings, so LAN peers can still go P2P (same as wanflow-mesh).
    Prefer,
    /// strict (self node has `tag:relay-strict`): no direct traffic of any kind, no answers to UDP pings,
    /// CallMeMaybe ignored. Stricter than wanflow-mesh, matches the product promise of "always relayed" (deviation #6).
    Strict,
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
    /// Endpoints learned from the peer's CallMeMaybe (Auto mode only).
    cmm_endpoints: Vec<SocketAddr>,
    best: Option<(SocketAddr, Duration)>,
    last_discovery: Option<Duration>,
    last_heartbeat: Option<Duration>,
    last_active: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    peer: NodePublic,
    /// Endpoint for a direct ping; `127.3.3.40:<region>` for a probe sent over DERP.
    to: SocketAddr,
    sent: Duration,
    /// Sent by [`PathSock::probe`]: its pong is reported as a [`ProbeResult`].
    probe: bool,
}

/// A pong answering [`PathSock::probe`] (the `flowmesh ping` command).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeResult {
    pub peer: NodePublic,
    /// `Direct(endpoint)` or `Derp(region)`.
    pub via: Route,
    pub latency: Duration,
}

pub struct PathSock {
    me: DiscoPrivate,
    my_node: NodePublic,
    mode: Mode,
    my_endpoints: Vec<SocketAddr>,
    peers: HashMap<NodePublic, PeerPath>,
    by_disco: HashMap<DiscoPublic, NodePublic>,
    pending: HashMap<[u8; TX_ID_LEN], Pending>,
    probe_results: Vec<ProbeResult>,
}

impl PathSock {
    pub fn new(me: DiscoPrivate, my_node: NodePublic) -> Self {
        Self {
            me,
            my_node,
            mode: Mode::Auto,
            my_endpoints: Vec::new(),
            peers: HashMap::new(),
            by_disco: HashMap::new(),
            pending: HashMap::new(),
            probe_results: Vec::new(),
        }
    }

    /// Any mode change drops established direct paths; after returning to Auto, paths are rediscovered.
    pub fn set_mode(&mut self, mode: Mode) {
        if self.mode != mode {
            for p in self.peers.values_mut() {
                p.best = None;
            }
        }
        self.mode = mode;
    }

    /// This node's endpoints, advertised to peers via CallMeMaybe in discovery rounds.
    pub fn set_my_endpoints(&mut self, endpoints: Vec<SocketAddr>) {
        self.my_endpoints = endpoints;
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
                    cmm_endpoints: Vec::new(),
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
        let relay_only = self.mode != Mode::Auto;
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
        let mut candidates = info.endpoints.clone();
        for e in &p.cmm_endpoints {
            if !candidates.contains(e) {
                candidates.push(*e);
            }
        }
        let mut actions = Vec::new();
        if !relay_only {
            for ep in candidates {
                if let Some(a) = self.ping(&info, Some(ep), false, now, rng) {
                    actions.push(a);
                }
            }
        }
        if let Some(a) = self.ping(&info, None, false, now, rng) {
            actions.push(a);
        }
        if !relay_only && !self.my_endpoints.is_empty() {
            if let Some(a) = self.call_me_maybe(&info, rng) {
                actions.push(a);
            }
        }
        (route, actions)
    }

    /// Ping a peer on demand over every path this mode allows (DERP always; candidate endpoints in
    /// Auto). Each pong comes back as a [`ProbeResult`] from [`PathSock::take_probe_results`]; a direct
    /// pong also establishes the path, as any direct pong does.
    pub fn probe(&mut self, peer: NodePublic, now: Duration, rng: &mut dyn Random) -> Vec<Action> {
        let Some(p) = self.peers.get(&peer) else {
            return Vec::new();
        };
        let info = p.info.clone();
        let mut actions = Vec::new();
        if self.mode == Mode::Auto {
            let mut candidates = info.endpoints.clone();
            for e in &p.cmm_endpoints {
                if !candidates.contains(e) {
                    candidates.push(*e);
                }
            }
            for ep in candidates {
                actions.extend(self.ping(&info, Some(ep), true, now, rng));
            }
        }
        actions.extend(self.ping(&info, None, true, now, rng));
        actions
    }

    /// Pongs to [`PathSock::probe`] received since the last call.
    pub fn take_probe_results(&mut self) -> Vec<ProbeResult> {
        std::mem::take(&mut self.probe_results)
    }

    /// Build a ping: `to` = Some(endpoint) means directly over UDP, None means via the home DERP.
    fn ping(
        &mut self,
        info: &PeerInfo,
        to: Option<SocketAddr>,
        probe: bool,
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
                        probe,
                    },
                );
                Some(Action::Udp { to: addr, data })
            }
            None => {
                let region = info.home_region?;
                // Only probes care about pongs over DERP; routine discovery pings over DERP exist to
                // make the peer learn our disco key, so they are not tracked.
                if probe {
                    self.pending.insert(
                        tx_id,
                        Pending {
                            peer: info.node,
                            to: derp_magic(region),
                            sent: now,
                            probe,
                        },
                    );
                }
                Some(Action::Derp {
                    to: info.node,
                    region,
                    data,
                })
            }
        }
    }

    /// Send our endpoints to the peer via DERP, asking it to ping them (helps NAT hole punching from both sides).
    fn call_me_maybe(&self, info: &PeerInfo, rng: &mut dyn Random) -> Option<Action> {
        let region = info.home_region?;
        let plain = message::encode(&Message::CallMeMaybe {
            endpoints: self.my_endpoints.clone(),
        });
        let data = self.seal(&info.disco, &plain, rng)?;
        Some(Action::Derp {
            to: info.node,
            region,
            data,
        })
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
        if self.mode == Mode::Strict && matches!(from, Source::Udp(_)) {
            return Vec::new();
        }
        let Ok((sender, plain)) = envelope::open(&self.me, bytes) else {
            return Vec::new();
        };
        let Some(&peer) = self.by_disco.get(&sender) else {
            return Vec::new();
        };
        let decoded = message::decode(&plain);
        // prefer: over UDP only Pings are answered (LAN peers can still go P2P); everything else is ignored.
        if self.mode == Mode::Prefer
            && matches!(from, Source::Udp(_))
            && !matches!(decoded, Ok(Message::Ping { .. }))
        {
            return Vec::new();
        }
        match decoded {
            Ok(Message::CallMeMaybe { endpoints }) => {
                if self.mode != Mode::Auto {
                    return Vec::new();
                }
                let Some(p) = self.peers.get_mut(&peer) else {
                    return Vec::new();
                };
                for e in &endpoints {
                    if !p.cmm_endpoints.contains(e) && p.cmm_endpoints.len() < MAX_CMM_ENDPOINTS {
                        p.cmm_endpoints.push(*e);
                    }
                }
                let info = p.info.clone();
                endpoints
                    .into_iter()
                    .take(MAX_CMM_ENDPOINTS)
                    .filter_map(|e| self.ping(&info, Some(e), false, now, rng))
                    .collect()
            }
            Ok(Message::Ping { tx_id, .. }) => {
                let src = match from {
                    Source::Udp(a) => a,
                    Source::Derp { region, .. } => derp_magic(region),
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
                let Some(pend) = self.pending.get(&tx_id).copied() else {
                    return Vec::new();
                };
                if pend.peer != peer || now.saturating_sub(pend.sent) > PING_TIMEOUT {
                    return Vec::new();
                }
                let via = match from {
                    Source::Udp(a) if pend.to == a => {
                        if let Some(p) = self.peers.get_mut(&peer) {
                            p.best = Some((a, now));
                            p.last_heartbeat = Some(now);
                        }
                        Route::Direct(a)
                    }
                    Source::Derp { region, .. } if pend.to == derp_magic(region) => {
                        Route::Derp(region)
                    }
                    _ => return Vec::new(),
                };
                self.pending.remove(&tx_id);
                if pend.probe {
                    self.probe_results.push(ProbeResult {
                        peer,
                        via,
                        latency: now.saturating_sub(pend.sent),
                    });
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
        if self.mode != Mode::Auto {
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
            .filter_map(|(info, addr)| self.ping(&info, Some(addr), false, now, rng))
            .collect()
    }

    /// Read-only query of the peer's current route (does not trigger discovery, does not change state), for status display.
    pub fn current_route(&self, peer: NodePublic, now: Duration) -> Route {
        let Some(p) = self.peers.get(&peer) else {
            return Route::None;
        };
        match p.best {
            Some((addr, confirmed)) if self.mode == Mode::Auto && now < confirmed + TRUST => {
                Route::Direct(addr)
            }
            _ => p.info.home_region.map_or(Route::None, Route::Derp),
        }
    }

    /// Which peer a packet arriving over UDP from `addr` belongs to: the established direct path takes precedence, then the candidate endpoints.
    pub fn peer_for_addr(&self, addr: SocketAddr) -> Option<NodePublic> {
        self.peers
            .values()
            .find(|p| p.best.is_some_and(|(a, _)| a == addr))
            .or_else(|| {
                self.peers
                    .values()
                    .find(|p| p.info.endpoints.contains(&addr) || p.cmm_endpoints.contains(&addr))
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

/// The address that stands for "via DERP region N" in disco pongs.
fn derp_magic(region: u32) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(DERP_MAGIC_IP), clamp_port(region))
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
    fn prefer_never_initiates_udp_but_answers_udp_pings() {
        let mut w = world(vec![E.parse().unwrap()]);
        w.a.set_mode(Mode::Prefer);
        let (r, acts) = w.a.route(w.b_node, 10 * S, &mut w.rng);
        assert_eq!(r, Route::Derp(1000));
        assert!(
            acts.iter().all(|a| matches!(a, Action::Derp { .. })),
            "{acts:?}"
        );
        // A LAN peer pings us directly: we answer over UDP (same as wanflow-mesh: in prefer, the LAN can still go P2P).
        let from: SocketAddr = E.parse().unwrap();
        let ping = b_says(
            &w,
            &Message::Ping {
                tx_id: [6; TX_ID_LEN],
                node_key: w.b_node,
            },
        );
        let acts = w.a.on_disco(Source::Udp(from), &ping, 11 * S, &mut w.rng);
        assert!(
            matches!(acts.as_slice(), [Action::Udp { to, .. }] if *to == from),
            "{acts:?}"
        );
        // CallMeMaybe is ignored and no direct ping is sent.
        let cmm = b_says(
            &w,
            &Message::CallMeMaybe {
                endpoints: vec![E.parse().unwrap()],
            },
        );
        assert!(
            w.a.on_disco(
                Source::Derp {
                    node: w.b_node,
                    region: 1000
                },
                &cmm,
                11 * S,
                &mut w.rng
            )
            .is_empty()
        );
        assert!(w.a.tick(20 * S, &mut w.rng).is_empty());
    }

    #[test]
    fn strict_produces_no_udp_at_all() {
        let mut w = world(vec![E.parse().unwrap()]);
        w.a.set_mode(Mode::Strict);
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
        let cmm = b_says(
            &w,
            &Message::CallMeMaybe {
                endpoints: vec![E.parse().unwrap()],
            },
        );
        assert!(
            w.a.on_disco(
                Source::Derp {
                    node: w.b_node,
                    region: 1000
                },
                &cmm,
                11 * S,
                &mut w.rng
            )
            .is_empty()
        );
        // Pings over DERP are still answered over DERP (latency probing, no direct path).
        let acts = w.a.on_disco(
            Source::Derp {
                node: w.b_node,
                region: 1000,
            },
            &ping,
            11 * S,
            &mut w.rng,
        );
        assert!(matches!(acts.as_slice(), [Action::Derp { .. }]), "{acts:?}");
    }

    #[test]
    fn switching_away_from_auto_drops_direct_path() {
        let mut w = world(vec![E.parse().unwrap()]);
        establish(&mut w, 10 * S);
        w.a.set_mode(Mode::Prefer);
        assert_eq!(w.a.route(w.b_node, 11 * S, &mut w.rng).0, Route::Derp(1000));
    }

    #[test]
    fn auto_call_me_maybe_adds_candidates_and_pings_them() {
        let mut w = world(vec![]);
        let theirs: SocketAddr = "203.0.113.9:41641".parse().unwrap();
        let cmm = b_says(
            &w,
            &Message::CallMeMaybe {
                endpoints: vec![theirs],
            },
        );
        let acts = w.a.on_disco(
            Source::Derp {
                node: w.b_node,
                region: 1000,
            },
            &cmm,
            10 * S,
            &mut w.rng,
        );
        let pings = udp_pings(&w, &acts);
        assert_eq!(pings.iter().map(|p| p.0).collect::<Vec<_>>(), vec![theirs]);
        let pong = b_says(
            &w,
            &Message::Pong {
                tx_id: pings[0].1,
                src: theirs,
            },
        );
        w.a.on_disco(Source::Udp(theirs), &pong, 10 * S, &mut w.rng);
        assert_eq!(
            w.a.route(w.b_node, 10 * S, &mut w.rng).0,
            Route::Direct(theirs)
        );
        assert_eq!(w.a.peer_for_addr(theirs), Some(w.b_node));
    }

    #[test]
    fn auto_discovery_sends_call_me_maybe_with_my_endpoints() {
        let mut w = world(vec![E.parse().unwrap()]);
        let mine: SocketAddr = "172.29.0.31:41641".parse().unwrap();
        w.a.set_my_endpoints(vec![mine]);
        let (_, acts) = w.a.route(w.b_node, 10 * S, &mut w.rng);
        let cmms: Vec<Message> = acts
            .iter()
            .filter_map(|a| match a {
                Action::Derp { data, .. } => Some(b_reads(&w, data)),
                _ => None,
            })
            .filter(|m| matches!(m, Message::CallMeMaybe { .. }))
            .collect();
        assert_eq!(
            cmms,
            vec![Message::CallMeMaybe {
                endpoints: vec![mine]
            }]
        );
    }

    #[test]
    fn no_call_me_maybe_without_my_endpoints() {
        let mut w = world(vec![E.parse().unwrap()]);
        let (_, acts) = w.a.route(w.b_node, 10 * S, &mut w.rng);
        assert!(acts.iter().all(|a| match a {
            Action::Derp { data, .. } => !matches!(b_reads(&w, data), Message::CallMeMaybe { .. }),
            _ => true,
        }));
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
    fn mode_change_drops_direct_path_but_same_mode_keeps_it() {
        let mut w = world(vec![E.parse().unwrap()]);
        let to = establish(&mut w, 10 * S);
        w.a.set_mode(Mode::Auto);
        assert_eq!(w.a.route(w.b_node, 11 * S, &mut w.rng).0, Route::Direct(to));
        w.a.set_mode(Mode::Prefer);
        w.a.set_mode(Mode::Auto);
        assert_eq!(
            w.a.route(w.b_node, 11 * S, &mut w.rng).0,
            Route::Derp(1000),
            "must rediscover after a mode round-trip"
        );
    }

    fn discovery_ping_targets(w: &mut World, t: Duration) -> Vec<SocketAddr> {
        let (_, acts) = w.a.route(w.b_node, t, &mut w.rng);
        let mut v: Vec<SocketAddr> = udp_pings(w, &acts).into_iter().map(|p| p.0).collect();
        v.sort();
        v
    }

    #[test]
    fn call_me_maybe_endpoints_are_deduplicated() {
        let mut w = world(vec![E.parse().unwrap()]);
        let extra: SocketAddr = "203.0.113.9:41641".parse().unwrap();
        for _ in 0..2 {
            let cmm = b_says(
                &w,
                &Message::CallMeMaybe {
                    endpoints: vec![extra, E.parse().unwrap()],
                },
            );
            w.a.on_disco(
                Source::Derp {
                    node: w.b_node,
                    region: 1000,
                },
                &cmm,
                S,
                &mut w.rng,
            );
        }
        // Discovery round: each candidate is pinged once (a CallMeMaybe endpoint that duplicates a netmap endpoint is not pinged twice).
        let mut expected = vec![E.parse().unwrap(), extra];
        expected.sort();
        assert_eq!(discovery_ping_targets(&mut w, 10 * S), expected);
    }

    #[test]
    fn call_me_maybe_endpoints_are_capped_per_peer() {
        let mut w = world(vec![]);
        let many: Vec<SocketAddr> = (0..MAX_CMM_ENDPOINTS as u16 + 1)
            .map(|i| SocketAddr::from(([203, 0, 113, 1], 40000 + i)))
            .collect();
        let cmm = b_says(&w, &Message::CallMeMaybe { endpoints: many });
        let immediate = w.a.on_disco(
            Source::Derp {
                node: w.b_node,
                region: 1000,
            },
            &cmm,
            S,
            &mut w.rng,
        );
        assert_eq!(udp_pings(&w, &immediate).len(), MAX_CMM_ENDPOINTS);
        assert_eq!(
            discovery_ping_targets(&mut w, 10 * S).len(),
            MAX_CMM_ENDPOINTS
        );
    }

    #[test]
    fn current_route_is_read_only() {
        let mut w = world(vec![E.parse().unwrap()]);
        assert_eq!(w.a.current_route(w.b_node, 10 * S), Route::Derp(1000));
        let to = establish(&mut w, 10 * S);
        assert_eq!(w.a.current_route(w.b_node, 11 * S), Route::Direct(to));
        // After the trust window it shows DERP, and the query does not start a discovery round (route() below still triggers one immediately).
        assert_eq!(
            w.a.current_route(w.b_node, 10 * S + TRUST),
            Route::Derp(1000)
        );
        w.a.set_mode(Mode::Prefer);
        assert_eq!(w.a.current_route(w.b_node, 11 * S), Route::Derp(1000));
        assert_eq!(w.a.current_route(NodePublic([77; 32]), S), Route::None);
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

    fn derp_pings(w: &World, acts: &[Action]) -> Vec<[u8; TX_ID_LEN]> {
        acts.iter()
            .filter_map(|a| match a {
                Action::Derp {
                    data, region: 1000, ..
                } => match b_reads(w, data) {
                    Message::Ping { tx_id, .. } => Some(tx_id),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    fn pong(w: &World, tx_id: [u8; TX_ID_LEN]) -> Vec<u8> {
        b_says(
            w,
            &Message::Pong {
                tx_id,
                src: "172.29.0.31:41641".parse().unwrap(),
            },
        )
    }

    fn via_derp(w: &World, region: u32) -> Source {
        Source::Derp {
            node: w.b_node,
            region,
        }
    }

    #[test]
    fn probe_reports_every_answered_path_with_latency() {
        let mut w = world(vec![E.parse().unwrap()]);
        let acts = w.a.probe(w.b_node, 10 * S, &mut w.rng);
        let udp = udp_pings(&w, &acts);
        let derp = derp_pings(&w, &acts);
        assert_eq!((udp.len(), derp.len()), (1, 1), "{acts:?}");

        let ms = Duration::from_millis;
        w.a.on_disco(
            via_derp(&w, 1000),
            &pong(&w, derp[0]),
            10 * S + ms(40),
            &mut w.rng,
        );
        w.a.on_disco(
            Source::Udp(udp[0].0),
            &pong(&w, udp[0].1),
            10 * S + ms(3),
            &mut w.rng,
        );
        assert_eq!(
            w.a.take_probe_results(),
            vec![
                ProbeResult {
                    peer: w.b_node,
                    via: Route::Derp(1000),
                    latency: ms(40)
                },
                ProbeResult {
                    peer: w.b_node,
                    via: Route::Direct(udp[0].0),
                    latency: ms(3)
                },
            ]
        );
        assert!(w.a.take_probe_results().is_empty(), "results are drained");
        // The direct pong also established the path.
        assert_eq!(w.a.current_route(w.b_node, 11 * S), Route::Direct(udp[0].0));
    }

    #[test]
    fn probe_includes_call_me_maybe_endpoints() {
        let mut w = world(vec![]);
        let cmm: SocketAddr = "10.10.1.21:41641".parse().unwrap();
        let msg = b_says(
            &w,
            &Message::CallMeMaybe {
                endpoints: vec![cmm],
            },
        );
        w.a.on_disco(via_derp(&w, 1000), &msg, 9 * S, &mut w.rng);
        let acts = w.a.probe(w.b_node, 10 * S, &mut w.rng);
        assert_eq!(
            udp_pings(&w, &acts).iter().map(|p| p.0).collect::<Vec<_>>(),
            vec![cmm]
        );
    }

    #[test]
    fn relay_modes_probe_only_over_derp() {
        for mode in [Mode::Prefer, Mode::Strict] {
            let mut w = world(vec![E.parse().unwrap()]);
            w.a.set_mode(mode);
            let acts = w.a.probe(w.b_node, 10 * S, &mut w.rng);
            assert!(udp_pings(&w, &acts).is_empty(), "{mode:?}");
            let derp = derp_pings(&w, &acts);
            assert_eq!(derp.len(), 1, "{mode:?}");
            w.a.on_disco(via_derp(&w, 1000), &pong(&w, derp[0]), 10 * S, &mut w.rng);
            assert_eq!(
                w.a.take_probe_results()[0].via,
                Route::Derp(1000),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn routine_pings_produce_no_probe_results() {
        let mut w = world(vec![E.parse().unwrap()]);
        let (_, acts) = w.a.route(w.b_node, 10 * S, &mut w.rng);
        let (to, tx) = udp_pings(&w, &acts)[0];
        let derp = derp_pings(&w, &acts);
        w.a.on_disco(Source::Udp(to), &pong(&w, tx), 10 * S, &mut w.rng);
        // A pong over DERP to a routine discovery ping is not tracked at all.
        w.a.on_disco(via_derp(&w, 1000), &pong(&w, derp[0]), 10 * S, &mut w.rng);
        assert!(w.a.take_probe_results().is_empty());
        assert_eq!(w.a.current_route(w.b_node, 10 * S), Route::Direct(to));
    }

    #[test]
    fn probe_pong_must_match_path_peer_and_time() {
        let mut w = world(vec![E.parse().unwrap()]);
        let acts = w.a.probe(w.b_node, 10 * S, &mut w.rng);
        let derp = derp_pings(&w, &acts)[0];
        let (to, tx) = udp_pings(&w, &acts)[0];
        // Wrong DERP region, and a DERP pong for the UDP ping's txid.
        w.a.on_disco(via_derp(&w, 1001), &pong(&w, derp), 10 * S, &mut w.rng);
        w.a.on_disco(via_derp(&w, 1000), &pong(&w, tx), 10 * S, &mut w.rng);
        // Too late.
        w.a.on_disco(
            Source::Udp(to),
            &pong(&w, tx),
            10 * S + PING_TIMEOUT + S,
            &mut w.rng,
        );
        assert!(w.a.take_probe_results().is_empty());
        // Exactly at the timeout still counts.
        w.a.on_disco(
            via_derp(&w, 1000),
            &pong(&w, derp),
            10 * S + PING_TIMEOUT,
            &mut w.rng,
        );
        assert_eq!(w.a.take_probe_results().len(), 1);
    }

    #[test]
    fn probe_pong_from_another_peer_is_ignored() {
        let mut w = world(vec![]);
        let c_disco = DiscoPrivate::generate().unwrap();
        let c_node = NodePublic([3; 32]);
        w.a.set_peers(vec![
            PeerInfo {
                node: w.b_node,
                disco: w.b_disco.public(),
                home_region: Some(1000),
                endpoints: vec![],
            },
            PeerInfo {
                node: c_node,
                disco: c_disco.public(),
                home_region: Some(1000),
                endpoints: vec![],
            },
        ]);
        let acts = w.a.probe(w.b_node, 10 * S, &mut w.rng);
        let derp = derp_pings(&w, &acts)[0];
        let forged = envelope::seal(
            &c_disco,
            &w.a_disco.public(),
            &message::encode(&Message::Pong {
                tx_id: derp,
                src: E.parse().unwrap(),
            }),
            [9; 24],
        )
        .unwrap();
        w.a.on_disco(
            Source::Derp {
                node: c_node,
                region: 1000,
            },
            &forged,
            10 * S,
            &mut w.rng,
        );
        assert!(w.a.take_probe_results().is_empty());
    }

    #[test]
    fn probe_unknown_peer_does_nothing() {
        let mut w = world(vec![E.parse().unwrap()]);
        assert!(
            w.a.probe(NodePublic([9; 32]), 10 * S, &mut w.rng)
                .is_empty()
        );
    }
}
