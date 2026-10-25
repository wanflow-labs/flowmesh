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

mod prefer;
pub use prefer::{
    PREFER_ACTIVE_WINDOW, PREFER_MIN_FALLBACK, PREFER_PROBE_INTERVAL, PREFER_RELAY_DEAD_AFTER,
    PREFER_RELAY_MAX_GAP, PREFER_RELAY_STABLE_FOR, is_lan,
};
use prefer::{PreferFallback, Transition};

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
    /// A disco message to a peer through its peer relay path: sent to the relay server with a Geneve
    /// header (this VNI, protocol disco, no O bit) in front of `data` (peer-relay.md §3).
    Relay {
        server: SocketAddr,
        vni: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Direct(SocketAddr),
    /// Through a bound peer relay that answered recently (peer-relay.md).
    PeerRelay {
        server: SocketAddr,
        vni: u32,
    },
    Derp(u32),
    /// Peer unknown or has no home relay.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Udp(SocketAddr),
    Derp {
        node: NodePublic,
        region: u32,
    },
    /// Received from a relay server with a Geneve header carrying this VNI.
    Relay {
        server: SocketAddr,
        vni: u32,
    },
}

/// Relay mode (disco.md §5; WanFlow tag semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Discover direct paths normally, sending and accepting CallMeMaybe.
    #[default]
    Auto,
    /// prefer (self node has `tag:relay-force`, or every DERP node has STUNPort == -1, deviation #1):
    /// relays first, decided per peer. Direct paths are used, pinged and answered only for LAN
    /// addresses ([`is_lan`]); public candidates (netmap or CallMeMaybe) are recorded but neither
    /// pinged nor answered. While a peer is active its relays are probed; when they stay silent
    /// ([`PREFER_RELAY_DEAD_AFTER`]) and the peer is online, it falls back to auto behaviour for
    /// direct paths, and returns once the relays have answered steadily again (dropping a public
    /// direct path, keeping a LAN one). CallMeMaybe is sent as in auto. Peer relays are always allowed.
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
    /// The control plane's view: false only when it marks the peer offline (unknown counts as
    /// online). Prefer mode does not fall back to direct for an offline peer.
    pub online: bool,
}

struct PeerPath {
    info: PeerInfo,
    /// Endpoints learned from the peer's CallMeMaybe (auto and prefer; prefer pings only the allowed ones).
    cmm_endpoints: Vec<SocketAddr>,
    best: Option<(SocketAddr, Duration)>,
    last_discovery: Option<Duration>,
    last_heartbeat: Option<Duration>,
    last_active: Option<Duration>,
    /// The peer relay endpoint the caller bound (flowmesh-udprelay), and its liveness.
    relay: Option<RelayPath>,
    /// Prefer mode: whether the relays went silent for this peer, so direct paths are allowed.
    prefer: PreferFallback,
    /// When the current prefer fallback began (for the exit event).
    fallback_at: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelayPath {
    server: SocketAddr,
    vni: u32,
    /// Last pong through the relay.
    confirmed: Option<Duration>,
    last_heartbeat: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    peer: NodePublic,
    /// Endpoint for a direct ping; `127.3.3.40:<region>` for a probe sent over DERP.
    to: SocketAddr,
    sent: Duration,
    purpose: Purpose,
    /// The VNI when the ping went through a peer relay (`to` is then the relay server).
    vni: Option<u32>,
}

/// Why a ping was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// Discovery or heartbeat. A routine ping over DERP is not tracked: it exists to make the peer
    /// learn our disco key.
    Routine,
    /// Sent by [`PathSock::probe`]: its pong is reported as a [`ProbeResult`].
    Probe,
    /// Prefer mode's relay probe: its pong over a relay feeds the fallback state machine.
    RelayCheck,
}

/// The state behind a peer's current path ([`PathSock::explain`]). Ages are measured back from `now`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathExplain {
    pub route: Route,
    pub reason: String,
    /// Endpoints that would be tried for a direct path (netmap first, then CallMeMaybe).
    pub candidates: Vec<SocketAddr>,
    pub from_call_me_maybe: Vec<SocketAddr>,
    /// The last direct path that answered, and how long ago.
    pub last_direct_pong: Option<(SocketAddr, Duration)>,
    pub last_discovery: Option<Duration>,
    pub last_active: Option<Duration>,
    /// The bound peer relay endpoint (server, VNI) and the age of its last pong.
    pub relay: Option<(SocketAddr, u32, Option<Duration>)>,
}

/// A prefer-mode peer entered or left direct fallback ([`PathSock::take_prefer_events`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferEvent {
    /// The relays stayed silent while we talked to `peer`: direct paths are now allowed for it.
    /// `no_relay_path` = there was nothing to probe through (no home region, no peer relay).
    Entered {
        peer: NodePublic,
        no_relay_path: bool,
    },
    /// The relays answered steadily again after `after` in fallback: back to relay (LAN direct kept).
    Exited { peer: NodePublic, after: Duration },
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
    /// Peers that answered a ping through their peer relay since the last call.
    relay_pongs: Vec<NodePublic>,
    /// Prefer-mode fallback transitions since the last call.
    prefer_events: Vec<PreferEvent>,
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
            relay_pongs: Vec::new(),
            prefer_events: Vec::new(),
        }
    }

    /// Any mode change drops established direct paths and prefer fallback state; paths are then
    /// rediscovered under the new mode.
    pub fn set_mode(&mut self, mode: Mode) {
        if self.mode != mode {
            for p in self.peers.values_mut() {
                p.best = None;
                p.prefer = PreferFallback::default();
                p.fallback_at = None;
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
                    relay: None,
                    prefer: PreferFallback::default(),
                    fallback_at: None,
                },
            };
            next.insert(path.info.node, path);
        }
        self.peers = next;
        self.pending.retain(|_, p| self.peers.contains_key(&p.peer));
    }

    /// The peer relay endpoint bound for `peer` (from flowmesh-udprelay), or `None`. A new endpoint
    /// starts unconfirmed and makes the next `route` call run discovery, which pings through it.
    pub fn set_relay(&mut self, peer: NodePublic, endpoint: Option<(SocketAddr, u32)>) {
        let Some(p) = self.peers.get_mut(&peer) else {
            return;
        };
        let same =
            matches!((p.relay, endpoint), (Some(r), Some((s, v))) if r.server == s && r.vni == v);
        if same {
            return;
        }
        p.relay = endpoint.map(|(server, vni)| RelayPath {
            server,
            vni,
            confirmed: None,
            last_heartbeat: None,
        });
        if p.relay.is_some() {
            p.last_discovery = None;
        }
    }

    /// Which peer a packet from relay server `server` with VNI `vni` belongs to.
    pub fn peer_for_relay(&self, server: SocketAddr, vni: u32) -> Option<NodePublic> {
        self.peers
            .values()
            .find(|p| p.relay.is_some_and(|r| r.server == server && r.vni == vni))
            .map(|p| p.info.node)
    }

    /// Peers that answered a ping through their peer relay since the last call (for
    /// flowmesh-udprelay's liveness tracking).
    pub fn take_relay_pongs(&mut self) -> Vec<NodePublic> {
        std::mem::take(&mut self.relay_pongs)
    }

    /// Data arrived from `peer` (any path): it counts as activity for prefer-mode fallback.
    pub fn note_received(&mut self, peer: NodePublic, now: Duration) {
        if let Some(p) = self.peers.get_mut(&peer) {
            p.prefer.note_active(now);
        }
    }

    /// Whether `peer` is in prefer-mode direct fallback (always false outside prefer mode).
    pub fn in_prefer_fallback(&self, peer: NodePublic) -> bool {
        self.mode == Mode::Prefer
            && self
                .peers
                .get(&peer)
                .is_some_and(|p| p.prefer.in_fallback())
    }

    /// Prefer-mode fallback transitions since the last call, for logging.
    pub fn take_prefer_events(&mut self) -> Vec<PreferEvent> {
        std::mem::take(&mut self.prefer_events)
    }

    /// Called when there is data to send to `peer`: returns the route to use, plus any disco traffic this triggers.
    pub fn route(
        &mut self,
        peer: NodePublic,
        now: Duration,
        rng: &mut dyn Random,
    ) -> (Route, Vec<Action>) {
        let mode = self.mode;
        let Some(p) = self.peers.get_mut(&peer) else {
            return (Route::None, Vec::new());
        };
        p.last_active = Some(now);
        p.prefer.note_active(now);
        if let Some((addr, confirmed)) = p.best {
            if direct_allowed(mode, p, addr) && now < confirmed + TRUST {
                return (Route::Direct(addr), Vec::new());
            }
            p.best = None;
        }
        let route = relay_route(p, now)
            .or(p.info.home_region.map(Route::Derp))
            .unwrap_or(Route::None);
        let due = p
            .last_discovery
            .is_none_or(|last| now.saturating_sub(last) >= DISCOVERY_INTERVAL);
        if !due {
            return (route, Vec::new());
        }
        p.last_discovery = Some(now);
        let info = p.info.clone();
        let candidates = allowed_candidates(mode, p);
        let mut actions = Vec::new();
        for ep in candidates {
            if let Some(a) = self.ping(&info, Some(ep), Purpose::Routine, now, rng) {
                actions.push(a);
            }
        }
        if let Some(a) = self.ping(&info, None, Purpose::Routine, now, rng) {
            actions.push(a);
        }
        if let Some(r) = self.peers.get(&peer).and_then(|p| p.relay) {
            actions.extend(self.relay_ping(&info, r.server, r.vni, Purpose::Routine, now, rng));
        }
        if mode != Mode::Strict && !self.my_endpoints.is_empty() {
            if let Some(a) = self.call_me_maybe(&info, rng) {
                actions.push(a);
            }
        }
        (route, actions)
    }

    /// Ping a peer on demand over every path this mode allows (DERP always; candidate endpoints in
    /// auto, the allowed ones in prefer, none in strict). Each pong comes back as a
    /// [`ProbeResult`] from [`PathSock::take_probe_results`]; a direct pong also establishes the
    /// path, as any direct pong does.
    pub fn probe(&mut self, peer: NodePublic, now: Duration, rng: &mut dyn Random) -> Vec<Action> {
        let Some(p) = self.peers.get(&peer) else {
            return Vec::new();
        };
        let info = p.info.clone();
        let p_relay = p.relay;
        let candidates = allowed_candidates(self.mode, p);
        let mut actions = Vec::new();
        for ep in candidates {
            actions.extend(self.ping(&info, Some(ep), Purpose::Probe, now, rng));
        }
        actions.extend(self.ping(&info, None, Purpose::Probe, now, rng));
        if let Some(r) = p_relay {
            actions.extend(self.relay_ping(&info, r.server, r.vni, Purpose::Probe, now, rng));
        }
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
        purpose: Purpose,
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
                        purpose,
                        vni: None,
                    },
                );
                Some(Action::Udp { to: addr, data })
            }
            None => {
                let region = info.home_region?;
                // Only probes care about pongs over DERP; routine discovery pings over DERP exist to
                // make the peer learn our disco key, so they are not tracked.
                if purpose != Purpose::Routine {
                    self.pending.insert(
                        tx_id,
                        Pending {
                            peer: info.node,
                            to: derp_magic(region),
                            sent: now,
                            purpose,
                            vni: None,
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

    /// Build a ping to the peer through its peer relay.
    fn relay_ping(
        &mut self,
        info: &PeerInfo,
        server: SocketAddr,
        vni: u32,
        purpose: Purpose,
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
        self.pending.insert(
            tx_id,
            Pending {
                peer: info.node,
                to: server,
                sent: now,
                purpose,
                vni: Some(vni),
            },
        );
        Some(Action::Relay { server, vni, data })
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
        let mode = self.mode;
        let Some(p) = self.peers.get_mut(&peer) else {
            return Vec::new();
        };
        // Anything authenticated from the peer, on any path, makes it active: a node that only
        // receives must still probe its relays and, if they are silent, fall back.
        p.prefer.note_active(now);
        // prefer: disco over UDP from an address we may not go direct to (public, outside fallback)
        // is dropped unanswered, so a peer cannot build a direct path towards us from outside.
        if let Source::Udp(a) = from {
            if !direct_allowed(mode, p, a) {
                return Vec::new();
            }
        }
        match message::decode(&plain) {
            Ok(Message::CallMeMaybe { endpoints }) => {
                if mode == Mode::Strict {
                    return Vec::new();
                }
                for e in &endpoints {
                    if !p.cmm_endpoints.contains(e) && p.cmm_endpoints.len() < MAX_CMM_ENDPOINTS {
                        p.cmm_endpoints.push(*e);
                    }
                }
                // prefer records every endpoint (they are the fallback candidates) but pings only
                // the allowed ones now.
                let now_allowed: Vec<SocketAddr> = endpoints
                    .into_iter()
                    .take(MAX_CMM_ENDPOINTS)
                    .filter(|e| direct_allowed(mode, p, *e))
                    .collect();
                let info = p.info.clone();
                now_allowed
                    .into_iter()
                    .filter_map(|e| self.ping(&info, Some(e), Purpose::Routine, now, rng))
                    .collect()
            }
            Ok(Message::Ping { tx_id, .. }) => {
                let src = match from {
                    Source::Udp(a) => a,
                    Source::Derp { region, .. } => derp_magic(region),
                    Source::Relay { server, .. } => server,
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
                    Source::Relay { server, vni } => vec![Action::Relay { server, vni, data }],
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
                        if let Some(p) = self.peers.get_mut(&peer) {
                            p.prefer.note_relay_pong(now);
                        }
                        Route::Derp(region)
                    }
                    Source::Relay { server, vni } if pend.to == server && pend.vni == Some(vni) => {
                        if let Some(p) = self.peers.get_mut(&peer) {
                            p.prefer.note_relay_pong(now);
                            if let Some(r) = p.relay.as_mut() {
                                if r.server == server && r.vni == vni {
                                    r.confirmed = Some(now);
                                    r.last_heartbeat = Some(now);
                                }
                            }
                        }
                        self.relay_pongs.push(peer);
                        Route::PeerRelay { server, vni }
                    }
                    _ => return Vec::new(),
                };
                self.pending.remove(&tx_id);
                if pend.purpose == Purpose::Probe {
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

    /// Periodic driver (call it about once a second or more often): heartbeats, expiry, and in
    /// prefer mode the relay probes and fallback decisions.
    pub fn tick(&mut self, now: Duration, rng: &mut dyn Random) -> Vec<Action> {
        self.pending
            .retain(|_, p| now.saturating_sub(p.sent) <= PING_TIMEOUT);
        let mut out = self.relay_heartbeats(now, rng);
        match self.mode {
            Mode::Strict => return out,
            Mode::Prefer => out.extend(self.prefer_tick(now, rng)),
            Mode::Auto => {}
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
        out.extend(
            due.into_iter().filter_map(|(info, addr)| {
                self.ping(&info, Some(addr), Purpose::Routine, now, rng)
            }),
        );
        out
    }

    /// Prefer mode, per peer: refresh its online state, probe its relays (cloud relay and bound
    /// peer relay) while it is active, then decide fallback. Leaving fallback drops a public direct
    /// path; a LAN one stays.
    fn prefer_tick(&mut self, now: Duration, rng: &mut dyn Random) -> Vec<Action> {
        let mut due = Vec::new();
        for p in self.peers.values_mut() {
            p.prefer.set_online(now, p.info.online);
            if p.prefer.want_probe(now) {
                p.prefer.note_probe_sent(now);
                due.push((p.info.clone(), p.relay));
            }
            match p.prefer.update(now) {
                Transition::NoChange => {}
                Transition::Entered => {
                    p.fallback_at = Some(now);
                    // Discover direct paths on the next send instead of waiting for the round.
                    p.last_discovery = None;
                    self.prefer_events.push(PreferEvent::Entered {
                        peer: p.info.node,
                        no_relay_path: p.info.home_region.is_none() && p.relay.is_none(),
                    });
                }
                Transition::Exited => {
                    if p.best.is_some_and(|(a, _)| !is_lan(a.ip())) {
                        p.best = None;
                    }
                    let after = p
                        .fallback_at
                        .take()
                        .map_or(Duration::ZERO, |t| now.saturating_sub(t));
                    self.prefer_events.push(PreferEvent::Exited {
                        peer: p.info.node,
                        after,
                    });
                }
            }
        }
        let mut out = Vec::new();
        for (info, relay) in due {
            out.extend(self.ping(&info, None, Purpose::RelayCheck, now, rng));
            if let Some(r) = relay {
                out.extend(self.relay_ping(&info, r.server, r.vni, Purpose::RelayCheck, now, rng));
            }
        }
        out
    }

    /// Peer relay paths in every mode: expire the trust of one that stopped answering (it stays bound,
    /// discovery keeps pinging it) and keep active ones alive with a heartbeat.
    fn relay_heartbeats(&mut self, now: Duration, rng: &mut dyn Random) -> Vec<Action> {
        let mut due = Vec::new();
        for p in self.peers.values_mut() {
            let Some(r) = p.relay.as_mut() else {
                continue;
            };
            let Some(confirmed) = r.confirmed else {
                continue;
            };
            if now >= confirmed + TRUST {
                r.confirmed = None;
                continue;
            }
            let active = p
                .last_active
                .is_some_and(|t| now.saturating_sub(t) < ACTIVE_WINDOW);
            let hb_due = r
                .last_heartbeat
                .is_none_or(|t| now.saturating_sub(t) >= HEARTBEAT);
            if active && hb_due {
                r.last_heartbeat = Some(now);
                due.push((p.info.clone(), r.server, r.vni));
            }
        }
        due.into_iter()
            .filter_map(|(info, server, vni)| {
                self.relay_ping(&info, server, vni, Purpose::Routine, now, rng)
            })
            .collect()
    }

    /// Why the peer is on its current path, for `flowmesh debug paths`. Read-only.
    pub fn explain(&self, peer: NodePublic, now: Duration) -> Option<PathExplain> {
        let p = self.peers.get(&peer)?;
        let route = self.current_route(peer, now);
        let mut candidates = p.info.endpoints.clone();
        candidates.extend(
            p.cmm_endpoints
                .iter()
                .filter(|e| !p.info.endpoints.contains(e)),
        );
        let since = |t: Option<Duration>| t.map(|t| now.saturating_sub(t));
        let direct = p
            .best
            .map(|(addr, confirmed)| (addr, now.saturating_sub(confirmed)));
        let relay = p.relay.map(|r| (r.server, r.vni, since(r.confirmed)));
        let reason = match (route, self.mode) {
            (Route::PeerRelay { server, vni }, _) => {
                let age = since(p.relay.and_then(|r| r.confirmed)).unwrap_or(Duration::ZERO);
                format!(
                    "peer relay: pong via {server} vni {vni} {:.1}s ago (trusted for {:.1}s)",
                    age.as_secs_f64(),
                    TRUST.as_secs_f64()
                )
            }
            (Route::Direct(addr), _) => {
                let age = direct.map_or(Duration::ZERO, |(_, a)| a);
                format!(
                    "direct: pong from {addr} {:.1}s ago (trusted for {:.1}s)",
                    age.as_secs_f64(),
                    TRUST.as_secs_f64()
                )
            }
            (_, Mode::Strict) => "relay: strict mode, no direct traffic at all".to_string(),
            (_, Mode::Prefer) if p.prefer.in_fallback() => {
                "relay: prefer mode fell back to direct discovery (relays silent), no direct pong yet"
                    .to_string()
            }
            (_, Mode::Prefer) => {
                "relay: prefer mode, direct only on the local network while the relays answer"
                    .to_string()
            }
            (_, Mode::Auto) if direct.is_some() => {
                "relay: the direct path stopped answering (trust window expired)".to_string()
            }
            (_, Mode::Auto) if p.last_discovery.is_none() => {
                "relay: no direct attempt yet (nothing sent to this peer since start)".to_string()
            }
            (_, Mode::Auto) if candidates.is_empty() => {
                "relay: no candidate endpoints (the peer reports none, nor sent CallMeMaybe)"
                    .to_string()
            }
            (_, Mode::Auto) => format!(
                "relay: no pong yet from any of {} candidate endpoint(s)",
                candidates.len()
            ),
        };
        Some(PathExplain {
            route,
            reason,
            candidates,
            from_call_me_maybe: p.cmm_endpoints.clone(),
            last_direct_pong: direct,
            last_discovery: since(p.last_discovery),
            last_active: since(p.last_active),
            relay,
        })
    }

    /// Read-only query of the peer's current route (does not trigger discovery, does not change state), for status display.
    pub fn current_route(&self, peer: NodePublic, now: Duration) -> Route {
        let Some(p) = self.peers.get(&peer) else {
            return Route::None;
        };
        match p.best {
            Some((addr, confirmed))
                if direct_allowed(self.mode, p, addr) && now < confirmed + TRUST =>
            {
                Route::Direct(addr)
            }
            _ => relay_route(p, now)
                .or(p.info.home_region.map(Route::Derp))
                .unwrap_or(Route::None),
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

/// Whether a direct path to `addr` may be used, pinged or answered: always in auto, never in strict;
/// in prefer only for a LAN address or while the peer is in fallback.
fn direct_allowed(mode: Mode, p: &PeerPath, addr: SocketAddr) -> bool {
    match mode {
        Mode::Auto => true,
        Mode::Strict => false,
        Mode::Prefer => is_lan(addr.ip()) || p.prefer.in_fallback(),
    }
}

/// The candidates to ping for a direct path (netmap endpoints, then CallMeMaybe ones, deduplicated)
/// that this mode allows.
fn allowed_candidates(mode: Mode, p: &PeerPath) -> Vec<SocketAddr> {
    let mut candidates: Vec<SocketAddr> = Vec::new();
    for e in p.info.endpoints.iter().chain(&p.cmm_endpoints) {
        if !candidates.contains(e) && direct_allowed(mode, p, *e) {
            candidates.push(*e);
        }
    }
    candidates
}

/// The peer relay route if one is bound and answered within the trust window.
fn relay_route(p: &PeerPath, now: Duration) -> Option<Route> {
    let r = p.relay?;
    let confirmed = r.confirmed?;
    (now < confirmed + TRUST).then_some(Route::PeerRelay {
        server: r.server,
        vni: r.vni,
    })
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
            online: true,
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

    /// Prefer mode with the relays answering: a public candidate is never pinged, by discovery or
    /// by the relay probes, and the route stays on the relay.
    #[test]
    fn prefer_never_initiates_public_direct_while_relays_answer() {
        let mut w = world(vec![PUB.parse().unwrap()]);
        w.a.set_mode(Mode::Prefer);
        for t in 0..=60 {
            let (r, acts) = step(&mut w, t * S, true, true, true);
            assert_eq!(r, Route::Derp(1000), "at {t}s");
            assert!(
                acts.iter().all(|a| matches!(a, Action::Derp { .. })),
                "at {t}s: {acts:?}"
            );
        }
        assert!(!w.a.in_prefer_fallback(w.b_node));
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
            online: true,
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
            online: true,
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
            // Prefer may probe a LAN candidate directly (prefer_probe_pings_only_lan_candidates).
            let ep = if mode == Mode::Strict { E } else { PUB };
            let mut w = world(vec![ep.parse().unwrap()]);
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
                online: true,
            },
            PeerInfo {
                node: c_node,
                disco: c_disco.public(),
                home_region: Some(1000),
                endpoints: vec![],
                online: true,
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

    #[test]
    fn explain_tells_why() {
        let e: SocketAddr = E.parse().unwrap();
        // Never tried: nothing was sent yet.
        let w = world(vec![e]);
        let x = w.a.explain(w.b_node, 10 * S).unwrap();
        assert_eq!(x.route, Route::Derp(1000));
        assert!(x.reason.contains("no direct attempt yet"), "{}", x.reason);
        assert_eq!((x.last_discovery, x.last_active), (None, None));
        // No endpoints at all.
        let mut w = world(vec![]);
        w.a.route(w.b_node, 10 * S, &mut w.rng);
        let x = w.a.explain(w.b_node, 10 * S).unwrap();
        assert!(x.reason.contains("no candidate endpoints"), "{}", x.reason);
        // Candidates, nothing answered yet.
        let mut w = world(vec![e]);
        w.a.route(w.b_node, 10 * S, &mut w.rng);
        let x = w.a.explain(w.b_node, 12 * S).unwrap();
        assert_eq!(x.candidates, vec![e]);
        assert!(
            x.reason.contains("no pong yet from any of 1"),
            "{}",
            x.reason
        );
        assert_eq!(
            (x.last_discovery, x.last_active),
            (Some(2 * S), Some(2 * S))
        );
        // Direct after a pong.
        let acts = w.a.route(w.b_node, 15 * S, &mut w.rng).1;
        let (to, tx_id) = udp_pings(&w, &acts)[0];
        let pong = b_says(&w, &Message::Pong { tx_id, src: to });
        w.a.on_disco(Source::Udp(to), &pong, 15 * S, &mut w.rng);
        let x = w.a.explain(w.b_node, 16 * S).unwrap();
        assert_eq!(x.route, Route::Direct(to));
        assert_eq!(x.last_direct_pong, Some((to, S)));
        assert!(
            x.reason
                .starts_with("direct: pong from 172.29.0.21:41641 1.0s ago"),
            "{}",
            x.reason
        );
        // The direct path went quiet.
        let x = w.a.explain(w.b_node, 30 * S).unwrap();
        assert!(x.reason.contains("stopped answering"), "{}", x.reason);
        // Relay modes.
        w.a.set_mode(Mode::Prefer);
        assert!(
            w.a.explain(w.b_node, 31 * S)
                .unwrap()
                .reason
                .contains("prefer mode")
        );
        w.a.set_mode(Mode::Strict);
        assert!(
            w.a.explain(w.b_node, 31 * S)
                .unwrap()
                .reason
                .contains("strict mode")
        );
        assert_eq!(w.a.explain(NodePublic([9; 32]), S), None);
    }

    #[test]
    fn explain_lists_call_me_maybe_endpoints_after_the_netmap_ones() {
        let e: SocketAddr = E.parse().unwrap();
        let cmm: SocketAddr = "10.10.1.21:41641".parse().unwrap();
        let mut w = world(vec![e]);
        let msg = b_says(
            &w,
            &Message::CallMeMaybe {
                endpoints: vec![e, cmm],
            },
        );
        w.a.on_disco(
            Source::Derp {
                node: w.b_node,
                region: 1000,
            },
            &msg,
            S,
            &mut w.rng,
        );
        let x = w.a.explain(w.b_node, 2 * S).unwrap();
        assert_eq!(x.candidates, vec![e, cmm]);
        assert_eq!(x.from_call_me_maybe, vec![e, cmm]);
    }

    const R: &str = "172.29.0.23:40000";

    fn relay_pings(w: &World, acts: &[Action]) -> Vec<(SocketAddr, u32, [u8; TX_ID_LEN])> {
        acts.iter()
            .filter_map(|a| match a {
                Action::Relay { server, vni, data } => match b_reads(w, data) {
                    Message::Ping { tx_id, .. } => Some((*server, *vni, tx_id)),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    fn relay_pong(w: &mut World, tx_id: [u8; TX_ID_LEN], vni: u32, now: Duration) -> Vec<Action> {
        let pong = b_says(
            w,
            &Message::Pong {
                tx_id,
                src: R.parse().unwrap(),
            },
        );
        w.a.on_disco(
            Source::Relay {
                server: R.parse().unwrap(),
                vni,
            },
            &pong,
            now,
            &mut w.rng,
        )
    }

    /// A bound relay is pinged at once; the route moves to it on the pong and back to DERP when
    /// it stops answering for the trust window.
    #[test]
    fn a_bound_relay_is_confirmed_by_a_pong_and_expires_without_one() {
        let mut w = world(vec![]);
        w.a.route(w.b_node, S, &mut w.rng);
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
        let (r, acts) = w.a.route(w.b_node, 2 * S, &mut w.rng);
        assert_eq!(r, Route::Derp(1000), "not confirmed yet");
        let pings = relay_pings(&w, &acts);
        assert_eq!(pings.len(), 1, "discovery runs at once for a new relay");
        let (server, vni, tx) = pings[0];
        assert_eq!((server, vni), (R.parse().unwrap(), 4));
        assert!(relay_pong(&mut w, tx, 5, 2 * S).is_empty(), "wrong VNI");
        assert_eq!(w.a.current_route(w.b_node, 2 * S), Route::Derp(1000));
        relay_pong(&mut w, tx, 4, 2 * S);
        let relayed = Route::PeerRelay {
            server: R.parse().unwrap(),
            vni: 4,
        };
        assert_eq!(w.a.current_route(w.b_node, 2 * S), relayed);
        assert_eq!(w.a.take_relay_pongs(), vec![w.b_node]);
        assert_eq!(w.a.route(w.b_node, 3 * S, &mut w.rng).0, relayed);
        w.a.tick(2 * S + TRUST, &mut w.rng);
        assert_eq!(
            w.a.current_route(w.b_node, 2 * S + TRUST),
            Route::Derp(1000)
        );
    }

    #[test]
    fn an_active_relay_path_gets_a_heartbeat_every_three_seconds() {
        let mut w = world(vec![]);
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
        let (_, acts) = w.a.route(w.b_node, S, &mut w.rng);
        let tx = relay_pings(&w, &acts)[0].2;
        relay_pong(&mut w, tx, 4, S);
        let early = w.a.tick(S + HEARTBEAT - S / 10, &mut w.rng);
        assert!(relay_pings(&w, &early).is_empty());
        let acts = w.a.tick(S + HEARTBEAT, &mut w.rng);
        assert_eq!(relay_pings(&w, &acts).len(), 1);
        // No traffic for the activity window: no heartbeat.
        let mut idle = world(vec![]);
        idle.a.set_relay(idle.b_node, Some((R.parse().unwrap(), 4)));
        let (_, acts) = idle.a.route(idle.b_node, S, &mut idle.rng);
        let tx = relay_pings(&idle, &acts)[0].2;
        let pong = b_says(
            &idle,
            &Message::Pong {
                tx_id: tx,
                src: R.parse().unwrap(),
            },
        );
        idle.a.on_disco(
            Source::Relay {
                server: R.parse().unwrap(),
                vni: 4,
            },
            &pong,
            S + ACTIVE_WINDOW,
            &mut idle.rng,
        );
        let late = idle.a.tick(S + ACTIVE_WINDOW + HEARTBEAT, &mut idle.rng);
        assert!(relay_pings(&idle, &late).is_empty());
    }

    #[test]
    fn a_direct_path_is_preferred_over_the_relay() {
        let mut w = world(vec![E.parse().unwrap()]);
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
        let (_, acts) = w.a.route(w.b_node, S, &mut w.rng);
        let rtx = relay_pings(&w, &acts)[0].2;
        let (_, dtx) = udp_pings(&w, &acts)[0];
        relay_pong(&mut w, rtx, 4, S);
        let pong = b_says(
            &w,
            &Message::Pong {
                tx_id: dtx,
                src: E.parse().unwrap(),
            },
        );
        w.a.on_disco(Source::Udp(E.parse().unwrap()), &pong, S, &mut w.rng);
        assert_eq!(
            w.a.current_route(w.b_node, S),
            Route::Direct(E.parse().unwrap())
        );
    }

    /// strict and prefer rule out direct paths, not the peer relay (OBS-20261010-peer-relay-behavior).
    #[test]
    fn strict_and_prefer_use_the_relay_and_answer_pings_through_it() {
        for mode in [Mode::Strict, Mode::Prefer] {
            // Prefer pings a LAN candidate directly (prefer_uses_lan_best_without_fallback).
            let ep = if mode == Mode::Strict { E } else { PUB };
            let mut w = world(vec![ep.parse().unwrap()]);
            w.a.set_mode(mode);
            w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
            let (_, acts) = w.a.route(w.b_node, S, &mut w.rng);
            assert!(udp_pings(&w, &acts).is_empty(), "{mode:?}: no direct pings");
            let tx = relay_pings(&w, &acts)[0].2;
            relay_pong(&mut w, tx, 4, S);
            assert_eq!(
                w.a.current_route(w.b_node, S),
                Route::PeerRelay {
                    server: R.parse().unwrap(),
                    vni: 4
                },
                "{mode:?}"
            );
            // A ping from the peer through the relay is answered through the relay.
            let ping = b_says(
                &w,
                &Message::Ping {
                    tx_id: [5; TX_ID_LEN],
                    node_key: w.b_node,
                },
            );
            let acts = w.a.on_disco(
                Source::Relay {
                    server: R.parse().unwrap(),
                    vni: 4,
                },
                &ping,
                S,
                &mut w.rng,
            );
            match acts.as_slice() {
                [
                    Action::Relay {
                        server,
                        vni: 4,
                        data,
                    },
                ] => {
                    assert_eq!(*server, R.parse().unwrap());
                    assert!(
                        matches!(b_reads(&w, data), Message::Pong { tx_id, src } if tx_id == [5; TX_ID_LEN] && src == R.parse().unwrap())
                    );
                }
                other => panic!("{mode:?}: {other:?}"),
            }
        }
        // strict still drops disco over plain UDP.
        let mut w = world(vec![E.parse().unwrap()]);
        w.a.set_mode(Mode::Strict);
        let ping = b_says(
            &w,
            &Message::Ping {
                tx_id: [5; TX_ID_LEN],
                node_key: w.b_node,
            },
        );
        assert!(
            w.a.on_disco(Source::Udp(E.parse().unwrap()), &ping, S, &mut w.rng)
                .is_empty()
        );
    }

    #[test]
    fn probe_pings_through_the_relay_too() {
        let mut w = world(vec![]);
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
        let acts = w.a.probe(w.b_node, S, &mut w.rng);
        let tx = relay_pings(&w, &acts)[0].2;
        relay_pong(&mut w, tx, 4, S + S / 100);
        let results = w.a.take_probe_results();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].via,
            Route::PeerRelay {
                server: R.parse().unwrap(),
                vni: 4
            }
        );
        assert_eq!(results[0].latency, S / 100);
    }

    #[test]
    fn relay_endpoint_lookup_and_replacement() {
        let mut w = world(vec![]);
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
        assert_eq!(w.a.peer_for_relay(R.parse().unwrap(), 4), Some(w.b_node));
        assert_eq!(w.a.peer_for_relay(R.parse().unwrap(), 5), None);
        let (_, acts) = w.a.route(w.b_node, S, &mut w.rng);
        let tx = relay_pings(&w, &acts)[0].2;
        relay_pong(&mut w, tx, 4, S);
        // Setting the same endpoint again keeps it confirmed; a new one starts unconfirmed.
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
        assert!(matches!(
            w.a.current_route(w.b_node, S),
            Route::PeerRelay { vni: 4, .. }
        ));
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 9)));
        assert_eq!(w.a.current_route(w.b_node, S), Route::Derp(1000));
        w.a.set_relay(w.b_node, None);
        assert_eq!(w.a.peer_for_relay(R.parse().unwrap(), 9), None);
    }

    #[test]
    fn explain_names_the_relay() {
        let mut w = world(vec![]);
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
        let (_, acts) = w.a.route(w.b_node, S, &mut w.rng);
        let tx = relay_pings(&w, &acts)[0].2;
        relay_pong(&mut w, tx, 4, S);
        let e = w.a.explain(w.b_node, 2 * S).unwrap();
        assert!(
            e.reason
                .starts_with("peer relay: pong via 172.29.0.23:40000 vni 4 1.0s ago"),
            "{}",
            e.reason
        );
        assert_eq!(e.relay, Some((R.parse().unwrap(), 4, Some(S))));
    }

    /// A pong for a ping sent before the relay endpoint changed must not confirm the new endpoint.
    #[test]
    fn a_late_pong_does_not_confirm_a_replaced_relay() {
        let mut w = world(vec![]);
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
        let (_, acts) = w.a.route(w.b_node, S, &mut w.rng);
        let tx = relay_pings(&w, &acts)[0].2;
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 9)));
        relay_pong(&mut w, tx, 4, S);
        assert_eq!(w.a.current_route(w.b_node, S), Route::Derp(1000));
    }

    /// Boundaries: the relay is trusted strictly less than TRUST after its pong, and gets a heartbeat
    /// only while the last traffic is strictly less than ACTIVE_WINDOW old.
    #[test]
    fn relay_trust_and_activity_boundaries() {
        let mut w = world(vec![]);
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
        let (_, acts) = w.a.route(w.b_node, S, &mut w.rng);
        let tx = relay_pings(&w, &acts)[0].2;
        relay_pong(&mut w, tx, 4, S);
        assert!(matches!(
            w.a.current_route(w.b_node, S + TRUST - S / 1000),
            Route::PeerRelay { .. }
        ));
        assert_eq!(w.a.current_route(w.b_node, S + TRUST), Route::Derp(1000));

        let mut w = world(vec![]);
        w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
        w.a.route(w.b_node, S, &mut w.rng); // last traffic at 1 s
        // Confirmed 4 s before the activity window ends (a probe does not count as traffic), so trust
        // and heartbeat timing are not the limit.
        let edge = S + ACTIVE_WINDOW;
        let acts = w.a.probe(w.b_node, edge - 4 * S, &mut w.rng);
        let tx = relay_pings(&w, &acts)[0].2;
        relay_pong(&mut w, tx, 4, edge - 4 * S);
        assert!(
            matches!(w.a.current_route(w.b_node, edge), Route::PeerRelay { .. }),
            "still trusted"
        );
        let at_edge = w.a.tick(S + ACTIVE_WINDOW, &mut w.rng);
        assert!(
            relay_pings(&w, &at_edge).is_empty(),
            "last traffic exactly ACTIVE_WINDOW ago"
        );
    }

    // ---- prefer relay: direct only on the LAN, or once the relays went silent ----

    /// A public (non-LAN) endpoint of b.
    const PUB: &str = "203.0.113.7:41641";

    fn prefer_world(endpoints: Vec<SocketAddr>) -> World {
        let mut w = world(endpoints);
        w.a.set_mode(Mode::Prefer);
        w
    }

    /// b answers every ping in `acts` over the paths that work.
    fn answer(w: &mut World, acts: &[Action], now: Duration, udp: bool, derp: bool, relay: bool) {
        for a in acts {
            let (from, data) = match a {
                Action::Udp { to, data } if udp => (Source::Udp(*to), data),
                Action::Derp { region, data, .. } if derp => (via_derp(w, *region), data),
                Action::Relay { server, vni, data } if relay => (
                    Source::Relay {
                        server: *server,
                        vni: *vni,
                    },
                    data,
                ),
                _ => continue,
            };
            if let Message::Ping { tx_id, .. } = b_reads(w, data) {
                let pong = pong(w, tx_id);
                w.a.on_disco(from, &pong, now, &mut w.rng);
            }
        }
    }

    /// One moment of a flow from a to b: tick, then send data; b answers on the working paths.
    fn step(
        w: &mut World,
        t: Duration,
        udp: bool,
        derp: bool,
        relay: bool,
    ) -> (Route, Vec<Action>) {
        let mut acts = w.a.tick(t, &mut w.rng);
        let (route, more) = w.a.route(w.b_node, t, &mut w.rng);
        acts.extend(more);
        answer(w, &acts, t, udp, derp, relay);
        (route, acts)
    }

    fn ping_from_b(w: &World, tx: u8) -> Vec<u8> {
        b_says(
            w,
            &Message::Ping {
                tx_id: [tx; TX_ID_LEN],
                node_key: w.b_node,
            },
        )
    }

    fn udp_targets(w: &World, acts: &[Action]) -> Vec<SocketAddr> {
        udp_pings(w, acts).into_iter().map(|p| p.0).collect()
    }

    #[test]
    fn prefer_uses_lan_best_without_fallback() {
        let e: SocketAddr = E.parse().unwrap();
        let mut w = prefer_world(vec![e]);
        let (r, acts) = w.a.route(w.b_node, 10 * S, &mut w.rng);
        assert_eq!(r, Route::Derp(1000));
        assert_eq!(
            udp_targets(&w, &acts),
            vec![e],
            "the LAN candidate is pinged"
        );
        answer(&mut w, &acts, 10 * S, true, false, false);
        assert_eq!(w.a.route(w.b_node, 11 * S, &mut w.rng).0, Route::Direct(e));
        assert_eq!(w.a.current_route(w.b_node, 11 * S), Route::Direct(e));
        assert!(!w.a.in_prefer_fallback(w.b_node));
        // The LAN path gets heartbeats like in auto.
        let hb = w.a.tick(13 * S, &mut w.rng);
        assert!(udp_targets(&w, &hb).contains(&e), "{hb:?}");
    }

    #[test]
    fn prefer_ignores_public_best_until_fallback() {
        let public: SocketAddr = PUB.parse().unwrap();
        let mut w = prefer_world(vec![public]);
        // The relays are silent from the start; b would answer direct pings.
        for t in 0..15 {
            let (r, acts) = step(&mut w, t * S, true, false, false);
            assert_eq!(r, Route::Derp(1000), "at {t}s");
            assert!(udp_targets(&w, &acts).is_empty(), "at {t}s: {acts:?}");
            assert!(!w.a.in_prefer_fallback(w.b_node), "at {t}s");
        }
        // 15 s active without any relay pong: fallback, and discovery runs at once.
        let (_, acts) = step(&mut w, 15 * S, true, false, false);
        assert!(w.a.in_prefer_fallback(w.b_node));
        assert_eq!(udp_targets(&w, &acts), vec![public]);
        assert_eq!(
            w.a.take_prefer_events(),
            vec![PreferEvent::Entered {
                peer: w.b_node,
                no_relay_path: false
            }]
        );
        assert_eq!(
            w.a.route(w.b_node, 16 * S, &mut w.rng).0,
            Route::Direct(public)
        );
    }

    /// With no home region and no peer relay there is nothing to probe: the peer falls back once it
    /// has been active for the dead-relay time, and the event says why.
    #[test]
    fn prefer_without_any_relay_path_falls_back() {
        let mut w = prefer_world(vec![PUB.parse().unwrap()]);
        w.a.set_peers(vec![PeerInfo {
            node: w.b_node,
            disco: w.b_disco.public(),
            home_region: None,
            endpoints: vec![PUB.parse().unwrap()],
            online: true,
        }]);
        for t in 0..15 {
            step(&mut w, t * S, false, false, false);
        }
        assert!(!w.a.in_prefer_fallback(w.b_node));
        step(&mut w, 15 * S, false, false, false);
        assert_eq!(
            w.a.take_prefer_events(),
            vec![PreferEvent::Entered {
                peer: w.b_node,
                no_relay_path: true
            }]
        );
    }

    #[test]
    fn prefer_public_ping_ignored_but_marks_active() {
        let public: SocketAddr = PUB.parse().unwrap();
        let mut w = prefer_world(vec![public]);
        assert!(w.a.tick(10 * S, &mut w.rng).is_empty(), "idle: no probe");
        let ping = ping_from_b(&w, 6);
        assert!(
            w.a.on_disco(Source::Udp(public), &ping, 10 * S, &mut w.rng)
                .is_empty(),
            "not answered"
        );
        // The ping made the peer active: the relays are probed.
        let acts = w.a.tick(10 * S, &mut w.rng);
        assert_eq!(derp_pings(&w, &acts).len(), 1, "{acts:?}");
        assert!(udp_pings(&w, &acts).is_empty());
        assert_eq!(w.a.current_route(w.b_node, 10 * S), Route::Derp(1000));
    }

    #[test]
    fn prefer_lan_ping_answered() {
        let lan: SocketAddr = E.parse().unwrap();
        let mut w = prefer_world(vec![]);
        let acts =
            w.a.on_disco(Source::Udp(lan), &ping_from_b(&w, 6), S, &mut w.rng);
        let [Action::Udp { to, data }] = acts.as_slice() else {
            panic!("{acts:?}")
        };
        assert_eq!(*to, lan);
        assert_eq!(
            b_reads(&w, data),
            Message::Pong {
                tx_id: [6; TX_ID_LEN],
                src: lan
            }
        );
    }

    #[test]
    fn prefer_records_call_me_maybe() {
        let public: SocketAddr = PUB.parse().unwrap();
        let lan: SocketAddr = "192.168.7.2:41641".parse().unwrap();
        let mut w = prefer_world(vec![]);
        let cmm = b_says(
            &w,
            &Message::CallMeMaybe {
                endpoints: vec![public, lan],
            },
        );
        let acts = w.a.on_disco(via_derp(&w, 1000), &cmm, S, &mut w.rng);
        assert_eq!(udp_targets(&w, &acts), vec![lan], "only the LAN one now");
        assert_eq!(
            w.a.explain(w.b_node, S).unwrap().from_call_me_maybe,
            vec![public, lan]
        );
        // The CallMeMaybe made the peer active at 1 s; discovery skips the public candidate until
        // the relays have been silent for 15 s, then pings it too.
        for t in 2..16 {
            let (_, acts) = step(&mut w, t * S, false, false, false);
            assert!(!udp_targets(&w, &acts).contains(&public), "at {t}s");
        }
        let (_, acts) = step(&mut w, 16 * S, false, false, false);
        assert!(w.a.in_prefer_fallback(w.b_node));
        let mut got = udp_targets(&w, &acts);
        got.sort();
        let mut want = vec![public, lan];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn prefer_sends_call_me_maybe_like_auto() {
        let mine: SocketAddr = "198.51.100.1:41641".parse().unwrap();
        let mut w = prefer_world(vec![PUB.parse().unwrap()]);
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
    fn prefer_probe_pings_only_lan_candidates() {
        let lan: SocketAddr = E.parse().unwrap();
        let mut w = prefer_world(vec![lan, PUB.parse().unwrap()]);
        let acts = w.a.probe(w.b_node, 10 * S, &mut w.rng);
        assert_eq!(udp_targets(&w, &acts), vec![lan]);
        assert_eq!(derp_pings(&w, &acts).len(), 1);
    }

    /// Leaving fallback drops a public direct path but keeps a LAN one.
    #[test]
    fn prefer_exit_drops_only_public_best() {
        for (ep, kept) in [(PUB, false), (E, true)] {
            let ep: SocketAddr = ep.parse().unwrap();
            let mut w = prefer_world(vec![ep]);
            // Relays silent until 20 s (fallback at 15 s); the direct path answers throughout.
            for t in 0..20 {
                step(&mut w, t * S, true, false, false);
            }
            assert!(w.a.in_prefer_fallback(w.b_node), "{ep}");
            assert_eq!(w.a.current_route(w.b_node, 19 * S), Route::Direct(ep));
            // Relays answer from 20 s. The probes run at 1, 6, …, 21, … (the flow became active
            // at 0 s, after that tick), so the steady pongs start at 21 s and last 30 s by 51 s.
            for t in 20..51 {
                step(&mut w, t * S, true, true, true);
                assert!(w.a.in_prefer_fallback(w.b_node), "{ep} at {t}s");
            }
            w.a.take_prefer_events();
            let (r, _) = step(&mut w, 51 * S, true, true, true);
            assert!(!w.a.in_prefer_fallback(w.b_node), "{ep}");
            assert_eq!(
                w.a.take_prefer_events(),
                vec![PreferEvent::Exited {
                    peer: w.b_node,
                    after: 36 * S
                }]
            );
            if kept {
                assert_eq!(r, Route::Direct(ep));
                assert_eq!(w.a.current_route(w.b_node, 52 * S), Route::Direct(ep));
            } else {
                assert_eq!(r, Route::Derp(1000));
                assert_eq!(w.a.current_route(w.b_node, 51 * S), Route::Derp(1000));
                // And the public candidate is no longer pinged, nor its pings answered.
                let (_, acts) = step(&mut w, 55 * S, true, true, true);
                assert!(udp_pings(&w, &acts).is_empty(), "{acts:?}");
                assert!(
                    w.a.on_disco(Source::Udp(ep), &ping_from_b(&w, 9), 56 * S, &mut w.rng)
                        .is_empty()
                );
            }
        }
    }

    /// Pongs through the cloud relay and through the peer relay both count as "the relays answer".
    #[test]
    fn prefer_relay_pong_feeds_state_machine() {
        for via_peer_relay in [false, true] {
            let mut w = prefer_world(vec![PUB.parse().unwrap()]);
            if via_peer_relay {
                w.a.set_relay(w.b_node, Some((R.parse().unwrap(), 4)));
            }
            // Active from 0 s (after that tick), so the probes run at 1, 6, 11, …; one relay pong,
            // at 6 s: fallback 15 s later, at 21 s (not 15 s).
            for t in 0..21 {
                let answers = t == 6;
                step(
                    &mut w,
                    t * S,
                    false,
                    answers && !via_peer_relay,
                    answers && via_peer_relay,
                );
                assert!(
                    !w.a.in_prefer_fallback(w.b_node),
                    "peer relay {via_peer_relay}: at {t}s"
                );
            }
            step(&mut w, 21 * S, false, false, false);
            assert!(
                w.a.in_prefer_fallback(w.b_node),
                "peer relay {via_peer_relay}"
            );
        }
    }

    /// An auto peer pings our public address while the relays work: never answered, and its pings
    /// do not push us into fallback (the relay probes they trigger are answered).
    #[test]
    fn prefer_auto_peer_public_ping_ignored() {
        let public: SocketAddr = PUB.parse().unwrap();
        let mut w = prefer_world(vec![public]);
        for t in 0..=60u8 {
            let now = u32::from(t) * S;
            let ping = ping_from_b(&w, t);
            assert!(
                w.a.on_disco(Source::Udp(public), &ping, now, &mut w.rng)
                    .is_empty(),
                "at {t}s"
            );
            let acts = w.a.tick(now, &mut w.rng);
            answer(&mut w, &acts, now, false, true, true);
            assert!(!w.a.in_prefer_fallback(w.b_node), "at {t}s");
        }
    }

    /// An offline peer never makes us fall back; once it is online again the relay clock restarts.
    #[test]
    fn prefer_offline_peer_does_not_fall_back() {
        let mut w = prefer_world(vec![PUB.parse().unwrap()]);
        let info = |online| PeerInfo {
            node: w.b_node,
            disco: w.b_disco.public(),
            home_region: Some(1000),
            endpoints: vec![PUB.parse().unwrap()],
            online,
        };
        let (offline, online) = (info(false), info(true));
        w.a.set_peers(vec![offline]);
        for t in 0..30 {
            step(&mut w, t * S, false, false, false);
            assert!(!w.a.in_prefer_fallback(w.b_node), "at {t}s");
        }
        w.a.set_peers(vec![online]);
        for t in 30..45 {
            step(&mut w, t * S, false, false, false);
            assert!(!w.a.in_prefer_fallback(w.b_node), "at {t}s");
        }
        step(&mut w, 45 * S, false, false, false);
        assert!(w.a.in_prefer_fallback(w.b_node));
    }

    /// Received data counts as activity: a peer that only receives still probes the relays.
    #[test]
    fn prefer_received_data_marks_active() {
        let mut w = prefer_world(vec![PUB.parse().unwrap()]);
        assert!(w.a.tick(10 * S, &mut w.rng).is_empty());
        w.a.note_received(w.b_node, 10 * S);
        let acts = w.a.tick(10 * S, &mut w.rng);
        assert_eq!(derp_pings(&w, &acts).len(), 1);
    }

    /// Strict mode keeps none of this: no probes, never a fallback, even with silent relays.
    #[test]
    fn strict_never_falls_back() {
        let mut w = world(vec![PUB.parse().unwrap()]);
        w.a.set_mode(Mode::Strict);
        for t in 0..=60 {
            let (r, acts) = step(&mut w, t * S, true, false, false);
            assert_eq!(r, Route::Derp(1000));
            assert!(udp_pings(&w, &acts).is_empty());
            assert!(!w.a.in_prefer_fallback(w.b_node));
        }
        assert!(w.a.take_prefer_events().is_empty());
    }

    /// Two nodes that only reach each other over UDP between their public addresses.
    struct Net {
        a_addr: SocketAddr,
        b_addr: SocketAddr,
        ra: Counter,
        rb: Counter,
        first_ping_to_b: Option<Duration>,
    }

    impl Net {
        /// Deliver the UDP actions (and the replies they cause); everything over DERP or the peer
        /// relay is lost. `from_a` names the sender of `acts`.
        fn deliver(
            &mut self,
            a: &mut PathSock,
            b: &mut PathSock,
            acts: Vec<Action>,
            from_a: bool,
            now: Duration,
        ) {
            let mut queue: Vec<(bool, Action)> = acts.into_iter().map(|x| (from_a, x)).collect();
            while let Some((from_a, act)) = queue.pop() {
                let Action::Udp { to, data } = act else {
                    continue;
                };
                let replies = if from_a && to == self.b_addr {
                    self.first_ping_to_b.get_or_insert(now);
                    b.on_disco(Source::Udp(self.a_addr), &data, now, &mut self.rb)
                } else if !from_a && to == self.a_addr {
                    a.on_disco(Source::Udp(self.b_addr), &data, now, &mut self.ra)
                } else {
                    continue;
                };
                queue.extend(replies.into_iter().map(|x| (!from_a, x)));
            }
        }
    }

    /// Two prefer-mode nodes, both relays down, only UDP between their public addresses. A sends, B
    /// only receives (Review Focus 1): A falls back after 15 s, B within 15 s of A's first public
    /// ping, and then A reaches B directly.
    #[test]
    fn prefer_silent_relay_falls_back_end_to_end() {
        let a_disco = DiscoPrivate::generate().unwrap();
        let b_disco = DiscoPrivate::generate().unwrap();
        let (a_node, b_node) = (NodePublic([1; 32]), NodePublic([2; 32]));
        let a_addr: SocketAddr = "198.51.100.1:41641".parse().unwrap();
        let b_addr: SocketAddr = PUB.parse().unwrap();
        let node =
            |me: &DiscoPrivate, my_node, my_addr, peer, peer_disco: &DiscoPrivate, peer_addr| {
                let mut s = PathSock::new(me.clone(), my_node);
                s.set_mode(Mode::Prefer);
                s.set_my_endpoints(vec![my_addr]);
                s.set_peers(vec![PeerInfo {
                    node: peer,
                    disco: peer_disco.public(),
                    home_region: Some(1000),
                    endpoints: vec![peer_addr],
                    online: true,
                }]);
                s
            };
        let mut a = node(&a_disco, a_node, a_addr, b_node, &b_disco, b_addr);
        let mut b = node(&b_disco, b_node, b_addr, a_node, &a_disco, a_addr);
        let mut net = Net {
            a_addr,
            b_addr,
            ra: Counter(0),
            rb: Counter(100),
            first_ping_to_b: None,
        };
        let (mut a_fb, mut b_fb, mut direct) = (None, None, None);
        for t in 0..=45 {
            let now = t * S;
            let acts = a.tick(now, &mut net.ra);
            net.deliver(&mut a, &mut b, acts, true, now);
            let acts = b.tick(now, &mut net.rb);
            net.deliver(&mut a, &mut b, acts, false, now);
            let (r, acts) = a.route(b_node, now, &mut net.ra);
            net.deliver(&mut a, &mut b, acts, true, now);
            if a.in_prefer_fallback(b_node) {
                a_fb.get_or_insert(now);
            }
            if b.in_prefer_fallback(a_node) {
                b_fb.get_or_insert(now);
            }
            if matches!(r, Route::Direct(_)) {
                direct.get_or_insert(now);
            } else {
                assert_eq!(r, Route::Derp(1000), "at {t}s");
            }
        }
        let first_ping_to_b = net.first_ping_to_b;
        let a_fb = a_fb.expect("A falls back");
        let b_fb = b_fb.expect("B falls back");
        let first = first_ping_to_b.expect("A pings B directly");
        let direct = direct.expect("A goes direct");
        // A: active from 0 s, relays silent ⇒ fallback at 15 s, and its first public ping then.
        assert_eq!((a_fb, first), (15 * S, 15 * S));
        assert!(first >= a_fb, "no public ping before A's fallback");
        // B: active from that ping, falls back 15 s later and answers A's next discovery round.
        assert!(b_fb <= first + 15 * S, "B fell back at {b_fb:?}");
        assert_eq!(b_fb, 30 * S);
        assert_eq!(direct, 31 * S, "direct right after B answers");
        assert_eq!(a.current_route(b_node, 45 * S), Route::Direct(b_addr));
    }
}
