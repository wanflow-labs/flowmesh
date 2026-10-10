// SPDX-License-Identifier: Apache-2.0
//! Peer relay client (docs/protocol/peer-relay.md), sans-IO: which allocation requests, forwards and
//! handshake messages to send, and when, for each peer that needs a relay. The caller seals and sends
//! the returned actions, feeds back the relay messages it receives, reports traffic and the relay
//! path's liveness, and drives time with `tick`.

use flowmesh_disco::message::Message;
use flowmesh_disco::relay::{Alloc, BindBody, CHALLENGE_LEN, sorted_pair};
use flowmesh_proto::key::{DiscoPublic, NodePublic};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

/// Rounds of allocation requests while a pair needs a relay (OBS-20261010-peer-relay-alloc-request).
pub const ROUND_INTERVAL: Duration = Duration::from_secs(30);
/// Each request and each forward is sent a second time after this delay, unchanged (same source).
pub const REPEAT_DELAY: Duration = Duration::from_secs(3);
/// A pair needs a relay only while it has had traffic this recently (disco.md §3 activity window).
pub const ACTIVE_WINDOW: Duration = Duration::from_secs(45);
/// Bind is retransmitted at this interval until a Challenge arrives, at most `BIND_TRIES` times.
pub const BIND_RETRY: Duration = Duration::from_secs(1);
pub const BIND_TRIES: u32 = 5;
/// A bound relay path counts as working while a disco pong came through it this recently (disco.md §3).
pub const TRUST: Duration = Duration::from_millis(6500);

/// A peer offering to relay: granted `cap/relay` by the control server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub node: NodePublic,
    pub disco: DiscoPublic,
    pub home_region: Option<u32>,
}

/// The peer a relay is wanted for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub node: NodePublic,
    pub disco: DiscoPublic,
    pub home_region: Option<u32>,
}

/// What to send. The caller seals `msg` with its disco key to `to_disco`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAction {
    /// A disco message over DERP: allocation requests to candidates, forwards to the peer.
    Derp {
        to: NodePublic,
        to_disco: DiscoPublic,
        region: u32,
        msg: Message,
    },
    /// A handshake message to the relay server, in a Geneve header with the O bit and `vni`.
    Server {
        addr: SocketAddr,
        vni: u32,
        to_disco: DiscoPublic,
        msg: Message,
    },
}

/// A usable relay path to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub vni: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Bind {
    /// Bind sent `tries` times, the last at `last`.
    Sent {
        generation: u32,
        tries: u32,
        last: Duration,
    },
    /// Challenge answered: the path may carry traffic. `confirmed` is the last pong through it.
    Bound {
        generation: u32,
        since: Duration,
        confirmed: Option<Duration>,
    },
}

#[derive(Debug, Clone)]
struct PeerState {
    peer: Peer,
    last_wanted: Duration,
    /// Next allocation round; `None` until the first `want`.
    next_round: Option<Duration>,
    /// Requests of the last round still to be repeated: (when, candidate, counter).
    repeats: Vec<(Duration, usize, u32)>,
    alloc: Option<Alloc>,
    /// Forward still to be repeated.
    forward_repeat: Option<Duration>,
    bind: Option<Bind>,
}

/// The peer relay client for all peers of this node.
#[derive(Debug, Clone)]
pub struct RelayClient {
    me: DiscoPublic,
    candidates: Vec<Candidate>,
    peers: HashMap<DiscoPublic, PeerState>,
    counter: u32,
    generation: u32,
}

impl RelayClient {
    pub fn new(me: DiscoPublic) -> Self {
        Self {
            me,
            candidates: Vec::new(),
            peers: HashMap::new(),
            counter: 0,
            generation: 0,
        }
    }

    /// Candidate relay servers (from the netmap's CapGrant). This node and the peer itself are skipped
    /// when sending requests.
    pub fn set_candidates(&mut self, candidates: Vec<Candidate>) {
        self.candidates = candidates;
    }

    /// The pair has traffic and no direct path: a relay is wanted. Called for every packet or tick
    /// with traffic; cheap when nothing is due.
    pub fn want(&mut self, peer: &Peer, now: Duration) -> Vec<RelayAction> {
        let st = self.peers.entry(peer.disco).or_insert_with(|| PeerState {
            peer: peer.clone(),
            last_wanted: now,
            next_round: None,
            repeats: Vec::new(),
            alloc: None,
            forward_repeat: None,
            bind: None,
        });
        st.peer = peer.clone();
        st.last_wanted = now;
        if st.next_round.is_none() {
            st.next_round = Some(now);
        }
        self.tick(now)
    }

    /// A disco pong arrived from `peer` through its relay path.
    pub fn on_relay_pong(&mut self, peer: &DiscoPublic, now: Duration) {
        if let Some(PeerState {
            bind: Some(Bind::Bound { confirmed, .. }),
            ..
        }) = self.peers.get_mut(peer)
        {
            *confirmed = Some(now);
        }
    }

    /// The usable relay path to `peer`: bound, and not known to have stopped answering.
    pub fn endpoint(&self, peer: &DiscoPublic) -> Option<Endpoint> {
        let st = self.peers.get(peer)?;
        let a = st.alloc.as_ref()?;
        match st.bind {
            Some(Bind::Bound { .. }) => Some(Endpoint {
                addr: *a.addrs.first()?,
                vni: a.vni,
            }),
            _ => None,
        }
    }

    /// A relay disco message received over DERP from the node with disco key `from`.
    pub fn on_derp(
        &mut self,
        from: &DiscoPublic,
        msg: &Message,
        now: Duration,
    ) -> Vec<RelayAction> {
        let me = self.me;
        match msg {
            // A server's answer to our request: keep the first one for a pair we have no allocation for.
            Message::AllocateResponse { alloc, .. } => {
                if !self.candidates.iter().any(|c| c.disco == *from) {
                    return Vec::new();
                }
                let Some(peer) = other_member(&alloc.pair, &me) else {
                    return Vec::new();
                };
                let Some(st) = self.peers.get_mut(&peer) else {
                    return Vec::new();
                };
                if st.alloc.is_some() {
                    return Vec::new();
                }
                st.alloc = Some(alloc.clone());
                st.repeats.clear();
                st.forward_repeat = Some(now + REPEAT_DELAY);
                let mut out = forward(st);
                out.extend(self.start_bind(&peer, now));
                out
            }
            // The peer forwards an allocation it got: bind to it unless already bound to the same one.
            Message::CallMeMaybeVia(alloc) => {
                if alloc.pair != sorted_pair(me, *from) {
                    return Vec::new();
                }
                let st = self.peers.entry(*from).or_insert_with(|| PeerState {
                    peer: Peer {
                        node: NodePublic::default(),
                        disco: *from,
                        home_region: None,
                    },
                    last_wanted: now,
                    next_round: None,
                    repeats: Vec::new(),
                    alloc: None,
                    forward_repeat: None,
                    bind: None,
                });
                let same = st
                    .alloc
                    .as_ref()
                    .is_some_and(|a| a.server == alloc.server && a.vni == alloc.vni);
                if same && st.bind.is_some() {
                    return Vec::new();
                }
                st.alloc = Some(alloc.clone());
                st.repeats.clear();
                self.start_bind(from, now)
            }
            _ => Vec::new(),
        }
    }

    /// A handshake message received from a relay server on the relayed path.
    pub fn on_server(&mut self, vni: u32, msg: &Message, now: Duration) -> Vec<RelayAction> {
        let Message::Challenge(ch) = msg else {
            return Vec::new();
        };
        if ch.vni != vni {
            return Vec::new();
        }
        let Some(st) = self.peers.get_mut(&ch.remote) else {
            return Vec::new();
        };
        let (Some(a), Some(Bind::Sent { generation, .. })) = (st.alloc.as_ref(), st.bind.as_ref())
        else {
            return Vec::new();
        };
        if a.vni != vni || *generation != ch.generation {
            return Vec::new();
        }
        let Some(&addr) = a.addrs.first() else {
            return Vec::new();
        };
        let answer = RelayAction::Server {
            addr,
            vni,
            to_disco: a.server,
            msg: Message::Answer(ch.clone()),
        };
        st.bind = Some(Bind::Bound {
            generation: ch.generation,
            since: now,
            confirmed: None,
        });
        vec![answer]
    }

    /// Repeats, rounds, bind retries and re-binds that are due.
    pub fn tick(&mut self, now: Duration) -> Vec<RelayAction> {
        let mut out = Vec::new();
        let keys: Vec<DiscoPublic> = self.peers.keys().copied().collect();
        for key in keys {
            out.extend(self.tick_peer(&key, now));
        }
        out
    }

    fn tick_peer(&mut self, key: &DiscoPublic, now: Duration) -> Vec<RelayAction> {
        let mut out = Vec::new();
        let candidates = self.candidates.clone();
        let me = self.me;
        let Some(st) = self.peers.get_mut(key) else {
            return out;
        };
        let wanted = now.saturating_sub(st.last_wanted) < ACTIVE_WINDOW;

        // Second copies of the last round's requests.
        let round_due = wanted && st.alloc.is_none() && st.next_round.is_some_and(|t| t <= now);
        // A due round replaces them, and an idle pair needs none.
        if round_due || !wanted {
            st.repeats.clear();
        }
        let (due, later): (Vec<_>, Vec<_>) = st.repeats.drain(..).partition(|(t, ..)| *t <= now);
        st.repeats = later;
        for (_, i, counter) in due {
            if let Some(c) = candidates.get(i) {
                out.extend(request(c, &st.peer, me, counter));
            }
        }
        // Second copy of the forward.
        if st.forward_repeat.is_some_and(|t| t <= now) {
            st.forward_repeat = None;
            out.extend(forward(st));
        }

        // A bound path that stopped answering while the pair still has traffic: bind again; a bind
        // that got no challenge after all tries: give the allocation up and request a new one.
        let mut rebind = false;
        match st.bind {
            Some(Bind::Bound {
                since, confirmed, ..
            }) if wanted => {
                let last = confirmed.unwrap_or(since);
                if now.saturating_sub(last) >= TRUST {
                    rebind = true;
                }
            }
            Some(Bind::Sent { tries, last, .. }) if now.saturating_sub(last) >= BIND_RETRY => {
                if tries >= BIND_TRIES {
                    st.alloc = None;
                    st.bind = None;
                    st.next_round = Some(now);
                } else if let Some(m) = bind_message(st) {
                    if let Some(Bind::Sent { tries, last, .. }) = st.bind.as_mut() {
                        *tries += 1;
                        *last = now;
                    }
                    out.push(m);
                }
            }
            _ => {}
        }
        if rebind {
            out.extend(self.start_bind(key, now));
            return out;
        }

        // Allocation rounds while wanted and without an allocation.
        let Some(st) = self.peers.get_mut(key) else {
            return out;
        };
        if wanted && st.alloc.is_none() && st.next_round.is_some_and(|t| t <= now) {
            st.next_round = Some(now + ROUND_INTERVAL);
            for (i, c) in candidates.iter().enumerate() {
                if c.disco == me || c.disco == st.peer.disco || c.home_region.is_none() {
                    continue;
                }
                self.counter = self.counter.wrapping_add(1).max(1);
                let counter = self.counter;
                out.extend(request(c, &st.peer, me, counter));
                st.repeats.push((now + REPEAT_DELAY, i, counter));
            }
        }
        out
    }

    /// Send Bind with a new generation for the peer's allocation.
    fn start_bind(&mut self, key: &DiscoPublic, now: Duration) -> Vec<RelayAction> {
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        let Some(st) = self.peers.get_mut(key) else {
            return Vec::new();
        };
        st.bind = Some(Bind::Sent {
            generation,
            tries: 1,
            last: now,
        });
        bind_message(st).into_iter().collect()
    }
}

/// The member of `pair` that is not `me`, if `me` is in it.
fn other_member(pair: &[DiscoPublic; 2], me: &DiscoPublic) -> Option<DiscoPublic> {
    match pair {
        [a, b] if a == me => Some(*b),
        [a, b] if b == me => Some(*a),
        _ => None,
    }
}

fn request(c: &Candidate, peer: &Peer, me: DiscoPublic, counter: u32) -> Option<RelayAction> {
    Some(RelayAction::Derp {
        to: c.node,
        to_disco: c.disco,
        region: c.home_region?,
        msg: Message::AllocateRequest {
            pair: sorted_pair(me, peer.disco),
            counter,
        },
    })
}

fn forward(st: &PeerState) -> Vec<RelayAction> {
    match (&st.alloc, st.peer.home_region) {
        (Some(a), Some(region)) => vec![RelayAction::Derp {
            to: st.peer.node,
            to_disco: st.peer.disco,
            region,
            msg: Message::CallMeMaybeVia(a.clone()),
        }],
        _ => Vec::new(),
    }
}

fn bind_message(st: &PeerState) -> Option<RelayAction> {
    let a = st.alloc.as_ref()?;
    let generation = match st.bind {
        Some(Bind::Sent { generation, .. }) => generation,
        _ => return None,
    };
    Some(RelayAction::Server {
        addr: *a.addrs.first()?,
        vni: a.vni,
        to_disco: a.server,
        msg: Message::Bind(BindBody {
            vni: a.vni,
            generation,
            remote: st.peer.disco,
            challenge: [0; CHALLENGE_LEN],
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    fn key(b: u8) -> DiscoPublic {
        DiscoPublic([b; 32])
    }
    fn node(b: u8) -> NodePublic {
        NodePublic([b; 32])
    }
    fn me() -> DiscoPublic {
        key(1)
    }
    fn peer() -> Peer {
        Peer {
            node: node(2),
            disco: key(2),
            home_region: Some(1001),
        }
    }
    fn server() -> Candidate {
        Candidate {
            node: node(9),
            disco: key(9),
            home_region: Some(1000),
        }
    }
    fn alloc(vni: u32) -> Alloc {
        Alloc {
            server: key(0xaa),
            pair: sorted_pair(me(), key(2)),
            generation: u64::from(vni),
            vni,
            durations: [Duration::from_secs(30), Duration::from_secs(300)],
            addrs: vec!["172.29.0.23:40000".parse().unwrap()],
        }
    }
    fn client() -> RelayClient {
        let mut c = RelayClient::new(me());
        c.set_candidates(vec![server()]);
        c
    }
    fn requests(acts: &[RelayAction]) -> Vec<u32> {
        acts.iter()
            .filter_map(|a| match a {
                RelayAction::Derp {
                    msg: Message::AllocateRequest { counter, .. },
                    ..
                } => Some(*counter),
                _ => None,
            })
            .collect()
    }
    fn binds(acts: &[RelayAction]) -> Vec<u32> {
        acts.iter()
            .filter_map(|a| match a {
                RelayAction::Server {
                    msg: Message::Bind(b),
                    ..
                } => Some(b.generation),
                _ => None,
            })
            .collect()
    }
    fn challenge(vni: u32, generation: u32) -> Message {
        Message::Challenge(BindBody {
            vni,
            generation,
            remote: key(2),
            challenge: [7; CHALLENGE_LEN],
        })
    }

    #[test]
    fn requests_go_to_candidates_with_the_pair_sorted_then_repeat_once() {
        let mut c = client();
        let acts = c.want(&peer(), S);
        assert_eq!(acts.len(), 1);
        match &acts[0] {
            RelayAction::Derp {
                to,
                region,
                msg: Message::AllocateRequest { pair, counter },
                ..
            } => {
                assert_eq!((*to, *region, *counter), (node(9), 1000, 1));
                assert_eq!(*pair, [key(1), key(2)]);
            }
            other => panic!("{other:?}"),
        }
        assert!(requests(&c.tick(S + REPEAT_DELAY - S / 2)).is_empty());
        assert_eq!(requests(&c.tick(S + REPEAT_DELAY)), vec![1], "same counter");
        assert!(requests(&c.tick(S + 10 * S)).is_empty());
    }

    #[test]
    fn rounds_every_thirty_seconds_while_wanted_and_stop_when_idle() {
        let mut c = client();
        c.want(&peer(), Duration::ZERO);
        c.tick(REPEAT_DELAY);
        c.want(&peer(), 20 * S);
        assert_eq!(
            requests(&c.tick(ROUND_INTERVAL)),
            vec![2],
            "new round, new counter"
        );
        // Last traffic at 20 s: the round at 60 s is still inside 45 s; the one at 90 s is not.
        assert_eq!(requests(&c.tick(2 * ROUND_INTERVAL)), vec![3]);
        c.tick(2 * ROUND_INTERVAL + REPEAT_DELAY);
        assert!(requests(&c.tick(3 * ROUND_INTERVAL)).is_empty());
    }

    #[test]
    fn requests_skip_this_node_the_peer_and_candidates_without_a_region() {
        let mut c = RelayClient::new(me());
        c.set_candidates(vec![
            Candidate {
                node: node(1),
                disco: me(),
                home_region: Some(1000),
            },
            Candidate {
                node: node(2),
                disco: key(2),
                home_region: Some(1000),
            },
            Candidate {
                node: node(8),
                disco: key(8),
                home_region: None,
            },
            server(),
        ]);
        let acts = c.want(&peer(), S);
        assert_eq!(requests(&acts), vec![1]);
    }

    #[test]
    fn a_response_is_forwarded_twice_and_starts_the_bind() {
        let mut c = client();
        c.want(&peer(), S);
        let resp = Message::AllocateResponse {
            counter: 1,
            alloc: alloc(4),
        };
        let acts = c.on_derp(&key(9), &resp, 2 * S);
        let forwards = |a: &[RelayAction]| {
            a.iter()
                .filter(|x| matches!(x, RelayAction::Derp { to, msg: Message::CallMeMaybeVia(_), .. } if *to == node(2)))
                .count()
        };
        assert_eq!(forwards(&acts), 1);
        assert_eq!(binds(&acts), vec![1]);
        match acts
            .iter()
            .find(|a| matches!(a, RelayAction::Server { .. }))
            .unwrap()
        {
            RelayAction::Server {
                addr,
                vni,
                to_disco,
                msg: Message::Bind(b),
            } => {
                assert_eq!((*vni, *to_disco), (4, key(0xaa)));
                assert_eq!(addr.port(), 40000);
                assert_eq!(
                    (b.vni, b.remote, b.challenge),
                    (4, key(2), [0; CHALLENGE_LEN])
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(forwards(&c.tick(2 * S + REPEAT_DELAY)), 1, "repeated once");
        assert_eq!(forwards(&c.tick(2 * S + 2 * REPEAT_DELAY)), 0);
        // The request repeat is dropped once an allocation exists.
        assert!(requests(&c.tick(S + REPEAT_DELAY)).is_empty());
    }

    #[test]
    fn responses_from_non_candidates_or_other_pairs_are_ignored() {
        let mut c = client();
        c.want(&peer(), S);
        let resp = Message::AllocateResponse {
            counter: 1,
            alloc: alloc(4),
        };
        assert!(
            c.on_derp(&key(5), &resp, 2 * S).is_empty(),
            "not a candidate"
        );
        let mut other = alloc(4);
        other.pair = sorted_pair(key(3), key(4));
        let resp = Message::AllocateResponse {
            counter: 1,
            alloc: other,
        };
        assert!(c.on_derp(&key(9), &resp, 2 * S).is_empty(), "not our pair");
        assert_eq!(c.endpoint(&key(2)), None);
    }

    #[test]
    fn the_challenge_is_answered_and_the_path_becomes_usable() {
        let mut c = client();
        c.want(&peer(), S);
        c.on_derp(
            &key(9),
            &Message::AllocateResponse {
                counter: 1,
                alloc: alloc(4),
            },
            2 * S,
        );
        assert_eq!(c.endpoint(&key(2)), None, "not bound before the answer");
        assert!(
            c.on_server(4, &challenge(4, 2), 2 * S).is_empty(),
            "wrong generation"
        );
        assert!(
            c.on_server(5, &challenge(4, 1), 2 * S).is_empty(),
            "header VNI differs"
        );
        let acts = c.on_server(4, &challenge(4, 1), 2 * S);
        match acts.as_slice() {
            [
                RelayAction::Server {
                    msg: Message::Answer(b),
                    to_disco,
                    ..
                },
            ] => {
                assert_eq!(
                    (b.vni, b.generation, b.challenge),
                    (4, 1, [7; CHALLENGE_LEN])
                );
                assert_eq!(*to_disco, key(0xaa));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            c.endpoint(&key(2)),
            Some(Endpoint {
                addr: "172.29.0.23:40000".parse().unwrap(),
                vni: 4
            })
        );
        assert!(
            c.on_server(4, &challenge(4, 1), 2 * S).is_empty(),
            "already answered"
        );
    }

    #[test]
    fn bind_is_retried_then_the_allocation_is_given_up() {
        let mut c = client();
        c.want(&peer(), Duration::ZERO);
        c.on_derp(
            &key(9),
            &Message::AllocateResponse {
                counter: 1,
                alloc: alloc(4),
            },
            Duration::ZERO,
        );
        let mut sent = 1;
        for i in 1..BIND_TRIES {
            assert!(binds(&c.tick(BIND_RETRY * i - S / 10)).is_empty());
            sent += binds(&c.tick(BIND_RETRY * i)).len();
        }
        assert_eq!(sent, BIND_TRIES as usize, "same generation each time");
        // After the last try the allocation is dropped and a new round starts at once.
        let acts = c.want(&peer(), BIND_RETRY * BIND_TRIES);
        assert_eq!(requests(&acts).len(), 1);
        assert_eq!(c.endpoint(&key(2)), None);
    }

    #[test]
    fn a_forward_from_the_peer_binds_without_a_request() {
        let mut c = client();
        let acts = c.on_derp(&key(2), &Message::CallMeMaybeVia(alloc(5)), S);
        assert_eq!(binds(&acts), vec![1]);
        assert!(requests(&acts).is_empty());
        // The same allocation again does not restart the handshake.
        assert!(
            c.on_derp(&key(2), &Message::CallMeMaybeVia(alloc(5)), 2 * S)
                .is_empty()
        );
        // A forward naming another pair is ignored.
        let mut other = alloc(6);
        other.pair = sorted_pair(key(3), key(4));
        assert!(
            c.on_derp(&key(2), &Message::CallMeMaybeVia(other), 2 * S)
                .is_empty()
        );
    }

    #[test]
    fn a_new_vni_from_the_same_server_is_a_new_allocation() {
        let mut c = client();
        c.on_derp(&key(2), &Message::CallMeMaybeVia(alloc(5)), S);
        c.on_server(5, &challenge(5, 1), S);
        let acts = c.on_derp(&key(2), &Message::CallMeMaybeVia(alloc(6)), 2 * S);
        assert_eq!(binds(&acts), vec![2]);
    }

    #[test]
    fn the_activity_window_ends_at_exactly_45_seconds() {
        let mut c = client();
        c.want(&peer(), Duration::ZERO);
        c.want(&peer(), 15 * S);
        c.tick(REPEAT_DELAY);
        assert_eq!(
            requests(&c.tick(ROUND_INTERVAL)).len(),
            1,
            "15 s after the last traffic"
        );
        // The next round falls exactly ACTIVE_WINDOW after the last traffic: no longer wanted.
        assert!(requests(&c.tick(15 * S + ACTIVE_WINDOW)).is_empty());
    }

    #[test]
    fn a_new_allocation_from_the_peer_replaces_the_old_one() {
        // A restarted relay server hands out a new key and VNI; the peer forwards it.
        let mut c = client();
        c.on_derp(&key(2), &Message::CallMeMaybeVia(alloc(5)), S);
        c.on_server(5, &challenge(5, 1), S);
        let mut fresh = alloc(1);
        fresh.server = key(0xbb);
        let acts = c.on_derp(&key(2), &Message::CallMeMaybeVia(fresh), 2 * S);
        assert_eq!(binds(&acts), vec![2], "new generation");
        assert_eq!(c.endpoint(&key(2)), None, "not bound to the new one yet");
    }

    #[test]
    fn an_unanswered_bound_path_is_bound_again_while_traffic_continues() {
        let mut c = client();
        c.want(&peer(), Duration::ZERO);
        c.on_derp(
            &key(9),
            &Message::AllocateResponse {
                counter: 1,
                alloc: alloc(4),
            },
            Duration::ZERO,
        );
        c.on_server(4, &challenge(4, 1), Duration::ZERO);
        c.on_relay_pong(&key(2), 5 * S);
        assert!(
            binds(&c.want(&peer(), 10 * S)).is_empty(),
            "pong 5 s ago: trusted"
        );
        assert!(
            binds(&c.tick(5 * S + TRUST - S / 10)).is_empty(),
            "still inside the window"
        );
        let acts = c.tick(5 * S + TRUST);
        assert_eq!(
            binds(&acts),
            vec![2],
            "no pong for the trust window: bind again"
        );
        // An idle pair is left alone (no traffic for the activity window).
        let mut idle = client();
        idle.want(&peer(), Duration::ZERO);
        idle.on_derp(
            &key(9),
            &Message::AllocateResponse {
                counter: 1,
                alloc: alloc(4),
            },
            Duration::ZERO,
        );
        idle.on_server(4, &challenge(4, 1), Duration::ZERO);
        assert!(binds(&idle.tick(ACTIVE_WINDOW + S)).is_empty());
    }

    #[test]
    fn other_member_finds_the_peer_only_when_we_are_in_the_pair() {
        assert_eq!(other_member(&[key(1), key(2)], &key(1)), Some(key(2)));
        assert_eq!(other_member(&[key(1), key(2)], &key(2)), Some(key(1)));
        assert_eq!(other_member(&[key(3), key(4)], &key(1)), None);
    }
}
