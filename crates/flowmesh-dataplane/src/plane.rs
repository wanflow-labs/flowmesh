// SPDX-License-Identifier: Apache-2.0
//! Per-peer WireGuard sessions plus routing and filtering.

use crate::ippkt;
use boringtun::noise::{Tunn, TunnResult};
use flowmesh_filter::compile::CompiledRule;
use flowmesh_filter::matcher::{Filter, Verdict};
use flowmesh_proto::key::{NodePrivate, NodePublic};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// boringtun shifts the session index left by 8 bits internally, so only the low 24 bits are usable.
fn next_session_index(current: u32) -> u32 {
    current.wrapping_add(1) & 0x00ff_ffff
}

/// Upper bound on the size of an IP packet.
pub const MAX_PACKET: usize = 65_535;
/// Upper bound on WireGuard encapsulation overhead, with headroom for handshake messages.
const BUF_OVERHEAD: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send to the peer (over DERP or directly).
    ToPeer(NodePublic, Vec<u8>),
    /// Write to the local TUN.
    ToTun(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub key: NodePublic,
    pub allowed_ips: Vec<IpNet>,
}

pub struct Dataplane {
    me: NodePrivate,
    peers: HashMap<NodePublic, Peer>,
    filter: Filter,
    next_index: u32,
}

struct Peer {
    tunn: Tunn,
    allowed: Vec<IpNet>,
}

impl Dataplane {
    /// Starts with no filter rules: inbound new connections are refused until rules arrive (fail-closed).
    pub fn new(me: NodePrivate) -> Self {
        Self {
            me,
            peers: HashMap::new(),
            filter: Filter::new(vec![]),
            next_index: 1,
        }
    }

    /// Replace the peer set. Peers whose key is unchanged keep their WireGuard session (only AllowedIPs are updated).
    pub fn set_peers(&mut self, peers: Vec<PeerConfig>) {
        let mut next = HashMap::with_capacity(peers.len());
        for cfg in peers {
            let peer = match self.peers.remove(&cfg.key) {
                Some(mut existing) => {
                    existing.allowed = cfg.allowed_ips;
                    existing
                }
                None => {
                    let index = self.next_index;
                    self.next_index = next_session_index(self.next_index);
                    Peer {
                        tunn: Tunn::new(
                            x25519_dalek::StaticSecret::from(*self.me.as_bytes()),
                            x25519_dalek::PublicKey::from(cfg.key.0),
                            None,
                            None,
                            index,
                            None,
                        ),
                        allowed: cfg.allowed_ips,
                    }
                }
            };
            next.insert(cfg.key, peer);
        }
        self.peers = next;
    }

    /// Longest-prefix match on AllowedIPs.
    fn route(&self, dst: IpAddr) -> Option<NodePublic> {
        self.peers
            .iter()
            .flat_map(|(k, p)| {
                p.allowed
                    .iter()
                    .filter(|n| n.contains(&dst))
                    .map(move |n| (n.prefix_len(), *k))
            })
            .max_by_key(|(len, _)| *len)
            .map(|(_, k)| k)
    }

    pub fn set_filter_rules(&mut self, rules: Vec<CompiledRule>) {
        self.filter.set_rules(rules);
    }

    pub fn outbound(&mut self, pkt: &[u8], now: Duration) -> Vec<Output> {
        let Some(meta) = ippkt::parse(pkt) else {
            return Vec::new();
        };
        let Some(key) = self.route(meta.dst) else {
            return Vec::new();
        };
        self.filter.check_out(&meta, now);
        let Some(peer) = self.peers.get_mut(&key) else {
            return Vec::new();
        };
        let mut buf = vec![0u8; pkt.len() + BUF_OVERHEAD];
        match peer.tunn.encapsulate(pkt, &mut buf) {
            TunnResult::WriteToNetwork(out) => vec![Output::ToPeer(key, out.to_vec())],
            _ => Vec::new(),
        }
    }

    pub fn inbound(&mut self, src: NodePublic, data: &[u8], now: Duration) -> Vec<Output> {
        let Some(peer) = self.peers.get_mut(&src) else {
            return Vec::new();
        };
        let mut outputs = Vec::new();
        let mut buf = vec![0u8; MAX_PACKET + BUF_OVERHEAD];
        let mut datagram: &[u8] = data;
        loop {
            match peer.tunn.decapsulate(None, datagram, &mut buf) {
                TunnResult::WriteToNetwork(out) => {
                    outputs.push(Output::ToPeer(src, out.to_vec()));
                    // After a handshake reply, keep calling with an empty input to flush packets queued while waiting for the handshake.
                    datagram = &[];
                }
                TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                    let pkt = pkt.to_vec();
                    if let Some(meta) = ippkt::parse(&pkt) {
                        // WireGuard cryptokey routing: the inner source address must be within that peer's AllowedIPs.
                        let owned = peer.allowed.iter().any(|n| n.contains(&meta.src));
                        if owned && self.filter.check_in(&meta, now) == Verdict::Accept {
                            outputs.push(Output::ToTun(pkt));
                        }
                    }
                    break;
                }
                TunnResult::Done | TunnResult::Err(_) => break,
            }
        }
        outputs
    }

    /// Traffic counters per peer (sent bytes, received bytes), for status display.
    pub fn stats(&self) -> Vec<(NodePublic, u64, u64)> {
        self.peers
            .iter()
            .map(|(k, p)| {
                let (_, tx, rx, _, _) = p.tunn.stats();
                (*k, tx as u64, rx as u64)
            })
            .collect()
    }

    /// Drive WireGuard timers (rekey, keepalive). Call roughly every 250 ms.
    pub fn tick(&mut self) -> Vec<Output> {
        let mut outputs = Vec::new();
        let mut buf = vec![0u8; BUF_OVERHEAD + 256];
        for (key, peer) in &mut self.peers {
            if let TunnResult::WriteToNetwork(out) = peer.tunn.update_timers(&mut buf) {
                outputs.push(Output::ToPeer(*key, out.to_vec()));
            }
        }
        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ippkt::build;
    use flowmesh_filter::compile::compile;
    use flowmesh_proto::filter::{FilterRule, NetPortRange, PortRange};

    const A_IP: [u8; 4] = [100, 64, 0, 1];
    const B_IP: [u8; 4] = [100, 64, 0, 2];

    fn allow_all() -> Vec<CompiledRule> {
        compile(&[FilterRule {
            src_ips: vec!["*".into()],
            dst_ports: vec![NetPortRange {
                ip: "*".into(),
                ports: PortRange {
                    first: 0,
                    last: 65535,
                },
            }],
            ..Default::default()
        }])
        .unwrap()
    }

    fn pair() -> (Dataplane, NodePublic, Dataplane, NodePublic) {
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
        (a, pa, b, pb)
    }

    /// Shuttle packets back and forth between the two ends until nothing is left to send; return what each end wrote to TUN.
    fn run(
        a: &mut Dataplane,
        pa: NodePublic,
        b: &mut Dataplane,
        pb: NodePublic,
        first: Vec<Output>,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let (mut tun_a, mut tun_b) = (Vec::new(), Vec::new());
        let mut queue: Vec<(bool, Output)> = first.into_iter().map(|o| (true, o)).collect();
        let mut rounds = 0;
        while let Some((from_a, out)) = queue.pop() {
            rounds += 1;
            assert!(rounds < 100, "ping-pong did not converge");
            match out {
                Output::ToTun(p) => {
                    if from_a {
                        tun_a.push(p)
                    } else {
                        tun_b.push(p)
                    }
                }
                Output::ToPeer(dst, bytes) => {
                    if from_a {
                        assert_eq!(dst, pb);
                        queue.extend(
                            b.inbound(pa, &bytes, Duration::ZERO)
                                .into_iter()
                                .map(|o| (false, o)),
                        );
                    } else {
                        assert_eq!(dst, pa);
                        queue.extend(
                            a.inbound(pb, &bytes, Duration::ZERO)
                                .into_iter()
                                .map(|o| (true, o)),
                        );
                    }
                }
            }
        }
        (tun_a, tun_b)
    }

    #[test]
    fn handshake_then_ping_reaches_peer_tun() {
        let (mut a, pa, mut b, pb) = pair();
        b.set_filter_rules(allow_all());
        let ping = build::v4(A_IP, B_IP, 1, &build::icmp(8));
        let first = a.outbound(&ping, Duration::ZERO);
        assert!(matches!(first.as_slice(), [Output::ToPeer(k, _)] if *k == pb));
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert_eq!(tun_b, vec![ping]);
    }

    #[test]
    fn inbound_new_tcp_connection_is_dropped_without_rule() {
        let (mut a, pa, mut b, pb) = pair();
        // B has no rules: a TCP SYN from A must not be written to TUN (filter.md F2).
        let syn = build::v4(A_IP, B_IP, 6, &build::tcp(40000, 22, 0x02));
        let first = a.outbound(&syn, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert!(tun_b.is_empty());
    }

    #[test]
    fn spoofed_inner_source_is_dropped() {
        let (mut a, pa, mut b, pb) = pair();
        b.set_filter_rules(allow_all());
        // A claims an inner source address that is not in A's AllowedIPs at B.
        a.set_peers(vec![PeerConfig {
            key: pb,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        }]);
        let spoof = build::v4([100, 64, 0, 9], B_IP, 1, &build::icmp(8));
        let first = a.outbound(&spoof, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert!(tun_b.is_empty());
        // Control: a legitimate packet in the same session does arrive, so the check above is not passing just because the path is broken.
        let legit = build::v4(A_IP, B_IP, 1, &build::icmp(8));
        let first = a.outbound(&legit, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert_eq!(tun_b, vec![legit]);
    }

    #[test]
    fn unknown_destination_and_unknown_peer_produce_nothing() {
        let (mut a, _pa, mut b, _pb) = pair();
        let to_nowhere = build::v4(A_IP, [100, 64, 0, 77], 1, &build::icmp(8));
        assert!(a.outbound(&to_nowhere, Duration::ZERO).is_empty());
        let stranger = NodePrivate::generate().unwrap().public();
        assert!(
            b.inbound(stranger, &[1, 0, 0, 0, 0, 0, 0, 0], Duration::ZERO)
                .is_empty()
        );
        assert!(a.outbound(&[0xff; 3], Duration::ZERO).is_empty());
    }

    #[test]
    fn stats_count_traffic_per_peer() {
        let (mut a, pa, mut b, pb) = pair();
        b.set_filter_rules(allow_all());
        let ping = build::v4(A_IP, B_IP, 1, &build::icmp(8));
        let first = a.outbound(&ping, Duration::ZERO);
        run(&mut a, pa, &mut b, pb, first);
        // Only A sends to B (B does not reply): A's sent bytes > 0, B's received bytes > 0.
        let (k, tx, _) = a.stats()[0];
        assert_eq!(k, pb);
        assert!(tx > 0, "a tx={tx}");
        let (k, _, rx) = b.stats()[0];
        assert_eq!(k, pa);
        assert!(rx > 0, "b rx={rx}");
    }

    #[test]
    fn session_index_stays_within_24_bits() {
        assert_eq!(next_session_index(1), 2);
        assert_eq!(next_session_index(0x00ff_fffe), 0x00ff_ffff);
        assert_eq!(next_session_index(0x00ff_ffff), 0);
    }

    /// When the handshake initiation is lost, tick() must retransmit after WireGuard's 5-second rekey timeout (real-time wait).
    #[test]
    fn tick_retransmits_lost_handshake() {
        let (mut a, _pa, _b, pb) = pair();
        let ping = build::v4(A_IP, B_IP, 1, &build::icmp(8));
        let first = a.outbound(&ping, Duration::ZERO);
        assert!(matches!(first.as_slice(), [Output::ToPeer(_, m)] if m[0] == 1));
        assert!(a.tick().is_empty(), "no retransmit before the timeout");
        std::thread::sleep(Duration::from_millis(5_600));
        let retry = a.tick();
        assert!(
            matches!(retry.as_slice(), [Output::ToPeer(k, m)] if *k == pb && m[0] == 1),
            "{retry:?}"
        );
    }

    #[test]
    fn set_peers_keeps_session_for_unchanged_key() {
        let (mut a, pa, mut b, pb) = pair();
        b.set_filter_rules(allow_all());
        let ping = build::v4(A_IP, B_IP, 1, &build::icmp(8));
        let first = a.outbound(&ping, Duration::ZERO);
        run(&mut a, pa, &mut b, pb, first);
        // Same peer, different AllowedIPs: the session is kept, so the next packet is sent directly as a data message (type 4) without a new handshake.
        a.set_peers(vec![PeerConfig {
            key: pb,
            allowed_ips: vec!["100.64.0.0/24".parse().unwrap()],
        }]);
        let again = a.outbound(&ping, Duration::ZERO);
        assert!(
            matches!(again.as_slice(), [Output::ToPeer(_, bytes)] if bytes[0] == 4),
            "{again:?}"
        );
    }
}
