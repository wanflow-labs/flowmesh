// SPDX-License-Identifier: Apache-2.0
//! Per-peer WireGuard sessions plus routing and filtering.

use crate::ippkt;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use flowmesh_filter::compile::CompiledRule;
use flowmesh_filter::matcher::{Filter, Verdict};
use flowmesh_proto::key::{DiscoPublic, NodePrivate, NodePublic};
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
/// Handshake messages per second checked for peers recognized from the datagram, before the rate
/// limiter answers with cookies (boringtun's default).
const HANDSHAKE_RATE_LIMIT: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send to the peer (over DERP or directly).
    ToPeer(NodePublic, Vec<u8>),
    /// Write to the local TUN.
    ToTun(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerConfig {
    pub key: NodePublic,
    pub allowed_ips: Vec<IpNet>,
    /// The peer's disco key (zero while unknown). It is new each time the peer starts, so a change
    /// from one known key to another means the peer lost its WireGuard session with us.
    pub disco: DiscoPublic,
}

/// The port SSH clients connect to.
pub const SSH_PORT: u16 = 22;

/// A TCP packet from one of `own` with source port `port`.
fn is_tcp_from(pkt: &[u8], own: &[IpAddr], port: u16) -> bool {
    ippkt::parse(pkt).is_some_and(|m| {
        m.proto == flowmesh_filter::packet::IpProto::Tcp
            && m.src_port == port
            && own.contains(&m.src)
    })
}

/// Packets dropped, by direction and reason (the official metric labels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Drops {
    /// Inbound, refused by the packet filter.
    pub inbound_acl: u64,
    /// Inbound, malformed or not for this node (inner source outside the peer's AllowedIPs,
    /// destination not local).
    pub inbound_error: u64,
    /// Outbound to a multicast destination.
    pub outbound_multicast: u64,
    /// Outbound with no peer to send it to, or that WireGuard could not encapsulate.
    pub outbound_error: u64,
}

pub struct Dataplane {
    me: NodePrivate,
    drops: Drops,
    peers: HashMap<NodePublic, Peer>,
    filter: Filter,
    next_index: u32,
    /// AllowedIPs that are single addresses (/32, /128): the usual tailnet case, one hash lookup.
    hosts: HashMap<IpAddr, NodePublic>,
    /// The other AllowedIPs (subnet routes), longest prefix first.
    subnets: Vec<(IpNet, NodePublic)>,
    /// Encapsulation/decapsulation output, allocated once; outputs copy out exactly what they need.
    scratch: Vec<u8>,
    /// Session index (as given to boringtun) -> peer, to recognize responses and data by the
    /// receiver index they carry.
    by_index: HashMap<u32, NodePublic>,
    /// Checks MACs and rate-limits handshakes recognized from the datagram.
    limiter: RateLimiter,
    static_secret: x25519_dalek::StaticSecret,
    static_public: x25519_dalek::PublicKey,
    /// Destinations inbound packets may have (own addresses, routed subnets, a shrunk default route
    /// when offering an exit node); `None` until the engine sets it.
    local: Option<crate::netset::LocalNets>,
    /// This node's peerapi listeners: TCP to them skips the filter (the service authorizes itself,
    /// as the official client's peerapi does).
    peerapi: std::collections::HashSet<std::net::SocketAddr>,
    /// The SSH server: TCP port 22 of this node's addresses is delivered to this port (where the
    /// server listens, on the mesh interface only), and its replies leave as port 22.
    ssh: Option<SshRedirect>,
}

#[derive(Debug, Clone)]
struct SshRedirect {
    port: u16,
    own: Vec<IpAddr>,
    admissions: Admissions,
}

/// Connections the dataplane let through to the SSH server: the source address of each SYN it
/// delivered from port 22 to the server's port, with when. The server accepts a connection only
/// if its source is here (and takes it out): a local process connecting to the server's port
/// directly never passes through the dataplane, whatever source address it manages to use.
#[derive(Debug, Clone, Default)]
pub struct Admissions(
    std::sync::Arc<std::sync::Mutex<HashMap<std::net::SocketAddr, std::time::Instant>>>,
);

/// How long a delivered SYN stays admissible (the handshake normally completes in one round trip).
pub const ADMISSION_TTL: Duration = Duration::from_secs(30);
/// Bound on remembered SYNs (a peer flooding SYNs cannot grow memory without limit).
const ADMISSIONS_MAX: usize = 4096;

impl Admissions {
    fn admit(&self, from: std::net::SocketAddr) {
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if m.len() >= ADMISSIONS_MAX {
            m.retain(|_, t| t.elapsed() < ADMISSION_TTL);
            if m.len() >= ADMISSIONS_MAX {
                return;
            }
        }
        m.insert(from, std::time::Instant::now());
    }

    /// Whether a connection from `from` came through the dataplane; one use per SYN.
    pub fn take(&self, from: std::net::SocketAddr) -> bool {
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        m.remove(&from).is_some_and(|t| t.elapsed() < ADMISSION_TTL)
    }
}

struct Peer {
    tunn: Tunn,
    allowed: Vec<IpNet>,
    disco: DiscoPublic,
    index: u32,
}

impl Dataplane {
    /// Starts with no filter rules: inbound new connections are refused until rules arrive (fail-closed).
    pub fn new(me: NodePrivate) -> Self {
        let static_secret = x25519_dalek::StaticSecret::from(*me.as_bytes());
        let static_public = x25519_dalek::PublicKey::from(&static_secret);
        Self {
            me,
            drops: Drops::default(),
            peers: HashMap::new(),
            filter: Filter::new(vec![]),
            next_index: 1,
            hosts: HashMap::new(),
            subnets: Vec::new(),
            scratch: vec![0u8; MAX_PACKET + BUF_OVERHEAD],
            by_index: HashMap::new(),
            limiter: RateLimiter::new(&static_public, HANDSHAKE_RATE_LIMIT),
            static_secret,
            static_public,
            local: None,
            peerapi: Default::default(),
            ssh: None,
        }
    }

    /// Replace the peer set. Peers whose key is unchanged keep their WireGuard session (only AllowedIPs
    /// are updated), unless their disco key changed from one known value to another: the peer
    /// restarted, so the old session is replaced right away (the reference client removes and
    /// re-adds such a peer for the same reason).
    pub fn set_peers(&mut self, peers: Vec<PeerConfig>) {
        let mut next = HashMap::with_capacity(peers.len());
        for cfg in peers {
            let restarted = |p: &Peer| p.disco != cfg.disco && p.disco != DiscoPublic::default();
            let peer = match self.peers.remove(&cfg.key) {
                Some(mut existing) if !restarted(&existing) => {
                    existing.allowed = cfg.allowed_ips;
                    if cfg.disco != DiscoPublic::default() {
                        existing.disco = cfg.disco;
                    }
                    existing
                }
                _ => {
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
                        disco: cfg.disco,
                        index,
                    }
                }
            };
            next.insert(cfg.key, peer);
        }
        self.peers = next;
        self.by_index = self.peers.iter().map(|(k, p)| (p.index, *k)).collect();
        self.hosts.clear();
        self.subnets.clear();
        for (k, p) in &self.peers {
            for n in &p.allowed {
                if n.prefix_len() == n.max_prefix_len() {
                    self.hosts.insert(n.addr(), *k);
                } else {
                    self.subnets.push((*n, *k));
                }
            }
        }
        self.subnets
            .sort_by_key(|(n, _)| std::cmp::Reverse(n.prefix_len()));
    }

    /// Longest-prefix match on AllowedIPs: a single address is the longest prefix there is, so the
    /// host table answers first, then the first containing subnet in longest-first order.
    fn route(&self, dst: IpAddr) -> Option<NodePublic> {
        self.hosts.get(&dst).copied().or_else(|| {
            self.subnets
                .iter()
                .find(|(n, _)| n.contains(&dst))
                .map(|(_, k)| *k)
        })
    }

    /// The peer a WireGuard datagram from `from` belongs to, read from the datagram itself: the
    /// static key inside a handshake initiation (after its MAC check and the rate limit), or our
    /// session index in a response, cookie or data message. For datagrams from an address no peer
    /// is known at yet, e.g. right after this node restarted.
    pub fn peer_for_datagram(&self, from: IpAddr, data: &[u8]) -> Option<NodePublic> {
        let mut cookie = [0u8; 64];
        let index = match self
            .limiter
            .verify_packet(Some(from), data, &mut cookie)
            .ok()?
        {
            Packet::HandshakeInit(init) => {
                let half =
                    parse_handshake_anon(&self.static_secret, &self.static_public, &init).ok()?;
                let key = NodePublic(half.peer_static_public);
                return self.peers.contains_key(&key).then_some(key);
            }
            Packet::HandshakeResponse(p) => p.receiver_idx,
            Packet::PacketCookieReply(p) => p.receiver_idx,
            Packet::PacketData(p) => p.receiver_idx,
        };
        // boringtun keeps the session index in the upper 24 bits.
        self.by_index.get(&(index >> 8)).copied()
    }

    /// The destinations this node accepts inbound packets for. Anything else is dropped, even if a
    /// filter rule would allow it: a peer must not reach networks this node does not route.
    pub fn set_local_nets(&mut self, local: crate::netset::LocalNets) {
        self.local = Some(local);
    }

    /// The peerapi listeners (address and port); inbound TCP to them is not checked by the filter.
    pub fn set_peerapi(&mut self, listeners: Vec<std::net::SocketAddr>) {
        self.peerapi = listeners.into_iter().collect();
    }

    pub fn set_filter_rules(&mut self, rules: Vec<CompiledRule>) {
        self.filter.set_rules(rules);
    }

    /// Deliver TCP port 22 of `own` to `port` (the SSH server), recording each SYN in
    /// `admissions`; or stop (`None`).
    pub fn set_ssh_redirect(&mut self, r: Option<(u16, Vec<IpAddr>, Admissions)>) {
        self.ssh = r.map(|(port, own, admissions)| SshRedirect {
            port,
            own,
            admissions,
        });
    }

    pub fn outbound(&mut self, pkt: &[u8], now: Duration) -> Vec<Output> {
        // The SSH server's replies go out from port 22, the port the peer connected to.
        let rewritten;
        let pkt = match &self.ssh {
            Some(r) if is_tcp_from(pkt, &r.own, r.port) => {
                let mut p = pkt.to_vec();
                ippkt::set_tcp_port(&mut p, false, SSH_PORT);
                rewritten = p;
                rewritten.as_slice()
            }
            _ => pkt,
        };
        let Some(meta) = ippkt::parse(pkt) else {
            self.drops.outbound_error += 1;
            return Vec::new();
        };
        if meta.dst.is_multicast() {
            self.drops.outbound_multicast += 1;
            return Vec::new();
        }
        let Some(key) = self.route(meta.dst) else {
            self.drops.outbound_error += 1;
            return Vec::new();
        };
        self.filter.check_out(&meta, now);
        let Some(peer) = self.peers.get_mut(&key) else {
            self.drops.outbound_error += 1;
            return Vec::new();
        };
        match peer.tunn.encapsulate(pkt, &mut self.scratch) {
            TunnResult::WriteToNetwork(out) => vec![Output::ToPeer(key, out.to_vec())],
            // Queued until the handshake completes: not dropped.
            TunnResult::Done => Vec::new(),
            _ => {
                self.drops.outbound_error += 1;
                Vec::new()
            }
        }
    }

    pub fn drops(&self) -> Drops {
        self.drops
    }

    pub fn inbound(&mut self, src: NodePublic, data: &[u8], now: Duration) -> Vec<Output> {
        let Some(peer) = self.peers.get_mut(&src) else {
            return Vec::new();
        };
        let mut outputs = Vec::new();
        let mut datagram: &[u8] = data;
        loop {
            match peer.tunn.decapsulate(None, datagram, &mut self.scratch) {
                TunnResult::WriteToNetwork(out) => {
                    outputs.push(Output::ToPeer(src, out.to_vec()));
                    // After a handshake reply, keep calling with an empty input to flush packets queued while waiting for the handshake.
                    datagram = &[];
                }
                TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                    let pkt = pkt.to_vec();
                    let Some(meta) = ippkt::parse(&pkt) else {
                        self.drops.inbound_error += 1;
                        break;
                    };
                    // WireGuard cryptokey routing: the inner source address must be within that peer's AllowedIPs.
                    let owned = peer.allowed.iter().any(|n| n.contains(&meta.src));
                    let ours = self.local.as_ref().is_none_or(|l| l.contains(&meta.dst));
                    let peerapi = meta.proto == flowmesh_filter::packet::IpProto::Tcp
                        && self
                            .peerapi
                            .contains(&std::net::SocketAddr::new(meta.dst, meta.dst_port));
                    let ssh = self.ssh.as_ref().filter(|r| {
                        meta.proto == flowmesh_filter::packet::IpProto::Tcp
                            && r.own.contains(&meta.dst)
                    });
                    if !owned || !ours {
                        self.drops.inbound_error += 1;
                    } else if ssh.is_some_and(|r| meta.dst_port == r.port) {
                        // The server's own port is reachable only through port 22.
                        self.drops.inbound_acl += 1;
                    } else if peerapi || self.filter.check_in(&meta, now) == Verdict::Accept {
                        let mut pkt = pkt;
                        if let Some(r) = ssh.filter(|_| meta.dst_port == SSH_PORT) {
                            ippkt::set_tcp_port(&mut pkt, true, r.port);
                            // SYN without ACK: a new connection.
                            if meta.tcp_flags & 0x12 == 0x02 {
                                r.admissions
                                    .admit(std::net::SocketAddr::new(meta.src, meta.src_port));
                            }
                        }
                        outputs.push(Output::ToTun(pkt));
                    } else {
                        self.drops.inbound_acl += 1;
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
        self.limiter.reset_count();
        let mut outputs = Vec::new();
        for (key, peer) in &mut self.peers {
            if let TunnResult::WriteToNetwork(out) = peer.tunn.update_timers(&mut self.scratch) {
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
            ..Default::default()
        }]);
        b.set_peers(vec![PeerConfig {
            key: pa,
            allowed_ips: vec!["100.64.0.1/32".parse().unwrap()],
            ..Default::default()
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
        assert_eq!(
            b.drops(),
            Drops {
                inbound_acl: 1,
                ..Default::default()
            }
        );
    }

    /// Port 22 of this node goes to the SSH server's port and the replies come back as port 22;
    /// the server's own port cannot be reached directly; other nodes' port 22 is untouched.
    #[test]
    fn ssh_port_redirect() {
        let (mut a, pa, mut b, pb) = pair();
        b.set_filter_rules(allow_all());
        a.set_filter_rules(allow_all());
        let admissions = Admissions::default();
        b.set_ssh_redirect(Some((41234, vec![IpAddr::from(B_IP)], admissions.clone())));
        let syn = build::v4(A_IP, B_IP, 6, &build::tcp(50000, 22, 0x02));
        let first = a.outbound(&syn, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert_eq!(tun_b.len(), 1);
        let m = ippkt::parse(&tun_b[0]).unwrap();
        assert_eq!((m.src_port, m.dst_port), (50000, 41234));
        // The SYN is admitted once; nothing else is.
        let from = std::net::SocketAddr::new(IpAddr::from(A_IP), 50000);
        assert!(!admissions.take(std::net::SocketAddr::new(IpAddr::from(A_IP), 50001)));
        assert!(admissions.take(from));
        assert!(!admissions.take(from));
        // The server answers from its port; A sees port 22.
        let synack = build::v4(B_IP, A_IP, 6, &build::tcp(41234, 50000, 0x12));
        let out = b.outbound(&synack, Duration::ZERO);
        let (_, tun_a) = run(&mut b, pb, &mut a, pa, out);
        assert_eq!(tun_a.len(), 1);
        let m = ippkt::parse(&tun_a[0]).unwrap();
        assert_eq!((m.src_port, m.dst_port), (22, 50000));
        // Straight to the server's port: dropped.
        let direct = build::v4(A_IP, B_IP, 6, &build::tcp(50001, 41234, 0x02));
        let first = a.outbound(&direct, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert!(tun_b.is_empty());
        // Off: port 22 reaches the host as it is.
        b.set_ssh_redirect(None);
        let syn = build::v4(A_IP, B_IP, 6, &build::tcp(50002, 22, 0x02));
        let first = a.outbound(&syn, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert_eq!(ippkt::parse(&tun_b[0]).unwrap().dst_port, 22);
    }

    #[test]
    fn outbound_drops_are_counted_by_reason() {
        let (mut a, _, _, _) = pair();
        let mcast = build::v4(A_IP, [224, 0, 0, 251], 17, &build::udp(5353, 5353));
        assert!(a.outbound(&mcast, Duration::ZERO).is_empty());
        let nowhere = build::v4(A_IP, [100, 64, 0, 77], 1, &build::icmp(8));
        assert!(a.outbound(&nowhere, Duration::ZERO).is_empty());
        assert_eq!(
            a.drops(),
            Drops {
                outbound_multicast: 1,
                outbound_error: 1,
                ..Default::default()
            }
        );
        // The first packet to a peer waits for the handshake: queued, not dropped.
        let ping = build::v4(A_IP, B_IP, 1, &build::icmp(8));
        a.outbound(&ping, Duration::ZERO);
        a.outbound(&ping, Duration::ZERO);
        assert_eq!(a.drops().outbound_error, 1);
    }

    #[test]
    fn spoofed_inner_source_is_dropped() {
        let (mut a, pa, mut b, pb) = pair();
        b.set_filter_rules(allow_all());
        // A claims an inner source address that is not in A's AllowedIPs at B.
        a.set_peers(vec![PeerConfig {
            key: pb,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            ..Default::default()
        }]);
        let spoof = build::v4([100, 64, 0, 9], B_IP, 1, &build::icmp(8));
        let first = a.outbound(&spoof, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert!(tun_b.is_empty());
        assert_eq!(b.drops().inbound_error, 1);
        assert_eq!(b.drops().inbound_acl, 0);
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

    /// Many packets of varying length both ways through one session: each arrives intact, so a reused
    /// buffer never leaks a previous packet's bytes or length.
    #[test]
    fn many_packets_both_directions_arrive_intact() {
        let (mut a, pa, mut b, pb) = pair();
        a.set_filter_rules(allow_all());
        b.set_filter_rules(allow_all());
        let (sa, sb) = (
            "100.64.0.1:5000".parse().unwrap(),
            "100.64.0.2:5001".parse().unwrap(),
        );
        let first = a.outbound(&ippkt::build_udp4(sa, sb, b"hello"), Duration::ZERO);
        run(&mut a, pa, &mut b, pb, first);
        for i in 0..10_000u32 {
            let payload: Vec<u8> = (0..(i % 1400) + 1).map(|j| (i + j) as u8).collect();
            let ab = ippkt::build_udp4(sa, sb, &payload);
            let wire = wire_of(a.outbound(&ab, Duration::ZERO), i);
            assert_eq!(
                b.inbound(pa, &wire, Duration::ZERO),
                vec![Output::ToTun(ab)],
                "A->B {i}"
            );
            let ba = ippkt::build_udp4(sb, sa, &payload);
            let wire = wire_of(b.outbound(&ba, Duration::ZERO), i);
            assert_eq!(
                a.inbound(pb, &wire, Duration::ZERO),
                vec![Output::ToTun(ba)],
                "B->A {i}"
            );
        }
    }

    /// The one encrypted datagram an outbound call must produce.
    fn wire_of(outs: Vec<Output>, i: u32) -> Vec<u8> {
        match <[Output; 1]>::try_from(outs) {
            Ok([Output::ToPeer(_, wire)]) => wire,
            other => panic!("packet {i}: {other:?}"),
        }
    }

    fn picked(dp: &mut Dataplane, dst: [u8; 4]) -> Option<NodePublic> {
        dp.route(IpAddr::from(dst))
    }

    /// Longest prefix wins between a host address and an overlapping subnet route, for both orders of
    /// arrival, and routing follows a peer set change.
    #[test]
    fn longest_prefix_wins_and_follows_peer_changes() {
        let me = NodePrivate::generate().unwrap();
        let (b, c) = (
            NodePrivate::generate().unwrap().public(),
            NodePrivate::generate().unwrap().public(),
        );
        let mut dp = Dataplane::new(me);
        let host = |k| PeerConfig {
            key: k,
            allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
            ..Default::default()
        };
        let subnet = |k| PeerConfig {
            key: k,
            allowed_ips: vec![
                "100.64.0.0/24".parse().unwrap(),
                "fd7a:115c:a1e0::/48".parse().unwrap(),
            ],
            ..Default::default()
        };
        dp.set_peers(vec![host(b), subnet(c)]);
        assert_eq!(picked(&mut dp, B_IP), Some(b));
        assert_eq!(picked(&mut dp, [100, 64, 0, 9]), Some(c));
        assert_eq!(
            picked(&mut dp, B_IP),
            Some(b),
            "a lookup of another address must not disturb this one"
        );
        dp.set_peers(vec![subnet(b), host(c)]);
        assert_eq!(picked(&mut dp, B_IP), Some(c), "the host route moved to C");
        assert_eq!(picked(&mut dp, [100, 64, 0, 9]), Some(b));
        dp.set_peers(vec![subnet(b)]);
        assert_eq!(
            picked(&mut dp, B_IP),
            Some(b),
            "host route gone: the subnet route takes over"
        );
        dp.set_peers(vec![]);
        assert_eq!(picked(&mut dp, B_IP), None);
    }

    /// The next outbound packet's WireGuard message type: 1 = handshake initiation (new session),
    /// 4 = data (session kept).
    fn next_type(a: &mut Dataplane) -> u8 {
        let ping = build::v4(A_IP, B_IP, 1, &build::icmp(8));
        match a.outbound(&ping, Duration::ZERO).as_slice() {
            [Output::ToPeer(_, bytes)] => bytes[0],
            other => panic!("{other:?}"),
        }
    }

    /// A peer whose disco key changes has restarted and lost our session: replace it at once
    /// instead of sending into the void until rekey (2-3 minutes in the lab). A key that was
    /// unknown (zero) and becomes known is not a restart.
    #[test]
    fn disco_key_change_replaces_the_session() {
        let (mut a, pa, mut b, pb) = pair();
        b.set_filter_rules(allow_all());
        let cfg = |disco: u8| PeerConfig {
            key: pb,
            allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
            disco: DiscoPublic([disco; 32]),
        };
        let ping = build::v4(A_IP, B_IP, 1, &build::icmp(8));
        let first = a.outbound(&ping, Duration::ZERO);
        run(&mut a, pa, &mut b, pb, first);
        a.set_peers(vec![cfg(0)]);
        a.set_peers(vec![cfg(7)]);
        assert_eq!(next_type(&mut a), 4, "zero -> known: session kept");
        a.set_peers(vec![cfg(7)]);
        assert_eq!(next_type(&mut a), 4, "unchanged: session kept");
        a.set_peers(vec![cfg(8)]);
        assert_eq!(next_type(&mut a), 1, "changed: new handshake");
    }

    /// A destination outside the local nets is dropped even though the filter allows everything.
    #[test]
    fn inbound_destination_must_be_local() {
        let (mut a, pa, mut b, pb) = pair();
        b.set_filter_rules(allow_all());
        b.set_local_nets(crate::netset::LocalNets::new(["100.64.0.2/32"
            .parse()
            .unwrap()]));
        let to_b = build::v4(A_IP, B_IP, 1, &build::icmp(8));
        let first = a.outbound(&to_b, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert_eq!(tun_b, vec![to_b], "control: B's own address passes");
        // A routes 10.9.9.9 to B (as if B were its router), but B does not route it.
        a.set_peers(vec![PeerConfig {
            key: pb,
            allowed_ips: vec![
                "100.64.0.2/32".parse().unwrap(),
                "10.9.9.0/24".parse().unwrap(),
            ],
            ..Default::default()
        }]);
        let elsewhere = build::v4(A_IP, [10, 9, 9, 9], 1, &build::icmp(8));
        let first = a.outbound(&elsewhere, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert!(tun_b.is_empty(), "not B's to deliver");
        b.set_local_nets(crate::netset::LocalNets::new([
            "100.64.0.2/32".parse().unwrap(),
            "10.9.9.0/24".parse().unwrap(),
        ]));
        let first = a.outbound(&elsewhere, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert_eq!(
            tun_b,
            vec![elsewhere],
            "once B routes the subnet, it delivers"
        );
    }

    /// TCP to a peerapi listener passes without a filter rule; other ports of the same address do not.
    #[test]
    fn peerapi_listener_skips_the_filter() {
        let (mut a, pa, mut b, pb) = pair();
        // No rules at B: new TCP connections are refused, except to its peerapi port.
        b.set_peerapi(vec!["100.64.0.2:4321".parse().unwrap()]);
        let to_api = build::v4(A_IP, B_IP, 6, &build::tcp(40000, 4321, 0x02));
        let first = a.outbound(&to_api, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert_eq!(tun_b, vec![to_api]);
        let to_ssh = build::v4(A_IP, B_IP, 6, &build::tcp(40000, 22, 0x02));
        let first = a.outbound(&to_ssh, Duration::ZERO);
        let (_, tun_b) = run(&mut a, pa, &mut b, pb, first);
        assert!(tun_b.is_empty(), "any other port still needs a rule");
    }

    /// WireGuard identifies the sender from the datagram, not the address: a handshake initiation by
    /// the static key inside it, later messages by our session index. A peer that just restarted
    /// has not mapped our address yet and must still accept our handshake.
    #[test]
    fn peer_is_recognized_from_the_datagram_itself() {
        let (mut a, pa, mut b, pb) = pair();
        b.set_filter_rules(allow_all());
        let from: IpAddr = "192.0.2.1".parse().unwrap();
        let ping = build::v4(A_IP, B_IP, 1, &build::icmp(8));
        let init = wire_of(a.outbound(&ping, Duration::ZERO), 0);
        assert_eq!(
            b.peer_for_datagram(from, &init),
            Some(pa),
            "initiation: by static key"
        );
        let resp = match b.inbound(pa, &init, Duration::ZERO).as_slice() {
            [Output::ToPeer(_, r), ..] => r.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            a.peer_for_datagram(from, &resp),
            Some(pb),
            "response: by session index"
        );
        let data = a.inbound(pb, &resp, Duration::ZERO);
        let Some(Output::ToPeer(_, data)) = data.into_iter().next() else {
            panic!("no queued data after the handshake")
        };
        assert_eq!(data[0], 4);
        assert_eq!(
            b.peer_for_datagram(from, &data),
            Some(pa),
            "data: by session index"
        );

        // Not a peer of B: a stranger's initiation is not attributed to anyone.
        let mut stranger = Dataplane::new(NodePrivate::generate().unwrap());
        stranger.set_peers(vec![PeerConfig {
            key: pb,
            allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
            ..Default::default()
        }]);
        let foreign = wire_of(stranger.outbound(&ping, Duration::ZERO), 0);
        assert_eq!(b.peer_for_datagram(from, &foreign), None);
        // Garbage, a bad MAC, an unknown index, a removed peer: nothing.
        assert_eq!(
            b.peer_for_datagram(from, &[4, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f]),
            None
        );
        let mut bad = init.clone();
        bad[100] ^= 1;
        assert_eq!(b.peer_for_datagram(from, &bad), None);
        assert_eq!(b.peer_for_datagram(from, b"not wireguard"), None);
        b.set_peers(vec![]);
        assert_eq!(b.peer_for_datagram(from, &init), None);
        assert_eq!(b.peer_for_datagram(from, &data), None);
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
            ..Default::default()
        }]);
        let again = a.outbound(&ping, Duration::ZERO);
        assert!(
            matches!(again.as_slice(), [Output::ToPeer(_, bytes)] if bytes[0] == 4),
            "{again:?}"
        );
    }
}
