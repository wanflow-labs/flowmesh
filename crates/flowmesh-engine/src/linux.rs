// SPDX-License-Identifier: Apache-2.0
//! Main loop: TUN, UDP (WireGuard / disco / STUN sharing one port), DERP, network map updates, and timers.
//!
//! Route selection is done by flowmesh-pathsock: direct (UDP) or DERP for each peer.

use crate::command::{EngineCommand, PendingPing, deliver_pings, expire_pings};
use crate::control_loop::{Backoff, BoxFut as LoopFut, ControlEvent, MessageStream};
use crate::logic::{
    apply_netmap, dns_upstreams, dns_view, endpoints_for, local_nets, looks_like_wireguard,
    mode_of, peer_home, relay_candidates, snapshot, subnet_routes,
};
use crate::relay_plan::{RelayAction, RelayPlan};
use crate::status::EngineStatus;
use crate::{EngineConfig, EngineError};
use flowmesh_control::client::ControlClient;
use flowmesh_control::netmap::NetMap;
use flowmesh_dataplane::plane::{Dataplane, Output};
use flowmesh_derp::client::{DerpClient, DerpSender, Event};
use flowmesh_disco::message::Message;
use flowmesh_disco::relay::{Geneve, PROTO_DISCO, PROTO_WIREGUARD, geneve_decode, geneve_encode};
use flowmesh_pathsock::{Action, Mode, PathSock, Random, Route, Source};
use flowmesh_proto::capver::CAPABILITY_VERSION;
use flowmesh_proto::control::{
    Hostinfo, MapRequest, MapResponse, NetInfo, RegisterAuth, RegisterRequest,
};
use flowmesh_proto::derp::{DerpMap, DerpNode};
use flowmesh_proto::key::{DiscoPrivate, DiscoPublic, NodePrivate, NodePublic};
use flowmesh_udprelay::{RelayAction as PeerRelayAction, RelayClient};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

const TICK: Duration = Duration::from_millis(250);
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Home may be down this long (a redial) before the health report mentions it.
const HOME_HEALTH_GRACE: Duration = Duration::from_secs(5);
const MTU: u16 = 1280;
const DEFAULT_STUN_PORT: u16 = 3478;

/// Resolve `--exit-node` against the current network map; returns why it cannot be used, if so.
/// The routing through the mesh stays in place either way: traffic does not leak around an exit
/// node that is unknown or offline (the official client also keeps routing to it).
fn select_exit_node(
    policy: &mut crate::logic::Policy,
    nm: &flowmesh_control::netmap::NetMap,
    spec: &str,
) -> Option<String> {
    if spec.is_empty() {
        policy.exit_node = None;
        return None;
    }
    match crate::logic::resolve_exit_node(nm, spec) {
        Ok(key) => {
            policy.exit_node = Some(key);
            let offers = nm
                .peers
                .values()
                .find(|n| n.key == key)
                .is_some_and(|n| n.allowed_ips.iter().any(|p| p.prefix_len() == 0));
            (!offers).then(|| format!("exit node {spec} does not offer to be an exit node; internet traffic is dropped"))
        }
        Err(e) => {
            policy.exit_node = None;
            Some(format!(
                "{e}; internet traffic is dropped until it is found"
            ))
        }
    }
}

/// With --accept-dns, the health message when resolv.conf belongs to another service (it is then
/// left alone; MagicDNS still answers).
fn dns_owner_message(accept_dns: bool) -> Option<String> {
    if !accept_dns {
        return None;
    }
    let target = flowmesh_netcfg::resolv::managed_elsewhere(std::path::Path::new(RESOLV))?;
    let msg = format!(
        "{RESOLV} links to {} (managed by another service), so it was left alone; MagicDNS still answers at {QUAD100}",
        target.display()
    );
    log(&msg);
    Some(msg)
}

pub(crate) fn log(msg: impl std::fmt::Display) {
    eprintln!("flowmesh: {msg}");
}

struct OsRandom;

impl Random for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) {
        if getrandom::fill(buf).is_err() {
            // Without a system random source we must not produce a predictable transaction ID; abort.
            panic!("system random source failed");
        }
    }
}

fn ip(args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new("ip")
        .args(args)
        .status()
        .map_err(|e| format!("ip {}: {e}", args.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("ip {} failed: {status}", args.join(" ")))
    }
}

/// This host's interface networks and addresses, both families, without the mesh interface and
/// loopback (`ip -o addr`), for the exit node's shrunk default route.
pub(crate) fn interfaces(tun: &str) -> crate::logic::Interfaces {
    let Ok(out) = std::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
    else {
        return Default::default();
    };
    let mut ifs = crate::logic::Interfaces::default();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut w = line.split_whitespace();
        let (Some(_), Some(dev)) = (w.next(), w.next()) else {
            continue;
        };
        if dev == tun || dev == "lo" {
            continue;
        }
        if !matches!(w.next(), Some("inet" | "inet6")) {
            continue;
        }
        let Some(net) = w.next().and_then(|c| c.parse::<IpNet>().ok()) else {
            continue;
        };
        if net.addr().is_loopback() || net.prefix_len() == net.max_prefix_len() {
            continue;
        }
        ifs.hosts.push(net.addr());
        ifs.nets.push(net.trunc());
    }
    ifs
}

/// Local IPv4 addresses (global scope, excluding the TUN itself) as endpoint candidates.
fn local_endpoints(tun: &str, port: u16) -> Vec<SocketAddr> {
    let Ok(out) = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show", "scope", "global"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.split_whitespace().nth(1) != Some(tun))
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            w.find(|t| *t == "inet")?;
            let cidr = w.next()?;
            let ip: IpAddr = cidr.split('/').next()?.parse().ok()?;
            Some(SocketAddr::new(ip, port))
        })
        .collect()
}

/// DERP connections, driven by `RelayPlan` (design §7.2): reconnect when a relay drops, back off on
/// failures, fail home over to another region. Connections after start-up are made in background
/// tasks whose results come back on `ready`, so a dead relay cannot stall the event loop.
struct Relays {
    me: NodePrivate,
    senders: HashMap<u32, DerpSender>,
    events: mpsc::Sender<(u32, Event)>,
    ready: mpsc::Sender<(u32, Result<DerpSender, String>)>,
    plan: RelayPlan,
    epoch: Instant,
    /// The last connection error per region, for the health report.
    last_error: HashMap<u32, String>,
}

impl Relays {
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }

    /// Start-up: try home once inline, so the first packets usually find a relay. If it cannot be
    /// reached the engine still comes up (peers may be reachable directly) and the plan keeps
    /// retrying and fails over; the outage shows in the health report.
    async fn connect_home(&mut self, region: u32, dm: &DerpMap) {
        let result = match relay_node(region, dm) {
            None => Err("region not in the DERP map".to_string()),
            Some(node) => match tokio::time::timeout(
                RELAY_CONNECT_TIMEOUT,
                DerpClient::connect(&node, &self.me),
            )
            .await
            {
                Ok(Ok(c)) => {
                    log(format!(
                        "connected to DERP region {region} ({})",
                        node.host_name
                    ));
                    Ok(forward_events(region, c, self.events.clone()))
                }
                Ok(Err(e)) => Err(format!("{}: {e}", node.host_name)),
                Err(_) => Err(format!(
                    "{}: no answer within {RELAY_CONNECT_TIMEOUT:?}",
                    node.host_name
                )),
            },
        };
        match result {
            Ok(s) => {
                self.senders.insert(region, s.clone());
                let _ = s.note_preferred(true).await;
            }
            Err(e) => {
                log(format!(
                    "cannot reach home DERP region {region}: {e}; retrying in the background"
                ));
                self.plan = RelayPlan::start_unreachable(region, self.now());
                self.last_error.insert(region, e);
            }
        }
    }

    /// Health line while home has been unreachable for a while (a quick redial stays silent).
    fn health(&self) -> Option<String> {
        let down = self.plan.home_down_for(self.now())?;
        if down < HOME_HEALTH_GRACE {
            return None;
        }
        let home = self.plan.home();
        Some(match self.last_error.get(&home) {
            Some(e) => format!("cannot reach home DERP region {home}: {e}"),
            None => format!("cannot reach home DERP region {home}"),
        })
    }

    fn spawn_connect(&self, region: u32, dm: &DerpMap) {
        let ready = self.ready.clone();
        let Some(node) = relay_node(region, dm) else {
            let _ = ready.try_send((region, Err("region not in the DERP map".into())));
            return;
        };
        let me = self.me.clone();
        let events = self.events.clone();
        tokio::spawn(async move {
            // An unreachable address may never answer the TCP handshake: bound the attempt.
            let result =
                match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, DerpClient::connect(&node, &me))
                    .await
                {
                    Ok(Ok(c)) => Ok(forward_events(region, c, events)),
                    Ok(Err(e)) => Err(format!("{}: {e}", node.host_name)),
                    Err(_) => Err(format!(
                        "{}: no answer within {RELAY_CONNECT_TIMEOUT:?}",
                        node.host_name
                    )),
                };
            let _ = ready.send((region, result)).await;
        });
    }

    /// Carry out the plan's actions; returns the new home if it changed.
    fn act(&mut self, acts: Vec<RelayAction>, dm: &DerpMap) -> Option<u32> {
        let mut new_home = None;
        for a in acts {
            match a {
                RelayAction::Connect(region) => self.spawn_connect(region, dm),
                RelayAction::SetHome(region) => new_home = Some(region),
            }
        }
        new_home
    }

    /// A background connection attempt finished.
    fn on_ready(&mut self, region: u32, result: Result<DerpSender, String>) {
        match result {
            Ok(s) => {
                self.plan.on_connected(region);
                self.senders.insert(region, s.clone());
                log(format!("connected to DERP region {region}"));
                if region == self.plan.home() {
                    tokio::spawn(async move {
                        let _ = s.note_preferred(true).await;
                    });
                }
            }
            Err(e) => {
                let now = self.now();
                self.plan.on_failed(region, now);
                log(format!("DERP region {region}: {e}"));
                self.last_error.insert(region, e);
            }
        }
    }

    fn on_closed(&mut self, region: u32, dm: &DerpMap) -> Option<u32> {
        self.senders.remove(&region);
        let now = self.now();
        let acts = self.plan.on_closed(region, now);
        self.act(acts, dm)
    }

    fn tick(&mut self, dm: &DerpMap) -> Option<u32> {
        let now = self.now();
        let acts = self.plan.tick(now, dm);
        let new_home = self.act(acts, dm);
        if let Some(home) = new_home {
            if let Some(s) = self.senders.get(&home).cloned() {
                tokio::spawn(async move {
                    let _ = s.note_preferred(true).await;
                });
            }
        }
        new_home
    }

    /// Send via `region` if connected; otherwise start connecting and drop the packet, as a lossy
    /// path would.
    async fn send(&mut self, region: u32, dm: &DerpMap, to: NodePublic, data: &[u8]) {
        let now = self.now();
        let (ready, acts) = self.plan.want(region, now);
        self.act(acts, dm);
        if !ready {
            return;
        }
        let Some(s) = self.senders.get(&region).cloned() else {
            return;
        };
        if let Err(e) = s.send(to, data).await {
            log(format!("DERP send via region {region}: {e}"));
            self.on_closed(region, dm);
        }
    }
}

/// Split a connection, forward its events (tagged with the region) to the loop, return its sender.
fn forward_events(region: u32, c: DerpClient, events: mpsc::Sender<(u32, Event)>) -> DerpSender {
    let (s, mut rx) = c.split();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if events.send((region, ev)).await.is_err() {
                return;
            }
        }
    });
    s
}

/// How long one latency probe may take before the region counts as not answering.
const HOME_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Pick home among several regions by TCP connect time to each region's relay (flowmesh's choice:
/// it works in every relay mode, including prefer where STUN is off; derp.md "Connection liveness").
async fn choose_home(dm: &DerpMap) -> Option<(u32, DerpNode)> {
    let candidates = crate::logic::home_candidates(dm);
    if candidates.len() <= 1 {
        return candidates.into_iter().next();
    }
    let mut probes = tokio::task::JoinSet::new();
    for (id, node) in &candidates {
        let id = *id;
        let host = if node.ipv4.is_empty() {
            node.host_name.clone()
        } else {
            node.ipv4.clone()
        };
        let port = if node.derp_port == 0 {
            443
        } else {
            node.derp_port
        };
        probes.spawn(async move {
            let t = Instant::now();
            let ok =
                tokio::time::timeout(HOME_PROBE_TIMEOUT, flowmesh_net::tcp_connect(&host, port))
                    .await
                    .is_ok_and(|r| r.is_ok());
            (id, ok.then(|| t.elapsed()))
        });
    }
    let mut measured = Vec::with_capacity(candidates.len());
    while let Some(r) = probes.join_next().await {
        if let Ok(m) = r {
            measured.push(m);
        }
    }
    measured.sort_by_key(|(id, _)| *id);
    log(format!("home DERP latency: {measured:?}"));
    let id = crate::logic::pick_by_latency(&measured)?;
    candidates.into_iter().find(|(c, _)| *c == id)
}

/// The node to connect to for a region: the first that is not STUN-only, in the server's order.
fn relay_node(region: u32, dm: &DerpMap) -> Option<DerpNode> {
    dm.regions
        .get(&region)?
        .nodes
        .iter()
        .find(|n| !n.stun_only)
        .cloned()
}

/// MagicDNS address (dns.md).
const QUAD100: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 100, 100, 100);
const RESOLV: &str = "/etc/resolv.conf";
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

/// Whether the host has a global IPv6 address (excluding our own TUN); used to decide whether to answer AAAA (dns.md §2, pending verification).
fn host_has_ipv6(tun: &str) -> bool {
    std::process::Command::new("ip")
        .args(["-o", "-6", "addr", "show", "scope", "global"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.split_whitespace().nth(1) != Some(tun))
        })
        .unwrap_or(false)
}

/// Forward a query to the first upstream; wrap the answer as a packet from 100.100.100.100 back to the querier and send it to the main loop to write to TUN.
fn forward_dns(
    upstreams: Vec<IpAddr>,
    query: Vec<u8>,
    client: std::net::SocketAddrV4,
    quad100: std::net::SocketAddrV4,
    tx: mpsc::Sender<Vec<u8>>,
) {
    tokio::spawn(async move {
        let Some(&up) = upstreams.first() else {
            return;
        };
        let bind = if up.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let Ok(sock) = UdpSocket::bind(bind).await.inspect(flowmesh_net::mark) else {
            return;
        };
        if sock.send_to(&query, (up, 53)).await.is_err() {
            return;
        }
        let mut buf = vec![0u8; 4096];
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(DNS_FORWARD_TIMEOUT, sock.recv_from(&mut buf)).await
        {
            let pkt = flowmesh_dataplane::ippkt::build_udp4(quad100, client, &buf[..n]);
            let _ = tx.send(pkt).await;
        }
    });
}

/// Send a MagicDNS query to the exit node's DNS proxy (POST /dns-query over the mesh; the socket is
/// marked, so it uses the main table, whose mesh route goes through the TUN).
fn forward_doh(
    target: SocketAddr,
    query: Vec<u8>,
    client: std::net::SocketAddrV4,
    quad100: std::net::SocketAddrV4,
    tx: mpsc::Sender<Vec<u8>>,
) {
    tokio::spawn(async move {
        let ask = async {
            let tcp = flowmesh_net::tcp_connect(&target.ip().to_string(), target.port())
                .await
                .ok()?;
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp))
                    .await
                    .ok()?;
            tokio::spawn(conn);
            let req = hyper::Request::post("/dns-query")
                .header(hyper::header::HOST, target.to_string())
                .header(hyper::header::CONTENT_TYPE, "application/dns-message")
                .header(hyper::header::ACCEPT, "application/dns-message")
                .body(http_body_util::Full::new(bytes::Bytes::from(query)))
                .ok()?;
            let resp = sender.send_request(req).await.ok()?;
            if !resp.status().is_success() {
                return None;
            }
            use http_body_util::BodyExt;
            Some(resp.into_body().collect().await.ok()?.to_bytes())
        };
        if let Ok(Some(answer)) = tokio::time::timeout(DNS_FORWARD_TIMEOUT, ask).await {
            let pkt = flowmesh_dataplane::ippkt::build_udp4(quad100, client, &answer);
            let _ = tx.send(pkt).await;
        }
    });
}

/// Bring the installed subnet routes in line with `want` (via the TUN).
fn sync_routes(
    tun: &str,
    installed: &mut std::collections::BTreeSet<ipnet::IpNet>,
    want: std::collections::BTreeSet<ipnet::IpNet>,
) {
    for gone in installed.difference(&want) {
        let fam = if gone.addr().is_ipv4() { "-4" } else { "-6" };
        if let Err(e) = ip(&[fam, "route", "del", &gone.to_string(), "dev", tun]) {
            log(format!("route del {gone}: {e}"));
        }
    }
    for new in want.difference(installed) {
        let fam = if new.addr().is_ipv4() { "-4" } else { "-6" };
        if let Err(e) = ip(&[fam, "route", "replace", &new.to_string(), "dev", tun]) {
            log(format!("route add {new}: {e}"));
        }
    }
    if *installed != want {
        log(format!("subnet routes: {want:?}"));
    }
    *installed = want;
}

/// How often the status snapshot is refreshed.
const STATUS_INTERVAL: Duration = Duration::from_secs(1);

/// The live netmap stream, as the reconnect loop sees it. With a tap directory (lab observation
/// only, `flowmesh-dev --tap-dir`) every message's JSON is saved as `map-<n>.json`.
struct Live {
    stream: flowmesh_control::client::MapStream,
    tap: Option<(std::path::PathBuf, Arc<std::sync::atomic::AtomicU64>)>,
}

impl MessageStream for Live {
    fn next(&mut self) -> LoopFut<'_, Result<Option<MapResponse>, String>> {
        Box::pin(async move {
            let m = self
                .stream
                .next()
                .await
                .map_err(|e| format!("map stream: {e}"))?;
            if let (Some(m), Some((dir, seq))) = (&m, &self.tap) {
                let n = seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = std::fs::write(dir.join(format!("map-{n:05}.json")), &m.json) {
                    log(format!("tap write: {e}"));
                }
            }
            Ok(m.map(|m| m.parsed))
        })
    }
}

/// Aborts the task when the engine returns, whichever way it returns.
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Design §7.2: an expired node key ends the run as "not authorized", so the daemon shows NeedsLogin
/// with the reason instead of carrying on with a key the mesh no longer accepts.
fn check_key(nm: &NetMap, control_time: Option<&str>) -> Result<(), EngineError> {
    let now = crate::logic::unix_now();
    match &nm.self_node {
        Some(me) if crate::logic::key_expired(me, control_time, now) => {
            log("node key expired");
            Err(EngineError::NotAuthorized {
                auth_url: String::new(),
                error: "node key expired".into(),
            })
        }
        _ => Ok(()),
    }
}

/// Send a one-shot, non-streaming map update to the control server (home relay and endpoints).
fn report(client: Arc<ControlClient>, req: MapRequest) {
    tokio::spawn(async move {
        match client.map(&req).await {
            Ok(mut s) => while let Ok(Some(_)) = s.next().await {},
            Err(e) => log(format!("map update: {e}")),
        }
    });
}

struct Ctx {
    udp: Arc<UdpSocket>,
    relays: Relays,
    ps: PathSock,
    nm: NetMap,
    rng: OsRandom,
    /// This run's disco key: seals peer relay messages and opens those addressed to us.
    disco: DiscoPrivate,
    /// The peer relay client (allocations, forwards, the bind handshake).
    peer_relay: RelayClient,
    /// Batched sends on `udp`.
    udp_tx: crate::udpio::UdpTx,
    /// WireGuard datagrams routed to a UDP address (direct or peer relay), sent together by
    /// `flush` so that runs to one destination can leave in one GSO send.
    pending: Vec<Pending>,
    /// WireGuard traffic per path, for `flowmesh metrics`.
    traffic: crate::metrics::Traffic,
    /// Datagrams for a peer that could not be sent (no path, send error).
    send_errors: u64,
}

/// A WireGuard datagram waiting in `Ctx::pending`.
struct Pending {
    to: SocketAddr,
    data: Vec<u8>,
    /// The peer, for a direct send: a failed send falls back to DERP. None for the peer relay.
    direct: Option<NodePublic>,
}

/// Flush `Ctx::pending` once it holds this many datagrams even if more input is waiting.
const PENDING_MAX: usize = 128;

/// A packet for a peer relay path: Geneve header (no O bit) + payload (peer-relay.md §3).
fn relayed(vni: u32, protocol: u16, payload: &[u8]) -> Vec<u8> {
    let h = Geneve {
        control: false,
        protocol,
        vni,
    };
    [&geneve_encode(&h)[..], payload].concat()
}

impl Ctx {
    async fn run_actions(&mut self, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Udp { to, data } => {
                    if let Err(e) = self.udp.send_to(&data, to).await {
                        log(format!("udp send {to}: {e}"));
                    }
                }
                Action::Derp { to, region, data } => {
                    self.relays.send(region, &self.nm.derp_map, to, &data).await;
                }
                Action::Relay { server, vni, data } => {
                    let packet = relayed(vni, PROTO_DISCO, &data);
                    if let Err(e) = self.udp.send_to(&packet, server).await {
                        log(format!("peer relay send {server}: {e}"));
                    }
                }
            }
        }
    }

    /// Seal and send what the peer relay client asks for, then hand the bound endpoints to path selection.
    async fn run_relay(&mut self, actions: Vec<PeerRelayAction>) {
        for a in actions {
            match a {
                PeerRelayAction::Derp {
                    to,
                    to_disco,
                    region,
                    msg,
                } => {
                    if let Some(sealed) = self.seal(&to_disco, &msg) {
                        self.relays
                            .send(region, &self.nm.derp_map, to, &sealed)
                            .await;
                    }
                }
                PeerRelayAction::Server {
                    addr,
                    vni,
                    to_disco,
                    msg,
                } => {
                    if let Some(sealed) = self.seal(&to_disco, &msg) {
                        let h = Geneve {
                            control: true,
                            protocol: PROTO_DISCO,
                            vni,
                        };
                        let packet = [&geneve_encode(&h)[..], &sealed].concat();
                        if let Err(e) = self.udp.send_to(&packet, addr).await {
                            log(format!("peer relay send {addr}: {e}"));
                        }
                    }
                }
            }
        }
        self.sync_relay();
    }

    fn seal(&mut self, to: &DiscoPublic, msg: &Message) -> Option<Vec<u8>> {
        let mut nonce = [0u8; flowmesh_disco::envelope::NONCE_LEN];
        self.rng.fill(&mut nonce);
        flowmesh_disco::envelope::seal(
            &self.disco,
            to,
            &flowmesh_disco::message::encode(msg),
            nonce,
        )
        .ok()
    }

    /// Each peer's bound peer relay endpoint (or none) to path selection.
    fn sync_relay(&mut self) {
        for n in self.nm.peers.values() {
            let ep = self
                .peer_relay
                .endpoint(&n.disco_key)
                .map(|e| (e.addr, e.vni));
            self.ps.set_relay(n.key, ep);
        }
    }

    /// Pongs that came through peer relays keep the relay client's liveness current.
    fn relay_pongs(&mut self, now: Duration) {
        for node in self.ps.take_relay_pongs() {
            if let Some(n) = self.nm.peers.values().find(|n| n.key == node) {
                self.peer_relay.on_relay_pong(&n.disco_key, now);
            }
        }
    }

    async fn send_to_peer(&mut self, key: NodePublic, bytes: Vec<u8>, now: Duration) {
        let (route, actions) = self.ps.route(key, now, &mut self.rng);
        self.run_actions(actions).await;
        // Traffic without a direct path: a peer relay is wanted (peer-relay.md §1).
        if !matches!(route, Route::Direct(_)) {
            let peer =
                self.nm
                    .peers
                    .values()
                    .find(|n| n.key == key)
                    .map(|n| flowmesh_udprelay::Peer {
                        node: n.key,
                        disco: n.disco_key,
                        home_region: peer_home(n),
                    });
            if let Some(peer) = peer {
                let acts = self.peer_relay.want(&peer, now);
                if !acts.is_empty() {
                    self.run_relay(acts).await;
                }
            }
        }
        use crate::metrics::Path;
        match route {
            Route::Direct(addr) => {
                self.traffic.sent(Path::Direct(addr.ip()), bytes.len());
                self.pending.push(Pending {
                    to: addr,
                    data: bytes,
                    direct: Some(key),
                });
            }
            Route::PeerRelay { server, vni } => {
                self.traffic.sent(Path::PeerRelay(server.ip()), bytes.len());
                self.pending.push(Pending {
                    to: server,
                    data: relayed(vni, PROTO_WIREGUARD, &bytes),
                    direct: None,
                });
            }
            Route::Derp(region) => {
                self.traffic.sent(Path::Derp, bytes.len());
                self.relays
                    .send(region, &self.nm.derp_map, key, &bytes)
                    .await
            }
            Route::None => self.send_errors += 1,
        }
    }

    /// Send the pending datagrams, grouped per destination (order kept within each destination).
    async fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let mut pending = std::mem::take(&mut self.pending);
        pending.sort_by_key(|p| p.to);
        let mut start = 0;
        while start < pending.len() {
            let to = pending[start].to;
            let end = start + pending[start..].iter().take_while(|p| p.to == to).count();
            let run = &pending[start..end];
            let dgrams: Vec<&[u8]> = run.iter().map(|p| p.data.as_slice()).collect();
            if let Err(e) = self.udp_tx.send(&self.udp, to, &dgrams).await {
                for p in run {
                    match p.direct {
                        // Send failure: fall back to DERP immediately and resend (observed behavior).
                        Some(key) => {
                            self.ps.on_send_error(key);
                            let region = self
                                .nm
                                .peers
                                .values()
                                .find(|n| n.key == key)
                                .and_then(peer_home);
                            self.relays
                                .send(
                                    region.unwrap_or(self.relays.plan.home()),
                                    &self.nm.derp_map,
                                    key,
                                    &p.data,
                                )
                                .await;
                        }
                        None => {
                            self.send_errors += 1;
                            log(format!("peer relay send {to}: {e}"));
                        }
                    }
                }
            }
            start = end;
        }
        // Keep the allocation for the next batch.
        pending.clear();
        self.pending = pending;
    }
}

/// Run the engine until `stop` becomes true (or a fatal error). The status snapshot is published periodically through `status`.
/// UDP socket buffer size each way. The kernel default (about 208 KiB) overflows under GSO bursts
/// at gigabit rates; the reference client asks for 7 MiB.
const SOCKET_BUFFER: usize = 7 << 20;

/// Force the buffer sizes first (as root this ignores net.core.rmem_max/wmem_max), else ask within
/// the system limit. Failure only costs throughput, so it is logged, not fatal.
fn set_socket_buffers(sock: &UdpSocket) {
    use nix::sys::socket::{getsockopt, setsockopt, sockopt};
    let rcv = setsockopt(sock, sockopt::RcvBufForce, &SOCKET_BUFFER)
        .or_else(|_| setsockopt(sock, sockopt::RcvBuf, &SOCKET_BUFFER));
    let snd = setsockopt(sock, sockopt::SndBufForce, &SOCKET_BUFFER)
        .or_else(|_| setsockopt(sock, sockopt::SndBuf, &SOCKET_BUFFER));
    let got = |o: nix::Result<()>| match o {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("failed: {e}"),
    };
    // The kernel reports twice the size set (bookkeeping overhead), or less when capped.
    log(format!(
        "udp buffers: receive {} ({:?}), send {} ({:?})",
        got(rcv),
        getsockopt(sock, sockopt::RcvBuf).ok(),
        got(snd),
        getsockopt(sock, sockopt::SndBuf).ok()
    ));
}

pub async fn run(
    cfg: EngineConfig,
    status: watch::Sender<EngineStatus>,
    mut stop: watch::Receiver<bool>,
    mut commands: mpsc::Receiver<EngineCommand>,
) -> Result<(), EngineError> {
    let args = &cfg;
    if let Some(dir) = &args.tap_dir {
        std::fs::create_dir_all(dir).map_err(|e| format!("tap dir: {e}"))?;
    }
    let tap = |prefix: &str, data: &[u8], t: Duration| {
        if let Some(dir) = &args.tap_dir {
            let name = format!("{prefix}-{:010}.bin", t.as_millis());
            if let Err(e) = std::fs::write(dir.join(name), data) {
                log(format!("tap write: {e}"));
            }
        }
    };
    let mut keys = flowmesh_state::load_or_create(&args.state_file).map_err(|e| e.to_string())?;
    // The disco key is regenerated on every start (see flowmesh-state).
    let disco = flowmesh_proto::key::DiscoPrivate::generate().map_err(|e| e.to_string())?;
    if let Some(dir) = &args.tap_dir {
        // Lab observation only: save this run's disco private key so tapped disco messages can be decrypted offline.
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join("disco.key"))
            .and_then(|mut f| f.write_all(disco.to_hex().as_bytes()))
            .map_err(|e| format!("tap key: {e}"))?;
    }
    let client = Arc::new(
        ControlClient::connect(&args.login_server, &keys.machine)
            .await
            .map_err(|e| format!("control connect: {e}"))?,
    );
    // An exit node keeps this host's own networks out of the default route it offers.
    let mut exit_ifaces = args.advertise_exit_node.then(|| interfaces(&args.tun));
    let mut hostinfo = Hostinfo {
        ipn_version: format!("flowmesh-{}", env!("CARGO_PKG_VERSION")),
        os: "linux".into(),
        machine: std::env::consts::ARCH.into(),
        ..Default::default()
    };
    crate::features::apply_to_hostinfo(&mut hostinfo, args, Vec::new());
    let mut policy = crate::logic::Policy {
        shields_up: args.shields_up,
        accept_routes: args.accept_routes,
        exit_node: None,
    };
    // Why the configured exit node is not in use, for the health list.
    let mut exit_health: Option<String>;
    let register_req = |node_key: NodePublic, old_node_key: NodePublic| RegisterRequest {
        version: CAPABILITY_VERSION,
        node_key,
        old_node_key,
        auth: args
            .authkey
            .clone()
            .map(|auth_key| RegisterAuth { auth_key }),
        hostinfo: hostinfo.clone(),
        ..Default::default()
    };
    let (mut reg, _) = client
        .register(&register_req(keys.node.public(), NodePublic::default()))
        .await
        .map_err(|e| format!("register: {e}"))?;
    if reg.node_key_expired {
        // An expired node key cannot be renewed: register a fresh one in its place (OldNodeKey ties
        // it to the same node), keeping the machine key.
        let old = keys.node.public();
        keys = flowmesh_state::rotate_node_key(&args.state_file).map_err(|e| e.to_string())?;
        log("node key expired on the server; registering a new node key");
        reg = client
            .register(&register_req(keys.node.public(), old))
            .await
            .map_err(|e| format!("register: {e}"))?
            .0;
    }
    if !reg.machine_authorized {
        return Err(EngineError::NotAuthorized {
            auth_url: reg.auth_url,
            error: reg.error,
        });
    }
    let base_req = MapRequest {
        version: CAPABILITY_VERSION,
        compress: "zstd".into(),
        keep_alive: true,
        node_key: keys.node.public(),
        disco_key: disco.public(),
        stream: true,
        ..Default::default()
    };
    let mut stream = client
        .map(&MapRequest {
            hostinfo: hostinfo.clone(),
            ..base_req.clone()
        })
        .await
        .map_err(|e| format!("map: {e}"))?;
    let mut nm = NetMap::default();
    let first = stream
        .next()
        .await
        .map_err(|e| format!("map: {e}"))?
        .ok_or("map stream closed before first message")?;
    nm.apply(&first.parsed);
    check_key(&nm, first.parsed.control_time.as_deref())?;

    let (mut home, home_node) = choose_home(&nm.derp_map)
        .await
        .ok_or("no usable DERP region")?;
    hostinfo.net_info = Some(NetInfo {
        preferred_derp: home,
    });
    let udp = Arc::new(
        UdpSocket::bind(("0.0.0.0", args.port))
            .await
            .map_err(|e| format!("udp bind :{}: {e}", args.port))?,
    );
    set_socket_buffers(&udp);
    flowmesh_net::mark(udp.as_ref());
    let gro = crate::udpio::enable_gro(&udp);
    log(format!(
        "udp: GRO {}",
        if gro { "on" } else { "unavailable" }
    ));
    let mut mode = mode_of(&nm);
    let local = local_endpoints(&args.tun, args.port);
    let mut stun_mapped: Option<SocketAddr> = None;
    let mut endpoints = endpoints_for(mode, &local, stun_mapped);
    let lite = MapRequest {
        stream: false,
        omit_peers: true,
        ..base_req.clone()
    };
    report(
        client.clone(),
        MapRequest {
            hostinfo: hostinfo.clone(),
            endpoints: endpoints.clone(),
            ..lite.clone()
        },
    );
    log(format!(
        "home DERP region {home} ({}); mode={mode:?}; endpoints {endpoints:?}",
        home_node.host_name
    ));

    // STUN to learn the externally visible address (skipped in relay-only mode or when the node has STUNPort == -1).
    let mut stun_tx = None;
    if mode == Mode::Auto && home_node.stun_port != -1 {
        let port = u16::try_from(home_node.stun_port)
            .ok()
            .filter(|p| *p != 0)
            .unwrap_or(DEFAULT_STUN_PORT);
        let host = if home_node.ipv4.is_empty() {
            home_node.host_name.clone()
        } else {
            home_node.ipv4.clone()
        };
        let mut tx = [0u8; flowmesh_stun::TX_ID_LEN];
        OsRandom.fill(&mut tx);
        match tokio::net::lookup_host((host.as_str(), port))
            .await
            .map(|mut a| a.next())
        {
            Ok(Some(addr)) => {
                if let Err(e) = udp.send_to(&flowmesh_stun::binding_request(tx), addr).await {
                    log(format!("stun send: {e}"));
                }
                stun_tx = Some(tx);
            }
            other => log(format!("stun resolve {host}: {other:?}")),
        }
    }

    let me = nm.self_node.clone().ok_or("no self node in netmap")?;
    let mut builder = tun_rs::DeviceBuilder::new()
        .name(args.tun.clone())
        .mtu(MTU)
        .offload(true);
    for a in &me.addresses {
        builder = match a.addr() {
            IpAddr::V4(v4) => builder.ipv4(v4, 32u8, None),
            IpAddr::V6(v6) => builder.ipv6(v6, 128u8),
        };
    }
    let mut tun = crate::tunio::TunIo::new(builder.build_async().map_err(|e| format!("tun: {e}"))?);
    log(format!(
        "tun: offload {}",
        if tun.offload() { "on" } else { "unavailable" }
    ));
    ip(&["route", "replace", "100.64.0.0/10", "dev", &args.tun])?;
    ip(&[
        "-6",
        "route",
        "replace",
        "fd7a:115c:a1e0::/48",
        "dev",
        &args.tun,
    ])?;
    log(format!("{} up as {:?}", args.tun, me.addresses));

    let (ev_tx, mut ev_rx) = mpsc::channel::<(u32, Event)>(1024);
    let (ready_tx, mut ready_rx) = mpsc::channel::<(u32, Result<DerpSender, String>)>(64);
    let mut relays = Relays {
        me: keys.node.clone(),
        senders: HashMap::new(),
        events: ev_tx,
        ready: ready_tx,
        plan: RelayPlan::new(home),
        epoch: Instant::now(),
        last_error: HashMap::new(),
    };
    relays.connect_home(home, &nm.derp_map).await;

    // The netmap stream is kept alive by the reconnect loop (design §7.2): a redial opens a new
    // Noise connection, which `report` then uses too, and streams with the latest host info.
    let (client_tx, client_rx) = watch::channel(client.clone());
    let (stream_req_tx, stream_req_rx) = watch::channel(MapRequest {
        hostinfo: hostinfo.clone(),
        endpoints: endpoints.clone(),
        ..base_req.clone()
    });
    let (ctl_tx, mut ctl_rx) = mpsc::channel::<ControlEvent>(64);
    let map_tap = args
        .tap_dir
        .clone()
        .map(|d| (d, Arc::new(std::sync::atomic::AtomicU64::new(0))));
    let dial = {
        let map_tap = map_tap.clone();
        let server = args.login_server.clone();
        let machine = keys.machine.clone();
        move || {
            let server = server.clone();
            let machine = machine.clone();
            let req = stream_req_rx.borrow().clone();
            let client_tx = client_tx.clone();
            let tap = map_tap.clone();
            async move {
                let c = Arc::new(
                    ControlClient::connect(&server, &machine)
                        .await
                        .map_err(|e| format!("control connect: {e}"))?,
                );
                let s = c.map(&req).await.map_err(|e| format!("map: {e}"))?;
                let _ = client_tx.send(c);
                Ok(Live { stream: s, tap })
            }
        }
    };
    let _control_loop = AbortOnDrop(tokio::spawn(crate::control_loop::run(
        Some(Live {
            stream,
            tap: map_tap,
        }),
        dial,
        ctl_tx,
        Backoff::default(),
    )));
    let mut control_health: Option<String> = None;
    // Health messages at the last status publish, for `flowmesh metrics`.
    let mut warnings = 0usize;
    let mut peer_ids: Vec<i64> = Vec::new();

    let mut dp = Dataplane::new(keys.node.clone());
    let mut ctx = Ctx {
        udp: udp.clone(),
        relays,
        ps: PathSock::new(disco.clone(), keys.node.public()),
        nm,
        rng: OsRandom,
        disco: disco.clone(),
        peer_relay: RelayClient::new(disco.public()),
        udp_tx: crate::udpio::UdpTx::new(),
        pending: Vec::with_capacity(PENDING_MAX),
        traffic: Default::default(),
        send_errors: 0,
    };
    exit_health = select_exit_node(&mut policy, &ctx.nm, &args.exit_node);
    if let Err(e) = apply_netmap(
        &mut dp,
        &mut ctx.ps,
        &ctx.nm,
        crate::logic::unix_now(),
        &policy,
    ) {
        log(e);
    }
    dp.set_local_nets(local_nets(
        &ctx.nm,
        &args.advertise_routes,
        exit_ifaces.as_ref(),
    ));
    ctx.peer_relay
        .set_candidates(relay_candidates(&ctx.nm, crate::logic::unix_now()));
    ctx.ps.set_my_endpoints(endpoints.clone());

    // The backup lives in the state directory, so /etc needs to be writable only for resolv.conf itself
    // (the systemd unit opens just that file).
    let resolv_backup = args.state_file.with_file_name("resolv.conf.backup");
    let health: Vec<String> = Vec::new();
    // Subnet router / exit node rules and exit node routing, kept in line with the settings.
    let mut features = crate::features::Features::default();
    let ipv6_mesh = me.addresses.iter().any(|a| a.addr().is_ipv6());
    features.sync_forwarding(args, None);
    features.sync_exit_routing(args, None, ipv6_mesh);
    // resolv.conf: taken over with --accept-dns unless another service manages it.
    let mut dns_msg = dns_owner_message(args.accept_dns);
    let mut dns_taken = args.accept_dns && dns_msg.is_none();
    // MagicDNS: the upstream is the host's original nameserver (if a backup was left by a crash, take it from the backup).
    let original_resolv = std::fs::read_to_string(&resolv_backup)
        .or_else(|_| std::fs::read_to_string(RESOLV))
        .unwrap_or_default();
    let host_upstreams: Vec<IpAddr> = flowmesh_netcfg::resolv::parse_nameservers(&original_resolv)
        .into_iter()
        .filter(|a| *a != IpAddr::V4(QUAD100))
        .collect();
    let answer_aaaa = host_has_ipv6(&args.tun);
    let mut view = dns_view(&ctx.nm, answer_aaaa);
    let take_over_dns = |nm: &NetMap| -> Result<(), String> {
        let domains = nm
            .dns
            .as_ref()
            .map(|d| d.domains.clone())
            .unwrap_or_default();
        let content = flowmesh_netcfg::resolv::render(IpAddr::V4(QUAD100), &domains);
        flowmesh_netcfg::resolv::takeover(std::path::Path::new(RESOLV), &resolv_backup, &content)
            .map_err(|e| format!("resolv.conf takeover: {e}"))
    };
    if dns_taken {
        take_over_dns(&ctx.nm)?;
        log(format!(
            "MagicDNS: resolv.conf -> {QUAD100}; upstreams {host_upstreams:?}; answer AAAA={answer_aaaa}"
        ));
    }
    let restore_dns = |taken: bool| {
        if taken {
            match flowmesh_netcfg::resolv::restore(std::path::Path::new(RESOLV), &resolv_backup) {
                Ok(_) => log("resolv.conf restored"),
                Err(e) => log(format!("resolv.conf restore failed: {e}")),
            }
        }
    };
    let mut installed_routes = std::collections::BTreeSet::new();
    if args.accept_routes {
        sync_routes(&args.tun, &mut installed_routes, subnet_routes(&ctx.nm));
    }
    // Offering an exit node: the DNS proxy peers reach over the mesh (peerapi.rs).
    let rules = flowmesh_filter::compile::compile(&ctx.nm.filter_rules()).unwrap_or_default();
    if features
        .sync_peerapi(args, &me.addresses, rules, &host_upstreams, &mut dp)
        .await
    {
        crate::features::apply_to_hostinfo(&mut hostinfo, args, features.services());
        report(
            client_rx.borrow().clone(),
            MapRequest {
                hostinfo: hostinfo.clone(),
                endpoints: endpoints.clone(),
                ..lite.clone()
            },
        );
        stream_req_tx.send_replace(MapRequest {
            hostinfo: hostinfo.clone(),
            endpoints: endpoints.clone(),
            ..base_req.clone()
        });
    }
    // The settings in force; `set`/`up` change them while running (EngineCommand::Reconfigure).
    let mut cur = args.clone();
    let quad100_dns = std::net::SocketAddrV4::new(QUAD100, 53);
    let (dns_tx, mut dns_rx) = mpsc::channel::<Vec<u8>>(64);
    let start = Instant::now();
    let mut last_publish: Option<Duration> = None;
    let mut ticker = tokio::time::interval(TICK);
    let mut pings: Vec<PendingPing> = Vec::new();
    let mut udp_rx = crate::udpio::UdpRx::new();
    // MagicDNS answers produced inside the select (the TUN is borrowed there), written afterwards.
    let mut tun_replies: Vec<Vec<u8>> = Vec::new();
    loop {
        let now = start.elapsed();
        let outputs = tokio::select! {
                r = tun.next() => {
                    let pkt = r.map_err(|e| format!("tun read: {e}"))?;
                    match flowmesh_dataplane::ippkt::udp4_payload(pkt).filter(|(_, d, _)| *d == quad100_dns) {
                        Some((client, _, query)) => {
                            match flowmesh_dns::handle(&view, query) {
                                flowmesh_dns::Decision::Local(resp) => {
                                    let reply = flowmesh_dataplane::ippkt::build_udp4(quad100_dns, client, &resp);
                                    // Queued: written with the batch at the end of this turn.
                                    tun_replies.push(reply);
                                }
                                // Using an exit node with a DNS proxy: all forwarded DNS goes
                                // through it, as the official client does.
                                flowmesh_dns::Decision::Forward => match policy
                                    .exit_node
                                    .and_then(|k| crate::logic::exit_dns_target(&ctx.nm, k))
                                {
                                    Some(target) => forward_doh(target, query.to_vec(), client, quad100_dns, dns_tx.clone()),
                                    None => forward_dns(
                                        dns_upstreams(&ctx.nm, &host_upstreams),
                                        query.to_vec(),
                                        client,
                                        quad100_dns,
                                        dns_tx.clone(),
                                    ),
                                },
                                flowmesh_dns::Decision::Drop => {}
                            }
                            Vec::new()
                        }
                        None => dp.outbound(pkt, now),
                    }
                }
                Some(reply) = dns_rx.recv() => {
                    tun_replies.push(reply);
                    Vec::new()
                }
                r = stop.changed() => {
                    if r.is_err() || *stop.borrow() {
                        restore_dns(dns_taken);
                        return Ok(());
                    }
                    Vec::new()
                }
                r = udp_rx.next(&udp) => {
                    let (data, from) = r.map_err(|e| format!("udp read: {e}"))?;
                    // From one of our relay servers: Geneve-framed (peer-relay.md §3).
                    let relayed = if ctx.peer_relay.is_server(from) { geneve_decode(data) } else { None };
                    if let Some((h, payload)) = relayed {
                        if h.protocol == PROTO_DISCO && h.control {
                            // The server's handshake message, sealed to us with the server key.
                            if let Ok((_, plain)) = flowmesh_disco::envelope::open(&ctx.disco, payload) {
                                if let Ok(m) = flowmesh_disco::message::decode(&plain) {
                                    let acts = ctx.peer_relay.on_server(h.vni, &m, now);
                                    ctx.run_relay(acts).await;
                                }
                            }
                            Vec::new()
                        } else if h.protocol == PROTO_DISCO {
                            let acts = ctx.ps.on_disco(Source::Relay { server: from, vni: h.vni }, payload, now, &mut ctx.rng);
                            deliver_pings(&mut pings, ctx.ps.take_probe_results(), &ctx.nm);
                            ctx.relay_pongs(now);
                            ctx.run_actions(acts).await;
                            Vec::new()
                        } else if h.protocol == PROTO_WIREGUARD {
                            match dp
                                .peer_for_datagram(from.ip(), payload)
                                .or_else(|| ctx.ps.peer_for_relay(from, h.vni))
                            {
                                Some(peer) => {
                                    ctx.traffic.received(crate::metrics::Path::PeerRelay(from.ip()), payload.len());
                                    dp.inbound(peer, payload, now)
                                }
                                None => Vec::new(),
                            }
                        } else {
                            Vec::new()
                        }
                    } else if flowmesh_disco::envelope::is_disco(data) {
                        tap("udp-disco", data, now);
                        let acts = ctx.ps.on_disco(Source::Udp(from), data, now, &mut ctx.rng);
                        deliver_pings(&mut pings, ctx.ps.take_probe_results(), &ctx.nm);
                        ctx.run_actions(acts).await;
                        Vec::new()
                    } else if flowmesh_stun::is_stun(data) {
                        match flowmesh_stun::parse_response(data) {
                            Ok((tx, mapped)) if Some(tx) == stun_tx => {
                                stun_mapped = Some(mapped);
                                let next = endpoints_for(mode, &local, stun_mapped);
                                if next != endpoints {
                                    endpoints = next;
                                    ctx.ps.set_my_endpoints(endpoints.clone());
                                    log(format!("STUN: external address {mapped}; endpoints {endpoints:?}"));
                                    report(client_rx.borrow().clone(), MapRequest {
                                        hostinfo: hostinfo.clone(),
                                        endpoints: endpoints.clone(),
                                        ..lite.clone()
                                    });
                                    stream_req_tx.send_replace(MapRequest {
                                        hostinfo: hostinfo.clone(),
                                        endpoints: endpoints.clone(),
                                        ..base_req.clone()
                                    });
                                }
                            }
                            other => log(format!("ignoring STUN message: {other:?}")),
                        }
                        Vec::new()
                    } else if let Some(peer) = dp
                        .peer_for_datagram(from.ip(), data)
                        // WireGuard names the sender inside the datagram (static key, session
                        // index); an address can be stale or shared by several node records (a
                        // re-registered device keeps its address), or not mapped yet after a
                        // restart. The address is the fallback, e.g. when handshakes are
                        // rate-limited.
                        .or_else(|| ctx.ps.peer_for_addr(from))
                    {
                        ctx.traffic.received(crate::metrics::Path::Direct(from.ip()), data.len());
                        dp.inbound(peer, data, now)
                    } else {
                        Vec::new()
                    }
                }
                Some((region, ev)) = ev_rx.recv() => match ev {
                    Event::Packet { src, data } => {
                        if flowmesh_disco::envelope::is_disco(&data) {
                            tap("derp-disco", &data, now);
                            let acts = ctx.ps.on_disco(Source::Derp { node: src, region }, &data, now, &mut ctx.rng);
                            deliver_pings(&mut pings, ctx.ps.take_probe_results(), &ctx.nm);
                            ctx.run_actions(acts).await;
                            // Allocation responses and forwarded allocations go to the peer relay client.
                            if let Ok((from, plain)) = flowmesh_disco::envelope::open(&ctx.disco, &data) {
                                if let Ok(m @ (Message::AllocateResponse { .. } | Message::CallMeMaybeVia(_))) =
                                    flowmesh_disco::message::decode(&plain)
                                {
                                    let acts = ctx.peer_relay.on_derp(&from, &m, now);
                                    ctx.run_relay(acts).await;
                                }
                            }
                            Vec::new()
                        } else {
                            if !looks_like_wireguard(&data) {
                                tap("derp-other", &data, now);
                            }
                            ctx.traffic.received(crate::metrics::Path::Derp, data.len());
                            dp.inbound(src, &data, now)
                        }
                    }
                    Event::Closed(reason) => {
                        log(format!("DERP region {region} closed: {reason}"));
                        if let Some(h) = ctx.relays.on_closed(region, &ctx.nm.derp_map) {
                            log(format!("home DERP region now {h}"));
                        }
                        Vec::new()
                    }
                    _ => Vec::new(),
                },
                Some(ev) = ctl_rx.recv() => {
                    let m = match ev {
                        ControlEvent::Map(m) => *m,
                        ControlEvent::Up => {
                            control_health = None;
                            log("control: connected again");
                            continue;
                        }
                        ControlEvent::Down(reason) => {
                            log(format!("control: {reason}; reconnecting"));
                            control_health = Some(format!(
                                "not connected to the control server ({reason}); reconnecting, the mesh keeps working on the last network map"
                            ));
                            continue;
                        }
                    };
                    let changed = ctx.nm.apply(&m);
                    if changed.self_node {
                        check_key(&ctx.nm, m.control_time.as_deref())?;
                    }
                    if changed.peers || changed.dns || changed.self_node {
                        view = dns_view(&ctx.nm, answer_aaaa);
                        if dns_taken && changed.dns {
                            take_over_dns(&ctx.nm)?;
                        }
                    }
                    if cur.accept_routes && changed.peers {
                        sync_routes(&args.tun, &mut installed_routes, subnet_routes(&ctx.nm));
                    }
                    if changed.peers || changed.filter || changed.derp || changed.self_node {
                        exit_health = select_exit_node(&mut policy, &ctx.nm, &cur.exit_node);
                        if let Err(e) = apply_netmap(&mut dp, &mut ctx.ps, &ctx.nm, crate::logic::unix_now(), &policy) {
            log(e);
        }
                        dp.set_local_nets(local_nets(&ctx.nm, &cur.advertise_routes, exit_ifaces.as_ref()));
                        if let Some(st) = features.peerapi.as_ref().map(|p| &p.state)
                            && let Ok(rules) = flowmesh_filter::compile::compile(&ctx.nm.filter_rules())
                            && let Ok(mut f) = st.filter.write()
                        {
                            f.set_rules(rules);
                        }
                        ctx.peer_relay.set_candidates(relay_candidates(&ctx.nm, crate::logic::unix_now()));
                        ctx.sync_relay();
                        // Online/last-seen patches arrive constantly; log only when the peer set changes.
                        let ids: Vec<i64> = ctx.nm.peers.keys().copied().collect();
                        if ids != peer_ids {
                            let summary: Vec<String> = ctx
                                .nm
                                .peers
                                .values()
                                .map(|n| format!("{}{:?}", n.hostinfo.hostname, n.endpoints))
                                .collect();
                            log(format!("netmap: {} peers {summary:?}", ctx.nm.peers.len()));
                            peer_ids = ids;
                        }
                        let next_mode = mode_of(&ctx.nm);
                        if next_mode != mode {
                            mode = next_mode;
                            endpoints = endpoints_for(mode, &local, stun_mapped);
                            ctx.ps.set_my_endpoints(endpoints.clone());
                            log(format!("relay mode now {mode:?}; endpoints {endpoints:?}"));
                            report(client_rx.borrow().clone(), MapRequest {
                                hostinfo: hostinfo.clone(),
                                endpoints: endpoints.clone(),
                                ..lite.clone()
                            });
                            stream_req_tx.send_replace(MapRequest {
                                hostinfo: hostinfo.clone(),
                                endpoints: endpoints.clone(),
                                ..base_req.clone()
                            });
                        }
                    }
                    Vec::new()
                }
                Some(cmd) = commands.recv() => {
                    match cmd {
                        EngineCommand::Debug { topic, reply } => {
                            use crate::debug::DebugTopic;
                            let v = match topic {
                                DebugTopic::Netmap => crate::debug::netmap(&ctx.nm),
                                DebugTopic::Paths => crate::debug::paths(&ctx.nm, &ctx.ps, now),
                                DebugTopic::Filter => crate::debug::filter(&ctx.nm),
                                DebugTopic::Derp => {
                                    let plan = ctx.relays.plan.describe(ctx.relays.now());
                                    crate::debug::derp(&ctx.nm, &plan)
                                }
                                DebugTopic::DerpMap => serde_json::to_value(&ctx.nm.derp_map).unwrap_or_default(),
                                DebugTopic::Dns => crate::debug::dns(&ctx.nm, cur.accept_dns, dns_taken, &original_resolv),
                                DebugTopic::Metrics => {
                                    let advertised = crate::features::advertised(&cur);
                                    let approved = ctx.nm.self_node.as_ref().map_or(0, |n| {
                                        advertised.iter().filter(|r| n.allowed_ips.contains(r)).count()
                                    });
                                    let snap = crate::metrics::Snapshot {
                                        advertised_routes: advertised.len(),
                                        approved_routes: approved,
                                        warnings,
                                        home_region: ctx.relays.plan.home(),
                                        traffic: ctx.traffic.clone(),
                                        drops: dp.drops(),
                                        send_errors: ctx.send_errors,
                                    };
                                    serde_json::Value::String(crate::metrics::prometheus(&snap))
                                }
                            };
                            let _ = reply.send(v);
                        }
                        EngineCommand::Reconfigure { cfg: new, reply } => {
                            if !crate::features::live_changeable(&cur, &new) {
                                let _ = reply.send(Err("this change needs a restart".into()));
                            } else {
                                let old = std::mem::replace(&mut cur, *new);
                                features.sync_forwarding(&cur, Some(&old));
                                features.sync_exit_routing(&cur, Some(&old), ipv6_mesh);
                                let rules = flowmesh_filter::compile::compile(&ctx.nm.filter_rules()).unwrap_or_default();
                                features
                                    .sync_peerapi(&cur, &me.addresses, rules, &host_upstreams, &mut dp)
                                    .await;
                                if cur.advertise_exit_node != old.advertise_exit_node {
                                    exit_ifaces = cur.advertise_exit_node.then(|| interfaces(&cur.tun));
                                }
                                if cur.accept_dns != old.accept_dns {
                                    restore_dns(dns_taken);
                                    dns_taken = false;
                                    dns_msg = dns_owner_message(cur.accept_dns);
                                    if cur.accept_dns && dns_msg.is_none() {
                                        match take_over_dns(&ctx.nm) {
                                            Ok(()) => {
                                                dns_taken = true;
                                                log(format!("MagicDNS: resolv.conf -> {QUAD100}"));
                                            }
                                            Err(e) => {
                                                log(&e);
                                                dns_msg = Some(e);
                                            }
                                        }
                                    }
                                }
                                if cur.accept_routes != old.accept_routes {
                                    let want = if cur.accept_routes {
                                        subnet_routes(&ctx.nm)
                                    } else {
                                        Default::default()
                                    };
                                    sync_routes(&cur.tun, &mut installed_routes, want);
                                }
                                policy.shields_up = cur.shields_up;
                                policy.accept_routes = cur.accept_routes;
                                exit_health = select_exit_node(&mut policy, &ctx.nm, &cur.exit_node);
                                if let Err(e) = apply_netmap(&mut dp, &mut ctx.ps, &ctx.nm, crate::logic::unix_now(), &policy) {
                                    log(e);
                                }
                                dp.set_local_nets(local_nets(&ctx.nm, &cur.advertise_routes, exit_ifaces.as_ref()));
                                let mut next = hostinfo.clone();
                                crate::features::apply_to_hostinfo(&mut next, &cur, features.services());
                                if next != hostinfo {
                                    hostinfo = next;
                                    report(client_rx.borrow().clone(), MapRequest {
                                        hostinfo: hostinfo.clone(),
                                        endpoints: endpoints.clone(),
                                        ..lite.clone()
                                    });
                                    stream_req_tx.send_replace(MapRequest {
                                        hostinfo: hostinfo.clone(),
                                        endpoints: endpoints.clone(),
                                        ..base_req.clone()
                                    });
                                }
                                last_publish = None;
                                log("settings changed without a restart");
                                let _ = reply.send(Ok(()));
                            }
                        }
                        EngineCommand::Whois { ip, reply } => {
                            let _ = reply.send(crate::command::whois(&ctx.nm, ip));
                        }
                        EngineCommand::Ping { ip, timeout, reply } => {
                            match crate::command::ping_target(&ctx.nm, ip, crate::logic::unix_now()) {
                                Ok((peer, node_ip, node_name)) => {
                                    let acts = ctx.ps.probe(peer, now, &mut ctx.rng);
                                    ctx.run_actions(acts).await;
                                    pings.push(PendingPing {
                                        peer,
                                        node_ip,
                                        node_name,
                                        deadline: now + timeout,
                                        reply,
                                    });
                                }
                                Err(e) => {
                                    let _ = reply.send(Err(e));
                                }
                            }
                        }
                    }
                    Vec::new()
                }
                Some((region, result)) = ready_rx.recv() => {
                    ctx.relays.on_ready(region, result);
                    Vec::new()
                }
                _ = ticker.tick() => {
                    if let Some(h) = ctx.relays.tick(&ctx.nm.derp_map) {
                        // Peers reach us via our home relay: tell the control server about the new one.
                        log(format!("home DERP region {home} unreachable; home is now region {h}"));
                        home = h;
                        hostinfo.net_info = Some(NetInfo { preferred_derp: h });
                        report(client_rx.borrow().clone(), MapRequest {
                            hostinfo: hostinfo.clone(),
                            endpoints: endpoints.clone(),
                            ..lite.clone()
                        });
                        stream_req_tx.send_replace(MapRequest {
                            hostinfo: hostinfo.clone(),
                            endpoints: endpoints.clone(),
                            ..base_req.clone()
                        });
                    }
                    expire_pings(&mut pings, now);
                    let acts = ctx.ps.tick(now, &mut ctx.rng);
                    ctx.run_actions(acts).await;
                    let acts = ctx.peer_relay.tick(now);
                    ctx.run_relay(acts).await;
                    if last_publish.is_none_or(|t| now.saturating_sub(t) >= STATUS_INTERVAL) {
                        last_publish = Some(now);
                        let mut all_health = health.clone();
                        all_health.extend(control_health.clone());
                        all_health.extend(ctx.relays.health());
                        all_health.extend(exit_health.clone());
                        all_health.extend(dns_msg.clone());
                        all_health.extend(features.health());
                        warnings = all_health.len();
                        let mut snap = snapshot(&ctx.nm, &ctx.ps, &dp, now, &all_health);
                        if let Some(key) = policy.exit_node {
                            let key = key.to_string();
                            for p in &mut snap.peers {
                                p.exit_node = p.public_key == key;
                            }
                        }
                        status.send_replace(snap);
                    }
                    dp.tick()
                }
            };
        for out in outputs {
            match out {
                Output::ToTun(p) => tun.queue(&p),
                Output::ToPeer(key, bytes) => ctx.send_to_peer(key, bytes, now).await,
            }
        }
        for reply in tun_replies.drain(..) {
            tun.queue(&reply);
        }
        // Write once both received batches are used up, so packets to one peer (or to the TUN)
        // leave together; the pending sets are bounded, so a long burst still flushes.
        if (udp_rx.is_empty() && tun.is_empty()) || ctx.pending.len() >= PENDING_MAX {
            ctx.flush().await;
        }
        if (udp_rx.is_empty() && tun.is_empty()) || tun.queued() >= PENDING_MAX {
            if let Err(e) = tun.flush().await {
                log(format!("tun write: {e}"));
            }
        }
    }
}
