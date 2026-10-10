// SPDX-License-Identifier: Apache-2.0
//! Main loop: TUN, UDP (WireGuard / disco / STUN sharing one port), DERP, network map updates, and timers.
//!
//! Route selection is done by flowmesh-pathsock: direct (UDP) or DERP for each peer.

use flowmesh_control::client::ControlClient;
use flowmesh_control::netmap::NetMap;
use flowmesh_dataplane::plane::{Dataplane, Output, PeerConfig};
use flowmesh_derp::client::{DerpClient, DerpSender, Event};
use flowmesh_pathsock::{Action, Mode, PathSock, PeerInfo, Random, Route, Source};
use flowmesh_proto::capver::CAPABILITY_VERSION;
use flowmesh_proto::control::{
    Hostinfo, MapRequest, MapResponse, NetInfo, Node, RegisterAuth, RegisterRequest,
};
use flowmesh_proto::derp::{DerpMap, DerpNode};
use flowmesh_proto::key::{NodePrivate, NodePublic};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const TICK: Duration = Duration::from_millis(250);
const MTU: u16 = 1280;
const DEFAULT_PORT: u16 = 41641;
const DEFAULT_STUN_PORT: u16 = 3478;

struct Args {
    login_server: String,
    authkey_file: PathBuf,
    state: PathBuf,
    hostname: String,
    tun: String,
    port: u16,
    /// Debug only: write every disco/unknown message received (UDP and DERP) into this directory, for observation.
    tap_dir: Option<PathBuf>,
    /// Take over the system DNS (resolv.conf → 100.100.100.100), same as the official default `--accept-dns=true`.
    accept_dns: bool,
    /// Accept subnet routes advertised by peers (the official Linux default is off).
    accept_routes: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let (mut login, mut authkey, mut state, mut host) = (None, None, None, None);
    let mut tun = "flowmesh0".to_string();
    let mut port = DEFAULT_PORT;
    let mut tap_dir = None;
    let mut accept_dns = false;
    let mut accept_routes = false;
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--login-server" => login = Some(val()?),
            "--authkey-file" => authkey = Some(PathBuf::from(val()?)),
            "--state" => state = Some(PathBuf::from(val()?)),
            "--hostname" => host = Some(val()?),
            "--tun" => tun = val()?,
            "--port" => {
                let v = val()?;
                port = v.parse().map_err(|_| format!("bad --port {v}"))?;
            }
            "--tap-dir" => tap_dir = Some(PathBuf::from(val()?)),
            "--accept-dns" => accept_dns = true,
            "--accept-routes" => accept_routes = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        login_server: login.ok_or("--login-server is required")?,
        authkey_file: authkey.ok_or("--authkey-file is required")?,
        state: state.ok_or("--state is required")?,
        hostname: host.ok_or("--hostname is required")?,
        tun,
        port,
        tap_dir,
        accept_dns,
        accept_routes,
    })
}

fn log(msg: impl std::fmt::Display) {
    eprintln!("flowmesh-dev: {msg}");
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

/// Choose the home relay: the lowest-numbered region that may be home and has a non-STUN-only node.
fn pick_home(dm: &DerpMap) -> Option<(u32, DerpNode)> {
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
fn relay_only(dm: &DerpMap) -> bool {
    let mut nodes = dm.regions.values().flat_map(|r| r.nodes.iter()).peekable();
    nodes.peek().is_some() && nodes.all(|n| n.stun_port == -1)
}

/// Relay mode: strict if the self node carries `tag:relay-strict`; prefer if every DERP node has STUNPort == -1; otherwise auto.
fn mode_of(nm: &NetMap) -> Mode {
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
fn endpoints_for(mode: Mode, local: &[SocketAddr], stun: Option<SocketAddr>) -> Vec<SocketAddr> {
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
fn peer_home(n: &Node) -> Option<u32> {
    if n.home_derp != 0 {
        return Some(n.home_derp);
    }
    n.legacy_derp
        .strip_prefix("127.3.3.40:")
        .and_then(|r| r.parse().ok())
        .filter(|r| *r != 0)
}

/// A WireGuard message starts with a type byte 1–4 followed by three zero bytes (WireGuard whitepaper §5.4, PUB-2).
fn looks_like_wireguard(b: &[u8]) -> bool {
    b.len() >= 4 && (1..=4).contains(&b[0]) && b[1..4] == [0, 0, 0]
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

struct Relays {
    me: NodePrivate,
    senders: HashMap<u32, DerpSender>,
    events: mpsc::Sender<(u32, Event)>,
}

impl Relays {
    async fn sender(&mut self, region: u32, dm: &DerpMap) -> Option<DerpSender> {
        if let Some(s) = self.senders.get(&region) {
            return Some(s.clone());
        }
        let node = dm
            .regions
            .get(&region)?
            .nodes
            .iter()
            .find(|n| !n.stun_only)?
            .clone();
        match DerpClient::connect(&node, &self.me).await {
            Ok(c) => {
                log(format!(
                    "connected to DERP region {region} ({})",
                    node.host_name
                ));
                let (s, mut rx) = c.split();
                let tx = self.events.clone();
                tokio::spawn(async move {
                    while let Some(ev) = rx.recv().await {
                        if tx.send((region, ev)).await.is_err() {
                            return;
                        }
                    }
                });
                self.senders.insert(region, s.clone());
                Some(s)
            }
            Err(e) => {
                log(format!("DERP region {region}: {e}"));
                None
            }
        }
    }

    async fn send(&mut self, region: u32, dm: &DerpMap, to: NodePublic, data: &[u8]) {
        if let Some(s) = self.sender(region, dm).await {
            if let Err(e) = s.send(to, data).await {
                log(format!("DERP send: {e}"));
            }
        }
    }
}

/// MagicDNS address (dns.md).
const QUAD100: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 100, 100, 100);
const RESOLV: &str = "/etc/resolv.conf";
const RESOLV_BACKUP: &str = "/etc/resolv.conf.flowmesh-backup";
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

fn dns_view(nm: &NetMap, answer_aaaa: bool) -> flowmesh_dns::DnsView {
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

/// Forwarding upstreams: `DNSConfig.Resolvers` first, otherwise the host's original nameservers.
fn dns_upstreams(nm: &NetMap, host: &[IpAddr]) -> Vec<IpAddr> {
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
        let Ok(sock) = UdpSocket::bind(bind).await else {
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

/// Subnet routes advertised by peers: prefixes in AllowedIPs outside the mesh address ranges, excluding default routes (exit nodes are a separate feature).
fn subnet_routes(nm: &NetMap) -> std::collections::BTreeSet<ipnet::IpNet> {
    let mesh4: ipnet::IpNet = "100.64.0.0/10".parse().unwrap_or_default();
    let mesh6: ipnet::IpNet = "fd7a:115c:a1e0::/48".parse().unwrap_or_default();
    nm.peers
        .values()
        .flat_map(|n| n.allowed_ips.iter().copied())
        .filter(|p| p.prefix_len() != 0 && !mesh4.contains(p) && !mesh6.contains(p))
        .collect()
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

fn apply_netmap(dp: &mut Dataplane, ps: &mut PathSock, nm: &NetMap) {
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
    match flowmesh_filter::compile::compile(&nm.filter_rules()) {
        Ok(rules) => dp.set_filter_rules(rules),
        // fail-closed: keep the previous valid rules (design doc §7.2).
        Err(e) => log(format!("filter rules rejected, keeping previous: {e}")),
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
    home: u32,
    rng: OsRandom,
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
            }
        }
    }

    async fn send_to_peer(&mut self, key: NodePublic, bytes: &[u8], now: Duration) {
        let (route, actions) = self.ps.route(key, now, &mut self.rng);
        self.run_actions(actions).await;
        match route {
            Route::Direct(addr) => {
                if self.udp.send_to(bytes, addr).await.is_err() {
                    // Send failure: fall back to DERP immediately and resend (observed behavior).
                    self.ps.on_send_error(key);
                    let region = self
                        .nm
                        .peers
                        .values()
                        .find(|n| n.key == key)
                        .and_then(peer_home);
                    self.relays
                        .send(region.unwrap_or(self.home), &self.nm.derp_map, key, bytes)
                        .await;
                }
            }
            Route::Derp(region) => {
                self.relays
                    .send(region, &self.nm.derp_map, key, bytes)
                    .await
            }
            Route::None => {}
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
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
    let authkey = std::fs::read_to_string(&args.authkey_file)
        .map_err(|e| format!("read authkey: {e}"))?
        .trim()
        .to_string();
    let keys = flowmesh_state::load_or_create(&args.state).map_err(|e| e.to_string())?;
    // The disco key is regenerated on every start (see flowmesh-state).
    let disco = flowmesh_proto::key::DiscoPrivate::generate().map_err(|e| e.to_string())?;
    if let Some(dir) = &args.tap_dir {
        // Lab observation only: save this run's disco private key so tapped disco messages can be decrypted offline.
        std::fs::write(dir.join("disco.key"), disco.to_hex())
            .map_err(|e| format!("tap key: {e}"))?;
    }
    let client = Arc::new(
        ControlClient::connect(&args.login_server, &keys.machine)
            .await
            .map_err(|e| format!("control connect: {e}"))?,
    );
    let mut hostinfo = Hostinfo {
        ipn_version: format!("flowmesh-{}", env!("CARGO_PKG_VERSION")),
        os: "linux".into(),
        hostname: args.hostname.clone(),
        machine: std::env::consts::ARCH.into(),
        ..Default::default()
    };
    let (reg, _) = client
        .register(&RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: keys.node.public(),
            auth: Some(RegisterAuth { auth_key: authkey }),
            hostinfo: hostinfo.clone(),
            ..Default::default()
        })
        .await
        .map_err(|e| format!("register: {e}"))?;
    if !reg.machine_authorized {
        return Err(format!(
            "not authorized: {:?} {:?}",
            reg.error, reg.auth_url
        ));
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

    let (home, home_node) = pick_home(&nm.derp_map).ok_or("no usable DERP region")?;
    hostinfo.net_info = Some(NetInfo {
        preferred_derp: home,
    });
    let udp = Arc::new(
        UdpSocket::bind(("0.0.0.0", args.port))
            .await
            .map_err(|e| format!("udp bind :{}: {e}", args.port))?,
    );
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
    let mut builder = tun_rs::DeviceBuilder::new().name(args.tun.clone()).mtu(MTU);
    for a in &me.addresses {
        builder = match a.addr() {
            IpAddr::V4(v4) => builder.ipv4(v4, 32u8, None),
            IpAddr::V6(v6) => builder.ipv6(v6, 128u8),
        };
    }
    let tun = builder.build_async().map_err(|e| format!("tun: {e}"))?;
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
    let mut relays = Relays {
        me: keys.node.clone(),
        senders: HashMap::new(),
        events: ev_tx,
    };
    let home_sender = relays
        .sender(home, &nm.derp_map)
        .await
        .ok_or("cannot reach home DERP")?;
    home_sender
        .note_preferred(true)
        .await
        .map_err(|e| e.to_string())?;

    let (map_tx, mut map_rx) = mpsc::channel::<MapResponse>(64);
    tokio::spawn(async move {
        loop {
            match stream.next().await {
                Ok(Some(m)) => {
                    if map_tx.send(m.parsed).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return log("map stream closed"),
                Err(e) => return log(format!("map stream: {e}")),
            }
        }
    });

    let mut dp = Dataplane::new(keys.node.clone());
    let mut ctx = Ctx {
        udp: udp.clone(),
        relays,
        ps: PathSock::new(disco.clone(), keys.node.public()),
        nm,
        home,
        rng: OsRandom,
    };
    apply_netmap(&mut dp, &mut ctx.ps, &ctx.nm);
    ctx.ps.set_my_endpoints(endpoints.clone());

    // MagicDNS: the upstream is the host's original nameserver (if a backup was left by a crash, take it from the backup).
    let original_resolv = std::fs::read_to_string(RESOLV_BACKUP)
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
        flowmesh_netcfg::resolv::takeover(
            std::path::Path::new(RESOLV),
            std::path::Path::new(RESOLV_BACKUP),
            &content,
        )
        .map_err(|e| format!("resolv.conf takeover: {e}"))
    };
    if args.accept_dns {
        take_over_dns(&ctx.nm)?;
        log(format!(
            "MagicDNS: resolv.conf -> {QUAD100}; upstreams {host_upstreams:?}; answer AAAA={answer_aaaa}"
        ));
    }
    let restore_dns = || {
        if args.accept_dns {
            match flowmesh_netcfg::resolv::restore(
                std::path::Path::new(RESOLV),
                std::path::Path::new(RESOLV_BACKUP),
            ) {
                Ok(_) => log("resolv.conf restored"),
                Err(e) => log(format!("resolv.conf restore failed: {e}")),
            }
        }
    };
    let mut installed_routes = std::collections::BTreeSet::new();
    if args.accept_routes {
        sync_routes(&args.tun, &mut installed_routes, subnet_routes(&ctx.nm));
    }
    let quad100_dns = std::net::SocketAddrV4::new(QUAD100, 53);
    let (dns_tx, mut dns_rx) = mpsc::channel::<Vec<u8>>(64);
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("signal: {e}"))?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| format!("signal: {e}"))?;
    let start = Instant::now();
    let mut ticker = tokio::time::interval(TICK);
    let mut tun_buf = vec![0u8; usize::from(u16::MAX)];
    let mut udp_buf = vec![0u8; usize::from(u16::MAX)];
    loop {
        let now = start.elapsed();
        let outputs = tokio::select! {
            r = tun.recv(&mut tun_buf) => {
                let n = r.map_err(|e| format!("tun read: {e}"))?;
                let pkt = &tun_buf[..n];
                match flowmesh_dataplane::ippkt::udp4_payload(pkt).filter(|(_, d, _)| *d == quad100_dns) {
                    Some((client, _, query)) => {
                        match flowmesh_dns::handle(&view, query) {
                            flowmesh_dns::Decision::Local(resp) => {
                                let reply = flowmesh_dataplane::ippkt::build_udp4(quad100_dns, client, &resp);
                                if let Err(e) = tun.send(&reply).await {
                                    log(format!("tun write: {e}"));
                                }
                            }
                            flowmesh_dns::Decision::Forward => forward_dns(
                                dns_upstreams(&ctx.nm, &host_upstreams),
                                query.to_vec(),
                                client,
                                quad100_dns,
                                dns_tx.clone(),
                            ),
                            flowmesh_dns::Decision::Drop => {}
                        }
                        Vec::new()
                    }
                    None => dp.outbound(pkt, now),
                }
            }
            Some(reply) = dns_rx.recv() => {
                if let Err(e) = tun.send(&reply).await {
                    log(format!("tun write: {e}"));
                }
                Vec::new()
            }
            _ = sigterm.recv() => {
                restore_dns();
                return Ok(());
            }
            _ = sigint.recv() => {
                restore_dns();
                return Ok(());
            }
            r = udp.recv_from(&mut udp_buf) => {
                let (n, from) = r.map_err(|e| format!("udp read: {e}"))?;
                let data = &udp_buf[..n];
                if flowmesh_disco::envelope::is_disco(data) {
                    tap("udp-disco", data, now);
                    let acts = ctx.ps.on_disco(Source::Udp(from), data, now, &mut ctx.rng);
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
                                report(client.clone(), MapRequest {
                                    hostinfo: hostinfo.clone(),
                                    endpoints: endpoints.clone(),
                                    ..lite.clone()
                                });
                            }
                        }
                        other => log(format!("ignoring STUN message: {other:?}")),
                    }
                    Vec::new()
                } else if let Some(peer) = ctx.ps.peer_for_addr(from) {
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
                        ctx.run_actions(acts).await;
                        Vec::new()
                    } else {
                        if !looks_like_wireguard(&data) {
                            tap("derp-other", &data, now);
                        }
                        dp.inbound(src, &data, now)
                    }
                }
                Event::Closed(reason) => {
                    log(format!("DERP connection closed: {reason}"));
                    Vec::new()
                }
                _ => Vec::new(),
            },
            Some(m) = map_rx.recv() => {
                let changed = ctx.nm.apply(&m);
                if changed.peers || changed.dns || changed.self_node {
                    view = dns_view(&ctx.nm, answer_aaaa);
                    if args.accept_dns && changed.dns {
                        take_over_dns(&ctx.nm)?;
                    }
                }
                if args.accept_routes && changed.peers {
                    sync_routes(&args.tun, &mut installed_routes, subnet_routes(&ctx.nm));
                }
                if changed.peers || changed.filter || changed.derp || changed.self_node {
                    apply_netmap(&mut dp, &mut ctx.ps, &ctx.nm);
                    let summary: Vec<String> = ctx
                        .nm
                        .peers
                        .values()
                        .map(|n| format!("{}{:?}", n.hostinfo.hostname, n.endpoints))
                        .collect();
                    log(format!("netmap: {} peers {summary:?}", ctx.nm.peers.len()));
                    let next_mode = mode_of(&ctx.nm);
                    if next_mode != mode {
                        mode = next_mode;
                        endpoints = endpoints_for(mode, &local, stun_mapped);
                        ctx.ps.set_my_endpoints(endpoints.clone());
                        log(format!("relay mode now {mode:?}; endpoints {endpoints:?}"));
                        report(client.clone(), MapRequest {
                            hostinfo: hostinfo.clone(),
                            endpoints: endpoints.clone(),
                            ..lite.clone()
                        });
                    }
                }
                Vec::new()
            }
            _ = ticker.tick() => {
                let acts = ctx.ps.tick(now, &mut ctx.rng);
                ctx.run_actions(acts).await;
                dp.tick()
            }
        };
        for out in outputs {
            match out {
                Output::ToTun(p) => {
                    if let Err(e) = tun.send(&p).await {
                        log(format!("tun write: {e}"));
                    }
                }
                Output::ToPeer(key, bytes) => ctx.send_to_peer(key, &bytes, now).await,
            }
        }
    }
}

pub fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("flowmesh-dev: {e}");
            return ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("flowmesh-dev: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("flowmesh-dev: {e}");
            ExitCode::FAILURE
        }
    }
}
