// SPDX-License-Identifier: Apache-2.0
//! Main loop: handles TUN reads, DERP receives, network map updates, and the WireGuard timer concurrently.

use flowmesh_control::client::ControlClient;
use flowmesh_control::netmap::NetMap;
use flowmesh_dataplane::plane::{Dataplane, Output, PeerConfig};
use flowmesh_derp::client::{DerpClient, DerpSender, Event};
use flowmesh_proto::capver::CAPABILITY_VERSION;
use flowmesh_proto::control::{
    Hostinfo, MapRequest, MapResponse, NetInfo, RegisterAuth, RegisterRequest,
};
use flowmesh_proto::derp::{DerpMap, DerpNode};
use flowmesh_proto::key::{NodePrivate, NodePublic};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const TICK: Duration = Duration::from_millis(250);
const MTU: u16 = 1280;

struct Args {
    login_server: String,
    authkey_file: PathBuf,
    state: PathBuf,
    hostname: String,
    tun: String,
    /// Debug only: write every non-WireGuard packet received via DERP into this directory (observation material for disco etc.).
    tap_dir: Option<PathBuf>,
    /// Debug only: send one disco Ping via DERP to every peer at startup (to observe the peer's Pong).
    disco_probe: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let (mut login, mut authkey, mut state, mut host) = (None, None, None, None);
    let mut tun = "flowmesh0".to_string();
    let mut tap_dir = None;
    let mut disco_probe = false;
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--login-server" => login = Some(val()?),
            "--authkey-file" => authkey = Some(PathBuf::from(val()?)),
            "--state" => state = Some(PathBuf::from(val()?)),
            "--hostname" => host = Some(val()?),
            "--tun" => tun = val()?,
            "--tap-dir" => tap_dir = Some(PathBuf::from(val()?)),
            "--disco-probe" => disco_probe = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        login_server: login.ok_or("--login-server is required")?,
        authkey_file: authkey.ok_or("--authkey-file is required")?,
        state: state.ok_or("--state is required")?,
        hostname: host.ok_or("--hostname is required")?,
        tun,
        tap_dir,
        disco_probe,
    })
}

fn log(msg: impl std::fmt::Display) {
    eprintln!("flowmesh-dev: {msg}");
}

/// A WireGuard message starts with a type byte 1–4 followed by three zero bytes (WireGuard whitepaper §5.4, PUB-2).
fn looks_like_wireguard(b: &[u8]) -> bool {
    b.len() >= 4 && (1..=4).contains(&b[0]) && b[1..4] == [0, 0, 0]
}

/// Choose the home relay: the lowest-numbered region that may be used as home and has a non-STUN-only node.
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

/// A peer's home relay: prefer `HomeDERP`, otherwise parse the legacy `127.3.3.40:<region>`.
fn peer_home(n: &flowmesh_proto::control::Node) -> Option<u32> {
    if n.home_derp != 0 {
        return Some(n.home_derp);
    }
    n.legacy_derp
        .strip_prefix("127.3.3.40:")
        .and_then(|r| r.parse().ok())
        .filter(|r| *r != 0)
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
}

fn apply_netmap(dp: &mut Dataplane, nm: &NetMap, homes: &mut HashMap<NodePublic, u32>) {
    let peers = nm
        .peers
        .values()
        .map(|n| PeerConfig {
            key: n.key,
            allowed_ips: n.allowed_ips.clone(),
        })
        .collect();
    dp.set_peers(peers);
    homes.clear();
    for n in nm.peers.values() {
        if let Some(r) = peer_home(n) {
            homes.insert(n.key, r);
        }
    }
    match flowmesh_filter::compile::compile(&nm.filter_rules()) {
        Ok(rules) => dp.set_filter_rules(rules),
        // fail-closed: keep the previous valid rules (design doc §7.2).
        Err(e) => log(format!("filter rules rejected, keeping previous: {e}")),
    }
}

async fn run(args: Args) -> Result<(), String> {
    if let Some(dir) = &args.tap_dir {
        std::fs::create_dir_all(dir).map_err(|e| format!("tap dir: {e}"))?;
    }
    let authkey = std::fs::read_to_string(&args.authkey_file)
        .map_err(|e| format!("read authkey: {e}"))?
        .trim()
        .to_string();
    let keys = flowmesh_state::load_or_create(&args.state).map_err(|e| e.to_string())?;
    let client = ControlClient::connect(&args.login_server, &keys.machine)
        .await
        .map_err(|e| format!("control connect: {e}"))?;
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
        disco_key: keys.disco.public(),
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
    // Tell the control server our home relay (one-shot, non-streaming update).
    let mut lite = client
        .map(&MapRequest {
            stream: false,
            omit_peers: true,
            hostinfo: hostinfo.clone(),
            ..base_req.clone()
        })
        .await
        .map_err(|e| format!("map update: {e}"))?;
    while let Ok(Some(_)) = lite.next().await {}
    log(format!("home DERP region {home} ({})", home_node.host_name));

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

    if args.disco_probe {
        for peer in nm.peers.values().filter(|p| p.online == Some(true)) {
            let mut tx_id = [0u8; flowmesh_disco::message::TX_ID_LEN];
            getrandom::fill(&mut tx_id).map_err(|e| e.to_string())?;
            let mut nonce = [0u8; flowmesh_disco::envelope::NONCE_LEN];
            getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
            let ping = flowmesh_disco::message::encode(&flowmesh_disco::message::Message::Ping {
                tx_id,
                node_key: keys.node.public(),
            });
            let sealed = flowmesh_disco::envelope::seal(&keys.disco, &peer.disco_key, &ping, nonce)
                .map_err(|e| e.to_string())?;
            let region = peer_home(peer).unwrap_or(home);
            if let Some(s) = relays.sender(region, &nm.derp_map).await {
                s.send(peer.key, &sealed).await.map_err(|e| e.to_string())?;
                log(format!("disco ping -> {} tx={tx_id:02x?}", peer.name));
            }
        }
    }

    let mut dp = Dataplane::new(keys.node.clone());
    let mut homes = HashMap::new();
    apply_netmap(&mut dp, &nm, &mut homes);
    let start = Instant::now();
    let mut ticker = tokio::time::interval(TICK);
    let mut buf = vec![0u8; usize::from(u16::MAX)];
    loop {
        let outputs = tokio::select! {
            r = tun.recv(&mut buf) => {
                let n = r.map_err(|e| format!("tun read: {e}"))?;
                dp.outbound(&buf[..n], start.elapsed())
            }
            Some((_region, ev)) = ev_rx.recv() => match ev {
                Event::Packet { src, data } => {
                    if !looks_like_wireguard(&data) {
                        if let Some(dir) = &args.tap_dir {
                            let name = format!("derp-{:010}-{}.bin", start.elapsed().as_millis(), &src.to_string()[8..16]);
                            if let Err(e) = std::fs::write(dir.join(name), &data) {
                                log(format!("tap write: {e}"));
                            }
                        }
                    }
                    dp.inbound(src, &data, start.elapsed())
                }
                Event::Closed(reason) => {
                    log(format!("DERP connection closed: {reason}"));
                    Vec::new()
                }
                _ => Vec::new(),
            },
            Some(m) = map_rx.recv() => {
                let changed = nm.apply(&m);
                if changed.peers || changed.filter {
                    apply_netmap(&mut dp, &nm, &mut homes);
                    log(format!("netmap: {} peers", nm.peers.len()));
                }
                Vec::new()
            }
            _ = ticker.tick() => dp.tick(),
        };
        for out in outputs {
            match out {
                Output::ToTun(p) => {
                    if let Err(e) = tun.send(&p).await {
                        log(format!("tun write: {e}"));
                    }
                }
                Output::ToPeer(key, bytes) => {
                    let region = homes.get(&key).copied().unwrap_or(home);
                    if let Some(s) = relays.sender(region, &nm.derp_map).await {
                        if let Err(e) = s.send(key, &bytes).await {
                            log(format!("DERP send: {e}"));
                        }
                    }
                }
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
