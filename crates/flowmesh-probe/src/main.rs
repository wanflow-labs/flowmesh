// SPDX-License-Identifier: Apache-2.0
//! flowmesh protocol probe: registers with a pre-auth key, receives the netmap, and writes the raw
//! messages to a directory as observation sources for the protocol specification (docs/protocol/control.md).
//!
//! Usage: flowmesh-probe --login-server <url> --authkey-file <path> --state <path>
//!        --hostname <name> --dump <dir> [--duration <seconds>]
//!        [--derp-region <id> [--disco-to <tailnet IP> --disco-payload <hex> ... [--disco-delay <seconds>]]]
//!
//! Disco mode (--derp-region): connects to that region's DERP and reports it as this node's home, and records
//! the disco messages peers send over DERP (decrypted with this run's disco private key and written to
//! disco.tsv; the private key is saved as disco.key and must not go into fixtures).
//! With --disco-to, after connecting to DERP it waits --disco-delay (default 5 seconds, so the peer first gets
//! this run's new disco public key), then seals each --disco-payload (type byte + version byte + body) and sends
//! it to that peer. A payload is hex and may contain the placeholders `{self}` (this run's disco public key) and
//! `{disco:<IP>}` (that node's current disco public key), expanded from the latest netmap when sending.
//!
//! Peer relay handshake experiments (--udp-payload, repeatable): the program remembers the most recent
//! allocation it received (0x09 or 0x07). After --udp-delay (default 12 seconds) it seals each payload with the
//! server key from the allocation, adds a Geneve header (--udp-control sets the O bit; the VNI comes from the
//! allocation), and sends it over UDP to the allocated relay address; UDP replies are decrypted and also
//! recorded in disco.tsv. Additional placeholders are `{alloc.server}`, `{alloc.pair}`, `{alloc.gen}`,
//! `{alloc.vni}`, and `{node}` (this node's node public key). --udp-answer: when the server sends a Challenge
//! (0x05), reply with an Answer (0x06, echoing the body). --relay-peer/--relay-payload: 1 second after the
//! Answer is sent, seal each payload with that peer's disco public key, without the O bit, and send it through
//! the relay (verifies relay forwarding).

mod disco;

use flowmesh_control::client::ControlClient;
use flowmesh_derp::client::{DerpClient, DerpSender, Event};
use flowmesh_proto::capver::CAPABILITY_VERSION;
use flowmesh_proto::control::{Hostinfo, MapRequest, NetInfo, RegisterAuth, RegisterRequest};
use flowmesh_proto::derp::DerpMap;
use flowmesh_proto::key::{NodePrivate, NodePublic};
use std::collections::HashMap;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

struct Args {
    login_server: String,
    authkey_file: PathBuf,
    state: PathBuf,
    hostname: String,
    dump: PathBuf,
    duration: Duration,
    derp_region: Option<u32>,
    disco_to: Option<IpAddr>,
    /// Payload templates: hex with `{self}` / `{disco:<ip>}` placeholders, expanded at send time.
    disco_payloads: Vec<String>,
    disco_delay: Duration,
    udp_payloads: Vec<String>,
    udp_delay: Duration,
    udp_control: bool,
    udp_answer: bool,
    relay_peer: Option<IpAddr>,
    relay_payloads: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let (mut login, mut authkey, mut state, mut host, mut dump) = (None, None, None, None, None);
    let mut duration = Duration::from_secs(30);
    let (mut derp_region, mut disco_to, mut disco_payloads) = (None, None, Vec::new());
    let mut disco_delay = Duration::from_secs(5);
    let (mut udp_payloads, mut udp_delay, mut udp_control) =
        (Vec::new(), Duration::from_secs(12), false);
    let (mut udp_answer, mut relay_peer, mut relay_payloads) = (false, None, Vec::new());
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--login-server" => login = Some(val()?),
            "--authkey-file" => authkey = Some(PathBuf::from(val()?)),
            "--state" => state = Some(PathBuf::from(val()?)),
            "--hostname" => host = Some(val()?),
            "--dump" => dump = Some(PathBuf::from(val()?)),
            "--duration" => {
                let v = val()?;
                duration =
                    Duration::from_secs(v.parse().map_err(|_| format!("bad --duration {v}"))?);
            }
            "--derp-region" => {
                let v = val()?;
                derp_region = Some(v.parse().map_err(|_| format!("bad --derp-region {v}"))?);
            }
            "--disco-to" => {
                let v = val()?;
                disco_to = Some(v.parse().map_err(|_| format!("bad --disco-to {v}"))?);
            }
            "--disco-payload" => disco_payloads.push(val()?),
            "--udp-payload" => udp_payloads.push(val()?),
            "--udp-delay" => {
                let v = val()?;
                udp_delay =
                    Duration::from_secs(v.parse().map_err(|_| format!("bad --udp-delay {v}"))?);
            }
            "--udp-control" => udp_control = true,
            "--udp-answer" => udp_answer = true,
            "--relay-peer" => {
                let v = val()?;
                relay_peer = Some(v.parse().map_err(|_| format!("bad --relay-peer {v}"))?);
            }
            "--relay-payload" => relay_payloads.push(val()?),
            "--disco-delay" => {
                let v = val()?;
                disco_delay =
                    Duration::from_secs(v.parse().map_err(|_| format!("bad --disco-delay {v}"))?);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if disco_to.is_some() && derp_region.is_none() {
        return Err("--disco-to needs --derp-region (disco messages go over DERP)".into());
    }
    Ok(Args {
        login_server: login.ok_or("--login-server is required")?,
        authkey_file: authkey.ok_or("--authkey-file is required")?,
        state: state.ok_or("--state is required")?,
        hostname: host.ok_or("--hostname is required")?,
        dump: dump.ok_or("--dump is required")?,
        duration,
        derp_region,
        disco_to,
        disco_payloads,
        disco_delay,
        udp_payloads,
        udp_delay,
        udp_control,
        udp_answer,
        relay_peer,
        relay_payloads,
    })
}

/// Same values as the official client: linux / macOS / windows.
fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        other => other,
    }
}

/// Write a secret readable by the owner only (0600), whatever the umask.
fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn append_line(path: &Path, line: &str) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    writeln!(f, "{line}").map_err(|e| format!("{}: {e}", path.display()))
}

fn write(dir: &Path, name: &str, data: &[u8]) -> Result<(), String> {
    std::fs::write(dir.join(name), data).map_err(|e| format!("write {name}: {e}"))
}

async fn run(args: Args) -> Result<(), String> {
    let authkey = std::fs::read_to_string(&args.authkey_file)
        .map_err(|e| format!("read authkey: {e}"))?
        .trim()
        .to_string();
    let keys = flowmesh_state::load_or_create(&args.state).map_err(|e| e.to_string())?;
    // The disco key is regenerated on every start (see flowmesh-state).
    let disco = flowmesh_proto::key::DiscoPrivate::generate().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&args.dump).map_err(|e| format!("create dump dir: {e}"))?;

    let client = ControlClient::connect(&args.login_server, &keys.machine)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    println!("connected; server key {}", client.server_key());
    if let Some(early) = client.early_payload() {
        write(&args.dump, "early.json", early.to_string().as_bytes())?;
        println!("early payload: {} bytes", early.to_string().len());
    }

    let hostinfo = Hostinfo {
        ipn_version: format!("flowmesh-{}", env!("CARGO_PKG_VERSION")),
        os: os_name().into(),
        hostname: args.hostname.clone(),
        machine: std::env::consts::ARCH.into(),
        // Peers send disco to our home region: make it the one we connect to.
        net_info: args.derp_region.map(|r| NetInfo { preferred_derp: r }),
        ..Default::default()
    };
    if args.derp_region.is_some() {
        // Lab observation only: lets disco.tsv be checked offline. Never copy it into fixtures.
        write_private(&args.dump.join("disco.key"), disco.to_hex().as_bytes())?;
    }
    let mut reg = RegisterRequest {
        version: CAPABILITY_VERSION,
        node_key: keys.node.public(),
        auth: Some(RegisterAuth { auth_key: authkey }),
        hostinfo: hostinfo.clone(),
        ..Default::default()
    };
    let (resp, raw) = client
        .register(&reg)
        .await
        .map_err(|e| format!("register: {e}"))?;
    reg.auth = Some(RegisterAuth {
        auth_key: "<redacted>".into(),
    });
    write(
        &args.dump,
        "register-request.json",
        &serde_json::to_vec(&reg).map_err(|e| e.to_string())?,
    )?;
    write(&args.dump, "register-response.json", &raw)?;
    if !resp.error.is_empty() || !resp.machine_authorized {
        return Err(format!(
            "register not authorized: error={:?} auth_url={:?}",
            resp.error, resp.auth_url
        ));
    }
    println!("registered as {:?}", resp.login.login_name);

    let map_req = MapRequest {
        version: CAPABILITY_VERSION,
        compress: "zstd".into(),
        keep_alive: true,
        node_key: keys.node.public(),
        disco_key: disco.public(),
        hostinfo,
        stream: true,
        ..Default::default()
    };
    write(
        &args.dump,
        "map-request.json",
        &serde_json::to_vec(&map_req).map_err(|e| e.to_string())?,
    )?;
    let mut stream = client
        .map(&map_req)
        .await
        .map_err(|e| format!("map: {e}"))?;
    // Also report in a non-streaming update, as flowmeshd does: with the streaming request alone,
    // peers saw no DiscoKey for this node and dropped its disco messages.
    {
        let lite = MapRequest {
            stream: false,
            omit_peers: true,
            ..map_req.clone()
        };
        let mut s = client
            .map(&lite)
            .await
            .map_err(|e| format!("map update: {e}"))?;
        while let Ok(Some(_)) = s.next().await {}
    }
    let start = tokio::time::Instant::now();
    let deadline = start + args.duration;
    let mut seq = 0usize;
    // DERP events reach the loop through this channel once a connection exists; until then (or
    // without --derp-region) nothing arrives on it.
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<Event>(256);
    // One connection per region: replies arrive on our home region, sends go through the peer's.
    let mut senders: HashMap<u32, DerpSender> = HashMap::new();
    let mut derp_map: Option<DerpMap> = None;
    let mut names: HashMap<NodePublic, String> = HashMap::new();
    let mut received = 0usize;
    let mut pending: Option<(tokio::time::Instant, IpAddr)> = None;
    let mut peers: Vec<flowmesh_proto::control::Node> = Vec::new();
    // Peer relay handshake experiments: the latest allocation seen, a UDP socket and its receive loop.
    let mut alloc: Option<disco::Alloc> = None;
    let (udp_tx, mut udp_rx) = tokio::sync::mpsc::channel::<(std::net::SocketAddr, Vec<u8>)>(256);
    let udp = if args.udp_payloads.is_empty() {
        None
    } else {
        let sock = std::sync::Arc::new(
            tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("udp bind: {e}"))?,
        );
        let rx = sock.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = rx.recv_from(&mut buf).await {
                if udp_tx.send((from, buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
        });
        Some(sock)
    };
    let mut udp_at = udp.as_ref().map(|_| start + args.udp_delay);
    let mut relay_at: Option<tokio::time::Instant> = None;
    let node_hex: String = keys
        .node
        .public()
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    loop {
        let send_at = pending.as_ref().map(|(t, _)| *t);
        let relay_due = relay_at;
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = tokio::time::sleep_until(udp_at.unwrap_or(deadline)), if udp_at.is_some() => {
                udp_at = None;
                let (Some(sock), Some(a)) = (udp.as_ref(), alloc.as_ref()) else {
                    println!("no allocation received before --udp-delay: nothing sent over UDP");
                    continue;
                };
                let to = *a.addrs.first().ok_or("allocation without an address")?;
                for template in &args.udp_payloads {
                    let payload =
                        disco::parse_hex(&disco::expand(template, &disco.public(), &peers, Some(a))?)?;
                    let mut nonce = [0u8; 24];
                    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
                    let sealed = flowmesh_disco::envelope::seal(&disco, &a.server, &payload, nonce)
                        .map_err(|e| e.to_string())?;
                    let packet = [&disco::geneve(a.vni, args.udp_control, 0x7a11)[..], &sealed].concat();
                    sock.send_to(&packet, to).await.map_err(|e| format!("udp send: {e}"))?;
                    println!(
                        "{}\tudp sent {} bytes (payload {}) to {to} vni {}",
                        start.elapsed().as_millis(),
                        packet.len(),
                        payload.len(),
                        a.vni
                    );
                }
            }
            _ = tokio::time::sleep_until(relay_due.unwrap_or(deadline)), if relay_due.is_some() => {
                relay_at = None;
                let (Some(sock), Some(a), Some(ip)) = (udp.as_ref(), alloc.as_ref(), args.relay_peer) else {
                    continue;
                };
                let peer = disco::find_peer(&peers, ip).ok_or(format!("no peer with address {ip}"))?;
                let to = *a.addrs.first().ok_or("allocation without an address")?;
                for template in &args.relay_payloads {
                    let template = template.replace("{node}", &node_hex);
                    let payload =
                        disco::parse_hex(&disco::expand(&template, &disco.public(), &peers, Some(a))?)?;
                    let mut nonce = [0u8; 24];
                    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
                    let sealed = flowmesh_disco::envelope::seal(&disco, &peer.disco_key, &payload, nonce)
                        .map_err(|e| e.to_string())?;
                    let packet = [&disco::geneve(a.vni, false, 0x7a11)[..], &sealed].concat();
                    sock.send_to(&packet, to).await.map_err(|e| format!("udp send: {e}"))?;
                    println!(
                        "{}\trelay sent {} bytes to {} via {to} vni {}",
                        start.elapsed().as_millis(),
                        payload.len(),
                        peer.name,
                        a.vni
                    );
                }
            }
            Some((from, data)) = udp_rx.recv() => {
                let t = start.elapsed().as_millis();
                let (head, inner) = data.split_at(data.len().min(8));
                let who = format!("udp:{from} hdr={}", head.iter().map(|b| format!("{b:02x}")).collect::<String>());
                let line = if inner.starts_with(&flowmesh_disco::envelope::MAGIC) {
                    match flowmesh_disco::envelope::open(&disco, inner) {
                        Ok((_, plain)) => {
                            // Handshake: answer the server's challenge by echoing its body as 0x06.
                            if let (true, Some(0x05), Some(a), Some(sock)) =
                                (args.udp_answer, plain.first().copied(), alloc.as_ref(), udp.as_ref())
                            {
                                let answer = [&[0x06, 0x00][..], &plain[2..]].concat();
                                let mut nonce = [0u8; 24];
                                getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
                                let sealed = flowmesh_disco::envelope::seal(&disco, &a.server, &answer, nonce)
                                    .map_err(|e| e.to_string())?;
                                let packet = [&disco::geneve(a.vni, true, 0x7a11)[..], &sealed].concat();
                                sock.send_to(&packet, from).await.map_err(|e| format!("udp send: {e}"))?;
                                println!("{}\tudp answered the challenge", start.elapsed().as_millis());
                                if !args.relay_payloads.is_empty() {
                                    relay_at = Some(tokio::time::Instant::now() + Duration::from_secs(1));
                                }
                            }
                            disco::tsv_line(t, &who, &plain)
                        }
                        Err(e) => format!("{t}\t{who}\tundecryptable: {e}"),
                    }
                } else {
                    disco::tsv_line(t, &format!("{who} raw"), inner)
                };
                println!("{line}");
                append_line(&args.dump.join("disco.tsv"), &line)?;
                received += 1;
            }
            _ = tokio::time::sleep_until(send_at.unwrap_or(deadline)), if send_at.is_some() => {
                let (Some((_, ip)), Some(dm)) = (pending.take(), derp_map.as_ref()) else {
                    continue;
                };
                let peer = disco::find_peer(&peers, ip)
                    .ok_or(format!("no peer with address {ip}"))?
                    .clone();
                let region = disco::peer_region(&peer)
                    .or(args.derp_region)
                    .ok_or("no DERP region to reach the peer")?;
                if let std::collections::hash_map::Entry::Vacant(e) = senders.entry(region) {
                    e.insert(connect_region(dm, region, &keys.node, &ev_tx).await?);
                }
                let sender = senders.get(&region).ok_or("DERP sender missing")?;
                for template in &args.disco_payloads {
                    let payload = disco::parse_hex(&disco::expand(template, &disco.public(), &peers, alloc.as_ref())?)?;
                    let mut nonce = [0u8; 24];
                    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
                    let sealed =
                        flowmesh_disco::envelope::seal(&disco, &peer.disco_key, &payload, nonce)
                            .map_err(|e| e.to_string())?;
                    sender
                        .send(peer.key, &sealed)
                        .await
                        .map_err(|e| format!("DERP send: {e}"))?;
                    println!(
                        "{}\tsent {} bytes to {} via region {region}",
                        start.elapsed().as_millis(),
                        payload.len(),
                        peer.name
                    );
                }
            }
            msg = stream.next() => {
                let Some(msg) = msg.map_err(|e| format!("map stream: {e}"))? else {
                    println!("map stream closed by server");
                    break;
                };
                write(&args.dump, &format!("map-{seq:04}.json"), &msg.json)?;
                let m = &msg.parsed;
                println!(
                    "map #{seq}: keepalive={} self={:?} peers={:?} changed={} removed={}",
                    m.keep_alive,
                    m.node.as_ref().map(|n| n.name.as_str()),
                    m.peers.as_ref().map(Vec::len),
                    m.peers_changed.len(),
                    m.peers_removed.len()
                );
                disco::apply_map(&mut peers, m);
                for p in &peers {
                    names.insert(p.key, p.name.clone());
                }
                if let Some(dm) = &m.derp_map {
                    derp_map = Some(dm.clone());
                }
                if let (Some(home), Some(dm), true) =
                    (args.derp_region, derp_map.as_ref(), senders.is_empty())
                {
                    let s = connect_region(dm, home, &keys.node, &ev_tx).await?;
                    senders.insert(home, s);
                    if let Some(ip) = args.disco_to {
                        // Our disco key is new this run: give the control server time to push it
                        // to the peer, which drops messages sealed with a key it doesn't know. The
                        // peer and the placeholders are looked up when the time comes.
                        pending = Some((tokio::time::Instant::now() + args.disco_delay, ip));
                    }
                }
                seq += 1;
            }
            Some(ev) = ev_rx.recv() => match ev {
                Event::Packet { src, data } if data.starts_with(&flowmesh_disco::envelope::MAGIC) => {
                    let t = start.elapsed().as_millis();
                    write(&args.dump, &format!("derp-{t:010}.bin"), &data)?;
                    let from = names.get(&src).cloned().unwrap_or_else(|| src.to_string());
                    let line = match flowmesh_disco::envelope::open(&disco, &data) {
                        Ok((_, plain)) => {
                            if let Some(a) = disco::parse_alloc(&plain) {
                                alloc = Some(a);
                            }
                            disco::tsv_line(t, &from, &plain)
                        }
                        Err(e) => format!("{t}\t{from}\tundecryptable: {e}"),
                    };
                    println!("{line}");
                    append_line(&args.dump.join("disco.tsv"), &line)?;
                    received += 1;
                }
                other => println!("derp: {other:?}"),
            },
        }
    }
    drop(senders);
    println!("done: {seq} map messages, {received} disco messages");
    Ok(())
}

/// Connect to `region`'s DERP server and forward its events into `tx`.
async fn connect_region(
    dm: &DerpMap,
    region: u32,
    me: &NodePrivate,
    tx: &tokio::sync::mpsc::Sender<Event>,
) -> Result<DerpSender, String> {
    let node =
        disco::derp_node(dm, region).ok_or(format!("DERP region {region} not in the map"))?;
    let client = DerpClient::connect(&node, me)
        .await
        .map_err(|e| format!("DERP region {region}: {e}"))?;
    println!("connected to DERP region {region} ({})", node.host_name);
    let (sender, mut events) = client.split();
    let tx = tx.clone();
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            if tx.send(ev).await.is_err() {
                break;
            }
        }
    });
    Ok(sender)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("flowmesh-probe: {e}");
            return ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("flowmesh-probe: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("flowmesh-probe: {e}");
            ExitCode::FAILURE
        }
    }
}
