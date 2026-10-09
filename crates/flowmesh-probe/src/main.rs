// SPDX-License-Identifier: Apache-2.0
//! flowmesh 协议探测程序：用预授权 key 注册，接收网络地图，并把原始报文写入目录，
//! 作为协议规范的观测出处（docs/protocol/control.md）。
//!
//! 用法：flowmesh-probe --login-server <url> --authkey-file <path> --state <path>
//!       --hostname <name> --dump <dir> [--duration <秒>]

mod state;

use flowmesh_control::client::ControlClient;
use flowmesh_proto::capver::CAPABILITY_VERSION;
use flowmesh_proto::control::{Hostinfo, MapRequest, RegisterAuth, RegisterRequest};
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
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let (mut login, mut authkey, mut state, mut host, mut dump) = (None, None, None, None, None);
    let mut duration = Duration::from_secs(30);
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
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        login_server: login.ok_or("--login-server is required")?,
        authkey_file: authkey.ok_or("--authkey-file is required")?,
        state: state.ok_or("--state is required")?,
        hostname: host.ok_or("--hostname is required")?,
        dump: dump.ok_or("--dump is required")?,
        duration,
    })
}

/// 与官方客户端的取值方式一致：linux / macOS / windows。
fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        other => other,
    }
}

fn write(dir: &Path, name: &str, data: &[u8]) -> Result<(), String> {
    std::fs::write(dir.join(name), data).map_err(|e| format!("write {name}: {e}"))
}

async fn run(args: Args) -> Result<(), String> {
    let authkey = std::fs::read_to_string(&args.authkey_file)
        .map_err(|e| format!("read authkey: {e}"))?
        .trim()
        .to_string();
    let keys = state::load_or_create(&args.state).map_err(|e| e.to_string())?;
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
        ..Default::default()
    };
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
        disco_key: keys.disco.public(),
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
    let deadline = tokio::time::Instant::now() + args.duration;
    let mut seq = 0usize;
    loop {
        let next = tokio::time::timeout_at(deadline, stream.next()).await;
        let Ok(msg) = next else { break };
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
        seq += 1;
    }
    println!("done: {seq} map messages");
    Ok(())
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
