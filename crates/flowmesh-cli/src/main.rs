// SPDX-License-Identifier: Apache-2.0
//! flowmesh: command-line client for flowmeshd.

use flowmesh_cli::args::{self, AuthKey, Command};
use flowmesh_cli::bugreport::{self, Section};
use flowmesh_cli::{dnsquery, netcheck, ping, query, render};
use flowmesh_daemon::client::{DEFAULT_SOCKET, LocalClient};
use serde_json::{Value, json};
use std::process::ExitCode;
use std::time::{Duration, Instant};

/// Write to stdout. A reader that went away (`flowmesh status | head -1`) ends the program quietly
/// with success, as a closed pipe should; any other write error is reported.
fn emit(args: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let mut o = std::io::stdout().lock();
    if let Err(e) = o.write_fmt(args).and_then(|()| o.flush()) {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("flowmesh: write: {e}");
        std::process::exit(1);
    }
}

macro_rules! out {
    ($($t:tt)*) => { emit(format_args!($($t)*)) };
}

macro_rules! outln {
    ($($t:tt)*) => { emit(format_args!("{}\n", format_args!($($t)*))) };
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let inv = match args::parse(&argv) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("flowmesh: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let socket = inv.socket.clone();
    let client = LocalClient::new(inv.socket.unwrap_or_else(|| DEFAULT_SOCKET.into()));
    match rt.block_on(run(&client, inv.command, &argv, socket.as_deref())) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("flowmesh: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(
    client: &LocalClient,
    command: Command,
    argv: &[String],
    socket: Option<&std::path::Path>,
) -> Result<u8, String> {
    let e = |e: flowmesh_daemon::client::ClientError| e.to_string();
    match command {
        Command::Ping { target, opts } => {
            let status = client.get("status").await.map_err(e)?;
            let Some(ip) = ping::resolve(&status, &target) else {
                eprintln!("error looking up IP of {target:?}: no such peer");
                return Ok(1);
            };
            let mut out = std::io::stdout();
            let mut err = std::io::stderr();
            let body = json!({
                "ip": ip,
                "timeout_ms": opts.timeout.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            });
            let code = ping::run(&ip, opts, &mut out, &mut err, || async {
                let v = client
                    .post("ping", &body)
                    .await
                    .map_err(|e| e.to_string())?;
                ping::parse_attempt(&v)
            })
            .await;
            Ok(code)
        }
        Command::Whois { addr, json } => {
            let encoded: String = addr
                .chars()
                .map(|c| match c {
                    ':' => "%3A".to_string(),
                    '[' => "%5B".to_string(),
                    ']' => "%5D".to_string(),
                    '%' => "%25".to_string(),
                    '&' => "%26".to_string(),
                    '#' => "%23".to_string(),
                    ' ' => "%20".to_string(),
                    other => other.to_string(),
                })
                .collect();
            match client.get(&format!("whois?addr={encoded}")).await {
                Ok(w) if json => {
                    outln!(
                        "{}",
                        serde_json::to_string_pretty(&w).map_err(|e| e.to_string())?
                    );
                    Ok(0)
                }
                Ok(w) => {
                    out!("{}", render::whois_text(&w));
                    Ok(0)
                }
                // Same wording as the official client for its two common failures.
                Err(flowmesh_daemon::client::ClientError::Api { status, message })
                    if status.as_u16() == 400 =>
                {
                    eprintln!("400 Bad Request: {message}");
                    Ok(1)
                }
                Err(flowmesh_daemon::client::ClientError::Api { status, message })
                    if status.as_u16() == 404 =>
                {
                    eprintln!("{message}");
                    Ok(1)
                }
                Err(other) => Err(other.to_string()),
            }
        }
        Command::Debug(topic) => {
            let v = client
                .get(&format!("debug?topic={topic}"))
                .await
                .map_err(e)?;
            outln!(
                "{}",
                serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
            );
            Ok(0)
        }
        Command::DebugPrefs => {
            let p = client.get("prefs").await.map_err(e)?;
            outln!(
                "{}",
                serde_json::to_string_pretty(&p).map_err(|e| e.to_string())?
            );
            Ok(0)
        }
        Command::Bugreport { output } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let bundle = bugreport::assemble(
                env!("CARGO_PKG_VERSION"),
                now,
                client.get("status").await.map_err(e),
                client.get("prefs").await.map_err(e),
                collect_system(),
            );
            let path = output.unwrap_or_else(|| format!("flowmesh-bugreport-{now}.json").into());
            write_private(
                &path,
                &serde_json::to_vec_pretty(&bundle).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("write {}: {e}", path.display()))?;
            outln!(
                "wrote {} (nothing was sent anywhere; review it before sharing)",
                path.display()
            );
            Ok(0)
        }
        Command::Ip { family, peer } => {
            let status = client.get("status").await.map_err(e)?;
            let resolve = |name: &str| {
                use std::net::ToSocketAddrs;
                (name, 0)
                    .to_socket_addrs()
                    .map(|a| a.map(|s| s.ip()).collect())
                    .map_err(|e| e.to_string())
            };
            match query::ip(&status, family, peer.as_deref(), resolve) {
                Ok(ips) => {
                    for ip in ips {
                        outln!("{ip}");
                    }
                    Ok(0)
                }
                Err(msg) => {
                    eprintln!("{msg}");
                    Ok(1)
                }
            }
        }
        Command::ExitNodeList { filter } => {
            let status = client.get("status").await.map_err(e)?;
            match query::exit_node_list(&status, filter.as_deref()) {
                Ok(t) => {
                    outln!("{t}");
                    Ok(0)
                }
                Err(msg) => {
                    eprintln!("{msg}");
                    Ok(1)
                }
            }
        }
        Command::DnsStatus { all } => {
            let v = client.get("dns").await.map_err(e)?;
            out!("{}", query::dns_status(&v, all));
            Ok(0)
        }
        Command::DnsQuery { name: None, .. } => {
            outln!(
                "usage: flowmesh dns query <name> [type]  (type: a, aaaa, cname, mx, ns, opt, ptr, srv or txt)\n\n\
                 Asks flowmesh's DNS resolver (100.100.100.100) for <name>, an A record unless\n\
                 another type is given, and shows the answer and the upstream resolvers that apply."
            );
            Ok(0)
        }
        Command::DnsQuery {
            name: Some(name),
            rtype,
        } => {
            out!("{}", dnsquery::heading(&name, rtype.as_deref()));
            // Failures are reported on the output with exit 0, as by the official command.
            match dns_query(client, &name, rtype.as_deref()).await {
                Ok(text) => out!("{text}"),
                Err(e) => outln!("failed to query DNS: {e}"),
            }
            Ok(0)
        }
        Command::Netcheck { json } => {
            let dm: flowmesh_proto::derp::DerpMap = match client.get("derpmap").await {
                Ok(v) => serde_json::from_value(v).map_err(|e| format!("relay map: {e}"))?,
                Err(flowmesh_daemon::client::ClientError::Api { status, .. })
                    if status.as_u16() == 503 =>
                {
                    // The official client would fetch a default map from its vendor here.
                    eprintln!(
                        "flowmesh is not running: netcheck measures the relays in the map from your control server, so connect first ('flowmesh up')"
                    );
                    return Ok(1);
                }
                Err(other) => return Err(other.to_string()),
            };
            let observed = netcheck::probe(&dm).await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let report = netcheck::summarize(&dm, &observed, now);
            if json {
                eprintln!("# Warning: this JSON format is not yet considered a stable interface");
                outln!("{}", netcheck::json(&report));
            } else {
                out!("{}", netcheck::text(&dm, &report));
            }
            Ok(0)
        }
        Command::Metrics { write } => {
            let v = client.get("metrics").await.map_err(e)?;
            let text = v.as_str().unwrap_or_default();
            match write {
                None => out!("{text}"),
                Some(path) => write_atomic(&path, text.as_bytes())
                    .map_err(|e| format!("write {}: {e}", path.display()))?,
            }
            Ok(0)
        }
        Command::Ssh { target, args } => {
            let status = client.get("status").await.map_err(e)?;
            let (user, host) = match target.rsplit_once('@') {
                Some((u, h)) => (Some(u), h),
                None => (None, target.as_str()),
            };
            let ip = match host.parse::<std::net::IpAddr>() {
                Ok(ip) => ip,
                Err(_) => query::peer_addr(&status, host)
                    .ok_or_else(|| format!("unknown host {host:?}: not a peer in the mesh"))?,
            };
            let known = known_hosts_path()?;
            write_known_hosts(&known, &query::known_hosts(&status))?;
            let exe = std::env::current_exe().map_err(|e| format!("own program path: {e}"))?;
            let mut proxy = format!("\"{}\"", exe.display());
            if let Some(s) = socket {
                proxy.push_str(&format!(" --socket=\"{}\"", s.display()));
            }
            proxy.push_str(" nc %h %p");
            let dest = match user {
                Some(u) => format!("{u}@{ip}"),
                None => ip.to_string(),
            };
            let mut ssh = std::process::Command::new("ssh");
            ssh.args([
                "-o".to_string(),
                format!("UserKnownHostsFile \"{}\"", known.display()),
                "-o".into(),
                "UpdateHostKeys no".into(),
                "-o".into(),
                "StrictHostKeyChecking yes".into(),
                "-o".into(),
                "CanonicalizeHostname no".into(),
                "-o".into(),
                format!("ProxyCommand {proxy}"),
                dest,
            ]);
            ssh.args(&args);
            use std::os::unix::process::CommandExt;
            let err = ssh.exec();
            Err(format!("run ssh: {err}"))
        }
        Command::Nc { host, port } => {
            let ip = match host.parse::<std::net::IpAddr>() {
                Ok(ip) => ip,
                Err(_) => {
                    let status = client.get("status").await.map_err(e)?;
                    query::peer_addr(&status, &host)
                        .ok_or_else(|| format!("unknown host {host:?}: not a peer in the mesh"))?
                }
            };
            let stream = tokio::net::TcpStream::connect((ip, port))
                .await
                .map_err(|e| format!("connect {ip} port {port}: {e}"))?;
            let (mut r, mut w) = stream.into_split();
            let up = async {
                let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut w).await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut w).await;
            };
            let down = async {
                let mut out = tokio::io::stdout();
                let _ = tokio::io::copy(&mut r, &mut out).await;
                let _ = tokio::io::AsyncWriteExt::flush(&mut out).await;
            };
            // Done when the peer closes; our input ending only half-closes the connection.
            tokio::select! {
                () = async { tokio::join!(up, std::future::pending::<()>()); } => {}
                () = down => {}
            }
            // Exit now: the read of stdin waits in a blocking thread the runtime would otherwise
            // wait for, and ssh keeps our stdin open until we exit.
            std::process::exit(0)
        }
        Command::Version => {
            outln!("{}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Command::Status { json } => {
            let s = client.get("status").await.map_err(e)?;
            if json {
                outln!(
                    "{}",
                    serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?
                );
            } else {
                out!("{}", render::text(&s));
            }
            Ok(render::exit_code(&s))
        }
        Command::Down => {
            if let Some(code) = change(client, "down", &json!({}), argv).await? {
                return Ok(code);
            }
            Ok(0)
        }
        Command::Logout => {
            if let Some(code) = change(client, "logout", &json!({}), argv).await? {
                return Ok(code);
            }
            Ok(0)
        }
        Command::Set(mut update) => {
            resolve_exit_node(client, &mut update).await?;
            warn_forwarding(&update);
            let body = serde_json::to_value(update).map_err(|e| e.to_string())?;
            if let Some(code) = change(client, "set", &body, argv).await? {
                return Ok(code);
            }
            Ok(0)
        }
        Command::Up {
            mut update,
            reset,
            authkey,
            timeout,
        } => {
            let authkey = match authkey {
                None => None,
                Some(AuthKey::Literal(k)) => Some(k),
                Some(AuthKey::File(p)) => Some(
                    std::fs::read_to_string(&p)
                        .map_err(|e| format!("read {}: {e}", p.display()))?
                        .trim()
                        .to_string(),
                ),
            };
            resolve_exit_node(client, &mut update).await?;
            warn_forwarding(&update);
            let body = json!({ "update": update, "reset": reset, "authkey": authkey });
            if let Some(code) = change(client, "up", &body, argv).await? {
                return Ok(code);
            }
            wait_running(client, timeout).await
        }
    }
}

/// Send a change. Refused for lack of rights: say how to run it, as the official CLI does
/// (OBS-20261012-cli-more-official/operator-access.txt), and return the exit code.
async fn change(
    client: &LocalClient,
    path: &str,
    body: &Value,
    argv: &[String],
) -> Result<Option<u8>, String> {
    match client.post(path, body).await {
        Ok(_) => Ok(None),
        Err(flowmesh_daemon::client::ClientError::Api { status, message })
            if status.as_u16() == 403 =>
        {
            eprintln!("{}", render::access_denied(&message, argv));
            Ok(Some(1))
        }
        Err(other) => Err(other.to_string()),
    }
}

/// Turn `--exit-node=<name or address>` into the address to store, checked against the current
/// status like the official CLI (a stopped daemon: an address is taken as given).
async fn resolve_exit_node(
    client: &LocalClient,
    update: &mut flowmesh_daemon::prefs::PrefsUpdate,
) -> Result<(), String> {
    let Some(spec) = update.exit_node.clone().filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let status = client.get("status").await.unwrap_or(Value::Null);
    update.exit_node = Some(flowmesh_cli::exitnode::resolve(&spec, &status)?);
    Ok(())
}

/// When the command advertises routes, warn if the kernel does not forward (the daemon never changes
/// sysctls, like the official client).
fn warn_forwarding(update: &flowmesh_daemon::prefs::PrefsUpdate) {
    let routes = update
        .advertise_routes
        .as_ref()
        .is_some_and(|r| !r.is_empty());
    if !routes && update.advertise_exit_node != Some(true) {
        return;
    }
    let read = |path: &str| std::fs::read_to_string(path).ok().map(|v| v.trim() != "0");
    if let Some(w) = render::forwarding_warning(
        read("/proc/sys/net/ipv4/ip_forward"),
        read("/proc/sys/net/ipv6/conf/all/forwarding"),
    ) {
        eprintln!("{w}");
    }
}

fn command_output(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// System facts for the bug report; each item records its own failure instead of aborting.
fn collect_system() -> Vec<Section> {
    vec![
        Section {
            name: "uname",
            content: command_output("uname", &["-a"]),
        },
        Section {
            name: "ip_addr",
            content: command_output("ip", &["-o", "addr"]),
        },
        Section {
            name: "ip_route",
            content: command_output("ip", &["route", "show", "table", "all"]),
        },
        Section {
            name: "ip_rule",
            content: command_output("ip", &["rule"]),
        },
        Section {
            name: "resolv_conf",
            content: std::fs::read_to_string("/etc/resolv.conf").map_err(|e| e.to_string()),
        },
        Section {
            name: "journal",
            content: command_output(
                "journalctl",
                &["-u", "flowmeshd", "-n", "300", "--no-pager"],
            ),
        },
    ]
}

/// One query to 100.100.100.100 over the mesh interface, rendered with the resolvers that apply.
async fn dns_query(
    client: &LocalClient,
    name: &str,
    rtype: Option<&str>,
) -> Result<String, String> {
    // The official wording carries its local API's status.
    let t =
        dnsquery::parse_type(rtype.unwrap_or("a")).map_err(|e| format!("400 Bad Request: {e}"))?;
    let view = client.get("dns").await.map_err(|e| e.to_string())?;
    let mut id = [0u8; 2];
    getrandom::fill(&mut id).map_err(|e| e.to_string())?;
    let id = u16::from_be_bytes(id);
    let query = dnsquery::build(name, t, id)?;
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| e.to_string())?;
    sock.connect("100.100.100.100:53")
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65535];
    for _ in 0..2 {
        sock.send(&query).await.map_err(|e| e.to_string())?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while let Ok(r) = tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
            let n = r.map_err(|e| e.to_string())?;
            // Ignore anything that is not the answer to this query.
            if n >= 2 && buf[..2] == id.to_be_bytes() {
                return dnsquery::render(&buf[..n], &dnsquery::resolvers_for(&view, name));
            }
        }
    }
    Err("no answer from 100.100.100.100".into())
}

/// `$XDG_CONFIG_HOME/flowmesh/ssh_known_hosts`, else `~/.config/flowmesh/ssh_known_hosts`.
fn known_hosts_path() -> Result<std::path::PathBuf, String> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
        .ok_or("cannot tell where your configuration directory is (no HOME)")?;
    Ok(base.join("flowmesh").join("ssh_known_hosts"))
}

/// The known_hosts file is rewritten from the netmap each time, so keys stay current.
fn write_known_hosts(path: &std::path::Path, content: &str) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    write_atomic(path, content.as_bytes()).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Replace `path` in one step (a temporary file renamed over it), so a metrics collector reading
/// the file never sees half of it.
fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp{}", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Bug reports can contain addresses and routes: create them readable by the owner only.
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

/// Block until Running (exit 0) or the control server refuses (exit 1), like the official `up`.
async fn wait_running(client: &LocalClient, timeout: Option<Duration>) -> Result<u8, String> {
    let start = Instant::now();
    let mut last_health = Value::Null;
    loop {
        let s = client.get("status").await.map_err(|e| e.to_string())?;
        match s["BackendState"].as_str() {
            Some("Running") => return Ok(0),
            Some("NeedsLogin") => {
                match s["AuthURL"].as_str().filter(|u| !u.is_empty()) {
                    Some(url) => eprintln!("To authenticate, visit:\n\n\t{url}\n"),
                    None => eprintln!(
                        "flowmesh: the control server did not accept this node (missing or invalid --auth-key?)"
                    ),
                }
                return Ok(1);
            }
            _ => {}
        }
        if s["Health"] != last_health {
            for h in s["Health"].as_array().into_iter().flatten() {
                if let Some(h) = h.as_str() {
                    eprintln!("flowmesh: {h}");
                }
            }
            last_health = s["Health"].clone();
        }
        if timeout.is_some_and(|t| start.elapsed() >= t) {
            eprintln!("flowmesh: timed out waiting for the network to come up");
            return Ok(1);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
