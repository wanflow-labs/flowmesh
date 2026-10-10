// SPDX-License-Identifier: Apache-2.0
//! flowmesh: command-line client for flowmeshd.

use flowmesh_cli::args::{self, AuthKey, Command};
use flowmesh_cli::bugreport::{self, Section};
use flowmesh_cli::{ping, render};
use flowmesh_daemon::client::{DEFAULT_SOCKET, LocalClient};
use serde_json::{Value, json};
use std::process::ExitCode;
use std::time::{Duration, Instant};

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
    let client = LocalClient::new(inv.socket.unwrap_or_else(|| DEFAULT_SOCKET.into()));
    match rt.block_on(run(&client, inv.command)) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("flowmesh: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(client: &LocalClient, command: Command) -> Result<u8, String> {
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
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&w).map_err(|e| e.to_string())?
                    );
                    Ok(0)
                }
                Ok(w) => {
                    print!("{}", render::whois_text(&w));
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
        Command::DebugPrefs => {
            let p = client.get("prefs").await.map_err(e)?;
            println!(
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
            println!(
                "wrote {} (nothing was sent anywhere; review it before sharing)",
                path.display()
            );
            Ok(0)
        }
        Command::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Command::Status { json } => {
            let s = client.get("status").await.map_err(e)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?
                );
            } else {
                print!("{}", render::text(&s));
            }
            Ok(render::exit_code(&s))
        }
        Command::Down => {
            client.post("down", &json!({})).await.map_err(e)?;
            Ok(0)
        }
        Command::Logout => {
            client.post("logout", &json!({})).await.map_err(e)?;
            Ok(0)
        }
        Command::Set(update) => {
            let body = serde_json::to_value(update).map_err(|e| e.to_string())?;
            client.post("set", &body).await.map_err(e)?;
            Ok(0)
        }
        Command::Up {
            update,
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
            let body = json!({ "update": update, "reset": reset, "authkey": authkey });
            client.post("up", &body).await.map_err(e)?;
            wait_running(client, timeout).await
        }
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
