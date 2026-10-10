// SPDX-License-Identifier: Apache-2.0
//! flowmesh: command-line client for flowmeshd.

use flowmesh_cli::args::{self, AuthKey, Command};
use flowmesh_cli::render;
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
            let r = client.post("logout", &json!({})).await.map_err(e)?;
            if let Some(w) = r["warning"].as_str() {
                eprintln!("warning: logged out locally, but the control server was not told: {w}");
            }
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
