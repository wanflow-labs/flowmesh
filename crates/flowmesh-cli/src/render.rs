// SPDX-License-Identifier: Apache-2.0
//! Human-readable `flowmesh status`, rendered from the same JSON that `status --json` prints.
//! Scripts should use `--json`; this text is for people and may change.

use serde_json::Value;

/// `status` exits 0 only while Running (cli.md §1).
pub fn exit_code(status: &Value) -> u8 {
    u8::from(status["BackendState"] != "Running")
}

pub fn text(status: &Value) -> String {
    let mut out = String::new();
    match status["BackendState"].as_str().unwrap_or("") {
        "Running" => {
            let mut rows = vec![row(&status["Self"], true)];
            if let Some(peers) = status["Peer"].as_object() {
                let mut list: Vec<&Value> = peers.values().collect();
                list.sort_by_key(|p| first_ip(p));
                rows.extend(list.into_iter().map(|p| row(p, false)));
            }
            out.push_str(&table(&rows));
        }
        "Stopped" => out.push_str("flowmesh is stopped.\n"),
        "NeedsLogin" => {
            out.push_str("Logged out.\n");
            if let Some(url) = status["AuthURL"].as_str().filter(|u| !u.is_empty()) {
                out.push_str(&format!("Log in at: {url}\n"));
            }
        }
        "Starting" => out.push_str("Starting…\n"),
        other => out.push_str(&format!("Unknown state {other:?}\n")),
    }
    let problems: Vec<&str> = status["Health"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|h| *h != "flowmesh is stopped.")
        .collect();
    if !problems.is_empty() {
        out.push_str("\n# Health check:\n");
        for p in problems {
            out.push_str(&format!("#     - {p}\n"));
        }
    }
    out
}

fn first_ip(n: &Value) -> String {
    n["TailscaleIPs"][0].as_str().unwrap_or("-").to_string()
}

fn short_name(n: &Value) -> String {
    let dns = n["DNSName"].as_str().unwrap_or("");
    match dns.split('.').next().filter(|s| !s.is_empty()) {
        Some(label) => label.to_string(),
        None => n["HostName"].as_str().unwrap_or("-").to_string(),
    }
}

fn row(n: &Value, is_self: bool) -> [String; 4] {
    let state = if is_self {
        "-".to_string()
    } else if n["Online"] != true {
        "offline".to_string()
    } else if n["Active"] == true {
        let path = match n["CurAddr"].as_str().filter(|a| !a.is_empty()) {
            Some(addr) => format!("direct {addr}"),
            None => format!("relay {:?}", n["Relay"].as_str().unwrap_or("")),
        };
        format!(
            "active; {path}, tx {} rx {}",
            n["TxBytes"].as_u64().unwrap_or(0),
            n["RxBytes"].as_u64().unwrap_or(0)
        )
    } else {
        "-".to_string()
    };
    [
        first_ip(n),
        short_name(n),
        n["OS"].as_str().unwrap_or("-").to_string(),
        state,
    ]
}

fn table(rows: &[[String; 4]]) -> String {
    let mut widths = [0usize; 3];
    for r in rows {
        for (w, cell) in widths.iter_mut().zip(r.iter()) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for r in rows {
        for (cell, w) in r.iter().zip(widths) {
            out.push_str(&format!("{cell:<w$}  "));
        }
        out.push_str(&r[3]);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn running() -> Value {
        json!({
            "BackendState": "Running",
            "Self": { "DNSName": "fm1.mesh.lab.internal.", "HostName": "fm1", "OS": "linux",
                      "TailscaleIPs": ["100.64.0.3"] },
            "Peer": {
                "nodekey:b": { "DNSName": "ts2.mesh.lab.internal.", "OS": "linux", "Online": true,
                               "Active": true, "CurAddr": "", "Relay": "wanflow-relay-1000",
                               "TxBytes": 10, "RxBytes": 20, "TailscaleIPs": ["100.64.0.2"] },
                "nodekey:a": { "DNSName": "ts1.mesh.lab.internal.", "OS": "linux", "Online": true,
                               "Active": true, "CurAddr": "172.29.0.21:41641",
                               "TxBytes": 1, "RxBytes": 2, "TailscaleIPs": ["100.64.0.1"] },
                "nodekey:c": { "DNSName": "", "HostName": "old", "OS": "windows", "Online": false,
                               "TailscaleIPs": ["100.64.0.9"] },
                "nodekey:d": { "DNSName": "idle.mesh.lab.internal.", "OS": "linux", "Online": true,
                               "Active": false, "TailscaleIPs": ["100.64.0.4"] }
            },
            "Health": []
        })
    }

    #[test]
    fn running_table() {
        assert_eq!(
            text(&running()),
            "\
100.64.0.3  fm1   linux    -
100.64.0.1  ts1   linux    active; direct 172.29.0.21:41641, tx 1 rx 2
100.64.0.2  ts2   linux    active; relay \"wanflow-relay-1000\", tx 10 rx 20
100.64.0.4  idle  linux    -
100.64.0.9  old   windows  offline
"
        );
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(&running()), 0);
        for s in ["Stopped", "NeedsLogin", "Starting"] {
            assert_eq!(exit_code(&json!({ "BackendState": s })), 1, "{s}");
        }
    }

    #[test]
    fn stopped_and_logged_out() {
        let stopped = json!({ "BackendState": "Stopped", "Health": ["flowmesh is stopped."] });
        assert_eq!(text(&stopped), "flowmesh is stopped.\n");
        assert_eq!(
            text(&json!({ "BackendState": "NeedsLogin", "AuthURL": "http://h/register/x" })),
            "Logged out.\nLog in at: http://h/register/x\n"
        );
        assert_eq!(
            text(&json!({ "BackendState": "NeedsLogin", "AuthURL": "" })),
            "Logged out.\n"
        );
    }

    #[test]
    fn health_problems_are_listed() {
        let s = json!({ "BackendState": "Starting", "Health": ["control connect: refused"] });
        assert_eq!(
            text(&s),
            "Starting…\n\n# Health check:\n#     - control connect: refused\n"
        );
        assert_eq!(
            text(&json!({ "BackendState": "Weird" })),
            "Unknown state \"Weird\"\n"
        );
    }
}
