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

/// `whois` text, in the official layout (OBS-20261010-whois). The User section for untagged nodes
/// follows the same layout but could not be observed in the lab (every lab node is tagged).
pub fn whois_text(w: &Value) -> String {
    let node = &w["Node"];
    let mut out = String::from("Machine:\n");
    let name = node["Name"].as_str().unwrap_or("").trim_end_matches('.');
    out.push_str(&format!("  Name:          {name}\n"));
    out.push_str(&format!("  ID:            {}\n", node["ID"]));
    let addrs: Vec<&str> = node["Addresses"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    out.push_str(&format!("  Addresses:     [{}]\n", addrs.join(" ")));
    let tags: Vec<&str> = node["Tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if tags.is_empty() {
        let user = &w["UserProfile"];
        if user.is_object() {
            out.push_str("User:\n");
            out.push_str(&format!(
                "  Name:     {}\n",
                user["LoginName"].as_str().unwrap_or("")
            ));
            out.push_str(&format!("  ID:       {}\n", user["ID"]));
        }
    } else {
        out.push_str(&format!("  Tags:          {}\n", tags.join(", ")));
    }
    if let Some(caps) = w["CapMap"].as_object().filter(|c| !c.is_empty()) {
        out.push_str("Capabilities:\n");
        for cap in caps.keys() {
            out.push_str(&format!("  - {cap}\n"));
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
        let cur = n["CurAddr"].as_str().filter(|a| !a.is_empty());
        let peer_relay = n["PeerRelay"].as_str().filter(|a| !a.is_empty());
        let path = match (cur, peer_relay) {
            (Some(addr), _) => format!("direct {addr}"),
            (None, Some(pr)) => format!("peer-relay {pr}"),
            (None, None) => format!("relay {:?}", n["Relay"].as_str().unwrap_or("")),
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

/// The warning `up`/`set` print when routes are advertised but the kernel will not forward them
/// (the official client's wording: IPv4 off is reported alone; IPv6 is reported when only it is
/// off). `None` for a value that could not be read.
pub fn forwarding_warning(ipv4: Option<bool>, ipv6: Option<bool>) -> Option<&'static str> {
    match (ipv4, ipv6) {
        (Some(false), _) => {
            Some("Warning: IP forwarding is disabled, subnet routing/exit nodes will not work.")
        }
        (_, Some(false)) => Some(
            "Warning: IPv6 forwarding is disabled.\nSubnet routes and exit nodes may not work correctly.",
        ),
        _ => None,
    }
}

/// The message for a change the daemon refused for lack of rights, laid out like the official
/// one: the reason, the command again with sudo, and how to avoid sudo for good.
pub fn access_denied(reason: &str, argv: &[String]) -> String {
    let mut reason = reason.to_string();
    if let Some(first) = reason.get(..1) {
        reason.replace_range(..1, &first.to_uppercase());
    }
    let quoted: Vec<String> = argv
        .iter()
        .map(|a| {
            let plain = a
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_=./:,@+".contains(c));
            if plain { a.clone() } else { format!("\"{a}\"") }
        })
        .collect();
    format!(
        "{reason}\n\nUse 'sudo flowmesh {}'.\nTo not require root, use 'sudo flowmesh set --operator=$USER' once.",
        quoted.join(" ")
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn access_denied_like_the_official_cli() {
        let argv: Vec<String> = ["set", "--shields-up"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            super::access_denied(
                "access denied: changing flowmesh requires root or the operator",
                &argv
            ),
            "Access denied: changing flowmesh requires root or the operator\n\nUse 'sudo flowmesh set --shields-up'.\nTo not require root, use 'sudo flowmesh set --operator=$USER' once."
        );
        let argv: Vec<String> = ["set", "--hostname=a b"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(
            super::access_denied("x", &argv).contains("'sudo flowmesh set \"--hostname=a b\"'")
        );
    }

    #[test]
    fn forwarding_warning_follows_the_official_client() {
        assert_eq!(
            forwarding_warning(Some(false), Some(false)),
            Some("Warning: IP forwarding is disabled, subnet routing/exit nodes will not work.")
        );
        assert!(
            forwarding_warning(Some(true), Some(false))
                .unwrap()
                .starts_with("Warning: IPv6 forwarding is disabled.")
        );
        assert_eq!(forwarding_warning(Some(true), Some(true)), None);
        assert_eq!(
            forwarding_warning(None, None),
            None,
            "unreadable: no claim either way"
        );
    }

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
                               "Active": false, "TailscaleIPs": ["100.64.0.4"] },
                "nodekey:e": { "DNSName": "tsr.mesh.lab.internal.", "OS": "linux", "Online": true,
                               "Active": true, "CurAddr": "", "PeerRelay": "172.29.0.23:40000:vni:5",
                               "Relay": "wanflow-relay-1000", "TxBytes": 3, "RxBytes": 4,
                               "TailscaleIPs": ["100.64.0.5"] }
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
100.64.0.5  tsr   linux    active; peer-relay 172.29.0.23:40000:vni:5, tx 3 rx 4
100.64.0.9  old   windows  offline
"
        );
    }

    #[test]
    fn whois_layout_matches_official() {
        let w = json!({
            "Node": { "ID": 1, "Name": "ts1.mesh.lab.internal.",
                      "Addresses": ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
                      "Tags": ["tag:relay-enabled"] },
            "UserProfile": { "ID": 1, "LoginName": "lab", "DisplayName": "lab" },
            "CapMap": { "tailscale.com/cap/relay": null, "tailscale.com/cap/relay-target": null }
        });
        assert_eq!(
            whois_text(&w),
            "\
Machine:
  Name:          ts1.mesh.lab.internal
  ID:            1
  Addresses:     [100.64.0.1/32 fd7a:115c:a1e0::1/128]
  Tags:          tag:relay-enabled
Capabilities:
  - tailscale.com/cap/relay
  - tailscale.com/cap/relay-target
"
        );
    }

    #[test]
    fn whois_untagged_shows_user_and_no_caps_section() {
        let w = json!({
            "Node": { "ID": 5, "Name": "laptop.mesh.lab.internal.", "Addresses": ["100.64.0.5/32"] },
            "UserProfile": { "ID": 3, "LoginName": "alice", "DisplayName": "Alice" },
            "CapMap": {}
        });
        assert_eq!(
            whois_text(&w),
            "Machine:\n  Name:          laptop.mesh.lab.internal\n  ID:            5\n  Addresses:     [100.64.0.5/32]\nUser:\n  Name:     alice\n  ID:       3\n"
        );
        let mut no_user = w.clone();
        no_user["UserProfile"] = Value::Null;
        assert!(!whois_text(&no_user).contains("User:"));
        let mut two_tags = w;
        two_tags["Node"]["Tags"] = json!(["tag:a", "tag:b"]);
        assert!(whois_text(&two_tags).contains("  Tags:          tag:a, tag:b\n"));
        assert!(
            !whois_text(&two_tags).contains("User:"),
            "tagged nodes hide the user"
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
