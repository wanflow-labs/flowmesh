// SPDX-License-Identifier: Apache-2.0
//! Read-only query commands rendered from daemon data, in the official CLI's shapes
//! (OBS-20261012-cli-more-official): `ip`, `exit-node list`, `dns status`. Pure functions; the
//! binary fetches the data and prints. Product names in human-facing text say flowmesh.

use serde_json::Value;
use std::net::IpAddr;

/// Which addresses `ip` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpFamily {
    #[default]
    All,
    V4,
    V6,
    /// `-1`: just one, IPv4 when there is one.
    One,
}

fn addrs(v: &Value) -> Vec<IpAddr> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a.as_str()?.split('/').next()?.parse().ok())
        .collect()
}

fn pick(list: Vec<IpAddr>, family: IpFamily) -> Vec<IpAddr> {
    match family {
        IpFamily::All => list,
        IpFamily::V4 => list.into_iter().filter(IpAddr::is_ipv4).collect(),
        IpFamily::V6 => list.into_iter().filter(IpAddr::is_ipv6).collect(),
        IpFamily::One => {
            let first = list.iter().find(|a| a.is_ipv4()).or(list.first()).copied();
            first.into_iter().collect()
        }
    }
}

/// The peer a name or address names: an address of a peer, its DNS name with or without the
/// MagicDNS suffix, or its host name (case-insensitive).
pub fn find_peer<'a>(status: &'a Value, who: &str) -> Option<&'a Value> {
    let peers = status["Peer"].as_object()?;
    if let Ok(ip) = who.parse::<IpAddr>() {
        return peers
            .values()
            .find(|p| addrs(&p["TailscaleIPs"]).contains(&ip));
    }
    peers.values().find(|p| {
        let dns = p["DNSName"]
            .as_str()
            .unwrap_or_default()
            .trim_end_matches('.');
        let base = dns.split('.').next().unwrap_or_default();
        let host = p["HostName"].as_str().unwrap_or_default();
        [dns, base, host]
            .iter()
            .any(|n| !n.is_empty() && n.eq_ignore_ascii_case(who))
    })
}

/// `ip [-4|-6|-1] [peer]`. `resolve` looks a name up outside the mesh (system DNS), as the
/// official CLI does for names it does not know.
pub fn ip(
    status: &Value,
    family: IpFamily,
    peer: Option<&str>,
    resolve: impl Fn(&str) -> Result<Vec<IpAddr>, String>,
) -> Result<Vec<IpAddr>, String> {
    let Some(who) = peer else {
        let own = addrs(&status["TailscaleIPs"]);
        if own.is_empty() {
            let state = status["BackendState"].as_str().unwrap_or("NoState");
            return Err(format!("no current flowmesh IPs; state: {state}"));
        }
        return Ok(pick(own, family));
    };
    if let Some(p) = find_peer(status, who) {
        return Ok(pick(addrs(&p["TailscaleIPs"]), family));
    }
    let found = resolve(who).map_err(|e| format!("error looking up IP of {who:?}: {e}"))?;
    // A name the system resolves to a peer's address means that peer.
    for ip in &found {
        if let Some(p) = find_peer(status, &ip.to_string()) {
            return Ok(pick(addrs(&p["TailscaleIPs"]), family));
        }
    }
    Err(format!(
        "error looking up IP of {who:?}: no peer with that address"
    ))
}

/// Lay out rows like Go's tabwriter with minwidth 10 and padding 5 (the official table).
fn table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|c| {
            let w = rows
                .iter()
                .filter_map(|r| r.get(c))
                .map(|s| s.chars().count())
                .max()
                .unwrap_or(0);
            (w + 5).max(10)
        })
        .collect();
    let mut out = String::new();
    for r in rows {
        for (c, cell) in r.iter().enumerate() {
            out.push_str(cell);
            out.push_str(&" ".repeat(widths[c] - cell.chars().count()));
        }
        out.push('\n');
    }
    out
}

/// `exit-node list [--filter=country]`: peers offering an exit node.
pub fn exit_node_list(status: &Value, filter: Option<&str>) -> Result<String, String> {
    let mut nodes: Vec<&Value> = status["Peer"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.values())
        .filter(|p| p["ExitNodeOption"] == true)
        .collect();
    let country = |p: &Value| {
        p["Location"]["Country"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or("-")
            .to_string()
    };
    if let Some(f) = filter {
        nodes.retain(|p| country(p).eq_ignore_ascii_case(f));
        if nodes.is_empty() {
            return Err(format!("no exit nodes found for {f:?}"));
        }
    }
    nodes.sort_by_key(|p| p["DNSName"].as_str().unwrap_or_default().to_string());
    let mut rows = vec![vec![
        " IP".to_string(),
        "HOSTNAME".into(),
        "COUNTRY".into(),
        "CITY".into(),
        "STATUS".into(),
    ]];
    for p in nodes {
        let ip = pick(addrs(&p["TailscaleIPs"]), IpFamily::One)
            .first()
            .map(ToString::to_string)
            .unwrap_or_default();
        let status = if p["ExitNode"] == true {
            "selected"
        } else if p["Online"] != true {
            "offline"
        } else {
            "-"
        };
        rows.push(vec![
            format!(" {ip}"),
            p["DNSName"]
                .as_str()
                .unwrap_or_default()
                .trim_end_matches('.')
                .to_string(),
            country(p),
            p["Location"]["City"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or("-")
                .to_string(),
            status.to_string(),
        ]);
    }
    Ok(format!(
        "\n{}\n# To list one country's exit nodes, add --filter=<country> to `flowmesh exit-node list`.\n# To use an exit node, use `flowmesh set --exit-node=` followed by the hostname or IP.",
        table(&rows)
    ))
}

/// The address to reach a peer named by `who` at: its first IPv4 address, else its first.
pub fn peer_addr(status: &Value, who: &str) -> Option<IpAddr> {
    let p = find_peer(status, who)?;
    pick(addrs(&p["TailscaleIPs"]), IpFamily::One)
        .first()
        .copied()
}

/// known_hosts lines for every peer that runs an SSH server: each host key under the peer's DNS
/// name (with the trailing dot) and each of its addresses, as the official CLI writes them
/// (OBS-20261012-ssh-official/ssh-known-hosts.txt).
pub fn known_hosts(status: &Value) -> String {
    let mut out = String::new();
    let mut peers: Vec<&Value> = status["Peer"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.values())
        .collect();
    peers.sort_by_key(|p| p["DNSName"].as_str().unwrap_or_default().to_string());
    for p in peers {
        let mut names: Vec<String> = Vec::new();
        if let Some(n) = p["DNSName"].as_str().filter(|n| !n.is_empty()) {
            names.push(if n.ends_with('.') {
                n.to_string()
            } else {
                format!("{n}.")
            });
        }
        names.extend(addrs(&p["TailscaleIPs"]).iter().map(ToString::to_string));
        for key in strings(&p["sshHostKeys"]) {
            for name in &names {
                out.push_str(&format!("{name} {key}\n"));
            }
        }
    }
    out
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str().map(str::to_owned))
        .collect()
}

fn list(out: &mut String, items: &[String], none: &str) {
    if items.is_empty() {
        out.push_str(&format!("  {none}\n"));
    }
    for i in items {
        out.push_str(&format!("  - {i}\n"));
    }
}

/// `dns status [--all]`, from the daemon's `dns` view: the official sections and order
/// (OBS-20261012-cli-more-official/dns-status*.txt), worded for flowmesh.
pub fn dns_status(v: &Value, all: bool) -> String {
    let mut o = String::from("\n=== 'Use flowmesh DNS' status ===\n\n");
    if v["acceptDNS"] == true {
        o.push_str("flowmesh DNS: enabled.\n\n");
        if v["resolvConfManaged"] == true {
            o.push_str(
                "DNS queries on this device go to the flowmesh resolver (100.100.100.100).\n",
            );
        } else {
            o.push_str("resolv.conf is managed by another service, so DNS queries on this device do not reach the flowmesh resolver (see 'flowmesh status').\n");
        }
        o.push_str("(Run 'flowmesh set --accept-dns=false' to go back to the system resolver)\n");
    } else {
        o.push_str("flowmesh DNS: disabled.\n\n");
        o.push_str("(Run 'flowmesh set --accept-dns=true' to start sending DNS queries to the flowmesh DNS resolver)\n");
    }
    o.push_str("\n=== MagicDNS configuration ===\n\n");
    o.push_str("As sent to this device by the control server.\n\n");
    let suffix = v["suffix"].as_str().unwrap_or_default();
    if v["magicDNS"] == true {
        o.push_str(&format!(
            "MagicDNS: enabled tailnet-wide (suffix = {suffix})\n\n"
        ));
        o.push_str(&format!(
            "Other devices in your tailnet can reach this device at {}.\n\n",
            v["selfName"].as_str().unwrap_or_default()
        ));
    } else {
        o.push_str("MagicDNS: disabled tailnet-wide.\n\n");
    }
    o.push_str("Resolvers (in preference order):\n");
    list(
        &mut o,
        &strings(&v["resolvers"]),
        "(none: names outside the mesh go to the system resolvers listed under 'System DNS configuration')",
    );
    o.push_str("\nSplit DNS Routes:\n");
    // Routes without resolvers are names MagicDNS answers itself (headscale sends one per reverse
    // zone of the mesh ranges); the official output leaves them out.
    for (suffix, rs) in v["routes"].as_object().into_iter().flatten() {
        let rs = strings(rs);
        if !rs.is_empty() {
            o.push_str(&format!("  - {suffix:<30} -> {}\n", rs.join(", ")));
        }
    }
    if all {
        o.push_str("\nFallback Resolvers:\n");
        let fb = strings(&v["fallbackResolvers"]);
        if fb.is_empty() {
            o.push_str("  (no fallback resolvers configured)\n");
        }
        for (i, r) in fb.iter().enumerate() {
            o.push_str(&format!("  {i}: {r}\n"));
        }
    }
    o.push_str("\nSearch Domains:\n");
    list(&mut o, &strings(&v["domains"]), "(no search domains found)");
    if all {
        o.push_str("\nNameservers IP Addresses:\n  (none were provided)\n");
        o.push_str("\nCertificate Domains:\n  (no certificate domains are configured)\n");
        o.push_str("\nAdditional DNS Records:\n");
        let recs = v["extraRecords"].as_array().cloned().unwrap_or_default();
        if recs.is_empty() {
            o.push_str("  (no additional records)\n");
        }
        for r in recs {
            o.push_str(&format!(
                "  - [{}] {:<50} -> {}\n",
                r["type"].as_str().unwrap_or_default(),
                r["name"].as_str().unwrap_or_default(),
                r["value"].as_str().unwrap_or_default()
            ));
        }
        o.push_str("\nFiltered suffixes when forwarding DNS queries as an exit node:\n  (no suffixes are filtered)\n");
    }
    o.push_str("\n=== System DNS configuration ===\n\n");
    o.push_str(
        "This is the DNS configuration that flowmesh believes your operating system is using.\n",
    );
    o.push_str("flowmesh uses it for names the coordination server has no resolvers for.\n\n");
    o.push_str("Nameservers:\n");
    list(
        &mut o,
        &strings(&v["system"]["nameservers"]),
        "(no nameservers found)",
    );
    o.push_str("\nSearch domains:\n");
    list(
        &mut o,
        &strings(&v["system"]["search"]),
        "(no search domains found)",
    );
    if all {
        o.push_str("\nMatch domains:\n  (no match domains found)\n");
    }
    o.push_str("\n[the layout of this report may still change]\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn status() -> Value {
        json!({
            "BackendState": "Running",
            "TailscaleIPs": ["100.64.0.41", "fd7a:115c:a1e0::29"],
            "Peer": {
                "k1": {"DNSName": "toe.mesh.lab.internal.", "HostName": "toE", "TailscaleIPs": ["100.64.0.42", "fd7a:115c:a1e0::2a"], "ExitNodeOption": true, "Online": true},
                "k2": {"DNSName": "gw.mesh.lab.internal.", "HostName": "gw", "TailscaleIPs": ["100.64.0.43"], "ExitNodeOption": false, "Online": true}
            }
        })
    }
    fn nores(_: &str) -> Result<Vec<IpAddr>, String> {
        Err("no such host".into())
    }
    fn s(v: Result<Vec<IpAddr>, String>) -> Vec<String> {
        v.unwrap().iter().map(ToString::to_string).collect()
    }

    /// The official CLI's output for the same situations (OBS-20261012-cli-more-official/ip*.txt).
    #[test]
    fn ip_like_the_official_cli() {
        let st = status();
        assert_eq!(
            s(ip(&st, IpFamily::All, None, nores)),
            ["100.64.0.41", "fd7a:115c:a1e0::29"]
        );
        assert_eq!(s(ip(&st, IpFamily::V4, None, nores)), ["100.64.0.41"]);
        assert_eq!(
            s(ip(&st, IpFamily::V6, None, nores)),
            ["fd7a:115c:a1e0::29"]
        );
        assert_eq!(s(ip(&st, IpFamily::One, None, nores)), ["100.64.0.41"]);
        assert_eq!(
            s(ip(&st, IpFamily::All, Some("toe"), nores)),
            ["100.64.0.42", "fd7a:115c:a1e0::2a"]
        );
        assert_eq!(
            s(ip(&st, IpFamily::All, Some("100.64.0.42"), nores)),
            ["100.64.0.42", "fd7a:115c:a1e0::2a"]
        );
        assert_eq!(
            s(ip(&st, IpFamily::V4, Some("TOE"), nores)),
            ["100.64.0.42"]
        );
        assert_eq!(
            ip(&st, IpFamily::All, Some("nosuchnode"), nores),
            Err("error looking up IP of \"nosuchnode\": no such host".into())
        );
        let via_dns = |_: &str| Ok(vec!["100.64.0.43".parse().unwrap()]);
        assert_eq!(
            s(ip(&st, IpFamily::All, Some("gw.example"), via_dns)),
            ["100.64.0.43"]
        );
        let stopped = json!({"BackendState": "NeedsLogin", "TailscaleIPs": null});
        assert_eq!(
            ip(&stopped, IpFamily::All, None, nores),
            Err("no current flowmesh IPs; state: NeedsLogin".into())
        );
    }

    fn dns_view() -> Value {
        json!({
            "acceptDNS": false, "resolvConfManaged": false, "magicDNS": true,
            "suffix": "mesh.lab.internal", "selfName": "toa.mesh.lab.internal",
            "resolvers": [], "routes": {"100.100.in-addr.arpa": []}, "fallbackResolvers": ["223.5.5.5"],
            "domains": ["mesh.lab.internal"],
            "extraRecords": [{"name": "svc.mesh.lab.internal", "type": "A", "value": "100.64.0.250"}],
            "system": {"nameservers": ["127.0.0.11"], "search": []}
        })
    }

    /// Same sections, order and content as the official output for the same settings
    /// (dns-status.txt, dns-status-all.txt); only the product wording differs.
    #[test]
    fn dns_status_follows_the_official_sections() {
        let official =
            include_str!("../../../fixtures/observed/20261012-cli-more-official/dns-status.txt");
        let ours = dns_status(&dns_view(), false);
        let heads = |s: &str| -> Vec<String> {
            s.lines()
                .filter(|l| {
                    l.starts_with("===")
                        || l.ends_with(':')
                        || l.starts_with("  - ")
                        || l.starts_with("MagicDNS")
                })
                .map(|l| l.replace("Tailscale", "flowmesh"))
                .collect()
        };
        assert_eq!(heads(&ours), heads(official));
        let official_all = include_str!(
            "../../../fixtures/observed/20261012-cli-more-official/dns-status-all.txt"
        );
        let ours_all = dns_status(&dns_view(), true);
        let heads_all = |s: &str| -> Vec<String> {
            heads(s)
                .into_iter()
                .filter(|l| !l.starts_with("  - [A]"))
                .collect()
        };
        assert_eq!(heads_all(&ours_all), heads_all(official_all));
        assert!(ours_all.contains(
            "  - [A] svc.mesh.lab.internal                              -> 100.64.0.250\n"
        ));
        assert!(ours_all.contains("  0: 223.5.5.5\n"));
        let mut on = dns_view();
        on["acceptDNS"] = json!(true);
        on["resolvConfManaged"] = json!(true);
        assert!(dns_status(&on, false).contains("flowmesh DNS: enabled."));
    }

    #[test]
    fn known_hosts_like_the_official_cli() {
        let mut st = status();
        st["Peer"]["k1"]["sshHostKeys"] =
            json!(["ssh-ed25519 AAAAk1", "ecdsa-sha2-nistp256 AAAAe1"]);
        assert_eq!(
            known_hosts(&st),
            "toe.mesh.lab.internal. ssh-ed25519 AAAAk1\n100.64.0.42 ssh-ed25519 AAAAk1\nfd7a:115c:a1e0::2a ssh-ed25519 AAAAk1\n\
             toe.mesh.lab.internal. ecdsa-sha2-nistp256 AAAAe1\n100.64.0.42 ecdsa-sha2-nistp256 AAAAe1\nfd7a:115c:a1e0::2a ecdsa-sha2-nistp256 AAAAe1\n"
        );
        assert_eq!(peer_addr(&st, "toe"), Some("100.64.0.42".parse().unwrap()));
        assert_eq!(peer_addr(&st, "nobody"), None);
    }

    /// Column layout of the official table (OBS-20261012-cli-more-official/exit-node-list.txt).
    #[test]
    fn exit_node_table_like_the_official_cli() {
        let out = exit_node_list(&status(), None).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "");
        assert_eq!(
            lines[1],
            " IP              HOSTNAME                  COUNTRY     CITY      STATUS     "
        );
        assert_eq!(
            lines[2],
            " 100.64.0.42     toe.mesh.lab.internal     -           -         -          "
        );
        assert_eq!(lines[3], "");
        assert!(lines[4].starts_with("# To list one country's exit nodes"));
        assert_eq!(
            exit_node_list(&status(), Some("nowhere")),
            Err("no exit nodes found for \"nowhere\"".into())
        );
        let mut sel = status();
        sel["Peer"]["k1"]["ExitNode"] = json!(true);
        assert!(exit_node_list(&sel, None).unwrap().contains(" selected "));
        sel["Peer"]["k1"]["ExitNode"] = json!(false);
        sel["Peer"]["k1"]["Online"] = json!(false);
        assert!(exit_node_list(&sel, None).unwrap().contains(" offline "));
    }
}
