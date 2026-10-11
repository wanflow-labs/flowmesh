// SPDX-License-Identifier: Apache-2.0
//! `--exit-node` is resolved by the CLI against the current status, as the official CLI does, and
//! stored as an address: a node renamed later does not change the exit node in use.

use serde_json::Value;
use std::net::IpAddr;

/// The address to use for `--exit-node=<spec>`, given `status --json`. An address is checked
/// (not our own; once running, a peer that offers an exit node); a name matches a peer's DNS name
/// with or without the MagicDNS suffix (case-insensitive) and must be unique. Errors are the
/// official client's.
pub fn resolve(spec: &str, status: &Value) -> Result<String, String> {
    let own = |ip: &IpAddr| {
        status["TailscaleIPs"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|v| v.as_str().and_then(|s| s.parse::<IpAddr>().ok()) == Some(*ip))
    };
    let local = |s: &str| {
        format!("cannot use {s} as an exit node as it is a local IP address to this machine")
    };
    let peers: Vec<&Value> = status["Peer"]
        .as_object()
        .map(|m| m.values().collect())
        .unwrap_or_default();
    let ips = |p: &Value| -> Vec<IpAddr> {
        p["TailscaleIPs"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str()?.parse().ok())
            .collect()
    };
    if let Ok(ip) = spec.parse::<IpAddr>() {
        if own(&ip) {
            return Err(local(spec));
        }
        if status["BackendState"] == "Running" {
            let peer = peers
                .iter()
                .find(|p| ips(p).contains(&ip))
                .ok_or_else(|| format!("no node found in netmap with IP {ip}"))?;
            if peer["ExitNodeOption"] != true {
                return Err(format!("node {ip} is not advertising an exit node"));
            }
        }
        return Ok(spec.to_string());
    }
    let suffix = status["MagicDNSSuffix"].as_str().unwrap_or_default();
    let mut matched = None;
    let mut count = 0;
    for p in &peers {
        let dns = p["DNSName"].as_str().unwrap_or_default();
        let base = dns
            .trim_end_matches('.')
            .strip_suffix(suffix)
            .and_then(|b| b.strip_suffix('.'))
            .filter(|_| !suffix.is_empty())
            .unwrap_or(dns.trim_end_matches('.'));
        if !spec.eq_ignore_ascii_case(base) && !spec.eq_ignore_ascii_case(dns) {
            continue;
        }
        count += 1;
        let first = ips(p)
            .into_iter()
            .next()
            .ok_or_else(|| format!("node {spec:?} has no Tailscale IP?"))?;
        if p["ExitNodeOption"] != true {
            return Err(format!("node {spec:?} is not advertising an exit node"));
        }
        matched = Some(first);
    }
    match (count, matched) {
        (0, _) => Err(format!(
            "invalid value {spec:?} for --exit-node; must be IP or unique node name"
        )),
        (1, Some(ip)) if own(&ip) => Err(local(spec)),
        (1, Some(ip)) => Ok(ip.to_string()),
        _ => Err(format!("ambiguous exit node name {spec:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn status() -> Value {
        json!({
            "BackendState": "Running",
            "TailscaleIPs": ["100.64.0.7", "fd7a:115c:a1e0::7"],
            "MagicDNSSuffix": "mesh.lab.internal",
            "Peer": {
                "k1": {"DNSName": "tse.mesh.lab.internal.", "TailscaleIPs": ["100.64.0.9", "fd7a:115c:a1e0::9"], "ExitNodeOption": true},
                "k2": {"DNSName": "gw-1.mesh.lab.internal.", "TailscaleIPs": ["100.64.0.11"], "ExitNodeOption": false},
                "k3": {"DNSName": "dup.mesh.lab.internal.", "TailscaleIPs": ["100.64.0.12"], "ExitNodeOption": true},
                "k4": {"DNSName": "dup.mesh.lab.internal.", "TailscaleIPs": ["100.64.0.13"], "ExitNodeOption": true}
            }
        })
    }

    #[test]
    fn names_resolve_to_the_first_address_like_the_official_cli() {
        let s = status();
        assert_eq!(
            resolve("TSE", &s),
            Ok("100.64.0.9".into()),
            "base name, any case"
        );
        assert_eq!(
            resolve("tse.mesh.lab.internal.", &s),
            Ok("100.64.0.9".into()),
            "full DNS name"
        );
        assert_eq!(
            resolve("gw-1", &s),
            Err("node \"gw-1\" is not advertising an exit node".into())
        );
        assert_eq!(
            resolve("dup", &s),
            Err("ambiguous exit node name \"dup\"".into())
        );
        let mut other = status();
        other["Peer"]["k4"]["DNSName"] = json!("dup.other.");
        assert_eq!(
            resolve("dup", &other),
            Ok("100.64.0.12".into()),
            "another suffix is not trimmed"
        );
        assert_eq!(
            resolve("nope", &s),
            Err("invalid value \"nope\" for --exit-node; must be IP or unique node name".into())
        );
    }

    #[test]
    fn addresses_are_checked_once_running() {
        let s = status();
        assert_eq!(resolve("100.64.0.9", &s), Ok("100.64.0.9".into()));
        assert_eq!(
            resolve("100.64.0.7", &s),
            Err(
                "cannot use 100.64.0.7 as an exit node as it is a local IP address to this machine"
                    .into()
            )
        );
        assert_eq!(
            resolve("100.64.0.99", &s),
            Err("no node found in netmap with IP 100.64.0.99".into())
        );
        assert_eq!(
            resolve("100.64.0.11", &s),
            Err("node 100.64.0.11 is not advertising an exit node".into())
        );
        let stopped = json!({"BackendState": "Stopped", "TailscaleIPs": null, "Peer": null});
        assert_eq!(
            resolve("100.64.0.99", &stopped),
            Ok("100.64.0.99".into()),
            "not running: taken as given"
        );
    }
}
