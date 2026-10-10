// SPDX-License-Identifier: Apache-2.0
//! Peer capabilities granted by `CapGrant` rules: what `whois` reports as `CapMap` for a peer
//! (cli.md §5). Packet filtering ignores these rules (filter.md F12); this is their only reader.

use crate::compile::parse_set;
use flowmesh_proto::filter::FilterRule;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Capabilities that rules grant to traffic from `src` towards any of `dsts` (this node's addresses).
/// A capability named in `Caps` has the value `null`; values from `CapMap` are arrays, concatenated
/// across rules. A rule whose sources cannot be parsed grants nothing.
pub fn peer_caps(rules: &[FilterRule], src: IpAddr, dsts: &[IpAddr]) -> BTreeMap<String, Value> {
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    for rule in rules.iter().filter(|r| !r.cap_grant.is_empty()) {
        let Ok(srcs) = parse_set(rule.src_ips.iter().map(String::as_str)) else {
            continue;
        };
        if !srcs.contains(&src) {
            continue;
        }
        for grant in &rule.cap_grant {
            if !grant
                .dsts
                .iter()
                .any(|net| dsts.iter().any(|d| net.contains(d)))
            {
                continue;
            }
            for cap in &grant.caps {
                out.entry(cap.clone()).or_insert(Value::Null);
            }
            for (cap, value) in grant.cap_map.iter().flatten() {
                let slot = out.entry(cap.clone()).or_insert(Value::Null);
                let items = match value {
                    Value::Array(a) => a.clone(),
                    Value::Null => Vec::new(),
                    other => vec![other.clone()],
                };
                match slot {
                    Value::Array(existing) => existing.extend(items),
                    _ if !items.is_empty() => *slot = Value::Array(items),
                    _ => {}
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmesh_proto::filter::CapGrant;
    use serde_json::json;

    fn me() -> Vec<IpAddr> {
        vec![
            "100.64.0.2".parse().unwrap(),
            "fd7a:115c:a1e0::2".parse().unwrap(),
        ]
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The rule WanFlow's control server sends for the high-performance relay (baseline netmap).
    fn relay_rule() -> FilterRule {
        serde_json::from_value(json!({
            "SrcIPs": ["*"],
            "CapGrant": [{ "Caps": ["tailscale.com/cap/relay", "tailscale.com/cap/relay-target"],
                           "Dsts": ["100.64.0.0/10", "fd7a:115c:a1e0::/48"] }]
        }))
        .unwrap()
    }

    #[test]
    fn relay_caps_match_the_official_whois() {
        let caps = peer_caps(&[relay_rule()], ip("100.64.0.1"), &me());
        assert_eq!(
            serde_json::to_value(&caps).unwrap(),
            json!({ "tailscale.com/cap/relay": null, "tailscale.com/cap/relay-target": null })
        );
    }

    #[test]
    fn source_and_destination_must_match() {
        let mut r = relay_rule();
        r.src_ips = vec!["100.64.0.1/32".into()];
        assert_eq!(peer_caps(&[r.clone()], ip("100.64.0.1"), &me()).len(), 2);
        assert!(peer_caps(&[r.clone()], ip("100.64.0.9"), &me()).is_empty());
        r.src_ips = vec!["*".into()];
        r.cap_grant[0].dsts = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(peer_caps(&[r], ip("100.64.0.1"), &me()).is_empty());
    }

    #[test]
    fn packet_rules_and_bad_sources_grant_nothing() {
        let packet: FilterRule = serde_json::from_value(json!({
            "SrcIPs": ["*"], "DstPorts": [{ "IP": "*", "Ports": { "First": 0, "Last": 65535 } }]
        }))
        .unwrap();
        let mut bad = relay_rule();
        bad.src_ips = vec!["not-an-address".into()];
        assert!(peer_caps(&[packet, bad], ip("100.64.0.1"), &me()).is_empty());
    }

    #[test]
    fn cap_map_values_are_concatenated() {
        let grant = |v: Value| CapGrant {
            dsts: vec!["100.64.0.2/32".parse().unwrap()],
            caps: vec![],
            cap_map: Some(serde_json::from_value(json!({ "example.com/cap/x": v })).unwrap()),
        };
        let rules: Vec<FilterRule> = [json!([{"a": 1}]), json!({"b": 2}), json!(null)]
            .into_iter()
            .map(|v| FilterRule {
                src_ips: vec!["*".into()],
                cap_grant: vec![grant(v)],
                ..Default::default()
            })
            .collect();
        let caps = peer_caps(&rules, ip("100.64.0.1"), &me());
        assert_eq!(caps["example.com/cap/x"], json!([{"a": 1}, {"b": 2}]));
        // A bare capability stays null until a value arrives.
        let only_null = peer_caps(&rules[2..], ip("100.64.0.1"), &me());
        assert_eq!(only_null["example.com/cap/x"], Value::Null);
    }

    #[test]
    fn caps_then_values_for_the_same_name() {
        let r = FilterRule {
            src_ips: vec!["*".into()],
            cap_grant: vec![CapGrant {
                dsts: vec!["100.64.0.0/10".parse().unwrap()],
                caps: vec!["example.com/cap/y".into()],
                cap_map: Some(serde_json::from_value(json!({ "example.com/cap/y": [7] })).unwrap()),
            }],
            ..Default::default()
        };
        assert_eq!(
            peer_caps(&[r], ip("100.64.0.1"), &me())["example.com/cap/y"],
            json!([7])
        );
    }
}
