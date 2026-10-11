// SPDX-License-Identifier: Apache-2.0
//! Who may log in as whom: the control server's SSH policy applied to one connection
//! (docs/protocol/ssh.md §2). Rules are tried in order; the first whose principals include the
//! connecting node and whose user map has a local user for the requested name decides.

use flowmesh_proto::control::{SshAction, SshPolicy, SshRule};
use std::net::IpAddr;

/// The connecting side, as the netmap names it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Peer {
    pub ip: Option<IpAddr>,
    /// Stable node ID.
    pub node: String,
    /// Login name of the node's user (empty for tagged nodes).
    pub user_login: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Accept {
        local_user: String,
        action: SshAction,
    },
    Reject {
        message: String,
    },
}

/// The local user `rule` maps `requested` to, if any (`=` keeps the name, `*` covers names not
/// listed, an empty value refuses). Names are taken literally: `autogroup:nonroot` is not
/// expanded, as observed of the official client.
fn local_user(rule: &SshRule, requested: &str) -> Option<String> {
    let v = rule
        .ssh_users
        .get(requested)
        .or_else(|| rule.ssh_users.get("*"))?;
    match v.as_str() {
        "" => None,
        "=" => Some(requested.to_string()),
        other => Some(other.to_string()),
    }
}

fn principal_matches(rule: &SshRule, peer: &Peer) -> bool {
    rule.principals.iter().any(|p| {
        p.any
            || (!p.node.is_empty() && p.node == peer.node)
            || (!p.user_login.is_empty() && p.user_login == peer.user_login)
            || (!p.node_ip.is_empty() && p.node_ip.parse::<IpAddr>().ok() == peer.ip)
    })
}

/// Seconds since the epoch for `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`; None if unparsable.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse().ok() };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    let offset = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() => {
            let o = num(i + 1..i + 3)? * 3600 + num(i + 4..i + 6)? * 60;
            if *sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let (y2, m2) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se - offset)
}

/// Decide a login of `requested` from `peer` at `now` (seconds since the epoch).
pub fn decide(policy: Option<&SshPolicy>, peer: &Peer, requested: &str, now: i64) -> Decision {
    let denied = || Decision::Reject {
        message: format!(
            "flowmesh: tailnet policy does not permit you to SSH as user {requested:?}"
        ),
    };
    let Some(policy) = policy else {
        return denied();
    };
    for rule in &policy.rules {
        let Some(action) = &rule.action else { continue };
        // An unreadable expiry counts as expired: fail closed.
        if let Some(t) = &rule.rule_expires {
            if parse_rfc3339(t).is_none_or(|t| t <= now) {
                continue;
            }
        }
        if !principal_matches(rule, peer) {
            continue;
        }
        let Some(user) = local_user(rule, requested) else {
            continue;
        };
        if action.reject || !action.accept {
            let message = if action.message.is_empty() {
                format!("flowmesh: access to user {requested:?} is denied by the tailnet policy")
            } else {
                action.message.clone()
            };
            return Decision::Reject { message };
        }
        if !action.hold_and_delegate.is_empty() {
            return Decision::Reject {
                message: "flowmesh: this rule asks for a check with the control server, which flowmesh does not support".into(),
            };
        }
        if !action.recorders.is_empty() {
            return Decision::Reject {
                message: "flowmesh: this rule requires session recording, which flowmesh does not support".into(),
            };
        }
        return Decision::Accept {
            local_user: user,
            action: action.clone(),
        };
    }
    denied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmesh_proto::control::SshPrincipal;

    fn observed_policy() -> SshPolicy {
        // OBS-20261012-ssh-official/server-ssh-policy.json, principals shortened.
        serde_json::from_value(serde_json::json!({
            "rules": [{
                "principals": [{"nodeIP": "100.64.0.51"}, {"nodeIP": "100.64.0.52"}],
                "sshUsers": {"alice": "=", "autogroup:nonroot": "=", "root": "="},
                "action": {"accept": true, "allowAgentForwarding": true, "allowLocalPortForwarding": true}
            }]
        }))
        .unwrap()
    }

    fn from(ip: &str) -> Peer {
        Peer {
            ip: Some(ip.parse().unwrap()),
            ..Default::default()
        }
    }

    fn accepted_as(d: Decision) -> String {
        match d {
            Decision::Accept { local_user, .. } => local_user,
            Decision::Reject { message } => panic!("rejected: {message}"),
        }
    }

    /// The observed cases: root and alice accepted, carol (nonroot, not listed), daemon and an
    /// unknown name refused with the official wording.
    #[test]
    fn observed_cases() {
        let p = observed_policy();
        let c = from("100.64.0.52");
        assert_eq!(accepted_as(decide(Some(&p), &c, "root", 0)), "root");
        assert_eq!(accepted_as(decide(Some(&p), &c, "alice", 0)), "alice");
        for user in ["carol", "daemon", "nosuchuser"] {
            assert_eq!(
                decide(Some(&p), &c, user, 0),
                Decision::Reject {
                    message: format!(
                        "flowmesh: tailnet policy does not permit you to SSH as user \"{user}\""
                    )
                }
            );
        }
        // Not a principal; no policy at all.
        assert!(matches!(
            decide(Some(&p), &from("100.64.0.9"), "root", 0),
            Decision::Reject { .. }
        ));
        assert!(matches!(
            decide(None, &c, "root", 0),
            Decision::Reject { .. }
        ));
    }

    #[test]
    fn user_maps_and_rule_order() {
        let rule = |users: &[(&str, &str)], accept: bool| SshRule {
            principals: vec![SshPrincipal {
                any: true,
                ..Default::default()
            }],
            ssh_users: users
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            action: Some(SshAction {
                accept,
                reject: !accept,
                ..Default::default()
            }),
            ..Default::default()
        };
        let p = SshPolicy {
            rules: vec![
                rule(&[("root", "")], true),        // root: not this rule
                rule(&[("admin", "ubuntu")], true), // renamed
                rule(&[("guest", "=")], false),     // explicit reject
                rule(&[("*", "=")], true),          // everyone else as themselves
            ],
        };
        let c = from("100.64.0.1");
        assert_eq!(accepted_as(decide(Some(&p), &c, "admin", 0)), "ubuntu");
        assert_eq!(accepted_as(decide(Some(&p), &c, "bob", 0)), "bob");
        // root falls through rule 1 (empty value) to the wildcard.
        assert_eq!(accepted_as(decide(Some(&p), &c, "root", 0)), "root");
        assert!(matches!(
            decide(Some(&p), &c, "guest", 0),
            Decision::Reject { .. }
        ));
    }

    #[test]
    fn principals_by_node_and_login() {
        let mut p = observed_policy();
        p.rules[0].principals = vec![
            SshPrincipal {
                node: "nStable1".into(),
                ..Default::default()
            },
            SshPrincipal {
                user_login: "alice@example.com".into(),
                ..Default::default()
            },
        ];
        let by_node = Peer {
            node: "nStable1".into(),
            ..Default::default()
        };
        let by_login = Peer {
            user_login: "alice@example.com".into(),
            ..Default::default()
        };
        assert_eq!(accepted_as(decide(Some(&p), &by_node, "root", 0)), "root");
        assert_eq!(accepted_as(decide(Some(&p), &by_login, "root", 0)), "root");
        assert!(matches!(
            decide(Some(&p), &Peer::default(), "root", 0),
            Decision::Reject { .. }
        ));
    }

    #[test]
    fn expired_check_and_recorded_rules() {
        let mut p = observed_policy();
        let c = from("100.64.0.52");
        let t = parse_rfc3339("2026-10-12T00:00:00Z").unwrap();
        p.rules[0].rule_expires = Some("2026-10-12T00:00:00Z".into());
        assert!(matches!(
            decide(Some(&p), &c, "root", t - 1),
            Decision::Accept { .. }
        ));
        assert!(matches!(
            decide(Some(&p), &c, "root", t),
            Decision::Reject { .. }
        ));
        p.rules[0].rule_expires = Some("garbage".into());
        assert!(matches!(
            decide(Some(&p), &c, "root", 0),
            Decision::Reject { .. }
        ));
        p.rules[0].rule_expires = None;
        p.rules[0].action.as_mut().unwrap().hold_and_delegate = "https://x/check".into();
        assert!(
            matches!(decide(Some(&p), &c, "root", 0), Decision::Reject { message } if message.contains("check"))
        );
        p.rules[0]
            .action
            .as_mut()
            .unwrap()
            .hold_and_delegate
            .clear();
        p.rules[0].action.as_mut().unwrap().recorders = vec!["100.64.0.9:80".into()];
        assert!(
            matches!(decide(Some(&p), &c, "root", 0), Decision::Reject { message } if message.contains("recording"))
        );
    }

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339("2026-10-11T16:36:01.76332421Z"),
            Some(1_791_736_561)
        );
        assert_eq!(
            parse_rfc3339("2026-10-12T01:36:01+09:00"),
            Some(1_791_736_561)
        );
        assert_eq!(parse_rfc3339("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-10-11 16:36:01Z"), None);
    }
}
