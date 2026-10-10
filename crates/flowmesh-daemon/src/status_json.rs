// SPDX-License-Identifier: Apache-2.0
//! `status --json` output (cli.md §2). Field names and shapes follow the official client so existing
//! consumers (the WanFlow gateway agent) keep working; fields flowmesh does not implement are omitted, not faked.

use crate::state::BackendState;
use flowmesh_engine::status::{EngineStatus, PeerStatus};
use serde_json::{Map, Value, json};

/// The time value the official client prints for "never".
pub const ZERO_TIME: &str = "0001-01-01T00:00:00Z";
/// The node key printed while logged out (official shape: all zeros).
pub const ZERO_NODE_KEY: &str =
    "nodekey:0000000000000000000000000000000000000000000000000000000000000000";

pub struct Input<'a> {
    pub state: BackendState,
    pub logged_in: bool,
    pub auth_url: &'a str,
    /// Engine errors to surface (in addition to the stopped notice).
    pub errors: &'a [String],
    /// The last netmap-derived snapshot; empty after logout.
    pub snap: &'a EngineStatus,
    /// Used for `Self.HostName` while there is no netmap.
    pub hostname: &'a str,
}

pub fn render(i: &Input<'_>) -> Value {
    let mut health: Vec<Value> = Vec::new();
    if matches!(i.state, BackendState::Stopped | BackendState::NeedsLogin) {
        health.push("flowmesh is stopped.".into());
    }
    health.extend(i.errors.iter().map(|e| Value::from(e.as_str())));
    health.extend(i.snap.health.iter().map(|h| Value::from(h.as_str())));

    let me = i.snap.self_node.as_ref();
    let self_json = match me {
        Some(n) => node(n),
        None => json!({
            "ID": "",
            "PublicKey": ZERO_NODE_KEY,
            "HostName": i.hostname,
            "DNSName": "",
            "OS": "linux",
            "TailscaleIPs": null,
            "CurAddr": "",
            "Relay": "",
            "RxBytes": 0,
            "TxBytes": 0,
            "LastSeen": ZERO_TIME,
            "Online": false,
            "ExitNodeOption": false,
            "Active": false,
        }),
    };
    let peers: Value = if i.snap.peers.is_empty() {
        Value::Null
    } else {
        Value::Object(
            i.snap
                .peers
                .iter()
                .map(|p| (p.public_key.clone(), node(p)))
                .collect::<Map<_, _>>(),
        )
    };
    let tailnet = if me.is_some() {
        json!({
            "Name": i.snap.tailnet_name,
            "MagicDNSSuffix": i.snap.magic_dns_suffix,
            "MagicDNSEnabled": !i.snap.magic_dns_suffix.is_empty(),
        })
    } else {
        Value::Null
    };
    let mut top = json!({
        "Version": env!("CARGO_PKG_VERSION"),
        "TUN": true,
        "BackendState": i.state.as_str(),
        "AuthURL": i.auth_url,
        "TailscaleIPs": me.map_or(Value::Null, |n| ips(&n.tailscale_ips)),
        "Self": self_json,
        "Health": health,
        "MagicDNSSuffix": i.snap.magic_dns_suffix,
        "CurrentTailnet": tailnet,
        "Peer": peers,
        // flowmesh additions (design §7.3), camelCase to set them apart from the official fields.
        "backend": "userspace",
        "relayMode": if i.snap.relay_mode.is_empty() { Value::Null } else { i.snap.relay_mode.as_str().into() },
    });
    // Official: present only while a node key is held.
    if i.logged_in
        && let Some(obj) = top.as_object_mut()
    {
        obj.insert("HaveNodeKey".into(), true.into());
    }
    top
}

fn ips(list: &[std::net::IpAddr]) -> Value {
    Value::Array(list.iter().map(|a| a.to_string().into()).collect())
}

fn node(n: &PeerStatus) -> Value {
    let mut v = json!({
        "ID": n.id.to_string(),
        "PublicKey": n.public_key,
        "HostName": n.host_name,
        "DNSName": n.dns_name,
        "OS": n.os,
        "TailscaleIPs": ips(&n.tailscale_ips),
        "CurAddr": n.cur_addr.map(|a| a.to_string()).unwrap_or_default(),
        "PeerRelay": n.peer_relay,
        "Relay": n.relay,
        "RxBytes": n.rx_bytes,
        "TxBytes": n.tx_bytes,
        "LastSeen": n.last_seen.as_deref().unwrap_or(ZERO_TIME),
        "Online": n.online,
        "ExitNodeOption": n.exit_node_option,
        "Active": n.active,
    });
    // Official shape: present only when set / true.
    if let Some(obj) = v.as_object_mut() {
        if let Some(e) = &n.key_expiry {
            obj.insert("KeyExpiry".into(), e.as_str().into());
        }
        if n.expired {
            obj.insert("Expired".into(), true.into());
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFICIAL_UP: &str =
        include_str!("../../../fixtures/observed/20261010-cli/status-after-up.json");
    const OFFICIAL_LOGOUT: &str =
        include_str!("../../../fixtures/observed/20261010-cli/status-after-logout.json");

    /// The fields the WanFlow gateway agent reads (cli.md §2).
    const AGENT_TOP: [&str; 5] = [
        "BackendState",
        "Self",
        "Health",
        "MagicDNSSuffix",
        "CurrentTailnet",
    ];
    const AGENT_PEER: [&str; 13] = [
        "HostName",
        "DNSName",
        "TailscaleIPs",
        "Online",
        "LastSeen",
        "OS",
        "Relay",
        "RxBytes",
        "TxBytes",
        "CurAddr",
        "Active",
        "PublicKey",
        "ExitNodeOption",
    ];

    fn peer(key: &str) -> PeerStatus {
        PeerStatus {
            peer_relay: String::new(),
            id: 7,
            public_key: key.into(),
            host_name: "ts1".into(),
            dns_name: "ts1.mesh.lab.internal.".into(),
            os: "linux".into(),
            tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
            online: true,
            last_seen: None,
            relay: "wanflow-relay-1000".into(),
            cur_addr: Some("172.29.0.21:41641".parse().unwrap()),
            rx_bytes: 5,
            tx_bytes: 6,
            active: true,
            exit_node_option: false,
            key_expiry: None,
            expired: false,
        }
    }

    fn running() -> EngineStatus {
        EngineStatus {
            self_node: Some(peer("nodekey:aa")),
            peers: vec![peer("nodekey:bb")],
            magic_dns_suffix: "mesh.lab.internal".into(),
            tailnet_name: "headscale.lab".into(),
            health: Vec::new(),
            relay_mode: String::new(),
        }
    }

    fn out(state: BackendState, logged_in: bool, snap: &EngineStatus) -> Value {
        render(&Input {
            state,
            logged_in,
            auth_url: "",
            errors: &[],
            snap,
            hostname: "fm1",
        })
    }

    /// Same JSON type (null/string/number/bool/array/object) as the official output for every field we emit.
    fn same_kind(a: &Value, b: &Value) -> bool {
        std::mem::discriminant(a) == std::mem::discriminant(b)
    }

    #[test]
    fn running_has_agent_fields_with_official_types() {
        let official: Value = serde_json::from_str(OFFICIAL_UP).unwrap();
        let ours = out(BackendState::Running, true, &running());
        for k in AGENT_TOP {
            assert!(
                same_kind(&ours[k], &official[k]),
                "{k}: {} vs {}",
                ours[k],
                official[k]
            );
        }
        assert!(
            ours["Self"]["PublicKey"]
                .as_str()
                .unwrap()
                .starts_with("nodekey:")
        );
        let off_peer = official["Peer"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap();
        let our_peer = &ours["Peer"]["nodekey:bb"];
        for k in AGENT_PEER {
            assert!(
                same_kind(&our_peer[k], &off_peer[k]),
                "Peer.{k}: {} vs {}",
                our_peer[k],
                off_peer[k]
            );
        }
        assert_eq!(ours["HaveNodeKey"], true);
        assert_eq!(ours["Health"], json!([]));
        assert_eq!(ours["CurrentTailnet"]["MagicDNSEnabled"], true);
        assert_eq!(our_peer["CurAddr"], "172.29.0.21:41641");
        assert_eq!(our_peer["LastSeen"], ZERO_TIME);
        assert_eq!(our_peer["ID"], "7");
        assert_eq!(ours["TailscaleIPs"], json!(["100.64.0.1"]));
    }

    #[test]
    fn logged_out_matches_official_shape() {
        let official: Value = serde_json::from_str(OFFICIAL_LOGOUT).unwrap();
        let ours = out(BackendState::NeedsLogin, false, &EngineStatus::default());
        for k in [
            "TailscaleIPs",
            "CurrentTailnet",
            "Peer",
            "BackendState",
            "AuthURL",
        ] {
            assert_eq!(ours[k], official[k], "{k}");
        }
        for k in ["ID", "PublicKey", "TailscaleIPs", "CurAddr", "Online"] {
            assert_eq!(ours["Self"][k], official["Self"][k], "Self.{k}");
        }
        assert_eq!(ours["Self"]["HostName"], "fm1");
        assert!(
            ours.get("HaveNodeKey").is_none(),
            "official omits it while logged out"
        );
        assert_eq!(ours["Health"], json!(["flowmesh is stopped."]));
    }

    #[test]
    fn stopped_keeps_last_netmap_and_says_so() {
        let ours = out(BackendState::Stopped, true, &running());
        assert_eq!(ours["BackendState"], "Stopped");
        assert_eq!(ours["Health"], json!(["flowmesh is stopped."]));
        assert!(
            ours["Peer"].is_object(),
            "official keeps the last netmap after down"
        );
    }

    #[test]
    fn errors_are_surfaced_in_health() {
        let errs = ["control connect: refused".to_string()];
        let v = render(&Input {
            state: BackendState::Starting,
            logged_in: true,
            auth_url: "",
            errors: &errs,
            snap: &EngineStatus::default(),
            hostname: "fm1",
        });
        assert_eq!(v["Health"], json!(["control connect: refused"]));
    }

    #[test]
    fn engine_health_is_surfaced() {
        let mut s = running();
        s.health = vec!["resolv.conf left alone".into()];
        assert_eq!(
            out(BackendState::Running, true, &s)["Health"],
            json!(["resolv.conf left alone"])
        );
    }

    #[test]
    fn expiry_fields_only_when_set() {
        let mut s = running();
        let plain = out(BackendState::Running, true, &s);
        assert!(plain["Peer"]["nodekey:bb"].get("KeyExpiry").is_none());
        assert!(plain["Peer"]["nodekey:bb"].get("Expired").is_none());
        s.peers[0].key_expiry = Some("2026-10-10T06:26:42Z".into());
        s.peers[0].expired = true;
        let v = out(BackendState::Running, true, &s);
        assert_eq!(v["Peer"]["nodekey:bb"]["KeyExpiry"], "2026-10-10T06:26:42Z");
        assert_eq!(v["Peer"]["nodekey:bb"]["Expired"], true);
    }

    #[test]
    fn flowmesh_fields() {
        let mut s = running();
        assert_eq!(
            out(BackendState::Running, true, &s)["relayMode"],
            Value::Null
        );
        s.relay_mode = "prefer".into();
        let v = out(BackendState::Running, true, &s);
        assert_eq!(
            (v["backend"].as_str(), v["relayMode"].as_str()),
            (Some("userspace"), Some("prefer"))
        );
    }

    #[test]
    fn tailnet_without_magic_dns() {
        let mut s = running();
        s.magic_dns_suffix.clear();
        assert_eq!(
            out(BackendState::Running, true, &s)["CurrentTailnet"]["MagicDNSEnabled"],
            false
        );
    }

    /// A peer on a peer relay: `PeerRelay` carries the path, `CurAddr` stays empty (as the official
    /// client, OBS-20261010-peer-relay-official); without one the field is present and empty.
    #[test]
    fn peer_relay_field() {
        let mut p = peer("nodekey:a");
        assert_eq!(node(&p)["PeerRelay"], "");
        // The snapshot sets one or the other, never both.
        p.cur_addr = None;
        p.peer_relay = "172.29.0.23:40000:vni:5".into();
        let v = node(&p);
        assert_eq!(v["PeerRelay"], "172.29.0.23:40000:vni:5");
        assert_eq!(v["CurAddr"], "");
    }
}
