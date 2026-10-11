// SPDX-License-Identifier: Apache-2.0
//! `flowmesh debug netmap|paths|filter|derp` (design §7.3): read-only views of the engine's state as
//! JSON, local only. They carry peers' keys and endpoints, so the daemon serves them to root only.

use crate::command::short_name;
use crate::logic::{live_peers, unix_now};
use flowmesh_control::netmap::NetMap;
use flowmesh_pathsock::{PathSock, Route};
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugTopic {
    Netmap,
    Paths,
    Filter,
    Derp,
}

impl std::str::FromStr for DebugTopic {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "netmap" => Ok(Self::Netmap),
            "paths" => Ok(Self::Paths),
            "filter" => Ok(Self::Filter),
            "derp" => Ok(Self::Derp),
            other => Err(format!(
                "unknown debug topic {other:?} (netmap, paths, filter, derp)"
            )),
        }
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or_else(|e| json!({ "error": e.to_string() }))
}

/// The merged netmap as this node sees it.
pub fn netmap(nm: &NetMap) -> Value {
    json!({
        "self": to_json(&nm.self_node),
        "peers": nm.peers.values().map(to_json).collect::<Vec<_>>(),
        "derpMap": to_json(&nm.derp_map),
        "dns": to_json(&nm.dns),
        "domain": nm.domain,
        "packetFilters": to_json(&nm.packet_filters),
        "userProfiles": nm.user_profiles.values().map(to_json).collect::<Vec<_>>(),
        "controlTime": nm.control_time,
    })
}

fn route_json(r: Route) -> Value {
    match r {
        Route::Direct(a) => json!({ "direct": a.to_string() }),
        Route::PeerRelay { server, vni } => json!({ "peerRelay": format!("{server}:vni:{vni}") }),
        Route::Derp(region) => json!({ "relay": region }),
        Route::None => Value::Null,
    }
}

fn secs(d: Option<Duration>) -> Value {
    d.map_or(Value::Null, |d| json!(d.as_secs_f64()))
}

/// For every peer: the path in use and why (design §7.3).
pub fn paths(nm: &NetMap, ps: &PathSock, now: Duration) -> Value {
    let reachable: Vec<i64> = live_peers(nm, unix_now()).map(|n| n.id).collect();
    Value::Array(
        nm.peers
            .values()
            .map(|n| {
                let base = json!({
                    "id": n.id,
                    "name": short_name(n),
                    "ip": n.addresses.first().map(|a| a.addr().to_string()),
                });
                let Some(x) = ps.explain(n.key, now) else {
                    let reason = if reachable.contains(&n.id) {
                        "not in path selection"
                    } else {
                        "node key expired: not reachable"
                    };
                    return json!({ "peer": base, "route": null, "reason": reason });
                };
                json!({
                    "peer": base,
                    "route": route_json(x.route),
                    "reason": x.reason,
                    "candidates": x.candidates.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "fromCallMeMaybe": x.from_call_me_maybe.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "lastDirectPong": x.last_direct_pong.map(|(a, age)| json!({ "addr": a.to_string(), "secondsAgo": age.as_secs_f64() })),
                    "lastDiscoverySecondsAgo": secs(x.last_discovery),
                    "lastActiveSecondsAgo": secs(x.last_active),
                    "peerRelay": x.relay.map(|(server, vni, age)| json!({
                        "endpoint": format!("{server}:vni:{vni}"),
                        "lastPongSecondsAgo": secs(age),
                    })),
                })
            })
            .collect(),
    )
}

/// The packet filter as received, and whether it compiles (fail-closed keeps the previous rules).
pub fn filter(nm: &NetMap) -> Value {
    let rules = nm.filter_rules();
    let compiled = match flowmesh_filter::compile::compile(&rules) {
        Ok(c) => json!({ "ok": true, "rules": c.len() }),
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    };
    json!({
        "groups": to_json(&nm.packet_filters),
        "capGrantRules": rules.iter().filter(|r| !r.cap_grant.is_empty()).count(),
        "compiled": compiled,
    })
}

/// Relay regions from the map, and the reconnect/home state.
pub fn derp(nm: &NetMap, plan: &Value) -> Value {
    json!({
        "regions": nm.derp_map.regions.values().map(|r| json!({
            "id": r.region_id,
            "code": r.region_code,
            "noMeasureNoHome": r.no_measure_no_home,
            "nodes": r.nodes.iter().map(|n| json!({ "host": n.host_name, "ipv4": n.ipv4, "stunPort": n.stun_port, "stunOnly": n.stun_only })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "plan": plan,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmesh_proto::control::Node;
    use flowmesh_proto::key::{DiscoPrivate, NodePublic};

    fn nm() -> NetMap {
        let mut nm = NetMap {
            control_time: Some("2026-10-10T07:00:00Z".into()),
            domain: "lab".into(),
            ..Default::default()
        };
        nm.peers.insert(
            1,
            Node {
                id: 1,
                key: NodePublic([1; 32]),
                name: "ts1.mesh.lab.internal.".into(),
                addresses: vec!["100.64.0.1/32".parse().unwrap()],
                home_derp: 1000,
                ..Default::default()
            },
        );
        nm.peers.insert(
            2,
            Node {
                id: 2,
                key: NodePublic([2; 32]),
                name: "old.mesh.lab.internal.".into(),
                key_expiry: Some("2026-10-10T06:00:00Z".into()),
                ..Default::default()
            },
        );
        nm.packet_filters.insert(
            "base".into(),
            vec![serde_json::from_value(json!({
                "SrcIPs": ["*"], "DstPorts": [{ "IP": "*", "Ports": { "First": 0, "Last": 65535 } }]
            })).unwrap(), serde_json::from_value(json!({
                "SrcIPs": ["*"], "CapGrant": [{ "Caps": ["x"], "Dsts": ["100.64.0.0/10"] }]
            })).unwrap()],
        );
        nm
    }

    #[test]
    fn topics_parse() {
        assert_eq!("netmap".parse(), Ok(DebugTopic::Netmap));
        assert_eq!("paths".parse(), Ok(DebugTopic::Paths));
        assert_eq!("filter".parse(), Ok(DebugTopic::Filter));
        assert_eq!("derp".parse(), Ok(DebugTopic::Derp));
        assert!("prefs".parse::<DebugTopic>().is_err());
    }

    #[test]
    fn netmap_view() {
        let v = netmap(&nm());
        assert_eq!(v["peers"].as_array().unwrap().len(), 2);
        assert_eq!(v["peers"][0]["Name"], "ts1.mesh.lab.internal.");
        assert_eq!(
            (v["domain"].as_str(), v["controlTime"].as_str()),
            (Some("lab"), Some("2026-10-10T07:00:00Z"))
        );
        assert!(v["packetFilters"]["base"].is_array());
    }

    #[test]
    fn paths_view_explains_each_peer() {
        let nm = nm();
        let mut ps = PathSock::new(DiscoPrivate::generate().unwrap(), NodePublic([9; 32]));
        let mut dp = flowmesh_dataplane::plane::Dataplane::new(
            flowmesh_proto::key::NodePrivate::generate().unwrap(),
        );
        crate::logic::apply_netmap(&mut dp, &mut ps, &nm, 0, &Default::default()).unwrap();
        let v = paths(&nm, &ps, Duration::ZERO);
        assert_eq!(v[0]["peer"]["name"], "ts1");
        assert_eq!(v[0]["peer"]["ip"], "100.64.0.1");
        assert_eq!(v[0]["route"], json!({ "relay": 1000 }));
        assert!(
            v[0]["reason"]
                .as_str()
                .unwrap()
                .contains("no direct attempt yet")
        );
        assert_eq!(v[0]["lastActiveSecondsAgo"], Value::Null);
        assert_eq!(v[0]["peerRelay"], Value::Null, "no relay bound");
        // A bound peer relay shows its endpoint (not yet answered: no pong age).
        ps.set_relay(
            NodePublic([1; 32]),
            Some(("172.29.0.23:40000".parse().unwrap(), 5)),
        );
        let bound = paths(&nm, &ps, Duration::ZERO);
        assert_eq!(
            bound[0]["peerRelay"],
            json!({ "endpoint": "172.29.0.23:40000:vni:5", "lastPongSecondsAgo": null })
        );
        ps.set_relay(NodePublic([1; 32]), None);
        // After sending to the peer at t=1 s, the ages are reported in seconds.
        struct Seq(u8);
        impl flowmesh_pathsock::Random for Seq {
            fn fill(&mut self, buf: &mut [u8]) {
                for b in buf {
                    self.0 = self.0.wrapping_add(1);
                    *b = self.0;
                }
            }
        }
        ps.route(NodePublic([1; 32]), Duration::from_secs(1), &mut Seq(0));
        let later = paths(&nm, &ps, Duration::from_millis(3500));
        assert_eq!(later[0]["lastActiveSecondsAgo"], 2.5);
        assert_eq!(later[0]["lastDiscoverySecondsAgo"], 2.5);
        assert!(
            later[0]["reason"]
                .as_str()
                .unwrap()
                .contains("no candidate endpoints")
        );
        assert_eq!(v[1]["route"], Value::Null);
        assert_eq!(v[1]["reason"], "node key expired: not reachable");
    }

    #[test]
    fn filter_view() {
        let mut nm = nm();
        let v = filter(&nm);
        assert_eq!(
            (
                v["capGrantRules"].as_u64(),
                v["compiled"]["ok"].as_bool(),
                v["compiled"]["rules"].as_u64()
            ),
            (Some(1), Some(true), Some(1))
        );
        nm.packet_filters.get_mut("base").unwrap()[0].src_ips = vec!["bogus".into()];
        let v = filter(&nm);
        assert_eq!(v["compiled"]["ok"], false);
        assert!(v["compiled"]["error"].as_str().unwrap().contains("bogus"));
    }

    #[test]
    fn derp_view() {
        let mut nm = nm();
        nm.derp_map.regions.insert(
            1000,
            flowmesh_proto::derp::DerpRegion {
                region_id: 1000,
                region_code: "r1000".into(),
                nodes: vec![flowmesh_proto::derp::DerpNode {
                    host_name: "derp.lab".into(),
                    stun_port: -1,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let v = derp(&nm, &json!({ "home": 1000 }));
        assert_eq!(v["regions"][0]["code"], "r1000");
        assert_eq!(v["regions"][0]["nodes"][0]["stunPort"], -1);
        assert_eq!(v["plan"]["home"], 1000);
    }
}
