// SPDX-License-Identifier: Apache-2.0
//! Merge the map stream's initial full snapshot and later deltas into a current, complete network map (pure function).
//! Message semantics in docs/protocol/control.md §5.

use flowmesh_proto::control::{DnsConfig, MapResponse, Node, UserProfile};
use flowmesh_proto::derp::DerpMap;
use flowmesh_proto::filter::FilterRule;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NetMap {
    pub self_node: Option<Node>,
    /// Keyed by node ID.
    pub peers: BTreeMap<i64, Node>,
    pub derp_map: DerpMap,
    pub dns: Option<DnsConfig>,
    pub domain: String,
    /// Packet filter rule groups (`PacketFilters`); a key with a null value means "delete this group".
    pub packet_filters: BTreeMap<String, Vec<FilterRule>>,
    /// Keyed by user ID. Each message carries the profiles it references; they accumulate.
    pub user_profiles: BTreeMap<i64, UserProfile>,
    /// The server's clock as of the latest message that carried it (`ControlTime`), for judging
    /// key expiry without trusting the local clock.
    pub control_time: Option<String>,
}

/// Which parts a message touched, so the caller only redoes the parts that need it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Changed {
    pub peers: bool,
    pub derp: bool,
    pub filter: bool,
    pub dns: bool,
    pub self_node: bool,
}

impl NetMap {
    pub fn apply(&mut self, m: &MapResponse) -> Changed {
        let mut c = Changed::default();
        if let Some(node) = &m.node {
            self.self_node = Some(node.clone());
            c.self_node = true;
        }
        if let Some(dm) = &m.derp_map {
            self.derp_map = dm.clone();
            c.derp = true;
        }
        if let Some(dns) = &m.dns_config {
            self.dns = Some(dns.clone());
            c.dns = true;
        }
        if !m.domain.is_empty() {
            self.domain = m.domain.clone();
        }
        if let Some(t) = &m.control_time {
            self.control_time = Some(t.clone());
        }
        for u in &m.user_profiles {
            self.user_profiles.insert(u.id, u.clone());
        }
        if let Some(peers) = &m.peers {
            self.peers = peers.iter().map(|n| (n.id, n.clone())).collect();
            c.peers = true;
        }
        for n in &m.peers_changed {
            self.peers.insert(n.id, n.clone());
            c.peers = true;
        }
        for id in &m.peers_removed {
            c.peers |= self.peers.remove(id).is_some();
        }
        for p in &m.peers_changed_patch {
            // A patch for an unknown peer is ignored: a patch only modifies, it never creates.
            let Some(n) = self.peers.get_mut(&p.node_id) else {
                continue;
            };
            if let Some(v) = p.derp_region {
                n.home_derp = v;
            }
            if let Some(v) = &p.endpoints {
                n.endpoints = v.clone();
            }
            if let Some(v) = p.key {
                n.key = v;
            }
            if let Some(v) = p.disco_key {
                n.disco_key = v;
            }
            if let Some(v) = p.online {
                n.online = Some(v);
            }
            if let Some(v) = &p.last_seen {
                n.last_seen = Some(v.clone());
            }
            if let Some(v) = &p.key_expiry {
                n.key_expiry = Some(v.clone());
            }
            if let Some(v) = p.cap {
                n.cap = v;
            }
            c.peers = true;
        }
        if let Some(groups) = &m.packet_filters {
            for (name, rules) in groups {
                match rules {
                    Some(r) => {
                        self.packet_filters.insert(name.clone(), r.clone());
                    }
                    None => {
                        self.packet_filters.remove(name);
                    }
                }
            }
            c.filter = true;
        }
        c
    }

    /// All rule groups concatenated into one list (group order follows key order).
    pub fn filter_rules(&self) -> Vec<FilterRule> {
        self.packet_filters.values().flatten().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmesh_proto::control::PeerChange;
    use flowmesh_proto::key::NodePublic;

    fn node(id: i64, name: &str) -> Node {
        Node {
            id,
            name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn full_peer_list_replaces_previous() {
        let mut nm = NetMap::default();
        let c = nm.apply(&MapResponse {
            peers: Some(vec![node(1, "a"), node(2, "b")]),
            ..Default::default()
        });
        assert!(c.peers);
        nm.apply(&MapResponse {
            peers: Some(vec![node(3, "c")]),
            ..Default::default()
        });
        assert_eq!(nm.peers.keys().copied().collect::<Vec<_>>(), vec![3]);
    }

    #[test]
    fn changed_and_removed_are_incremental() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponse {
            peers: Some(vec![node(1, "a"), node(2, "b")]),
            ..Default::default()
        });
        let c = nm.apply(&MapResponse {
            peers_changed: vec![node(2, "b2"), node(4, "d")],
            peers_removed: vec![1],
            ..Default::default()
        });
        assert!(c.peers);
        assert_eq!(nm.peers.len(), 2);
        assert_eq!(nm.peers[&2].name, "b2");
        assert!(nm.peers.contains_key(&4));
    }

    #[test]
    fn patch_updates_only_given_fields_of_known_peers() {
        let mut nm = NetMap::default();
        let mut n = node(1, "a");
        n.home_derp = 1000;
        n.online = Some(false);
        nm.apply(&MapResponse {
            peers: Some(vec![n]),
            ..Default::default()
        });
        let c = nm.apply(&MapResponse {
            peers_changed_patch: vec![
                PeerChange {
                    node_id: 1,
                    online: Some(true),
                    derp_region: Some(1001),
                    ..Default::default()
                },
                PeerChange {
                    node_id: 99,
                    online: Some(true),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        assert!(c.peers);
        assert_eq!(nm.peers[&1].online, Some(true));
        assert_eq!(nm.peers[&1].home_derp, 1001);
        assert_eq!(nm.peers[&1].name, "a");
        assert!(
            !nm.peers.contains_key(&99),
            "patch for unknown peer must not create it"
        );
    }

    #[test]
    fn patch_key_change_replaces_key() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponse {
            peers: Some(vec![node(1, "a")]),
            ..Default::default()
        });
        nm.apply(&MapResponse {
            peers_changed_patch: vec![PeerChange {
                node_id: 1,
                key: Some(NodePublic([5; 32])),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert_eq!(nm.peers[&1].key, NodePublic([5; 32]));
    }

    #[test]
    fn keepalive_changes_nothing() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponse {
            peers: Some(vec![node(1, "a")]),
            domain: "d".into(),
            ..Default::default()
        });
        let before = nm.clone();
        let c = nm.apply(&MapResponse {
            keep_alive: true,
            ..Default::default()
        });
        assert_eq!(c, Changed::default());
        assert_eq!(nm, before);
    }

    #[test]
    fn packet_filters_set_and_delete_groups() {
        let mut nm = NetMap::default();
        let rule = FilterRule {
            src_ips: vec!["*".into()],
            ..Default::default()
        };
        let mut pf = BTreeMap::new();
        pf.insert("base".to_string(), Some(vec![rule.clone()]));
        let c = nm.apply(&MapResponse {
            packet_filters: Some(pf),
            ..Default::default()
        });
        assert!(c.filter);
        assert_eq!(nm.filter_rules(), vec![rule]);
        let mut del = BTreeMap::new();
        del.insert("base".to_string(), None);
        nm.apply(&MapResponse {
            packet_filters: Some(del),
            ..Default::default()
        });
        assert!(nm.filter_rules().is_empty());
    }

    #[test]
    fn self_node_derp_and_dns_are_replaced_when_present() {
        let mut nm = NetMap::default();
        let dm = DerpMap {
            omit_default_regions: true,
            ..Default::default()
        };
        let c = nm.apply(&MapResponse {
            node: Some(node(7, "me")),
            derp_map: Some(dm.clone()),
            dns_config: Some(DnsConfig::default()),
            ..Default::default()
        });
        assert!(c.self_node && c.derp && c.dns);
        assert_eq!(nm.self_node.as_ref().map(|n| n.id), Some(7));
        assert_eq!(nm.derp_map, dm);
        let c = nm.apply(&MapResponse {
            domain: "x".into(),
            ..Default::default()
        });
        assert!(!c.derp && !c.self_node);
        assert_eq!(nm.derp_map, dm, "absent DERPMap keeps the previous one");
    }

    /// Replay the real message sequence (OBS-20261010-flowmesh-probe): the final map should contain ts1 and ts2.
    #[test]
    fn replays_observed_probe_session() {
        let mut nm = NetMap::default();
        for raw in [
            include_str!("../../../fixtures/observed/20261010-flowmesh-probe/map-0000.json"),
            include_str!("../../../fixtures/observed/20261010-flowmesh-probe/map-0001.json"),
            include_str!("../../../fixtures/observed/20261010-flowmesh-probe/map-0002.json"),
            include_str!("../../../fixtures/observed/20261010-flowmesh-probe/map-0003.json"),
            include_str!("../../../fixtures/observed/20261010-flowmesh-probe/map-0004.json"),
        ] {
            nm.apply(&serde_json::from_str(raw).unwrap());
        }
        let mut names: Vec<&str> = nm.peers.values().map(|n| n.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["ts1.mesh.lab.internal.", "ts2.mesh.lab.internal."]);
        assert_eq!(
            nm.self_node.as_ref().map(|n| n.name.as_str()),
            Some("fm1.mesh.lab.internal.")
        );
        assert!(nm.derp_map.regions.contains_key(&1000));
        assert!(!nm.filter_rules().is_empty());
    }

    #[test]
    fn user_profiles_accumulate_and_update() {
        let profile = |id: i64, name: &str| UserProfile {
            id,
            login_name: name.into(),
            display_name: name.into(),
        };
        let mut nm = NetMap::default();
        nm.apply(&MapResponse {
            user_profiles: vec![profile(1, "lab")],
            ..Default::default()
        });
        nm.apply(&MapResponse {
            user_profiles: vec![profile(2, "ops")],
            ..Default::default()
        });
        nm.apply(&MapResponse {
            user_profiles: vec![profile(1, "lab2")],
            ..Default::default()
        });
        nm.apply(&MapResponse::default());
        assert_eq!(nm.user_profiles.len(), 2);
        assert_eq!(nm.user_profiles[&1].login_name, "lab2");
        assert_eq!(nm.user_profiles[&2].login_name, "ops");
    }

    #[test]
    fn domain_survives_messages_without_it() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponse {
            domain: "lab".into(),
            ..Default::default()
        });
        nm.apply(&MapResponse::default());
        assert_eq!(nm.domain, "lab");
        nm.apply(&MapResponse {
            domain: "other".into(),
            ..Default::default()
        });
        assert_eq!(nm.domain, "other");
    }

    #[test]
    fn a_removal_alone_marks_peers_changed() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponse {
            peers: Some(vec![
                Node {
                    id: 1,
                    ..Default::default()
                },
                Node {
                    id: 2,
                    ..Default::default()
                },
            ]),
            ..Default::default()
        });
        let c = nm.apply(&MapResponse {
            peers_removed: vec![2, 99],
            ..Default::default()
        });
        assert!(c.peers);
        assert_eq!(nm.peers.keys().copied().collect::<Vec<_>>(), vec![1]);
        let c = nm.apply(&MapResponse {
            peers_removed: vec![99],
            ..Default::default()
        });
        assert!(!c.peers, "removing an unknown peer changes nothing");
    }

    #[test]
    fn control_time_is_the_latest_one_given() {
        let mut nm = NetMap::default();
        nm.apply(&MapResponse {
            control_time: Some("2026-10-10T06:00:00Z".into()),
            ..Default::default()
        });
        nm.apply(&MapResponse::default());
        assert_eq!(nm.control_time.as_deref(), Some("2026-10-10T06:00:00Z"));
        nm.apply(&MapResponse {
            control_time: Some("2026-10-10T06:01:00Z".into()),
            ..Default::default()
        });
        assert_eq!(nm.control_time.as_deref(), Some("2026-10-10T06:01:00Z"));
    }
}
