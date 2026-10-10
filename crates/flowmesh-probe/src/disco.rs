// SPDX-License-Identifier: Apache-2.0
//! Pure helpers for the probe's disco mode: which peer, which DERP node, how payloads are given and recorded.

use flowmesh_proto::control::{MapResponse, Node};
use flowmesh_proto::derp::{DerpMap, DerpNode};
use flowmesh_proto::key::DiscoPublic;
use std::net::IpAddr;

/// The peer that owns `ip` (any of its addresses).
pub fn find_peer(peers: &[Node], ip: IpAddr) -> Option<&Node> {
    peers
        .iter()
        .find(|p| p.addresses.iter().any(|a| a.addr() == ip))
}

/// Keep a peer table current from one map message: a full `Peers` list replaces it,
/// `PeersChanged` replaces entries by ID, `PeersRemoved` drops them, and `PeersChangedPatch`
/// updates the disco key, node key and home region in place.
pub fn apply_map(peers: &mut Vec<Node>, m: &MapResponse) {
    if let Some(full) = &m.peers {
        *peers = full.clone();
    }
    for c in &m.peers_changed {
        match peers.iter_mut().find(|p| p.id == c.id) {
            Some(p) => *p = c.clone(),
            None => peers.push(c.clone()),
        }
    }
    peers.retain(|p| !m.peers_removed.contains(&p.id));
    for patch in &m.peers_changed_patch {
        if let Some(p) = peers.iter_mut().find(|p| p.id == patch.node_id) {
            if let Some(k) = patch.disco_key {
                p.disco_key = k;
            }
            if let Some(k) = patch.key {
                p.key = k;
            }
            if let Some(r) = patch.derp_region {
                p.home_derp = r;
            }
        }
    }
}

/// Expand the placeholders of a payload template into hex: `{self}` is this node's disco public
/// key, `{disco:<tailnet IP>}` that peer's current disco public key. The result goes to [`parse_hex`].
pub fn expand(template: &str, me: &DiscoPublic, peers: &[Node]) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..]
            .find('}')
            .ok_or(format!("unclosed {{ in {template:?}"))?
            + open;
        let token = &rest[open + 1..close];
        let key = if token == "self" {
            *me
        } else if let Some(ip) = token.strip_prefix("disco:") {
            let ip: IpAddr = ip
                .parse()
                .map_err(|_| format!("bad address in {{{token}}}"))?;
            find_peer(peers, ip)
                .ok_or(format!("no peer with address {ip}"))?
                .disco_key
        } else {
            return Err(format!("unknown placeholder {{{token}}}"));
        };
        out.extend(key.0.iter().map(|b| format!("{b:02x}")));
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The peer's home DERP region: `HomeDERP`, else the legacy `DERP` field `127.3.3.40:<region>`.
/// Disco over DERP must be sent through the peer's home region: a relay only delivers to clients
/// connected to it (it answers PeerGone otherwise).
pub fn peer_region(n: &Node) -> Option<u32> {
    if n.home_derp != 0 {
        return Some(n.home_derp);
    }
    n.legacy_derp
        .strip_prefix("127.3.3.40:")
        .and_then(|r| r.parse().ok())
        .filter(|r| *r != 0)
}

/// The first node of `region` that carries DERP traffic (not STUN-only).
pub fn derp_node(dm: &DerpMap, region: u32) -> Option<DerpNode> {
    dm.regions
        .get(&region)?
        .nodes
        .iter()
        .find(|n| !n.stun_only)
        .cloned()
}

/// Parse a hex payload given on the command line (spaces allowed between bytes).
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let digits: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() % 2 != 0 {
        return Err(format!("odd number of hex digits in {s:?}"));
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|_| format!("bad hex in {s:?}")))
        .collect()
}

/// One record line: milliseconds since start, sender, payload length, payload hex.
pub fn tsv_line(t_ms: u128, from: &str, payload: &[u8]) -> String {
    let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
    format!("{t_ms}\t{from}\tlen={}\tpayload={hex}", payload.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmesh_proto::derp::DerpRegion;

    fn node(name: &str, ip: &str) -> Node {
        Node {
            name: name.into(),
            addresses: vec![format!("{ip}/32").parse().unwrap()],
            ..Default::default()
        }
    }

    #[test]
    fn finds_the_peer_by_any_address() {
        let peers = vec![node("ts1", "100.64.0.1"), node("ts2", "100.64.0.2")];
        assert_eq!(
            find_peer(&peers, "100.64.0.2".parse().unwrap()).map(|n| n.name.as_str()),
            Some("ts2")
        );
        assert!(find_peer(&peers, "100.64.0.9".parse().unwrap()).is_none());
    }

    fn with_id(id: i64, name: &str, ip: &str, disco: u8) -> Node {
        Node {
            id,
            disco_key: DiscoPublic([disco; 32]),
            ..node(name, ip)
        }
    }

    #[test]
    fn apply_map_replaces_updates_removes_and_patches() {
        let mut peers = Vec::new();
        apply_map(
            &mut peers,
            &MapResponse {
                peers: Some(vec![
                    with_id(1, "a", "100.64.0.1", 1),
                    with_id(2, "b", "100.64.0.2", 2),
                ]),
                ..Default::default()
            },
        );
        assert_eq!(peers.len(), 2);
        apply_map(
            &mut peers,
            &MapResponse {
                peers_changed: vec![
                    with_id(2, "b2", "100.64.0.2", 2),
                    with_id(3, "c", "100.64.0.3", 3),
                ],
                peers_removed: vec![1],
                peers_changed_patch: vec![flowmesh_proto::control::PeerChange {
                    node_id: 3,
                    disco_key: Some(DiscoPublic([9; 32])),
                    derp_region: Some(1001),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let names: Vec<&str> = peers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["b2", "c"]);
        assert_eq!(peers[1].disco_key, DiscoPublic([9; 32]));
        assert_eq!(peers[1].home_derp, 1001);
    }

    #[test]
    fn expand_fills_self_and_peer_keys() {
        let peers = vec![with_id(2, "b", "100.64.0.2", 0xbb)];
        let me = DiscoPublic([0xaa; 32]);
        let out = expand("08 00 {self} {disco:100.64.0.2} 00000001", &me, &peers).unwrap();
        assert_eq!(
            parse_hex(&out).unwrap(),
            [&[0x08, 0x00][..], &[0xaa; 32], &[0xbb; 32], &[0, 0, 0, 1]].concat()
        );
        assert_eq!(expand("0800", &me, &peers).unwrap(), "0800");
    }

    #[test]
    fn expand_rejects_unknown_peers_and_placeholders() {
        let me = DiscoPublic([0xaa; 32]);
        assert!(expand("{disco:100.64.0.9}", &me, &[]).is_err());
        assert!(expand("{other}", &me, &[]).is_err());
        assert!(expand("{self", &me, &[]).is_err());
    }

    #[test]
    fn peer_region_prefers_home_derp_then_the_legacy_field() {
        let n = |home, legacy: &str| Node {
            home_derp: home,
            legacy_derp: legacy.into(),
            ..Default::default()
        };
        assert_eq!(peer_region(&n(1001, "127.3.3.40:1000")), Some(1001));
        assert_eq!(peer_region(&n(0, "127.3.3.40:1000")), Some(1000));
        assert_eq!(peer_region(&n(0, "127.3.3.40:0")), None);
        assert_eq!(peer_region(&n(0, "")), None);
    }

    #[test]
    fn skips_stun_only_nodes() {
        let mut dm = DerpMap::default();
        dm.regions.insert(
            1000,
            DerpRegion {
                region_id: 1000,
                nodes: vec![
                    DerpNode {
                        host_name: "stun".into(),
                        stun_only: true,
                        ..Default::default()
                    },
                    DerpNode {
                        host_name: "derp".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );
        assert_eq!(
            derp_node(&dm, 1000).map(|n| n.host_name),
            Some("derp".to_string())
        );
        assert!(derp_node(&dm, 1001).is_none());
    }

    #[test]
    fn parses_hex_with_spaces_and_rejects_bad_input() {
        assert_eq!(parse_hex("08 00 ff").unwrap(), vec![0x08, 0x00, 0xff]);
        assert!(parse_hex("080").is_err());
        assert!(parse_hex("zz").is_err());
    }

    #[test]
    fn record_line_has_time_sender_length_and_hex() {
        assert_eq!(
            tsv_line(1500, "tsr", &[0x09, 0x00, 0xab]),
            "1500\ttsr\tlen=3\tpayload=0900ab"
        );
    }
}
