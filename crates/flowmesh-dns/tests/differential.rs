// SPDX-License-Identifier: Apache-2.0
//! Differential: run the query set observed from the official client (OBS-20261010-magicdns/answers.txt)
//! against a DNS view built from the real netmap (OBS-20261010-flowmesh-probe/map-0000.json); rcode and answers must match.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use flowmesh_dns::{Decision, DnsView, HostEntry, handle};
use flowmesh_proto::control::MapResponse;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};

fn view() -> DnsView {
    let m: MapResponse = serde_json::from_str(include_str!(
        "../../../fixtures/observed/20261010-flowmesh-probe/map-0000.json"
    ))
    .unwrap();
    let dns = m.dns_config.unwrap();
    let routes: Vec<(String, bool)> = dns
        .routes
        .iter()
        .map(|(k, v)| (k.clone(), v.is_empty()))
        .collect();
    let mut nodes: Vec<HostEntry> = m
        .peers
        .unwrap()
        .iter()
        .chain(m.node.iter())
        .map(|n| HostEntry {
            fqdn: n.name.clone(),
            addrs: n.addresses.iter().map(|a| a.addr()).collect(),
        })
        .collect();
    nodes.sort_by(|a, b| a.fqdn.cmp(&b.fqdn));
    // The official observer has no host IPv6 connectivity (dns.md §2), so AAAA is not answered.
    DnsView::new(&dns.domains, &routes, &nodes, &dns.extra_records, false)
}

/// The tail of each answers.txt line, e.g. "A 100.64.0.1 ts1.mesh.lab.internal.|NOERROR,"
fn render(m: &Message) -> String {
    let mut s = String::new();
    for r in &m.answers {
        let rendered = r.data.to_string();
        s.push_str(&format!("{} {} {}|", r.record_type(), rendered, r.name));
    }
    let rcode = match m.metadata.response_code {
        hickory_proto::op::ResponseCode::NoError => "NOERROR",
        hickory_proto::op::ResponseCode::NXDomain => "NXDOMAIN",
        other => panic!("unexpected rcode {other:?}"),
    };
    s.push_str(&format!("{rcode},"));
    s
}

#[test]
fn matches_official_magicdns_answers() {
    let v = view();
    let mut checked = 0;
    for line in include_str!("../../../fixtures/observed/20261010-magicdns/answers.txt").lines() {
        let (q, expected) = line.split_once(" => ").unwrap();
        let (name, ty) = q.split_once(' ').unwrap();
        let ty: RecordType = ty.parse().unwrap();
        let mut msg = Message::query();
        msg.metadata.id = 7;
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(
            Name::from_ascii(format!("{name}.")).unwrap(),
            ty,
        ));
        let decision = handle(&v, &msg.to_vec().unwrap());
        let official_local = !(name == "ts1" || name == "example.com" || name == "headscale.lab");
        match decision {
            Decision::Local(bytes) => {
                assert!(
                    official_local,
                    "{q}: flowmesh answered locally, the official client forwarded"
                );
                let got = render(&Message::from_vec(&bytes).unwrap());
                assert_eq!(got, expected, "{q}");
            }
            Decision::Forward => assert!(
                !official_local,
                "{q}: flowmesh forwarded, the official client answered locally: {expected}"
            ),
            Decision::Drop => panic!("{q}: dropped"),
        }
        checked += 1;
    }
    assert_eq!(checked, 14);
}
