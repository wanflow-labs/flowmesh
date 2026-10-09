// SPDX-License-Identifier: Apache-2.0
//! Differential test: every judgment must match the official client's observed result (design doc §5.2).
#![allow(clippy::unwrap_used)]

use flowmesh_filter::compile::compile;
use flowmesh_filter::matcher::{Filter, Verdict};
use flowmesh_filter::packet::{IpProto, Packet, TCP_ACK, TCP_SYN};
use flowmesh_proto::filter::FilterRule;
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    rules: Vec<FilterRule>,
    probes: Vec<Probe>,
}

#[derive(Deserialize)]
struct Probe {
    id: String,
    proto: String,
    src: String,
    dst: String,
    dport: u16,
    tcp_flags: String,
    #[serde(default)]
    icmp_type: Option<u8>,
    delivered: bool,
}

fn packet(p: &Probe) -> Packet {
    let proto = match p.proto.as_str() {
        "tcp" => IpProto::Tcp,
        "udp" => IpProto::Udp,
        "icmp" => IpProto::Icmp4,
        "icmp6" => IpProto::Icmp6,
        "gre" => IpProto::Other(47),
        other => panic!("unknown probe proto {other}"),
    };
    let mut flags = 0;
    if p.tcp_flags.contains('S') {
        flags |= TCP_SYN;
    }
    if p.tcp_flags.contains('A') {
        flags |= TCP_ACK;
    }
    Packet {
        proto,
        src: p.src.parse().unwrap(),
        dst: p.dst.parse().unwrap(),
        src_port: 40000,
        dst_port: p.dport,
        tcp_flags: flags,
        icmp_type: p.icmp_type.unwrap_or(0),
    }
}

#[test]
fn matches_official_client_on_every_observed_probe() {
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../../fixtures/observed/20261010-acl-diff/cases.json"
    ))
    .unwrap();
    assert!(cases.len() >= 13);
    let mut mismatches = Vec::new();
    let mut total = 0;
    for case in &cases {
        let filter = Filter::new(compile(&case.rules).unwrap());
        for probe in &case.probes {
            total += 1;
            let got = filter.check_in(&packet(probe)) == Verdict::Accept;
            if got != probe.delivered {
                mismatches.push(format!(
                    "{}/{}: official delivered={} flowmesh accept={}",
                    case.name, probe.id, probe.delivered, got
                ));
            }
        }
    }
    assert!(total >= 300, "only {total} probes");
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
