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
    for (c, bit) in [('F', 0x01), ('S', TCP_SYN), ('R', 0x04), ('A', TCP_ACK)] {
        if p.tcp_flags.contains(c) {
            flags |= bit;
        }
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
    check_cases(include_str!(
        "../../../fixtures/observed/20261010-acl-diff/cases.json"
    ));
}

/// Receiver-side only: flowmesh as the sender (no outbound filter), official ts1 as the receiver (filter.md §4 attribution).
#[test]
fn matches_official_receiver_when_sender_does_not_filter() {
    check_cases(include_str!(
        "../../../fixtures/observed/20261010-acl-diff-receiver/cases.json"
    ));
}

fn check_cases(raw: &str) {
    let cases: Vec<Case> = serde_json::from_str(raw).unwrap();
    assert!(cases.len() >= 13);
    let mut mismatches = Vec::new();
    let mut total = 0;
    for case in &cases {
        let filter = Filter::new(compile(&case.rules).unwrap());
        let now = std::time::Duration::ZERO;
        for probe in &case.probes {
            total += 1;
            let got = filter.check_in(&packet(probe), now) == Verdict::Accept;
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

#[derive(Deserialize)]
struct Stateful {
    rules: Vec<FilterRule>,
    ts1: String,
    ts2: String,
    observed: std::collections::BTreeMap<String, bool>,
}

fn v4(proto: IpProto, src: &str, sport: u16, dst: &str, dport: u16, flags: u8, icmp: u8) -> Packet {
    Packet {
        proto,
        src: src.parse().unwrap(),
        dst: dst.parse().unwrap(),
        src_port: sport,
        dst_port: dport,
        tcp_flags: flags,
        icmp_type: icmp,
    }
}

/// Replay the stateful sequences (OBS-20261010-acl-stateful) on the receiver ts2's filter.
#[test]
fn matches_official_client_on_stateful_sequences() {
    let s: Stateful = serde_json::from_str(include_str!(
        "../../../fixtures/observed/20261010-acl-stateful/cases.json"
    ))
    .unwrap();
    assert!(s.observed["control-ts1-actually-sent-icmp-port-unreachable"]);
    let (ts1, ts2) = (s.ts1.as_str(), s.ts2.as_str());
    let mut f = Filter::new(compile(&s.rules).unwrap());
    let t0 = std::time::Duration::from_secs(1000);
    let accept = |v: Verdict| v == Verdict::Accept;

    // s1: ts2 → ts1:5555 SYN goes out first; then ts1's SYN-ACK comes in.
    f.check_out(&v4(IpProto::Tcp, ts2, 46000, ts1, 5555, TCP_SYN, 0), t0);
    let synack = v4(IpProto::Tcp, ts1, 5555, ts2, 46000, TCP_SYN | TCP_ACK, 0);
    assert_eq!(
        accept(f.check_in(&synack, t0)),
        s.observed["s1-synack-after-outbound"]
    );
    // s1 control: an unsolicited SYN-ACK.
    let unsolicited = v4(IpProto::Tcp, ts1, 7777, ts2, 46666, TCP_SYN | TCP_ACK, 0);
    assert_eq!(
        accept(f.check_in(&unsolicited, t0)),
        s.observed["s1-control-unsolicited-synack"]
    );

    // s2: UDP flow.
    f.check_out(&v4(IpProto::Udp, ts2, 47000, ts1, 5353, 0, 0), t0);
    let reply = v4(IpProto::Udp, ts1, 5353, ts2, 47000, 0, 0);
    assert_eq!(
        accept(f.check_in(&reply, t0)),
        s.observed["s2-udp-reply-after-outbound"]
    );
    let other = v4(IpProto::Udp, ts1, 5354, ts2, 47000, 0, 0);
    assert_eq!(
        accept(f.check_in(&other, t0)),
        s.observed["s2-control-other-sport"]
    );

    // s3: ICMP port unreachable following an outbound UDP packet.
    f.check_out(&v4(IpProto::Udp, ts2, 48000, ts1, 9, 0, 0), t0);
    let unreach = v4(IpProto::Icmp4, ts1, 0, ts2, 0, 0, 3);
    assert_eq!(
        accept(f.check_in(&unreach, t0)),
        s.observed["s3-icmp-port-unreachable-for-outbound"]
    );
}
