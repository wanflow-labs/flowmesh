// SPDX-License-Identifier: Apache-2.0
//! In-process data path benchmark (M11): two dataplanes peered with each other, handshake, then N
//! IPv4/UDP packets of 1280 bytes from A's TUN side through encrypt (A) and decrypt (B). No sockets:
//! this is the ceiling the I/O paths can approach.
//! Usage: cargo run --release -p flowmesh-dataplane --example dp_bench [-- PACKETS]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use flowmesh_dataplane::ippkt;
use flowmesh_dataplane::plane::{Dataplane, Output, PeerConfig};
use flowmesh_filter::compile::compile;
use flowmesh_proto::filter::{FilterRule, NetPortRange, PortRange};
use flowmesh_proto::key::{NodePrivate, NodePublic};
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

const SIZE: usize = 1280;

fn allow_all() -> Vec<flowmesh_filter::compile::CompiledRule> {
    compile(&[FilterRule {
        src_ips: vec!["*".into()],
        dst_ports: vec![NetPortRange {
            ip: "*".into(),
            ports: PortRange {
                first: 0,
                last: 65535,
            },
        }],
        ..Default::default()
    }])
    .unwrap()
}

/// Shuttle outputs between the two ends until nothing is left; count what reached B's TUN.
fn settle(
    a: &mut Dataplane,
    pa: NodePublic,
    b: &mut Dataplane,
    pb: NodePublic,
    first: Vec<Output>,
) -> usize {
    let mut queue: Vec<(bool, Output)> = first.into_iter().map(|o| (true, o)).collect();
    let mut delivered = 0;
    while let Some((from_a, out)) = queue.pop() {
        match out {
            Output::ToPeer(_, data) => {
                let next = if from_a {
                    b.inbound(pa, &data, Duration::ZERO)
                } else {
                    a.inbound(pb, &data, Duration::ZERO)
                };
                queue.extend(next.into_iter().map(|o| (!from_a, o)));
            }
            Output::ToTun(_) => delivered += usize::from(!from_a),
        }
    }
    delivered
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .map_or(200_000, |s| s.parse().unwrap());
    let (ka, kb) = (
        NodePrivate::generate().unwrap(),
        NodePrivate::generate().unwrap(),
    );
    let (pa, pb) = (ka.public(), kb.public());
    let (mut a, mut b) = (Dataplane::new(ka), Dataplane::new(kb));
    a.set_peers(vec![PeerConfig {
        key: pb,
        allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
        ..Default::default()
    }]);
    b.set_peers(vec![PeerConfig {
        key: pa,
        allowed_ips: vec!["100.64.0.1/32".parse().unwrap()],
        ..Default::default()
    }]);
    a.set_filter_rules(allow_all());
    b.set_filter_rules(allow_all());
    let src: SocketAddrV4 = "100.64.0.1:5000".parse().unwrap();
    let dst: SocketAddrV4 = "100.64.0.2:5001".parse().unwrap();
    let pkt = ippkt::build_udp4(src, dst, &vec![0x5a; SIZE - 28]);
    assert_eq!(pkt.len(), SIZE);

    // Handshake: repeat until a data packet arrives (the first one may be queued or dropped).
    for _ in 0..4 {
        let first = a.outbound(&pkt, Duration::ZERO);
        if settle(&mut a, pa, &mut b, pb, first) > 0 {
            break;
        }
    }

    let (mut enc, mut dec, mut delivered) = (Duration::ZERO, Duration::ZERO, 0usize);
    let start = Instant::now();
    for _ in 0..n {
        let t0 = Instant::now();
        let outs = a.outbound(&pkt, Duration::ZERO);
        let t1 = Instant::now();
        for o in outs {
            if let Output::ToPeer(_, data) = o {
                for r in b.inbound(pa, &data, Duration::ZERO) {
                    delivered += usize::from(matches!(r, Output::ToTun(_)));
                }
            }
        }
        enc += t1 - t0;
        dec += t1.elapsed();
    }
    let total = start.elapsed();
    assert_eq!(delivered, n, "every packet delivered");
    let gbps = (n * SIZE * 8) as f64 / total.as_secs_f64() / 1e9;
    println!(
        "{n} packets of {SIZE} B: {:.0} kpkt/s, {gbps:.2} Gbit/s; encrypt {:.0} ns/pkt, decrypt {:.0} ns/pkt",
        n as f64 / total.as_secs_f64() / 1e3,
        enc.as_nanos() as f64 / n as f64,
        dec.as_nanos() as f64 / n as f64
    );
}
