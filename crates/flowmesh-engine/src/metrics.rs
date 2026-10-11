// SPDX-License-Identifier: Apache-2.0
//! `flowmesh metrics`: user-facing counters in Prometheus text format. Metric names, labels and
//! types are the official client's (OBS-20261012-cli-more-official/metrics-print.txt), so
//! dashboards and alerts written for it read flowmesh unchanged; the help texts are flowmesh's.

use flowmesh_dataplane::plane::Drops;
use std::fmt::Write;
use std::net::IpAddr;

/// How a WireGuard datagram travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Derp,
    /// Directly to/from this address.
    Direct(IpAddr),
    /// Through a peer relay server at this address.
    PeerRelay(IpAddr),
}

const PATHS: [&str; 5] = [
    "derp",
    "direct_ipv4",
    "direct_ipv6",
    "peer_relay_ipv4",
    "peer_relay_ipv6",
];

impl Path {
    fn index(self) -> usize {
        let v4 = |a: IpAddr| a.to_canonical().is_ipv4();
        match self {
            Path::Derp => 0,
            Path::Direct(a) if v4(a) => 1,
            Path::Direct(_) => 2,
            Path::PeerRelay(a) if v4(a) => 3,
            Path::PeerRelay(_) => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Count {
    bytes: u64,
    packets: u64,
}

/// WireGuard traffic per path, both directions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Traffic {
    inbound: [Count; 5],
    outbound: [Count; 5],
}

impl Traffic {
    pub fn received(&mut self, path: Path, len: usize) {
        let c = &mut self.inbound[path.index()];
        c.bytes += len as u64;
        c.packets += 1;
    }

    pub fn sent(&mut self, path: Path, len: usize) {
        let c = &mut self.outbound[path.index()];
        c.bytes += len as u64;
        c.packets += 1;
    }
}

/// Everything one `metrics print` shows.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub advertised_routes: usize,
    pub approved_routes: usize,
    pub warnings: usize,
    pub home_region: u32,
    pub traffic: Traffic,
    pub drops: Drops,
    /// Datagrams the engine could not hand to the network (send errors, no path).
    pub send_errors: u64,
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# TYPE tailscaled_{name} {kind}");
    let _ = writeln!(out, "# HELP tailscaled_{name} {help}");
}

fn per_path(out: &mut String, name: &str, help: &str, counts: &[Count; 5], f: fn(&Count) -> u64) {
    header(out, name, "counter", help);
    for (label, c) in PATHS.iter().zip(counts) {
        let _ = writeln!(out, "tailscaled_{name}{{path=\"{label}\"}} {}", f(c));
    }
}

/// Prometheus text exposition, metrics in name order like the official output.
pub fn prometheus(s: &Snapshot) -> String {
    let mut o = String::new();
    header(
        &mut o,
        "advertised_routes",
        "gauge",
        "Number of advertised network routes (e.g. by a subnet router)",
    );
    let _ = writeln!(o, "tailscaled_advertised_routes {}", s.advertised_routes);
    header(
        &mut o,
        "approved_routes",
        "gauge",
        "Number of approved network routes (e.g. by a subnet router)",
    );
    let _ = writeln!(o, "tailscaled_approved_routes {}", s.approved_routes);
    header(
        &mut o,
        "health_messages",
        "gauge",
        "Number of health messages broken down by type.",
    );
    let _ = writeln!(
        o,
        "tailscaled_health_messages{{type=\"warning\"}} {}",
        s.warnings
    );
    header(
        &mut o,
        "home_derp_region_id",
        "gauge",
        "DERP region ID of this node's home relay server",
    );
    let _ = writeln!(o, "tailscaled_home_derp_region_id {}", s.home_region);
    let t = &s.traffic;
    per_path(
        &mut o,
        "inbound_bytes_total",
        "Counts the number of bytes received from other peers",
        &t.inbound,
        |c| c.bytes,
    );
    header(
        &mut o,
        "inbound_dropped_packets_total",
        "counter",
        "Packets from peers that were dropped on arrival",
    );
    let _ = writeln!(
        o,
        "tailscaled_inbound_dropped_packets_total{{reason=\"acl\"}} {}",
        s.drops.inbound_acl
    );
    let _ = writeln!(
        o,
        "tailscaled_inbound_dropped_packets_total{{reason=\"error\"}} {}",
        s.drops.inbound_error
    );
    per_path(
        &mut o,
        "inbound_packets_total",
        "Counts the number of packets received from other peers",
        &t.inbound,
        |c| c.packets,
    );
    per_path(
        &mut o,
        "outbound_bytes_total",
        "Counts the number of bytes sent to other peers",
        &t.outbound,
        |c| c.bytes,
    );
    header(
        &mut o,
        "outbound_dropped_packets_total",
        "counter",
        "Packets for peers that were dropped instead of sent",
    );
    let _ = writeln!(
        o,
        "tailscaled_outbound_dropped_packets_total{{reason=\"error\"}} {}",
        s.drops.outbound_error + s.send_errors
    );
    let _ = writeln!(
        o,
        "tailscaled_outbound_dropped_packets_total{{reason=\"multicast\"}} {}",
        s.drops.outbound_multicast
    );
    per_path(
        &mut o,
        "outbound_packets_total",
        "Counts the number of packets sent to other peers",
        &t.outbound,
        |c| c.packets,
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same lines as the official output for an idle node (metrics-print.txt), plus the inbound
    /// drop reasons flowmesh counts.
    #[test]
    fn idle_node_matches_the_official_layout() {
        let s = Snapshot {
            home_region: 1001,
            drops: Drops {
                outbound_multicast: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let text = prometheus(&s);
        let official =
            include_str!("../../../fixtures/observed/20261012-cli-more-official/metrics-print.txt");
        // Help texts are worded independently; everything a scraper reads must match.
        let official: Vec<&str> = official
            .lines()
            .filter(|l| !l.starts_with('$') && !l.starts_with("[exit") && !l.starts_with("# HELP"))
            .collect();
        let ours: Vec<&str> = text
            .lines()
            .filter(|l| {
                !l.starts_with("tailscaled_inbound_dropped_packets_total{")
                    && !l.starts_with("# HELP")
            })
            .collect();
        assert_eq!(ours, official);
        assert!(text.contains("tailscaled_inbound_dropped_packets_total{reason=\"acl\"} 0\n"));
    }

    #[test]
    fn traffic_is_counted_per_path() {
        let mut t = Traffic::default();
        t.received(Path::Direct("192.0.2.1".parse().unwrap()), 100);
        t.received(Path::Direct("::ffff:192.0.2.1".parse().unwrap()), 50);
        t.received(Path::Direct("2001:db8::1".parse().unwrap()), 7);
        t.sent(Path::PeerRelay("192.0.2.9".parse().unwrap()), 60);
        t.sent(Path::Derp, 30);
        let text = prometheus(&Snapshot {
            traffic: t,
            ..Default::default()
        });
        for line in [
            "tailscaled_inbound_bytes_total{path=\"direct_ipv4\"} 150",
            "tailscaled_inbound_packets_total{path=\"direct_ipv4\"} 2",
            "tailscaled_inbound_bytes_total{path=\"direct_ipv6\"} 7",
            "tailscaled_outbound_bytes_total{path=\"peer_relay_ipv4\"} 60",
            "tailscaled_outbound_packets_total{path=\"derp\"} 1",
        ] {
            assert!(text.contains(&format!("{line}\n")), "{line}");
        }
    }
}
