// SPDX-License-Identifier: Apache-2.0
//! Prefix sets for the inbound destination check: which destinations this node accepts packets
//! for (its own addresses, the subnets it routes, and for an exit node the default route shrunk
//! the way the official client shrinks it; OBS-20261011-exit-node-official).

use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;

/// Never reachable through an exit node, even when advertised as the default route: private and
/// link-local ranges, multicast, and the mesh's own ranges (the official client's list).
pub const NOT_VIA_EXIT_NODE: [&str; 9] = [
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "100.64.0.0/10",
    "fe80::/10",
    "ff00::/8",
    "fd7a:115c:a1e0::/48",
];

/// `from` minus `remove`, as a list of disjoint prefixes.
pub fn subtract(from: &[IpNet], remove: &[IpNet]) -> Vec<IpNet> {
    let mut out = Vec::new();
    for &base in from {
        split_out(base, remove, &mut out);
    }
    out
}

fn split_out(base: IpNet, remove: &[IpNet], out: &mut Vec<IpNet>) {
    let overlapping: Vec<IpNet> = remove
        .iter()
        .copied()
        .filter(|r| same_family(r, &base) && (r.contains(&base) || base.contains(r)))
        .collect();
    if overlapping.is_empty() {
        out.push(base);
        return;
    }
    if overlapping.iter().any(|r| r.contains(&base)) {
        return;
    }
    // Some removal lies strictly inside `base`: split it in two and look again.
    if let Ok(halves) = base.subnets(base.prefix_len() + 1) {
        for half in halves {
            split_out(half, &overlapping, out);
        }
    }
}

fn same_family(a: &IpNet, b: &IpNet) -> bool {
    matches!(
        (a, b),
        (IpNet::V4(_), IpNet::V4(_)) | (IpNet::V6(_), IpNet::V6(_))
    )
}

/// What an advertised default route lets peers reach, as the official client computes it: the
/// route minus the networks of this host's interfaces, plus this host's own interface addresses
/// (a client may talk to the exit node's public address, not its LAN), minus `NOT_VIA_EXIT_NODE`.
pub fn shrink_default_route(route: IpNet, iface_nets: &[IpNet], host_ips: &[IpAddr]) -> Vec<IpNet> {
    let mut nets = subtract(&[route], iface_nets);
    nets.extend(
        host_ips
            .iter()
            .filter(|ip| route.contains(*ip))
            .map(|ip| IpNet::from(*ip)),
    );
    let never: Vec<IpNet> = NOT_VIA_EXIT_NODE
        .iter()
        .filter_map(|p| p.parse().ok())
        .collect();
    subtract(&nets, &never)
}

/// The destinations inbound packets may have.
#[derive(Debug, Clone, Default)]
pub struct LocalNets {
    hosts: HashSet<IpAddr>,
    nets: Vec<IpNet>,
}

impl LocalNets {
    pub fn new(prefixes: impl IntoIterator<Item = IpNet>) -> Self {
        let mut s = Self::default();
        for p in prefixes {
            if p.prefix_len() == p.max_prefix_len() {
                s.hosts.insert(p.addr());
            } else {
                s.nets.push(p);
            }
        }
        s
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.hosts.contains(ip) || self.nets.iter().any(|n| n.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(s: &[&str]) -> Vec<IpNet> {
        s.iter().map(|p| p.parse().unwrap()).collect()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn subtract_splits_around_holes() {
        assert_eq!(
            subtract(&nets(&["10.0.0.0/24"]), &nets(&["10.0.0.0/25"])),
            nets(&["10.0.0.128/25"])
        );
        assert_eq!(
            subtract(&nets(&["10.0.0.0/24"]), &nets(&["10.0.0.0/8"])),
            Vec::<IpNet>::new()
        );
        assert_eq!(
            subtract(&nets(&["10.0.0.0/24"]), &nets(&["192.168.0.0/16"])),
            nets(&["10.0.0.0/24"])
        );
        let hole = subtract(&nets(&["10.0.0.0/30"]), &nets(&["10.0.0.1/32"]));
        assert_eq!(hole, nets(&["10.0.0.0/32", "10.0.0.2/31"]));
        // Families never interact.
        assert_eq!(
            subtract(&nets(&["::/0"]), &nets(&["0.0.0.0/0"])),
            nets(&["::/0"])
        );
    }

    #[test]
    fn exit_node_reaches_the_internet_but_not_its_lan_or_private_ranges() {
        // Like the observed official exit node: LAN 172.29.0.0/24 on eth0, host address 172.29.0.91.
        let set = LocalNets::new(shrink_default_route(
            "0.0.0.0/0".parse().unwrap(),
            &nets(&["172.29.0.0/24", "203.0.113.0/24"]),
            &[ip("172.29.0.91"), ip("203.0.113.7")],
        ));
        assert!(set.contains(&ip("1.1.1.1")), "the internet");
        assert!(
            set.contains(&ip("203.0.113.7")),
            "the exit node's own public address"
        );
        assert!(!set.contains(&ip("203.0.113.8")), "its public LAN");
        assert!(!set.contains(&ip("172.29.0.10")), "its private LAN");
        assert!(
            !set.contains(&ip("172.29.0.91")),
            "a private host address stays private"
        );
        assert!(
            !set.contains(&ip("10.98.0.10")),
            "any RFC 1918 network, even a routed one"
        );
        assert!(!set.contains(&ip("100.64.0.5")), "the mesh itself");
        assert!(!set.contains(&ip("224.0.0.251")), "multicast");
        let v6 = LocalNets::new(shrink_default_route("::/0".parse().unwrap(), &[], &[]));
        assert!(v6.contains(&ip("2606:4700::1111")));
        assert!(!v6.contains(&ip("fe80::1")));
        assert!(!v6.contains(&ip("fd7a:115c:a1e0::5")));
    }

    #[test]
    fn local_nets_match_hosts_and_prefixes() {
        let set = LocalNets::new(nets(&["100.64.0.2/32", "10.99.0.0/24"]));
        assert!(set.contains(&ip("100.64.0.2")));
        assert!(set.contains(&ip("10.99.0.200")));
        assert!(!set.contains(&ip("10.99.1.1")));
        assert!(!set.contains(&ip("100.64.0.3")));
    }
}
