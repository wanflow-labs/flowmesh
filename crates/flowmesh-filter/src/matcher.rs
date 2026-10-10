// SPDX-License-Identifier: Apache-2.0
//! Inbound judgment (filter.md §2) and outbound flow tracking (filter.md §2a).

use crate::compile::CompiledRule;
use crate::packet::{IpProto, Packet, TCP_ACK, TCP_SYN};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

/// Lifetime of a UDP flow record. Not yet observed (filter.md §4); takes a provisional value.
pub const UDP_FLOW_TTL: Duration = Duration::from_secs(120);
/// Capacity of the flow table; when full, the oldest record is evicted, so a peer cannot exhaust memory.
pub const MAX_FLOWS: usize = 65_536;

/// Flow key in the outbound direction: (local address, local port, remote address, remote port).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    local: IpAddr,
    local_port: u16,
    remote: IpAddr,
    remote_port: u16,
}

#[derive(Default)]
struct FlowTable {
    expires: HashMap<FlowKey, Duration>,
    order: VecDeque<FlowKey>,
}

impl FlowTable {
    fn insert(&mut self, key: FlowKey, now: Duration) {
        if self.expires.insert(key, now + UDP_FLOW_TTL).is_none() {
            self.order.push_back(key);
            while self.order.len() > MAX_FLOWS {
                if let Some(old) = self.order.pop_front() {
                    self.expires.remove(&old);
                }
            }
        }
    }

    fn live(&self, key: &FlowKey, now: Duration) -> bool {
        self.expires.get(key).is_some_and(|exp| now < *exp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    NoRule,
    IcmpError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop(DropReason),
}

pub struct Filter {
    rules: Vec<CompiledRule>,
    udp_flows: FlowTable,
}

impl Filter {
    pub fn new(rules: Vec<CompiledRule>) -> Self {
        Self {
            rules,
            udp_flows: FlowTable::default(),
        }
    }

    /// Replace the rules and keep the existing flow records (connections already established are not cut off by a rule update).
    pub fn set_rules(&mut self, rules: Vec<CompiledRule>) {
        self.rules = rules;
    }

    /// Record an outbound packet (this node initiating). `now` is a monotonic time supplied by the caller.
    /// Only UDP needs tracking: TCP replies are non-pure-SYN packets and already pass under F1.
    pub fn check_out(&mut self, p: &Packet, now: Duration) {
        if p.proto == IpProto::Udp {
            self.udp_flows.insert(
                FlowKey {
                    local: p.src,
                    local_port: p.src_port,
                    remote: p.dst,
                    remote_port: p.dst_port,
                },
                now,
            );
        }
    }

    pub fn check_in(&self, p: &Packet, now: Duration) -> Verdict {
        match p.proto {
            // F1: only a pure SYN (SYN without ACK) is a new connection; every other TCP packet is allowed.
            IpProto::Tcp if !is_pure_syn(p.tcp_flags) => Verdict::Accept,
            IpProto::Tcp => self.port_match(p),
            // F10: a reply to a UDP flow this node initiated is allowed only if the full 4-tuple matches.
            IpProto::Udp if self.is_udp_reply(p, now) => Verdict::Accept,
            IpProto::Udp => self.port_match(p),
            IpProto::Icmp4 => match p.icmp_type {
                // F6: echo reply is always allowed.
                ICMP4_ECHO_REPLY => Verdict::Accept,
                // F7: error types are dropped.
                t if ICMP4_ERRORS.contains(&t) => Verdict::Drop(DropReason::IcmpError),
                // F5: request types match on address only.
                _ => self.addr_match(p),
            },
            IpProto::Icmp6 => match p.icmp_type {
                // F6: echo reply is always allowed.
                ICMP6_ECHO_REPLY => Verdict::Accept,
                // F7b: ICMPv6 errors are always allowed (asymmetric with ICMPv4).
                t if t < ICMP6_FIRST_INFO => Verdict::Accept,
                _ => self.addr_match(p),
            },
            // F8: other protocols must be listed explicitly in the rule's IPProto.
            IpProto::Other(_) => self.proto_match(p),
        }
    }

    fn is_udp_reply(&self, p: &Packet, now: Duration) -> bool {
        self.udp_flows.live(
            &FlowKey {
                local: p.dst,
                local_port: p.dst_port,
                remote: p.src,
                remote_port: p.src_port,
            },
            now,
        )
    }

    /// F2/F3: source, destination, port, and protocol must all match.
    fn port_match(&self, p: &Packet) -> Verdict {
        let proto = p.proto.number();
        let hit = self.rules.iter().any(|r| {
            r.protos.contains(&proto)
                && r.srcs.contains(&p.src)
                && r.dsts
                    .iter()
                    .any(|d| d.net.contains(&p.dst) && (d.first..=d.last).contains(&p.dst_port))
        });
        verdict(hit)
    }

    /// F5: ICMP requests look only at the address pair, ignoring ports and the rule's protocol set.
    fn addr_match(&self, p: &Packet) -> Verdict {
        let hit = self
            .rules
            .iter()
            .any(|r| r.srcs.contains(&p.src) && r.dsts.iter().any(|d| d.net.contains(&p.dst)));
        verdict(hit)
    }

    /// F8: protocols without ports look at the protocol number and the address pair.
    fn proto_match(&self, p: &Packet) -> Verdict {
        let proto = p.proto.number();
        let hit = self.rules.iter().any(|r| {
            r.protos.contains(&proto)
                && r.srcs.contains(&p.src)
                && r.dsts.iter().any(|d| d.net.contains(&p.dst))
        });
        verdict(hit)
    }
}

fn is_pure_syn(flags: u8) -> bool {
    flags & TCP_SYN != 0 && flags & TCP_ACK == 0
}

fn verdict(hit: bool) -> Verdict {
    if hit {
        Verdict::Accept
    } else {
        Verdict::Drop(DropReason::NoRule)
    }
}

const ICMP4_ECHO_REPLY: u8 = 0;
/// ICMPv4 error message types (all observed, filter.md F7): destination unreachable, source quench, redirect, time exceeded, parameter problem.
const ICMP4_ERRORS: [u8; 5] = [3, 4, 5, 11, 12];
const ICMP6_ECHO_REPLY: u8 = 129;
/// ICMPv6 types below 128 are error messages (RFC 4443 §2.1); 1, 2, 3 are observed (filter.md F7b).
const ICMP6_FIRST_INFO: u8 = 128;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::IpProto;

    fn udp(src: &str, sport: u16, dst: &str, dport: u16) -> Packet {
        Packet {
            proto: IpProto::Udp,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            src_port: sport,
            dst_port: dport,
            tcp_flags: 0,
            icmp_type: 0,
        }
    }

    #[test]
    fn udp_flow_expires_after_ttl() {
        let mut f = Filter::new(vec![]);
        let t0 = Duration::from_secs(10);
        f.check_out(&udp("100.64.0.2", 5000, "100.64.0.1", 53), t0);
        let reply = udp("100.64.0.1", 53, "100.64.0.2", 5000);
        assert_eq!(
            f.check_in(&reply, t0 + UDP_FLOW_TTL - Duration::from_millis(1)),
            Verdict::Accept
        );
        assert_eq!(
            f.check_in(&reply, t0 + UDP_FLOW_TTL),
            Verdict::Drop(DropReason::NoRule)
        );
    }

    #[test]
    fn repeated_outbound_refreshes_ttl() {
        let mut f = Filter::new(vec![]);
        let out = udp("100.64.0.2", 5000, "100.64.0.1", 53);
        let reply = udp("100.64.0.1", 53, "100.64.0.2", 5000);
        f.check_out(&out, Duration::ZERO);
        f.check_out(&out, UDP_FLOW_TTL);
        assert_eq!(
            f.check_in(&reply, UDP_FLOW_TTL + Duration::from_secs(1)),
            Verdict::Accept
        );
    }

    #[test]
    fn flow_table_is_bounded_and_evicts_oldest() {
        let mut f = Filter::new(vec![]);
        for i in 0..=MAX_FLOWS {
            let port = (i % 60_000) as u16 + 1;
            let remote = if i < 60_000 {
                "100.64.0.1"
            } else {
                "100.64.0.3"
            };
            f.check_out(&udp("100.64.0.2", port, remote, 53), Duration::ZERO);
        }
        assert_eq!(f.udp_flows.expires.len(), MAX_FLOWS);
        assert_eq!(f.udp_flows.order.len(), MAX_FLOWS);
        // The first record has been evicted; the last one is still present.
        assert_eq!(
            f.check_in(&udp("100.64.0.1", 53, "100.64.0.2", 1), Duration::ZERO),
            Verdict::Drop(DropReason::NoRule)
        );
        let last = MAX_FLOWS;
        let port = (last % 60_000) as u16 + 1;
        assert_eq!(
            f.check_in(&udp("100.64.0.3", 53, "100.64.0.2", port), Duration::ZERO),
            Verdict::Accept
        );
    }

    #[test]
    fn set_rules_replaces_rules() {
        use crate::compile::{AddrSet, CompiledRule, DstRange};
        let syn = Packet {
            proto: IpProto::Tcp,
            src: "100.64.0.1".parse().unwrap(),
            dst: "100.64.0.2".parse().unwrap(),
            src_port: 40000,
            dst_port: 22,
            tcp_flags: crate::packet::TCP_SYN,
            icmp_type: 0,
        };
        let mut f = Filter::new(vec![]);
        assert_eq!(
            f.check_in(&syn, Duration::ZERO),
            Verdict::Drop(DropReason::NoRule)
        );
        f.set_rules(vec![CompiledRule {
            srcs: AddrSet::Any,
            dsts: vec![DstRange {
                net: AddrSet::Any,
                first: 22,
                last: 22,
            }],
            protos: vec![6],
        }]);
        assert_eq!(f.check_in(&syn, Duration::ZERO), Verdict::Accept);
    }

    #[test]
    fn rule_update_keeps_existing_flows() {
        let mut f = Filter::new(vec![]);
        f.check_out(&udp("100.64.0.2", 5000, "100.64.0.1", 53), Duration::ZERO);
        f.set_rules(vec![]);
        assert_eq!(
            f.check_in(&udp("100.64.0.1", 53, "100.64.0.2", 5000), Duration::ZERO),
            Verdict::Accept
        );
    }
}
