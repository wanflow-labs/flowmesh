// SPDX-License-Identifier: Apache-2.0
//! Inbound judgment (filter.md §2).

use crate::compile::CompiledRule;
use crate::packet::{IpProto, Packet, TCP_SYN};

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
}

impl Filter {
    pub fn new(rules: Vec<CompiledRule>) -> Self {
        Self { rules }
    }

    pub fn check_in(&self, p: &Packet) -> Verdict {
        match p.proto {
            // F1: non-SYN TCP packets are always allowed.
            IpProto::Tcp if p.tcp_flags & TCP_SYN == 0 => Verdict::Accept,
            IpProto::Tcp | IpProto::Udp => self.port_match(p),
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
