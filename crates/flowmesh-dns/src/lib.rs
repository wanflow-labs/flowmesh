// SPDX-License-Identifier: Apache-2.0
//! MagicDNS answering logic (sans-IO): DNS query packet + "DNS view" → local answer, or forward upstream.
//! Semantics come from docs/protocol/dns.md.

use flowmesh_proto::control::DnsRecord;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::collections::HashMap;
use std::net::IpAddr;

/// TTL of local answers (observed 600).
pub const TTL: u32 = 600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Answered locally; this is the response packet.
    Local(Vec<u8>),
    /// Not ours to answer; forward to the upstream.
    Forward,
    /// The query packet could not be parsed; drop it silently.
    Drop,
}

/// The data needed for answering, assembled from the netmap.
#[derive(Debug, Clone, Default)]
pub struct DnsView {
    /// Domains we are authoritative for (`DNSConfig.Domains`), lowercase, no trailing dot.
    suffixes: Vec<String>,
    /// Reverse zones we answer locally (keys of `DNSConfig.Routes` with an empty value), lowercase, no trailing dot.
    reverse_zones: Vec<String>,
    /// FQDN (lowercase, no trailing dot) → addresses.
    hosts: HashMap<String, Vec<IpAddr>>,
    /// address → FQDN (with trailing dot).
    ptr: HashMap<IpAddr, String>,
    /// Whether to answer AAAA (see dns.md §2: only when the host has IPv6 connectivity).
    answer_aaaa: bool,
}

/// One node in the netmap: its full name (`Node.Name`, ending in a dot) and addresses.
#[derive(Debug, Clone)]
pub struct HostEntry {
    pub fqdn: String,
    pub addrs: Vec<IpAddr>,
}

impl DnsView {
    pub fn new(
        domains: &[String],
        routes: &[(String, bool)],
        nodes: &[HostEntry],
        extra: &[DnsRecord],
        answer_aaaa: bool,
    ) -> Self {
        let mut v = Self {
            suffixes: domains.iter().map(|d| normalize(d)).collect(),
            reverse_zones: routes
                .iter()
                .filter(|(_, local)| *local)
                .map(|(z, _)| normalize(z))
                .filter(|z| z.ends_with(".arpa"))
                .collect(),
            answer_aaaa,
            ..Default::default()
        };
        for n in nodes {
            let key = normalize(&n.fqdn);
            let fqdn = format!("{key}.");
            for a in &n.addrs {
                v.ptr.insert(*a, fqdn.clone());
            }
            v.hosts
                .entry(key)
                .or_default()
                .extend(n.addrs.iter().copied());
        }
        for r in extra {
            let ok_type = matches!(r.record_type.as_str(), "" | "A" | "AAAA");
            if let (true, Ok(ip)) = (ok_type, r.value.parse::<IpAddr>()) {
                v.hosts.entry(normalize(&r.name)).or_default().push(ip);
            }
        }
        v
    }

    fn in_suffix(&self, name: &str) -> bool {
        self.suffixes.iter().any(|s| within(name, s))
    }

    fn in_reverse_zone(&self, name: &str) -> bool {
        self.reverse_zones.iter().any(|z| within(name, z))
    }
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn within(name: &str, zone: &str) -> bool {
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|head| head.ends_with('.'))
}

/// Recover the address from a reverse-lookup name (in-addr.arpa: 4 octets reversed; ip6.arpa: 32 nibbles reversed).
fn parse_ptr(name: &str) -> Option<IpAddr> {
    if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let mut octets: Vec<u8> = rest
            .split('.')
            .map(|l| l.parse().ok())
            .collect::<Option<_>>()?;
        if octets.len() != 4 {
            return None;
        }
        octets.reverse();
        return Some(IpAddr::from([octets[0], octets[1], octets[2], octets[3]]));
    }
    let rest = name.strip_suffix(".ip6.arpa")?;
    let nibbles: Vec<u8> = rest
        .split('.')
        .map(|l| {
            (l.len() == 1)
                .then(|| u8::from_str_radix(l, 16).ok())
                .flatten()
        })
        .collect::<Option<_>>()?;
    if nibbles.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, pair) in nibbles
        .iter()
        .rev()
        .collect::<Vec<_>>()
        .chunks(2)
        .enumerate()
    {
        bytes[i] = (pair[0] << 4) | pair[1];
    }
    Some(IpAddr::from(bytes))
}

pub fn handle(view: &DnsView, query: &[u8]) -> Decision {
    let Ok(req) = Message::from_vec(query) else {
        return Decision::Drop;
    };
    let Some(q) = req.queries.first() else {
        return Decision::Drop;
    };
    let qname = q.name().clone();
    let name = normalize(&qname.to_ascii());
    let qtype = q.query_type();

    let respond = |code: ResponseCode, data: Vec<RData>| -> Decision {
        let mut m = Message::response(req.metadata.id, req.metadata.op_code);
        m.metadata.authoritative = true;
        m.metadata.recursion_desired = req.metadata.recursion_desired;
        m.metadata.recursion_available = true;
        m.metadata.authentic_data = true;
        m.metadata.response_code = code;
        m.add_query(q.clone());
        for d in data {
            m.add_answer(Record::from_rdata(qname.clone(), TTL, d));
        }
        m.to_vec().map_or(Decision::Drop, Decision::Local)
    };

    if let Some(addrs) = view.hosts.get(&name) {
        let data = addrs
            .iter()
            .filter_map(|a| match (qtype, a) {
                (RecordType::A, IpAddr::V4(v4)) => Some(RData::A(A(*v4))),
                (RecordType::AAAA, IpAddr::V6(v6)) if view.answer_aaaa => {
                    Some(RData::AAAA(AAAA(*v6)))
                }
                _ => None,
            })
            .collect();
        return respond(ResponseCode::NoError, data);
    }
    if qtype == RecordType::PTR && view.in_reverse_zone(&name) {
        let target = parse_ptr(&name).and_then(|ip| view.ptr.get(&ip));
        return match target.and_then(|t| Name::from_ascii(t).ok()) {
            Some(t) => respond(ResponseCode::NoError, vec![RData::PTR(PTR(t))]),
            None => respond(ResponseCode::NXDomain, Vec::new()),
        };
    }
    if view.in_suffix(&name) {
        return respond(ResponseCode::NXDomain, Vec::new());
    }
    Decision::Forward
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    pub(crate) fn query(name: &str, ty: RecordType) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.id = 0x4242;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), ty));
        m.to_vec().unwrap()
    }

    pub(crate) fn view() -> DnsView {
        DnsView::new(
            &["mesh.lab.internal".into()],
            &[
                ("100.100.in-addr.arpa".into(), true),
                ("64.100.in-addr.arpa".into(), true),
            ],
            &[HostEntry {
                fqdn: "ts1.mesh.lab.internal.".into(),
                addrs: vec![
                    "100.64.0.1".parse().unwrap(),
                    "fd7a:115c:a1e0::1".parse().unwrap(),
                ],
            }],
            &[DnsRecord {
                name: "svc.mesh.lab.internal".into(),
                record_type: "A".into(),
                value: "100.64.0.250".into(),
            }],
            false,
        )
    }

    fn answer(d: Decision) -> Message {
        match d {
            Decision::Local(b) => Message::from_vec(&b).unwrap(),
            other => panic!("expected local answer, got {other:?}"),
        }
    }

    #[test]
    fn header_flags_match_observation() {
        let m = answer(handle(
            &view(),
            &query("ts1.mesh.lab.internal.", RecordType::A),
        ));
        assert_eq!(m.metadata.id, 0x4242);
        assert!(m.metadata.authoritative && m.metadata.recursion_desired);
        assert!(m.metadata.recursion_available && m.metadata.authentic_data);
        assert_eq!(m.answers[0].ttl, TTL);
        assert_eq!(m.queries.len(), 1);
    }

    #[test]
    fn aaaa_enabled_returns_v6() {
        let mut v = view();
        v.answer_aaaa = true;
        let m = answer(handle(
            &v,
            &query("ts1.mesh.lab.internal.", RecordType::AAAA),
        ));
        assert_eq!(m.answers.len(), 1);
    }

    #[test]
    fn garbage_is_dropped() {
        assert_eq!(handle(&view(), &[1, 2, 3]), Decision::Drop);
    }

    #[test]
    fn ipv6_ptr_in_reverse_zone() {
        let v = DnsView::new(
            &["mesh.lab.internal".into()],
            &[("0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa".into(), true)],
            &[HostEntry {
                fqdn: "ts1.mesh.lab.internal.".into(),
                addrs: vec!["fd7a:115c:a1e0::1".parse().unwrap()],
            }],
            &[],
            false,
        );
        // Build the 32-nibble reverse name from the address directly instead of typing it by hand.
        let ip: std::net::Ipv6Addr = "fd7a:115c:a1e0::1".parse().unwrap();
        let hex: String = ip.octets().iter().map(|b| format!("{b:02x}")).collect();
        let name: String = hex
            .chars()
            .rev()
            .map(|c| format!("{c}."))
            .collect::<String>()
            + "ip6.arpa.";
        let m = answer(handle(&v, &query(&name, RecordType::PTR)));
        assert_eq!(
            m.answers[0].data,
            RData::PTR(PTR(Name::from_ascii("ts1.mesh.lab.internal.").unwrap()))
        );
    }

    #[test]
    fn reverse_zone_routes_with_upstream_are_not_local() {
        let v = DnsView::new(
            &[],
            &[("64.100.in-addr.arpa".into(), false)],
            &[],
            &[],
            false,
        );
        assert_eq!(
            handle(&v, &query("1.0.64.100.in-addr.arpa.", RecordType::PTR)),
            Decision::Forward
        );
    }
}
