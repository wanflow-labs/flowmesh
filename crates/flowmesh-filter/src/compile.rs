// SPDX-License-Identifier: Apache-2.0
//! Compile wire-format rules into a structure that can be matched directly (filter.md §1).

use flowmesh_proto::filter::FilterRule;
use ipnet::IpNet;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompileError {
    #[error("unrecognized address {0:?}")]
    BadAddress(String),
    #[error("protocol number {0} out of range")]
    BadProto(i32),
}

/// An address set: any, or a list of CIDRs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrSet {
    Any,
    Nets(Vec<IpNet>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DstRange {
    pub net: AddrSet,
    pub first: u16,
    pub last: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRule {
    pub srcs: AddrSet,
    pub dsts: Vec<DstRange>,
    /// Allowed protocol numbers.
    pub protos: Vec<u8>,
}

/// Protocol set used when `IPProto` is empty (filter.md F4).
pub const DEFAULT_PROTOS: [u8; 4] = [6, 17, 1, 58];

impl AddrSet {
    pub fn contains(&self, ip: &std::net::IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Nets(nets) => nets.iter().any(|n| n.contains(ip)),
        }
    }
}

fn parse_addr(s: &str) -> Result<Option<IpNet>, CompileError> {
    if s == "*" {
        return Ok(None);
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(Some(net));
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(Some(IpNet::from(ip)));
    }
    Err(CompileError::BadAddress(s.to_string()))
}

fn parse_set<'a>(items: impl IntoIterator<Item = &'a str>) -> Result<AddrSet, CompileError> {
    let mut nets = Vec::new();
    for item in items {
        match parse_addr(item)? {
            None => return Ok(AddrSet::Any),
            Some(n) => nets.push(n),
        }
    }
    Ok(AddrSet::Nets(nets))
}

/// Any unrecognized rule content makes the whole compile fail; the caller then keeps the previous valid rules (fail-closed, design doc §7.2).
pub fn compile(rules: &[FilterRule]) -> Result<Vec<CompiledRule>, CompileError> {
    let mut out = Vec::new();
    for rule in rules {
        if rule.dst_ports.is_empty() {
            // Rules with only a CapGrant allow no packets (filter.md §1).
            continue;
        }
        let srcs = parse_set(rule.src_ips.iter().map(String::as_str))?;
        let mut dsts = Vec::with_capacity(rule.dst_ports.len());
        for d in &rule.dst_ports {
            dsts.push(DstRange {
                net: parse_set([d.ip.as_str()])?,
                first: d.ports.first,
                last: d.ports.last,
            });
        }
        let protos = if rule.ip_proto.is_empty() {
            DEFAULT_PROTOS.to_vec()
        } else {
            rule.ip_proto
                .iter()
                .map(|&n| u8::try_from(n).map_err(|_| CompileError::BadProto(n)))
                .collect::<Result<_, _>>()?
        };
        out.push(CompiledRule { srcs, dsts, protos });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmesh_proto::filter::{NetPortRange, PortRange};

    fn rule(src: &[&str], dst: &[(&str, u16, u16)], proto: &[i32]) -> FilterRule {
        FilterRule {
            src_ips: src.iter().map(|s| s.to_string()).collect(),
            dst_ports: dst
                .iter()
                .map(|(ip, f, l)| NetPortRange {
                    ip: ip.to_string(),
                    ports: PortRange {
                        first: *f,
                        last: *l,
                    },
                })
                .collect(),
            ip_proto: proto.to_vec(),
            cap_grant: vec![],
        }
    }

    #[test]
    fn star_bare_ip_and_cidr() {
        let c = compile(&[rule(
            &["*", "100.64.0.1", "fd7a::/48"],
            &[("*", 0, 65535)],
            &[],
        )])
        .unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].srcs, AddrSet::Any);
        assert_eq!(c[0].dsts[0].net, AddrSet::Any);
        assert_eq!(c[0].protos, DEFAULT_PROTOS.to_vec());

        let c = compile(&[rule(
            &["100.64.0.1", "fd7a::/48"],
            &[("100.64.0.2/32", 80, 80)],
            &[17],
        )])
        .unwrap();
        assert_eq!(
            c[0].srcs,
            AddrSet::Nets(vec![
                "100.64.0.1/32".parse().unwrap(),
                "fd7a::/48".parse().unwrap()
            ])
        );
        assert_eq!(c[0].protos, vec![17]);
        assert_eq!((c[0].dsts[0].first, c[0].dsts[0].last), (80, 80));
    }

    #[test]
    fn capgrant_only_rule_is_skipped() {
        let mut r = rule(&["*"], &[], &[]);
        r.cap_grant = vec![Default::default()];
        assert_eq!(compile(&[r]).unwrap(), vec![]);
    }

    #[test]
    fn bad_inputs_fail_closed() {
        assert!(matches!(
            compile(&[rule(&["not-an-ip"], &[("*", 0, 1)], &[])]),
            Err(CompileError::BadAddress(_))
        ));
        assert!(matches!(
            compile(&[rule(&["*"], &[("*", 0, 1)], &[300])]),
            Err(CompileError::BadProto(300))
        ));
    }
}
