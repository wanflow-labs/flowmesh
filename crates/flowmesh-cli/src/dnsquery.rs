// SPDX-License-Identifier: Apache-2.0
//! `flowmesh dns query <name> [type]`: one query to the built-in resolver (100.100.100.100), shown
//! like the official command (OBS-20261012-dns-query-official). The query goes the way any program's
//! does: over the mesh interface to the engine's resolver.

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

/// The record types the official command accepts.
pub fn parse_type(t: &str) -> Result<RecordType, String> {
    Ok(match t.to_ascii_lowercase().as_str() {
        "a" => RecordType::A,
        "aaaa" => RecordType::AAAA,
        "cname" => RecordType::CNAME,
        "mx" => RecordType::MX,
        "ns" => RecordType::NS,
        "opt" => RecordType::OPT,
        "ptr" => RecordType::PTR,
        "srv" => RecordType::SRV,
        "txt" => RecordType::TXT,
        _ => {
            return Err(format!(
                "unknown DNS message type: {}",
                t.to_ascii_uppercase()
            ));
        }
    })
}

pub fn build(name: &str, rtype: RecordType, id: u16) -> Result<Vec<u8>, String> {
    let mut n = Name::from_ascii(name).map_err(|e| format!("bad name {name:?}: {e}"))?;
    n.set_fqdn(true);
    let mut m = Message::query();
    m.metadata.id = id;
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(n, rtype));
    m.to_vec().map_err(|e| e.to_string())
}

/// The heading line, with the type as the user wrote it (`A` when not given).
pub fn heading(name: &str, type_arg: Option<&str>) -> String {
    format!(
        "DNS query for {name:?} ({}) using internal resolver:\n\n",
        type_arg.unwrap_or("A")
    )
}

fn rcode_name(c: ResponseCode) -> String {
    match c {
        ResponseCode::NoError => "RCodeSuccess".into(),
        ResponseCode::FormErr => "RCodeFormatError".into(),
        ResponseCode::ServFail => "RCodeServerFailure".into(),
        ResponseCode::NXDomain => "RCodeNameError".into(),
        ResponseCode::NotImp => "RCodeNotImplemented".into(),
        ResponseCode::Refused => "RCodeRefused".into(),
        other => format!("RCode({})", u16::from(other)),
    }
}

fn class_name(c: DNSClass) -> String {
    match c {
        DNSClass::IN => "ClassINET".into(),
        DNSClass::CH => "ClassCHAOS".into(),
        DNSClass::HS => "ClassHESIOD".into(),
        DNSClass::ANY => "ClassANY".into(),
        other => format!("Class({})", u16::from(other)),
    }
}

fn type_name(t: RecordType) -> String {
    format!("Type{t}")
}

fn body(r: &Record) -> String {
    match &r.data {
        RData::A(a) => a.to_string(),
        RData::AAAA(a) => a.to_string(),
        RData::CNAME(n) => n.to_string(),
        RData::NS(n) => n.to_string(),
        RData::PTR(n) => n.to_string(),
        RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange),
        RData::SRV(s) => format!("{} {} {} {}", s.priority, s.weight, s.port, s.target),
        RData::TXT(t) => t
            .txt_data
            .iter()
            .map(|s| format!("{:?}", String::from_utf8_lossy(s)))
            .collect::<Vec<_>>()
            .join(" "),
        other => other.to_string(),
    }
}

/// Lay out rows like Go's tabwriter with padding 2; the last column is not padded.
fn table(rows: &[[String; 5]]) -> String {
    let mut widths = [0usize; 5];
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    let mut out = String::new();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            out.push_str(c);
            if i < 4 {
                out.push_str(&" ".repeat(widths[i] - c.chars().count() + 2));
            }
        }
        out.push('\n');
    }
    out
}

/// Everything after the heading for a response; `resolvers` are the upstreams that apply to
/// the name (none: answered locally or by the system's resolvers).
pub fn render(resp: &[u8], resolvers: &[String]) -> Result<String, String> {
    let m = Message::from_vec(resp).map_err(|e| format!("bad response: {e}"))?;
    let mut o = match resolvers {
        [one] => format!("Forwarding to resolver: {one}\n"),
        many => {
            let mut o = String::from("Multiple resolvers available:\n");
            for r in many {
                o.push_str(&format!("  - {r}\n"));
            }
            o
        }
    };
    o.push_str(&format!(
        "\nResponse code: {}\n\n",
        rcode_name(m.metadata.response_code)
    ));
    let answers = &m.answers;
    if answers.is_empty() && m.metadata.response_code != ResponseCode::NoError {
        o.push_str("No answers were returned.\n");
        return Ok(o);
    }
    if answers.is_empty() {
        o.push_str("  (no answers found)\n");
    }
    let mut rows = vec![
        ["Name", "TTL", "Class", "Type", "Body"].map(String::from),
        ["----", "---", "-----", "----", "----"].map(String::from),
    ];
    for r in answers {
        rows.push([
            r.name.to_string(),
            r.ttl.to_string(),
            class_name(r.dns_class),
            type_name(r.record_type()),
            body(r),
        ]);
    }
    o.push_str(&table(&rows));
    o.push('\n');
    Ok(o)
}

/// The upstreams the resolver would forward `name` to, from the daemon's `dns` view: the longest
/// matching split DNS route that has resolvers, else the default resolvers, else (with
/// `--accept-dns`) the host's own nameservers; without `--accept-dns` nothing is forwarded.
/// The official command shows these for every name, local ones included (observed).
pub fn resolvers_for(view: &serde_json::Value, name: &str) -> Vec<String> {
    if view["acceptDNS"] != true {
        return Vec::new();
    }
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let strings = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(str::to_owned))
            .collect()
    };
    let best = view["routes"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(suffix, rs)| {
            let s = suffix.trim_end_matches('.').to_ascii_lowercase();
            !strings(rs).is_empty() && (name == s || name.ends_with(&format!(".{s}")))
        })
        .max_by_key(|(suffix, _)| suffix.len());
    match best {
        Some((_, rs)) => strings(rs),
        None => {
            let d = strings(&view["resolvers"]);
            if d.is_empty() {
                strings(&view["system"]["nameservers"])
                    .into_iter()
                    .filter(|n| n != "100.100.100.100")
                    .collect()
            } else {
                d
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::OpCode;
    use hickory_proto::rr::rdata::{A, PTR};
    use std::net::Ipv4Addr;

    fn response(code: ResponseCode, answers: Vec<Record>) -> Vec<u8> {
        let mut m = Message::response(7, OpCode::Query);
        m.metadata.response_code = code;
        for a in answers {
            m.add_answer(a);
        }
        m.to_vec().unwrap()
    }

    fn fixture(name: &str) -> String {
        let p = format!(
            "{}/../../fixtures/observed/20261012-dns-query-official/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let s = std::fs::read_to_string(p).unwrap();
        // Without the command line and the exit code.
        s.lines()
            .skip(1)
            .filter(|l| !l.starts_with("[exit"))
            .map(|l| format!("{l}\n"))
            .collect()
    }

    /// Same text as the official command for the same answers.
    #[test]
    fn like_the_official_command() {
        let a = Record::from_rdata(
            Name::from_ascii("toq.mesh.lab.internal.").unwrap(),
            600,
            RData::A(A(Ipv4Addr::new(100, 64, 0, 37))),
        );
        let out = heading("toq.mesh.lab.internal", None)
            + &render(&response(ResponseCode::NoError, vec![a]), &[]).unwrap();
        assert_eq!(out, fixture("accept-dns-false/official/peer-fqdn.txt"));

        let ptr = Record::from_rdata(
            Name::from_ascii("1.0.64.100.in-addr.arpa.").unwrap(),
            600,
            RData::PTR(PTR(Name::from_ascii("ts1.mesh.lab.internal.").unwrap())),
        );
        let out = heading("1.0.64.100.in-addr.arpa", Some("ptr"))
            + &render(&response(ResponseCode::NoError, vec![ptr]), &[]).unwrap();
        assert_eq!(out, fixture("accept-dns-false/official/reverse-ptr.txt"));

        let out = heading("toq.mesh.lab.internal", Some("aaaa"))
            + &render(&response(ResponseCode::NoError, vec![]), &[]).unwrap();
        assert_eq!(out, fixture("accept-dns-false/official/peer-aaaa.txt"));

        let out = heading("nosuch.mesh.lab.internal", None)
            + &render(&response(ResponseCode::ServFail, vec![]), &[]).unwrap();
        // The official output has no blank line after "No answers were returned.".
        assert_eq!(
            out,
            fixture("accept-dns-false/official/unknown-mesh-name.txt")
        );

        // With --accept-dns, one upstream (the host's nameserver) for every name.
        let a = Record::from_rdata(
            Name::from_ascii("toq.mesh.lab.internal.").unwrap(),
            600,
            RData::A(A(Ipv4Addr::new(100, 64, 0, 37))),
        );
        let out = heading("toq.mesh.lab.internal", None)
            + &render(
                &response(ResponseCode::NoError, vec![a]),
                &["127.0.0.11".into()],
            )
            .unwrap();
        assert_eq!(out, fixture("accept-dns-true/official/peer-fqdn.txt"));
    }

    #[test]
    fn types_and_errors() {
        assert_eq!(parse_type("AAAA"), Ok(RecordType::AAAA));
        assert_eq!(parse_type("ptr"), Ok(RecordType::PTR));
        assert_eq!(
            parse_type("bogus"),
            Err("unknown DNS message type: BOGUS".into())
        );
        let q = Message::from_vec(&build("example.com", RecordType::MX, 9).unwrap()).unwrap();
        assert_eq!(q.queries[0].name().to_string(), "example.com.");
        assert_eq!(q.queries[0].query_type(), RecordType::MX);
        assert!(q.metadata.recursion_desired);
    }

    #[test]
    fn resolvers_by_route() {
        let mut v = serde_json::json!({
            "acceptDNS": true,
            "resolvers": ["1.1.1.1"],
            "routes": {"corp.example": ["10.0.0.53"], "a.corp.example": ["10.0.0.54"], "mesh.lab.internal": []},
            "system": {"nameservers": ["127.0.0.11"]}
        });
        assert_eq!(resolvers_for(&v, "x.a.corp.example."), ["10.0.0.54"]);
        assert_eq!(resolvers_for(&v, "corp.example"), ["10.0.0.53"]);
        assert_eq!(resolvers_for(&v, "example.com"), ["1.1.1.1"]);
        // A MagicDNS-only route is not an upstream; the defaults apply (as observed).
        assert_eq!(resolvers_for(&v, "toq.mesh.lab.internal"), ["1.1.1.1"]);
        v["resolvers"] = serde_json::json!([]);
        assert_eq!(resolvers_for(&v, "example.com"), ["127.0.0.11"]);
        v["acceptDNS"] = serde_json::json!(false);
        assert!(resolvers_for(&v, "example.com").is_empty());
    }
}
