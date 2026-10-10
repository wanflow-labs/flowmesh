// SPDX-License-Identifier: Apache-2.0
//! Peer relay: the disco message bodies of types 0x04–0x09 and the Geneve header on relayed packets
//! (docs/protocol/peer-relay.md). Encoding and parsing only; the state machine lives in flowmesh-udprelay.

use crate::Error;
use crate::message::{ADDR_LEN, addr_bytes, parse_addr};
use flowmesh_proto::key::DiscoPublic;
use std::net::SocketAddr;
use std::time::Duration;

pub const TYPE_BIND: u8 = 0x04;
pub const TYPE_CHALLENGE: u8 = 0x05;
pub const TYPE_ANSWER: u8 = 0x06;
pub const TYPE_CALL_ME_MAYBE_VIA: u8 = 0x07;
pub const TYPE_ALLOCATE_REQUEST: u8 = 0x08;
pub const TYPE_ALLOCATE_RESPONSE: u8 = 0x09;

/// Body length shared by Bind, Challenge and Answer (OBS-20261010-peer-relay-handshake).
pub const BIND_LEN: usize = 72;
pub const CHALLENGE_LEN: usize = 32;
/// Allocation body up to the first address (OBS-20261010-peer-relay-forward).
const ALLOC_FIXED_LEN: usize = 124;
/// Allocation request body: the pair and the counter (OBS-20261010-peer-relay-alloc-request).
const REQUEST_LEN: usize = 68;

/// The body shared by the three handshake messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindBody {
    /// Must equal the VNI in the packet's Geneve header.
    pub vni: u32,
    /// Chosen by the client, nonzero, new for each handshake.
    pub generation: u32,
    /// The other member of the pair.
    pub remote: DiscoPublic,
    /// Zero in Bind (padding), the server's value in Challenge, echoed in Answer.
    pub challenge: [u8; CHALLENGE_LEN],
}

/// An allocation as the relay server reports it (0x09, after the counter) or a client forwards it (0x07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alloc {
    /// The server's key for relay messages: constant while the server runs, new after a restart.
    pub server: DiscoPublic,
    /// The pair, smaller key first.
    pub pair: [DiscoPublic; 2],
    pub generation: u64,
    pub vni: u32,
    /// Two durations carried in nanoseconds (30 s and 300 s observed); meaning not yet established.
    pub durations: [Duration; 2],
    pub addrs: Vec<SocketAddr>,
}

/// The pair in the order servers and official clients use: smaller key first.
pub fn sorted_pair(a: DiscoPublic, b: DiscoPublic) -> [DiscoPublic; 2] {
    if a.0 <= b.0 { [a, b] } else { [b, a] }
}

fn key_at(b: &[u8], at: usize) -> Result<DiscoPublic, Error> {
    let k: [u8; 32] = b
        .get(at..at + 32)
        .and_then(|k| k.try_into().ok())
        .ok_or(Error::Truncated)?;
    Ok(DiscoPublic(k))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    b.get(at..at + 4)
        .and_then(|x| x.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(Error::Truncated)
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    b.get(at..at + 8)
        .and_then(|x| x.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(Error::Truncated)
}

impl BindBody {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.vni.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.remote.0);
        out.extend_from_slice(&self.challenge);
    }

    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < BIND_LEN {
            return Err(Error::Truncated);
        }
        let mut challenge = [0u8; CHALLENGE_LEN];
        challenge.copy_from_slice(&b[40..40 + CHALLENGE_LEN]);
        Ok(Self {
            vni: u32_at(b, 0)?,
            generation: u32_at(b, 4)?,
            remote: key_at(b, 8)?,
            challenge,
        })
    }
}

impl Alloc {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.server.0);
        out.extend_from_slice(&self.pair[0].0);
        out.extend_from_slice(&self.pair[1].0);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.vni.to_be_bytes());
        for d in &self.durations {
            let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
            out.extend_from_slice(&ns.to_be_bytes());
        }
        for a in &self.addrs {
            out.extend_from_slice(&addr_bytes(a));
        }
    }

    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < ALLOC_FIXED_LEN || (b.len() - ALLOC_FIXED_LEN) % ADDR_LEN != 0 {
            return Err(Error::Truncated);
        }
        let addrs = b[ALLOC_FIXED_LEN..]
            .chunks(ADDR_LEN)
            .map(parse_addr)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            server: key_at(b, 0)?,
            pair: [key_at(b, 32)?, key_at(b, 64)?],
            generation: u64_at(b, 96)?,
            vni: u32_at(b, 104)?,
            durations: [
                Duration::from_nanos(u64_at(b, 108)?),
                Duration::from_nanos(u64_at(b, 116)?),
            ],
            addrs,
        })
    }
}

/// Encode an allocation request body: the pair and the counter.
pub fn encode_request(pair: &[DiscoPublic; 2], counter: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&pair[0].0);
    out.extend_from_slice(&pair[1].0);
    out.extend_from_slice(&counter.to_be_bytes());
}

/// Parse an allocation request body.
pub fn parse_request(b: &[u8]) -> Result<([DiscoPublic; 2], u32), Error> {
    if b.len() < REQUEST_LEN {
        return Err(Error::Truncated);
    }
    Ok(([key_at(b, 0)?, key_at(b, 32)?], u32_at(b, 64)?))
}

/// Geneve protocol type of a disco message on a relayed path.
pub const PROTO_DISCO: u16 = 0x7a11;
/// Geneve protocol type of a WireGuard message on a relayed path.
pub const PROTO_WIREGUARD: u16 = 0x7a12;
pub const GENEVE_LEN: usize = 8;

/// The Geneve header (RFC 8926) as relayed packets use it: no options; the O bit marks messages to
/// the relay server itself (OBS-20261010-peer-relay-datapath).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geneve {
    pub control: bool,
    pub protocol: u16,
    /// 24 bits.
    pub vni: u32,
}

pub fn geneve_encode(h: &Geneve) -> [u8; GENEVE_LEN] {
    let p = h.protocol.to_be_bytes();
    let v = h.vni.to_be_bytes();
    [
        0,
        if h.control { 0x80 } else { 0 },
        p[0],
        p[1],
        v[1],
        v[2],
        v[3],
        0,
    ]
}

/// Split a relayed packet into its header and payload. `None` if it is shorter than the header, has
/// a version other than 0 or carries options.
pub fn geneve_decode(b: &[u8]) -> Option<(Geneve, &[u8])> {
    let (head, rest) = (b.get(..GENEVE_LEN)?, b.get(GENEVE_LEN..)?);
    // Byte 0: version (2 bits) and option length (6 bits), both zero on relayed packets.
    if head[0] != 0 {
        return None;
    }
    let h = Geneve {
        control: head[1] & 0x80 != 0,
        protocol: u16::from_be_bytes([head[2], head[3]]),
        vni: u32::from_be_bytes([0, head[4], head[5], head[6]]),
    };
    Some((h, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Payloads (hex after `payload=`) of the lines of a fixture's tsv, optionally filtered by prefix.
    fn fixture(path: &str, prefix: &str) -> Vec<Vec<u8>> {
        let p = format!(
            "{}/../../fixtures/observed/{path}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("{p}: {e}"))
            .lines()
            .filter_map(|l| l.split("payload=").nth(1))
            .filter(|h| h.starts_with(prefix))
            .map(hex)
            .collect()
    }

    fn reencode_alloc(a: &Alloc) -> Vec<u8> {
        let mut v = Vec::new();
        a.encode(&mut v);
        v
    }

    #[test]
    fn allocation_response_round_trips() {
        let replies = fixture("20261010-peer-relay-alloc-response/run-A.tsv", "09");
        assert_eq!(replies.len(), 1);
        let body = &replies[0][2..];
        let counter = u32::from_be_bytes(body[..4].try_into().unwrap());
        let a = Alloc::parse(&body[4..]).unwrap();
        assert_eq!(counter, 1);
        assert_eq!((a.generation, a.vni), (1, 1));
        assert_eq!(
            a.durations,
            [Duration::from_secs(30), Duration::from_secs(300)]
        );
        assert_eq!(a.addrs, vec!["172.29.0.23:40000".parse().unwrap()]);
        assert!(a.pair[0].0 < a.pair[1].0, "the server sorts the pair");
        assert_eq!(reencode_alloc(&a), body[4..]);
    }

    #[test]
    fn forwarded_allocation_round_trips() {
        let fwd = fixture("20261010-peer-relay-forward/disco.tsv", "07");
        assert_eq!(fwd.len(), 2);
        let a = Alloc::parse(&fwd[0][2..]).unwrap();
        assert_eq!((a.generation, a.vni), (5, 5));
        assert_eq!(reencode_alloc(&a), fwd[0][2..]);
    }

    #[test]
    fn allocation_request_round_trips() {
        let reqs = fixture("20261010-peer-relay-alloc-request/disco.tsv", "08");
        assert!(!reqs.is_empty());
        for r in &reqs {
            let (pair, counter) = parse_request(&r[2..]).unwrap();
            assert!(counter > 0);
            assert_eq!(pair, sorted_pair(pair[1], pair[0]));
            let mut v = Vec::new();
            encode_request(&pair, counter, &mut v);
            assert_eq!(v, r[2..]);
        }
    }

    #[test]
    fn challenge_round_trips() {
        let ch = fixture("20261010-peer-relay-handshake/run-h3.tsv", "05");
        assert_eq!(ch.len(), 1);
        let b = BindBody::parse(&ch[0][2..]).unwrap();
        assert_eq!(b.vni, 3);
        assert_eq!(b.generation, 1);
        assert_ne!(b.challenge, [0; CHALLENGE_LEN]);
        let mut v = Vec::new();
        b.encode(&mut v);
        assert_eq!(v, ch[0][2..]);
    }

    /// Every captured relay message decodes to its variant and encodes back to the same bytes.
    #[test]
    fn captured_messages_round_trip_through_message() {
        use crate::message::{Message, decode, encode};
        let cases = [
            ("20261010-peer-relay-alloc-request/disco.tsv", "08"),
            ("20261010-peer-relay-alloc-response/run-A.tsv", "09"),
            ("20261010-peer-relay-forward/disco.tsv", "07"),
            ("20261010-peer-relay-handshake/run-h3.tsv", "05"),
        ];
        for (path, prefix) in cases {
            for raw in fixture(path, prefix) {
                let m = decode(&raw).unwrap();
                let ok = matches!(
                    (&m, raw[0]),
                    (Message::AllocateRequest { .. }, TYPE_ALLOCATE_REQUEST)
                        | (Message::AllocateResponse { .. }, TYPE_ALLOCATE_RESPONSE)
                        | (Message::CallMeMaybeVia(_), TYPE_CALL_ME_MAYBE_VIA)
                        | (Message::Challenge(_), TYPE_CHALLENGE)
                );
                assert!(ok, "{path}: decoded as {m:?}");
                assert_eq!(encode(&m), raw, "{path}");
            }
        }
        let body = BindBody {
            vni: 4,
            generation: 1,
            remote: DiscoPublic([7; 32]),
            challenge: [0; 32],
        };
        for m in [Message::Bind(body.clone()), Message::Answer(body)] {
            assert_eq!(decode(&encode(&m)).unwrap(), m);
        }
        assert!(
            decode(&[TYPE_ALLOCATE_RESPONSE, 0, 0, 0]).is_err(),
            "counter truncated"
        );
    }

    #[test]
    fn rejects_short_or_misaligned_bodies() {
        assert!(BindBody::parse(&[0; BIND_LEN - 1]).is_err());
        assert!(Alloc::parse(&[0; ALLOC_FIXED_LEN - 1]).is_err());
        assert!(
            Alloc::parse(&[0; ALLOC_FIXED_LEN + ADDR_LEN - 1]).is_err(),
            "partial address"
        );
        assert!(parse_request(&[0; REQUEST_LEN - 1]).is_err());
    }

    /// Boundaries: an allocation without addresses still parses (the caller finds no endpoint); a
    /// request with bytes after the counter is accepted, as other disco bodies tolerate trailing bytes.
    #[test]
    fn boundary_lengths() {
        let a = Alloc::parse(&[0; ALLOC_FIXED_LEN]).unwrap();
        assert!(a.addrs.is_empty());
        let mut long = vec![0u8; REQUEST_LEN + 4];
        long[REQUEST_LEN - 1] = 7;
        assert_eq!(parse_request(&long).unwrap().1, 7);
    }

    #[test]
    fn allocation_with_two_addresses() {
        let a = Alloc {
            server: DiscoPublic([1; 32]),
            pair: [DiscoPublic([2; 32]), DiscoPublic([3; 32])],
            generation: 0x0102_0304_0506_0708,
            vni: 9,
            durations: [Duration::from_secs(30), Duration::from_secs(300)],
            addrs: vec![
                "192.0.2.1:40000".parse().unwrap(),
                "[2001:db8::1]:40001".parse().unwrap(),
            ],
        };
        assert_eq!(Alloc::parse(&reencode_alloc(&a)), Ok(a));
    }

    #[test]
    fn sorted_pair_puts_the_smaller_key_first() {
        let (lo, hi) = (DiscoPublic([1; 32]), DiscoPublic([2; 32]));
        assert_eq!(sorted_pair(hi, lo), [lo, hi]);
        assert_eq!(sorted_pair(lo, hi), [lo, hi]);
    }

    #[test]
    fn geneve_header_of_a_relayed_ping() {
        // Header of the relayed disco ping a probe received (OBS-20261010-peer-relay-handshake, run h4).
        let mut pkt = hex("00007a1100000400");
        pkt.extend_from_slice(b"rest");
        let (h, rest) = geneve_decode(&pkt).unwrap();
        assert_eq!(
            h,
            Geneve {
                control: false,
                protocol: PROTO_DISCO,
                vni: 4
            }
        );
        assert_eq!(rest, b"rest");
        assert_eq!(geneve_encode(&h), pkt[..GENEVE_LEN]);
        // The handshake header has the O bit.
        let (c, _) = geneve_decode(&hex("00807a1100000300")).unwrap();
        assert!(c.control);
        assert_eq!(c.vni, 3);
        let w = Geneve {
            control: false,
            protocol: PROTO_WIREGUARD,
            vni: 0x01_02_03,
        };
        assert_eq!(geneve_encode(&w), [0, 0, 0x7a, 0x12, 1, 2, 3, 0]);
    }

    #[test]
    fn geneve_rejects_short_versioned_or_optioned_headers() {
        assert!(geneve_decode(&[0; GENEVE_LEN - 1]).is_none());
        assert!(
            geneve_decode(&hex("40007a1100000400")).is_none(),
            "version 1"
        );
        assert!(
            geneve_decode(&hex("01007a1100000400")).is_none(),
            "options present"
        );
    }
}
