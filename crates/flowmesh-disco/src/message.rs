// SPDX-License-Identifier: Apache-2.0
//! disco payloads (disco.md §2). Format: 1-byte type + 1-byte version + type-specific body.

use crate::Error;
use flowmesh_proto::key::NodePublic;
use std::net::SocketAddr;

pub const TYPE_PING: u8 = 0x01;
pub const TYPE_PONG: u8 = 0x02;
pub const TYPE_CALL_ME_MAYBE: u8 = 0x03;
pub const TX_ID_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Observed: type 0x01, version 0, 12-byte transaction ID + 32-byte sender node key (OBS-20261010-disco).
    Ping {
        tx_id: [u8; TX_ID_LEN],
        node_key: NodePublic,
    },
    /// Observed: type 0x02, version 0, 12-byte transaction ID + the source address the replier saw
    /// (16-byte IPv6 form; IPv4 is mapped as ::ffff:a.b.c.d) + 2-byte big-endian port. A pong over DERP carries 127.3.3.40:<region>.
    Pong {
        tx_id: [u8; TX_ID_LEN],
        src: SocketAddr,
    },
    /// Observed: type 0x03, version 0, followed by zero or more 18-byte addresses (same encoding as Pong):
    /// the sender's endpoints, asking the receiver to ping them (OBS-20261010-disco/decrypted-callmemaybe.tsv).
    CallMeMaybe { endpoints: Vec<SocketAddr> },
    /// A type this module doesn't recognize yet (e.g. 0x08 peer-relay endpoint allocation, belongs to v2); preserved as-is.
    Unknown { ty: u8, version: u8, body: Vec<u8> },
}

pub fn encode(m: &Message) -> Vec<u8> {
    match m {
        Message::Ping { tx_id, node_key } => {
            let mut v = vec![TYPE_PING, 0];
            v.extend_from_slice(tx_id);
            v.extend_from_slice(&node_key.0);
            v
        }
        Message::Pong { tx_id, src } => {
            let mut v = vec![TYPE_PONG, 0];
            v.extend_from_slice(tx_id);
            v.extend_from_slice(&addr_bytes(src));
            v
        }
        Message::CallMeMaybe { endpoints } => {
            let mut v = vec![TYPE_CALL_ME_MAYBE, 0];
            for e in endpoints {
                v.extend_from_slice(&addr_bytes(e));
            }
            v
        }
        Message::Unknown { ty, version, body } => {
            let mut v = vec![*ty, *version];
            v.extend_from_slice(body);
            v
        }
    }
}

pub fn decode(b: &[u8]) -> Result<Message, Error> {
    let (&ty, rest) = b.split_first().ok_or(Error::Truncated)?;
    let (&version, body) = rest.split_first().ok_or(Error::Truncated)?;
    match ty {
        TYPE_PING => {
            let tx_id: [u8; TX_ID_LEN] = body
                .get(..TX_ID_LEN)
                .and_then(|t| t.try_into().ok())
                .ok_or(Error::Truncated)?;
            let key: [u8; 32] = body
                .get(TX_ID_LEN..TX_ID_LEN + 32)
                .and_then(|k| k.try_into().ok())
                .ok_or(Error::Truncated)?;
            Ok(Message::Ping {
                tx_id,
                node_key: NodePublic(key),
            })
        }
        TYPE_PONG => {
            let tx_id: [u8; TX_ID_LEN] = body
                .get(..TX_ID_LEN)
                .and_then(|t| t.try_into().ok())
                .ok_or(Error::Truncated)?;
            let src = parse_addr(
                body.get(TX_ID_LEN..TX_ID_LEN + ADDR_LEN)
                    .ok_or(Error::Truncated)?,
            )?;
            Ok(Message::Pong { tx_id, src })
        }
        TYPE_CALL_ME_MAYBE => {
            if body.len() % ADDR_LEN != 0 {
                return Err(Error::Truncated);
            }
            let endpoints = body
                .chunks(ADDR_LEN)
                .map(parse_addr)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Message::CallMeMaybe { endpoints })
        }
        _ => Ok(Message::Unknown {
            ty,
            version,
            body: body.to_vec(),
        }),
    }
}

/// Address encoding: 16-byte IPv6 form + 2-byte big-endian port.
pub const ADDR_LEN: usize = 18;

pub fn addr_bytes(a: &SocketAddr) -> [u8; ADDR_LEN] {
    let ip6 = match a.ip() {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        std::net::IpAddr::V6(v6) => v6,
    };
    let mut out = [0u8; ADDR_LEN];
    out[..16].copy_from_slice(&ip6.octets());
    out[16..].copy_from_slice(&a.port().to_be_bytes());
    out
}

pub fn parse_addr(b: &[u8]) -> Result<SocketAddr, Error> {
    let ip: [u8; 16] = b
        .get(..16)
        .and_then(|x| x.try_into().ok())
        .ok_or(Error::Truncated)?;
    let port = u16::from_be_bytes([
        *b.get(16).ok_or(Error::Truncated)?,
        *b.get(17).ok_or(Error::Truncated)?,
    ]);
    let ip6 = std::net::Ipv6Addr::from(ip);
    let ip = match ip6.to_ipv4_mapped() {
        Some(v4) => std::net::IpAddr::V4(v4),
        None => std::net::IpAddr::V6(ip6),
    };
    Ok(SocketAddr::new(ip, port))
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

    /// Real ping sent by ts1 (OBS-20261010-disco/decrypted-from-ts1.tsv, row 1).
    #[test]
    fn decodes_observed_ping() {
        let raw = hex(
            "0100b10660786c44d6684b8f7df2eb0b5cd0c6d2755d28357e02f6c0c261c0b024633c9919ff83261f505eda840b",
        );
        let m = decode(&raw).unwrap();
        let Message::Ping { tx_id, node_key } = &m else {
            panic!("{m:?}")
        };
        assert_eq!(tx_id, &hex("b10660786c44d6684b8f7df2")[..]);
        assert_eq!(node_key.0[..4], [0xeb, 0x0b, 0x5c, 0xd0]);
        assert_eq!(encode(&m), raw, "re-encoding must be byte-identical");
    }

    /// Real pong from ts1 (OBS-20261010-disco/decrypted-pongs.tsv): the source address over DERP is 127.3.3.40:1000.
    #[test]
    fn decodes_observed_pong_over_derp() {
        let raw = hex("0200307c4d992d161ff791ab905400000000000000000000ffff7f03032803e8");
        let m = decode(&raw).unwrap();
        assert_eq!(
            m,
            Message::Pong {
                tx_id: hex("307c4d992d161ff791ab9054").try_into().unwrap(),
                src: "127.3.3.40:1000".parse().unwrap()
            }
        );
        assert_eq!(encode(&m), raw);
    }

    #[test]
    fn pong_with_ipv6_source_roundtrips() {
        let m = Message::Pong {
            tx_id: [7; TX_ID_LEN],
            src: "[fd7a:115c:a1e0::1]:41641".parse().unwrap(),
        };
        assert_eq!(decode(&encode(&m)).unwrap(), m);
    }

    /// Real CallMeMaybe from wanflow-mesh (wm1) (OBS-20261010-disco/decrypted-callmemaybe.tsv): one endpoint 172.29.0.41:41641.
    #[test]
    fn decodes_observed_call_me_maybe() {
        let raw = hex("030000000000000000000000ffffac1d0029a2a9");
        let m = decode(&raw).unwrap();
        assert_eq!(
            m,
            Message::CallMeMaybe {
                endpoints: vec!["172.29.0.41:41641".parse().unwrap()]
            }
        );
        assert_eq!(encode(&m), raw);
        assert_eq!(
            decode(&hex("0300")).unwrap(),
            Message::CallMeMaybe { endpoints: vec![] }
        );
        assert_eq!(decode(&hex("0300aabb")), Err(Error::Truncated));
    }

    #[test]
    fn unknown_type_roundtrips_unchanged() {
        let raw = hex("0800aabbcc");
        let m = decode(&raw).unwrap();
        assert_eq!(
            m,
            Message::Unknown {
                ty: 8,
                version: 0,
                body: hex("aabbcc")
            }
        );
        assert_eq!(encode(&m), raw);
    }

    #[test]
    fn truncated_ping_is_rejected() {
        assert_eq!(decode(&hex("0100b106")), Err(Error::Truncated));
        assert_eq!(decode(&[]), Err(Error::Truncated));
        assert_eq!(decode(&hex("0200aabb")), Err(Error::Truncated));
    }
}
