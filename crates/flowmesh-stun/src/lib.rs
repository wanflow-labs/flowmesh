// SPDX-License-Identifier: Apache-2.0
//! STUN Binding (RFC 5389, PUB-3): learn this node's address as seen from outside. sans-IO.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
pub const TX_ID_LEN: usize = 12;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
/// SOFTWARE value carried by the official client; the derper ignores requests without it (OBS-20261010-stun).
pub const SOFTWARE: &[u8; 8] = b"tailnode";
/// RFC 5389 §15.5: FINGERPRINT = CRC-32 XOR this value.
const FINGERPRINT_XOR: u32 = 0x5354_554e;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("not a STUN message")]
    NotStun,
    #[error("not a binding success response")]
    NotSuccess,
    #[error("truncated STUN message")]
    Truncated,
    #[error("response has no mapped address")]
    NoAddress,
}

/// Header-only check: the top two bits are 0, the magic cookie is at bytes 4–8, and the length is a multiple of 4 (RFC 5389 §6).
pub fn is_stun(b: &[u8]) -> bool {
    b.len() >= 20
        && b[0] & 0xc0 == 0
        && b[4..8] == MAGIC_COOKIE
        && u16::from_be_bytes([b[2], b[3]]) % 4 == 0
}

/// Binding request: SOFTWARE `tailnode` + FINGERPRINT, byte-for-byte identical to the official client (OBS-20261010-stun).
pub fn binding_request(tx_id: [u8; TX_ID_LEN]) -> Vec<u8> {
    // Attribute length: SOFTWARE (4+8) + FINGERPRINT (4+4) = 20.
    let mut v = Vec::with_capacity(40);
    v.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    v.extend_from_slice(&20u16.to_be_bytes());
    v.extend_from_slice(&MAGIC_COOKIE);
    v.extend_from_slice(&tx_id);
    v.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    v.extend_from_slice(&8u16.to_be_bytes());
    v.extend_from_slice(SOFTWARE);
    let fp = crc32(&v) ^ FINGERPRINT_XOR;
    v.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    v.extend_from_slice(&4u16.to_be_bytes());
    v.extend_from_slice(&fp.to_be_bytes());
    v
}

/// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320), as used for the STUN FINGERPRINT.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Parse a Binding success response, returning (transaction ID, mapped address). XOR-MAPPED-ADDRESS takes priority.
pub fn parse_response(b: &[u8]) -> Result<([u8; TX_ID_LEN], SocketAddr), Error> {
    if !is_stun(b) {
        return Err(Error::NotStun);
    }
    if u16::from_be_bytes([b[0], b[1]]) != BINDING_SUCCESS {
        return Err(Error::NotSuccess);
    }
    let len = usize::from(u16::from_be_bytes([b[2], b[3]]));
    let body = b.get(20..20 + len).ok_or(Error::Truncated)?;
    let mut tx_id = [0u8; TX_ID_LEN];
    tx_id.copy_from_slice(&b[8..20]);

    let mut xor_mapped = None;
    let mut mapped = None;
    let mut rest = body;
    while rest.len() >= 4 {
        let ty = u16::from_be_bytes([rest[0], rest[1]]);
        let alen = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        let value = rest.get(4..4 + alen).ok_or(Error::Truncated)?;
        match ty {
            ATTR_XOR_MAPPED_ADDRESS => xor_mapped = parse_address(value, Some(&tx_id)),
            ATTR_MAPPED_ADDRESS => mapped = parse_address(value, None),
            _ => {}
        }
        // Attributes are padded to a 4-byte boundary.
        let padded = (4 + alen + 3) & !3;
        rest = rest.get(padded..).unwrap_or_default();
    }
    xor_mapped
        .or(mapped)
        .map(|a| (tx_id, a))
        .ok_or(Error::NoAddress)
}

/// Parse a (XOR-)MAPPED-ADDRESS value; when `xor_tx` is present, XOR-decode it per RFC 5389 §15.2.
fn parse_address(v: &[u8], xor_tx: Option<&[u8; TX_ID_LEN]>) -> Option<SocketAddr> {
    let family = *v.get(1)?;
    let mut port = u16::from_be_bytes([*v.get(2)?, *v.get(3)?]);
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&MAGIC_COOKIE);
    if let Some(tx) = xor_tx {
        key[4..].copy_from_slice(tx);
        port ^= u16::from_be_bytes([MAGIC_COOKIE[0], MAGIC_COOKIE[1]]);
    }
    let xor = xor_tx.is_some();
    let ip = match family {
        0x01 => {
            let mut o: [u8; 4] = v.get(4..8)?.try_into().ok()?;
            if xor {
                o.iter_mut().zip(&key).for_each(|(b, k)| *b ^= k);
            }
            IpAddr::V4(Ipv4Addr::from(o))
        }
        0x02 => {
            let mut o: [u8; 16] = v.get(4..20)?.try_into().ok()?;
            if xor {
                o.iter_mut().zip(&key).for_each(|(b, k)| *b ^= k);
            }
            // The derper returns IPv4 as IPv4-mapped IPv6 (::ffff:a.b.c.d, OBS-20261010-stun); normalize it to IPv4.
            let v6 = Ipv6Addr::from(o);
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5769 §2.2 sample IPv4 response (192.0.2.1:32853). The 20-byte MESSAGE-INTEGRITY body is replaced with zeros: we don't verify integrity.
    fn rfc5769_ipv4_response() -> Vec<u8> {
        let mut v = vec![
            0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01,
            0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14,
        ];
        v.extend_from_slice(&[0u8; 20]);
        v.extend_from_slice(&[0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96]);
        v
    }

    const RFC_TX: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    #[test]
    fn rfc5769_ipv4_xor_mapped_address() {
        let r = rfc5769_ipv4_response();
        assert!(is_stun(&r));
        assert_eq!(
            parse_response(&r).unwrap(),
            (RFC_TX, "192.0.2.1:32853".parse().unwrap())
        );
    }

    /// The IPv6 XOR key is magic cookie + transaction ID (RFC 5389 §15.2). The expected bytes are computed independently here, not via the implementation.
    #[test]
    fn ipv6_xor_mapped_address() {
        let addr: Ipv6Addr = "2001:db8:1234:5678:11:2233:4455:6677".parse().unwrap();
        let mut key = MAGIC_COOKIE.to_vec();
        key.extend_from_slice(&RFC_TX);
        let xaddr: Vec<u8> = addr.octets().iter().zip(&key).map(|(a, k)| a ^ k).collect();
        let mut attr = vec![0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47];
        attr.extend_from_slice(&xaddr);
        let mut msg = vec![0x01, 0x01, 0x00, attr.len() as u8];
        msg.extend_from_slice(&MAGIC_COOKIE);
        msg.extend_from_slice(&RFC_TX);
        msg.extend_from_slice(&attr);
        assert_eq!(
            parse_response(&msg).unwrap().1,
            SocketAddr::new(IpAddr::V6(addr), 32853)
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_is_normalized_to_ipv4() {
        let v6: Ipv6Addr = "::ffff:172.29.0.31".parse().unwrap();
        let mut key = MAGIC_COOKIE.to_vec();
        key.extend_from_slice(&RFC_TX);
        let x: Vec<u8> = v6.octets().iter().zip(&key).map(|(a, k)| a ^ k).collect();
        let mut attr = vec![0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47];
        attr.extend_from_slice(&x);
        let mut msg = vec![0x01, 0x01, 0x00, attr.len() as u8];
        msg.extend_from_slice(&MAGIC_COOKIE);
        msg.extend_from_slice(&RFC_TX);
        msg.extend_from_slice(&attr);
        assert_eq!(
            parse_response(&msg).unwrap().1,
            "172.29.0.31:32853".parse().unwrap()
        );
    }

    #[test]
    fn plain_mapped_address_is_a_fallback() {
        let mut msg = vec![0x01, 0x01, 0x00, 0x0c];
        msg.extend_from_slice(&MAGIC_COOKIE);
        msg.extend_from_slice(&RFC_TX);
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x1f, 0x90, 10, 0, 0, 7]);
        assert_eq!(
            parse_response(&msg).unwrap().1,
            "10.0.0.7:8080".parse().unwrap()
        );
    }

    /// Byte-for-byte identical to the request the official client sent (OBS-20261010-stun/ts1-netcheck-stun.pcap).
    #[test]
    fn request_matches_observed_official_request() {
        let observed: [u8; 40] = [
            0x00, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42, 0x0d, 0xef, 0xf1, 0x1a, 0x68, 0xf6,
            0xb2, 0x57, 0xb6, 0x0a, 0x76, 0x7c, 0x80, 0x22, 0x00, 0x08, 0x74, 0x61, 0x69, 0x6c,
            0x6e, 0x6f, 0x64, 0x65, 0x80, 0x28, 0x00, 0x04, 0x87, 0xbf, 0x84, 0x62,
        ];
        let tx: [u8; 12] = observed[8..20].try_into().unwrap();
        let r = binding_request(tx);
        assert_eq!(r, observed);
        assert!(is_stun(&r));
    }

    /// The standard CRC-32 check value: CRC32("123456789") = 0xCBF43926.
    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn rejections() {
        assert_eq!(
            parse_response(b"\x04\x00\x00\x00wireguard-message!!"),
            Err(Error::NotStun)
        );
        assert!(!is_stun(&[0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac]));
        assert_eq!(
            parse_response(&binding_request(RFC_TX)),
            Err(Error::NotSuccess)
        );
        let mut truncated = rfc5769_ipv4_response();
        truncated.truncate(44);
        assert_eq!(parse_response(&truncated), Err(Error::Truncated));
        let mut empty = vec![0x01, 0x01, 0x00, 0x00];
        empty.extend_from_slice(&MAGIC_COOKIE);
        empty.extend_from_slice(&RFC_TX);
        assert_eq!(parse_response(&empty), Err(Error::NoAddress));
    }
}
