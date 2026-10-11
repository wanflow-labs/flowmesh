// SPDX-License-Identifier: Apache-2.0
//! Extract the fields needed for filtering from an IP packet. Only reads headers; does not verify checksums.

use flowmesh_filter::packet::{IpProto, Packet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn parse(pkt: &[u8]) -> Option<Packet> {
    match pkt.first()? >> 4 {
        4 => {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            if ihl < 20 || pkt.len() < ihl {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]));
            l4(IpProto::from_number(pkt[9]), src, dst, &pkt[ihl..])
        }
        6 => {
            let hdr = pkt.get(..40)?;
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&hdr[8..24]);
            d.copy_from_slice(&hdr[24..40]);
            l4(
                IpProto::from_number(hdr[6]),
                IpAddr::V6(Ipv6Addr::from(s)),
                IpAddr::V6(Ipv6Addr::from(d)),
                &pkt[40..],
            )
        }
        _ => None,
    }
}

fn l4(proto: IpProto, src: IpAddr, dst: IpAddr, body: &[u8]) -> Option<Packet> {
    let mut p = Packet {
        proto,
        src,
        dst,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        icmp_type: 0,
    };
    match proto {
        IpProto::Tcp => {
            let h = body.get(..20)?;
            p.src_port = u16::from_be_bytes([h[0], h[1]]);
            p.dst_port = u16::from_be_bytes([h[2], h[3]]);
            p.tcp_flags = h[13];
        }
        IpProto::Udp => {
            let h = body.get(..8)?;
            p.src_port = u16::from_be_bytes([h[0], h[1]]);
            p.dst_port = u16::from_be_bytes([h[2], h[3]]);
        }
        IpProto::Icmp4 | IpProto::Icmp6 => p.icmp_type = *body.first()?,
        IpProto::Other(_) => {}
    }
    Some(p)
}

/// Where the TCP header starts, when `pkt` is a TCP packet (or the first fragment of one) whose
/// ports and checksum are inside it.
fn tcp_header(pkt: &[u8]) -> Option<usize> {
    let off = match pkt.first()? >> 4 {
        4 => {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            let frag_offset = u16::from_be_bytes([*pkt.get(6)?, *pkt.get(7)?]) & 0x1fff;
            if ihl < 20 || pkt[9] != 6 || frag_offset != 0 {
                return None;
            }
            ihl
        }
        6 if *pkt.get(6)? == 6 => 40,
        _ => return None,
    };
    (pkt.len() >= off + 18).then_some(off)
}

/// One's complement sum fold (RFC 1071).
fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Set a TCP port (`dst`: destination, else source) and update the checksum incrementally
/// (RFC 1624: HC' = ~(~HC + ~m + m')). Returns false when `pkt` is not such a TCP packet.
pub fn set_tcp_port(pkt: &mut [u8], dst: bool, port: u16) -> bool {
    let Some(off) = tcp_header(pkt) else {
        return false;
    };
    let at = off + if dst { 2 } else { 0 };
    let old = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
    let hc = u16::from_be_bytes([pkt[off + 16], pkt[off + 17]]);
    let sum = u32::from(!hc) + u32::from(!old) + u32::from(port);
    let new = !fold(sum);
    pkt[at..at + 2].copy_from_slice(&port.to_be_bytes());
    pkt[off + 16..off + 18].copy_from_slice(&new.to_be_bytes());
    true
}

/// UDP payload: (source address, destination address, payload), IPv4 only (used for quad-100 DNS interception).
pub fn udp4_payload(pkt: &[u8]) -> Option<(std::net::SocketAddrV4, std::net::SocketAddrV4, &[u8])> {
    if pkt.first()? >> 4 != 4 || *pkt.get(9)? != 17 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    // A header shorter than its fixed 20 bytes is malformed (and the addresses would not be there).
    if ihl < 20 {
        return None;
    }
    let udp = pkt.get(ihl..ihl + 8)?;
    let ulen = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    let payload = pkt.get(ihl + 8..ihl + ulen.checked_sub(8)? + 8)?;
    let src = std::net::SocketAddrV4::new(
        Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        u16::from_be_bytes([udp[0], udp[1]]),
    );
    let dst = std::net::SocketAddrV4::new(
        Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
        u16::from_be_bytes([udp[2], udp[3]]),
    );
    Some((src, dst, payload))
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for part in parts {
        for &b in *part {
            match odd.take() {
                Some(hi) => sum += (u32::from(hi) << 8) | u32::from(b),
                None => odd = Some(b),
            }
        }
    }
    if let Some(hi) = odd {
        sum += u32::from(hi) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4/UDP packet (TTL 64, correct IP header and UDP checksums).
pub fn build_udp4(
    src: std::net::SocketAddrV4,
    dst: std::net::SocketAddrV4,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let total = udp_len.saturating_add(20);
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&src.ip().octets());
    ip.extend_from_slice(&dst.ip().octets());
    let ip_sum = checksum(&[&ip]);
    ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let mut udp = Vec::with_capacity(usize::from(udp_len));
    udp.extend_from_slice(&src.port().to_be_bytes());
    udp.extend_from_slice(&dst.port().to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let pseudo = [&ip[12..20], &[0, 17], &udp_len.to_be_bytes()[..]].concat();
    let mut udp_sum = checksum(&[&pseudo, &udp]);
    if udp_sum == 0 {
        // RFC 768: a computed checksum of 0 is transmitted as all ones.
        udp_sum = 0xffff;
    }
    udp[6..8].copy_from_slice(&udp_sum.to_be_bytes());
    ip.extend_from_slice(&udp);
    ip
}

#[cfg(test)]
pub(crate) mod build {
    //! Test packet builders (headers only, checksums are zero).

    pub fn v4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
        let total = 20 + l4.len();
        let mut p = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0,
            0,
            64,
            proto,
            0,
            0,
        ];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(l4);
        p
    }

    pub fn v6(src: [u8; 16], dst: [u8; 16], next: u8, l4: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x60,
            0,
            0,
            0,
            (l4.len() >> 8) as u8,
            l4.len() as u8,
            next,
            64,
        ];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(l4);
        p
    }

    pub fn tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[12] = 0x50;
        t[13] = flags;
        t
    }

    pub fn udp(sport: u16, dport: u16) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&sport.to_be_bytes());
        u[2..4].copy_from_slice(&dport.to_be_bytes());
        u[4..6].copy_from_slice(&8u16.to_be_bytes());
        u
    }

    pub fn icmp(ty: u8) -> Vec<u8> {
        vec![ty, 0, 0, 0, 0x12, 0x34, 0, 1]
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    /// TCP checksum from scratch (pseudo-header + segment), to check the incremental update.
    fn tcp_checksum(pkt: &[u8]) -> u16 {
        let (off, mut sum) = match pkt[0] >> 4 {
            4 => {
                let ihl = usize::from(pkt[0] & 0x0f) * 4;
                let mut s = 0u32;
                for c in pkt[12..20].chunks(2) {
                    s += u32::from(u16::from_be_bytes([c[0], c[1]]));
                }
                (ihl, s + 6 + (pkt.len() - ihl) as u32)
            }
            _ => {
                let mut s = 0u32;
                for c in pkt[8..40].chunks(2) {
                    s += u32::from(u16::from_be_bytes([c[0], c[1]]));
                }
                (40, s + 6 + (pkt.len() - 40) as u32)
            }
        };
        for (i, c) in pkt[off..].chunks(2).enumerate() {
            if i == 8 {
                continue; // the checksum field itself
            }
            sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
        !fold(sum)
    }

    fn with_checksum(mut pkt: Vec<u8>) -> Vec<u8> {
        let off = tcp_header(&pkt).unwrap();
        let c = tcp_checksum(&pkt);
        pkt[off + 16..off + 18].copy_from_slice(&c.to_be_bytes());
        pkt
    }

    #[test]
    fn tcp_port_rewrite_keeps_the_checksum_valid() {
        let mut seg = tcp(51000, 22, 0x02);
        seg.extend_from_slice(b"payload!x");
        for mut p in [
            with_checksum(v4([100, 64, 0, 2], [100, 64, 0, 1], 6, &seg)),
            with_checksum(v6([0xfd; 16], [0xfe; 16], 6, &seg)),
        ] {
            assert!(set_tcp_port(&mut p, true, 41234));
            assert_eq!(parse(&p).unwrap().dst_port, 41234);
            let off = tcp_header(&p).unwrap();
            assert_eq!(
                u16::from_be_bytes([p[off + 16], p[off + 17]]),
                tcp_checksum(&p)
            );
            assert!(set_tcp_port(&mut p, false, 22));
            assert_eq!(parse(&p).unwrap().src_port, 22);
            assert_eq!(
                u16::from_be_bytes([p[off + 16], p[off + 17]]),
                tcp_checksum(&p)
            );
        }
        // Not TCP, a later fragment, or a truncated header: left alone.
        let mut u = v4([1; 4], [2; 4], 17, &udp(1, 22));
        assert!(!set_tcp_port(&mut u, true, 9));
        let mut frag = v4([1; 4], [2; 4], 6, &seg);
        frag[7] = 1;
        assert!(!set_tcp_port(&mut frag, true, 9));
        let mut short = v4([1; 4], [2; 4], 6, &seg[..10]);
        assert!(!set_tcp_port(&mut short, true, 9));
    }

    /// Found by fuzzing (fuzz/artifacts/ippkt): an IPv4 header length below 20 bytes made
    /// udp4_payload read the addresses past the end of a 12-byte packet.
    #[test]
    fn short_ipv4_header_length_is_rejected() {
        let crash = [0x40, 0, 0, 0, 0, 0x0c, 0x20, 0, 0, 0x11, 0x30, 0x16];
        assert_eq!(udp4_payload(&crash), None);
        assert_eq!(parse(&crash), None);
        // IHL 4 (16 bytes) on an otherwise long enough packet: still not a valid header.
        let mut p = vec![0x44u8; 64];
        p[9] = 17;
        assert_eq!(udp4_payload(&p), None);
    }

    #[test]
    fn ipv4_tcp_fields() {
        let p = parse(&v4(
            [100, 64, 0, 1],
            [100, 64, 0, 2],
            6,
            &tcp(40000, 80, 0x02),
        ))
        .unwrap();
        assert_eq!(p.proto, IpProto::Tcp);
        assert_eq!(p.src, IpAddr::from([100, 64, 0, 1]));
        assert_eq!(p.dst, IpAddr::from([100, 64, 0, 2]));
        assert_eq!((p.src_port, p.dst_port, p.tcp_flags), (40000, 80, 0x02));
    }

    #[test]
    fn ipv4_respects_header_length_options() {
        let mut pkt = v4([1, 1, 1, 1], [2, 2, 2, 2], 17, &[]);
        pkt[0] = 0x46; // IHL = 6, 4 bytes of options
        pkt.extend_from_slice(&[1, 1, 1, 1]);
        pkt.extend_from_slice(&udp(53, 5353));
        let p = parse(&pkt).unwrap();
        assert_eq!((p.proto, p.src_port, p.dst_port), (IpProto::Udp, 53, 5353));
    }

    #[test]
    fn ipv4_icmp_type_and_other_proto() {
        let p = parse(&v4([1, 1, 1, 1], [2, 2, 2, 2], 1, &icmp(8))).unwrap();
        assert_eq!((p.proto, p.icmp_type), (IpProto::Icmp4, 8));
        let g = parse(&v4([1, 1, 1, 1], [2, 2, 2, 2], 47, &[0; 4])).unwrap();
        assert_eq!(g.proto, IpProto::Other(47));
    }

    #[test]
    fn ipv6_udp_and_icmp6() {
        let a = [
            0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let b = [
            0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ];
        let p = parse(&v6(a, b, 17, &udp(1, 2))).unwrap();
        assert_eq!((p.proto, p.src_port, p.dst_port), (IpProto::Udp, 1, 2));
        assert_eq!(p.dst, IpAddr::from(b));
        let q = parse(&v6(a, b, 58, &icmp(128))).unwrap();
        assert_eq!((q.proto, q.icmp_type), (IpProto::Icmp6, 128));
    }

    #[test]
    fn header_only_packet_of_portless_protocol_parses() {
        let g = parse(&v4([1, 1, 1, 1], [2, 2, 2, 2], 47, &[])).unwrap();
        assert_eq!(g.proto, IpProto::Other(47));
    }

    /// Independent ones'-complement sum: a correct checksum sums to 0xffff over the full header/pseudo-header.
    fn ones_sum(chunks: &[&[u8]]) -> u16 {
        let mut sum: u32 = 0;
        let bytes: Vec<u8> = chunks.concat();
        for pair in bytes.chunks(2) {
            let hi = u32::from(pair[0]) << 8;
            let lo = u32::from(*pair.get(1).unwrap_or(&0));
            sum += hi | lo;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    #[test]
    fn build_udp4_has_valid_checksums_and_roundtrips() {
        let src: std::net::SocketAddrV4 = "100.100.100.100:53".parse().unwrap();
        let dst: std::net::SocketAddrV4 = "100.64.0.5:40000".parse().unwrap();
        let payload = b"dns-answer-bytes!";
        let pkt = build_udp4(src, dst, payload);
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        assert_eq!(pkt[0], 0x45);
        assert_eq!(usize::from(u16::from_be_bytes([pkt[2], pkt[3]])), pkt.len());
        assert_eq!(pkt[9], 17);
        assert_eq!(ones_sum(&[&pkt[..20]]), 0xffff, "IPv4 header checksum");
        let udp_len = (8 + payload.len()) as u16;
        let pseudo = [&pkt[12..20], &[0, 17], &udp_len.to_be_bytes()[..]].concat();
        assert_eq!(ones_sum(&[&pseudo, &pkt[20..]]), 0xffff, "UDP checksum");
        let (s, d, p) = udp4_payload(&pkt).unwrap();
        assert_eq!((s, d, p), (src, dst, &payload[..]));
        let meta = parse(&pkt).unwrap();
        assert_eq!((meta.src_port, meta.dst_port), (53, 40000));
    }

    #[test]
    fn udp4_payload_rejects_non_udp_and_short() {
        assert!(udp4_payload(&v4([1, 1, 1, 1], [2, 2, 2, 2], 6, &tcp(1, 2, 2))).is_none());
        assert!(udp4_payload(&[0x45, 0, 0]).is_none());
        let mut lying = v4([1, 1, 1, 1], [2, 2, 2, 2], 17, &udp(1, 53));
        lying[24..26].copy_from_slice(&200u16.to_be_bytes()); // UDP length longer than the packet
        assert!(udp4_payload(&lying).is_none());
    }

    /// Non-UDP packets are rejected even if their body happens to look like a valid UDP header; IPv6 packets are not handled by this function.
    #[test]
    fn udp4_payload_requires_ipv4_and_udp_protocol() {
        let body = udp(1, 53);
        assert!(udp4_payload(&v4([1, 1, 1, 1], [2, 2, 2, 2], 6, &body)).is_none());
        let mut v6pkt = v6([0; 16], [0; 16], 17, &body);
        v6pkt[9] = 17;
        assert!(udp4_payload(&v6pkt).is_none());
    }

    #[test]
    fn checksum_boundaries() {
        // When the sum is exactly 0xffff no further folding is needed; the result is 0.
        assert_eq!(checksum(&[&[0xff, 0xff]]), 0);
        // A trailing odd byte is padded on the right with zeros: 0x0100 + 0x0200 = 0x0300 → !0x0300.
        assert_eq!(checksum(&[&[0x01], &[0x00, 0x02]]), !0x0300u16);
        // Carry folding: 0xffff + 0x0001 = 0x10000 → 0x0001 → !0x0001.
        assert_eq!(checksum(&[&[0xff, 0xff, 0x00, 0x01]]), !0x0001u16);
    }

    #[test]
    fn truncated_or_garbage_is_none() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45, 0, 0]).is_none());
        let short_tcp = v4([1, 1, 1, 1], [2, 2, 2, 2], 6, &[0; 4]);
        assert!(parse(&short_tcp).is_none());
        assert!(parse(&[0x70; 40]).is_none());
    }
}
