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

    #[test]
    fn truncated_or_garbage_is_none() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45, 0, 0]).is_none());
        let short_tcp = v4([1, 1, 1, 1], [2, 2, 2, 2], 6, &[0; 4]);
        assert!(parse(&short_tcp).is_none());
        assert!(parse(&[0x70; 40]).is_none());
    }
}
