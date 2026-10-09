// SPDX-License-Identifier: Apache-2.0
//! The packet fields needed for filtering.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProto {
    Tcp,
    Udp,
    Icmp4,
    Icmp6,
    Other(u8),
}

impl IpProto {
    pub fn number(self) -> u8 {
        match self {
            Self::Icmp4 => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp6 => 58,
            Self::Other(n) => n,
        }
    }

    pub fn from_number(n: u8) -> Self {
        match n {
            1 => Self::Icmp4,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmp6,
            other => Self::Other(other),
        }
    }
}

pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub proto: IpProto,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// TCP flag byte; 0 for non-TCP.
    pub tcp_flags: u8,
    /// ICMP/ICMPv6 type; 0 for non-ICMP.
    pub icmp_type: u8,
}
