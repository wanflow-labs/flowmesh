// SPDX-License-Identifier: Apache-2.0
//! DERP frame: 1-byte type + 4-byte big-endian length + payload (derp.md §2).

use crate::Error;

pub const HEADER_LEN: usize = 5;
/// Single-frame payload limit: a packet (≤ 64 KiB) plus a 32-byte key and some headroom.
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024 + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    ServerKey,
    ClientInfo,
    ServerInfo,
    SendPacket,
    RecvPacket,
    KeepAlive,
    NotePreferred,
    PeerGone,
    Ping,
    Pong,
    Health,
    Restarting,
    Other(u8),
}

impl FrameType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::ServerKey,
            0x02 => Self::ClientInfo,
            0x03 => Self::ServerInfo,
            0x04 => Self::SendPacket,
            0x05 => Self::RecvPacket,
            0x06 => Self::KeepAlive,
            0x07 => Self::NotePreferred,
            0x08 => Self::PeerGone,
            0x12 => Self::Ping,
            0x13 => Self::Pong,
            0x14 => Self::Health,
            0x15 => Self::Restarting,
            other => Self::Other(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::ServerKey => 0x01,
            Self::ClientInfo => 0x02,
            Self::ServerInfo => 0x03,
            Self::SendPacket => 0x04,
            Self::RecvPacket => 0x05,
            Self::KeepAlive => 0x06,
            Self::NotePreferred => 0x07,
            Self::PeerGone => 0x08,
            Self::Ping => 0x12,
            Self::Pong => 0x13,
            Self::Health => 0x14,
            Self::Restarting => 0x15,
            Self::Other(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ty: FrameType,
    pub payload: Vec<u8>,
}

pub fn encode(ty: FrameType, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(Error::FrameTooLarge(payload.len()));
    }
    let len = u32::try_from(payload.len()).map_err(|_| Error::FrameTooLarge(payload.len()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(ty.to_u8());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, Error> {
        let Some(h) = self.buf.get(..HEADER_LEN) else {
            return Ok(None);
        };
        let ty = FrameType::from_u8(h[0]);
        let len = usize::try_from(u32::from_be_bytes([h[1], h[2], h[3], h[4]]))
            .map_err(|_| Error::FrameTooLarge(usize::MAX))?;
        if len > MAX_FRAME_PAYLOAD {
            return Err(Error::FrameTooLarge(len));
        }
        if self.buf.len() < HEADER_LEN + len {
            return Ok(None);
        }
        let payload = self.buf[HEADER_LEN..HEADER_LEN + len].to_vec();
        self.buf.drain(..HEADER_LEN + len);
        Ok(Some(Frame { ty, payload }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_layout_is_type_then_u32_be_length() {
        assert_eq!(
            encode(FrameType::NotePreferred, &[1]).unwrap(),
            vec![0x07, 0, 0, 0, 1, 1]
        );
    }

    #[test]
    fn split_input_decodes_in_order() {
        let mut wire = encode(FrameType::KeepAlive, &[]).unwrap();
        wire.extend(encode(FrameType::RecvPacket, &[9u8; 40]).unwrap());
        let mut d = FrameDecoder::default();
        let mut got = Vec::new();
        for b in &wire {
            d.push(std::slice::from_ref(b));
            while let Some(f) = d.next_frame().unwrap() {
                got.push((f.ty, f.payload.len()));
            }
        }
        assert_eq!(
            got,
            vec![(FrameType::KeepAlive, 0), (FrameType::RecvPacket, 40)]
        );
    }

    #[test]
    fn oversized_frames_are_rejected_both_ways() {
        assert!(matches!(
            encode(FrameType::SendPacket, &vec![0; MAX_FRAME_PAYLOAD + 1]),
            Err(Error::FrameTooLarge(_))
        ));
        let mut d = FrameDecoder::default();
        d.push(&[0x05, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(d.next_frame(), Err(Error::FrameTooLarge(_))));
    }

    #[test]
    fn type_numbers_roundtrip() {
        for v in 0u8..=0x20 {
            assert_eq!(FrameType::from_u8(v).to_u8(), v);
        }
    }
}
