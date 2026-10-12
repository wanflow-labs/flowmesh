// SPDX-License-Identifier: Apache-2.0
//! Frame: 1-byte type + 2-byte big-endian length + payload (control.md §3, observed).

use crate::Error;

pub const HEADER_LEN: usize = 3;
/// Maximum payload of one frame.
pub const MAX_FRAME_PAYLOAD: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Initiation,
    Response,
    Record,
    Other(u8),
}

impl FrameType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Initiation,
            2 => Self::Response,
            4 => Self::Record,
            other => Self::Other(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Initiation => 1,
            Self::Response => 2,
            Self::Record => 4,
            Self::Other(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ty: FrameType,
    pub payload: Vec<u8>,
}

/// Encodes one frame. The caller guarantees the payload is at most [`MAX_FRAME_PAYLOAD`].
pub fn encode(ty: FrameType, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(Error::FrameTooLarge(payload.len()));
    }
    let len = u16::try_from(payload.len()).map_err(|_| Error::FrameTooLarge(payload.len()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(ty.to_u8());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Incremental decoder: feed bytes split at any point, take out whole frames one by one.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, Error> {
        let Some(header) = self.buf.get(..HEADER_LEN) else {
            return Ok(None);
        };
        let ty = FrameType::from_u8(header[0]);
        let len = usize::from(u16::from_be_bytes([header[1], header[2]]));
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

    /// Number of buffered bytes that do not yet form a complete frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_layout() {
        let f = encode(FrameType::Record, &[0xaa, 0xbb]).unwrap();
        assert_eq!(f, vec![4, 0x00, 0x02, 0xaa, 0xbb]);
    }

    #[test]
    fn encode_rejects_oversized_payload() {
        let big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        assert!(matches!(
            encode(FrameType::Record, &big),
            Err(Error::FrameTooLarge(n)) if n == MAX_FRAME_PAYLOAD + 1
        ));
    }

    /// Observed server frame sequence (framing-summary.json): type 2 with length 48, then type 4 frames of 21, 20 and 111 bytes.
    #[test]
    fn decodes_observed_length_sequence_split_arbitrarily() {
        let mut wire = Vec::new();
        for (ty, len) in [(2u8, 48usize), (4, 21), (4, 20), (4, 111)] {
            wire.extend(encode(FrameType::from_u8(ty), &vec![ty; len]).unwrap());
        }
        let mut dec = FrameDecoder::default();
        let mut got = Vec::new();
        for chunk in wire.chunks(7) {
            dec.push(chunk);
            while let Some(f) = dec.next_frame().unwrap() {
                got.push((f.ty.to_u8(), f.payload.len()));
            }
        }
        assert_eq!(got, vec![(2, 48), (4, 21), (4, 20), (4, 111)]);
        assert_eq!(dec.buffered(), 0);
    }

    #[test]
    fn partial_header_and_partial_payload_yield_nothing() {
        let mut dec = FrameDecoder::default();
        dec.push(&[4, 0x00]);
        assert_eq!(dec.next_frame().unwrap(), None);
        dec.push(&[0x03, 1, 2]);
        assert_eq!(dec.next_frame().unwrap(), None);
        dec.push(&[3]);
        assert_eq!(
            dec.next_frame().unwrap(),
            Some(Frame {
                ty: FrameType::Record,
                payload: vec![1, 2, 3]
            })
        );
    }

    #[test]
    fn decoder_rejects_oversized_length_before_buffering_payload() {
        let mut dec = FrameDecoder::default();
        dec.push(&[4, 0xff, 0xff]);
        assert!(matches!(dec.next_frame(), Err(Error::FrameTooLarge(65535))));
    }
}
