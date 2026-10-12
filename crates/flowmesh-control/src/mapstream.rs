// SPDX-License-Identifier: Apache-2.0
//! Framing of the map stream: each message is prefixed with a 4-byte little-endian length, optionally zstd-compressed (control.md §5).

use crate::Error;
use bytes::BytesMut;

/// Maximum size of one message (before decompression), so a malicious server cannot exhaust memory.
pub const MAX_MESSAGE: usize = 32 * 1024 * 1024;

/// Takes one complete message from the front of the buffer and returns the decompressed JSON bytes; returns `None` when less than one message is buffered.
pub fn decode_frame(buf: &mut BytesMut, compressed: bool) -> Result<Option<Vec<u8>>, Error> {
    let Some(prefix) = buf.get(..4) else {
        return Ok(None);
    };
    let len = usize::try_from(u32::from_le_bytes([
        prefix[0], prefix[1], prefix[2], prefix[3],
    ]))
    .map_err(|_| Error::Protocol("map message length overflow".into()))?;
    if len > MAX_MESSAGE {
        return Err(Error::Protocol(format!(
            "map message of {len} bytes is too large"
        )));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let _ = buf.split_to(4);
    let body = buf.split_to(len);
    if !compressed {
        return Ok(Some(body.to_vec()));
    }
    let mut out = Vec::new();
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(&body[..])
        .map_err(|e| Error::Protocol(format!("zstd: {e}")))?;
    // Limit before reading, so a "decompression bomb" cannot exhaust memory before the length check.
    let limit = u64::try_from(MAX_MESSAGE)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    std::io::Read::read_to_end(&mut std::io::Read::take(&mut decoder, limit), &mut out)
        .map_err(|e| Error::Protocol(format!("zstd: {e}")))?;
    if out.len() > MAX_MESSAGE {
        return Err(Error::Protocol(
            "decompressed map message is too large".into(),
        ));
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn two_messages_back_to_back() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&framed(br#"{"KeepAlive":true}"#));
        buf.extend_from_slice(&framed(br#"{"Domain":"x"}"#));
        assert_eq!(
            decode_frame(&mut buf, false).unwrap().unwrap(),
            br#"{"KeepAlive":true}"#
        );
        assert_eq!(
            decode_frame(&mut buf, false).unwrap().unwrap(),
            br#"{"Domain":"x"}"#
        );
        assert_eq!(decode_frame(&mut buf, false).unwrap(), None);
    }

    #[test]
    fn partial_message_waits() {
        let whole = framed(br#"{"KeepAlive":true}"#);
        let mut buf = BytesMut::from(&whole[..whole.len() - 1]);
        assert_eq!(decode_frame(&mut buf, false).unwrap(), None);
        assert_eq!(buf.len(), whole.len() - 1);
    }

    #[test]
    fn zstd_message_is_decompressed() {
        let json = br#"{"Peers":[],"Domain":"mesh.lab.internal"}"#;
        let z = ruzstd::encoding::compress_to_vec(
            &json[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        assert_ne!(z.as_slice(), json.as_slice());
        let mut buf = BytesMut::from(framed(&z).as_slice());
        assert_eq!(decode_frame(&mut buf, true).unwrap().unwrap(), json);
    }

    #[test]
    fn decompression_bomb_is_rejected() {
        let huge = vec![0u8; MAX_MESSAGE + 10];
        let z = ruzstd::encoding::compress_to_vec(
            &huge[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        assert!(z.len() < 4 * 1024 * 1024, "bomb should compress well");
        let mut buf = BytesMut::from(framed(&z).as_slice());
        assert!(decode_frame(&mut buf, true).is_err());
    }

    #[test]
    fn oversized_length_is_rejected() {
        let mut buf = BytesMut::from(((MAX_MESSAGE + 1) as u32).to_le_bytes().as_slice());
        assert!(decode_frame(&mut buf, false).is_err());
    }
}
