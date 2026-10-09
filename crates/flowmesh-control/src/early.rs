// SPDX-License-Identifier: Apache-2.0
//! 服务端在握手后先发的"前置载荷"：5 字节魔数 + 4 字节大端长度 + JSON（control.md §4）。

use crate::Error;

pub const EARLY_MAGIC: [u8; 5] = [0xff, 0xff, 0xff, b'T', b'S'];
/// 前置载荷 JSON 的长度上限，防止恶意服务端让我们分配超大缓冲。
pub const MAX_EARLY_JSON: usize = 64 * 1024;

#[derive(Debug, PartialEq)]
pub enum Early {
    /// 还需要更多明文才能判断。
    NeedMore,
    /// 不是前置载荷，缓冲保持原样交给 HTTP/2。
    Absent,
    /// 已从缓冲头部剥离前置载荷。
    Present(serde_json::Value),
}

/// 检查明文缓冲头部是否为前置载荷；若是，就把它从缓冲中移除。
pub fn take_early(buf: &mut Vec<u8>) -> Result<Early, Error> {
    let seen = buf.len().min(EARLY_MAGIC.len());
    if buf[..seen] != EARLY_MAGIC[..seen] {
        return Ok(Early::Absent);
    }
    if buf.len() < EARLY_MAGIC.len() + 4 {
        return Ok(Early::NeedMore);
    }
    let len_bytes = [buf[5], buf[6], buf[7], buf[8]];
    let len = usize::try_from(u32::from_be_bytes(len_bytes))
        .map_err(|_| Error::Protocol("early payload length overflow".into()))?;
    if len > MAX_EARLY_JSON {
        return Err(Error::Protocol(format!(
            "early payload of {len} bytes is too large"
        )));
    }
    let total = EARLY_MAGIC.len() + 4 + len;
    if buf.len() < total {
        return Ok(Early::NeedMore);
    }
    let value = serde_json::from_slice(&buf[EARLY_MAGIC.len() + 4..total])?;
    buf.drain(..total);
    Ok(Early::Present(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn early_bytes(json: &str) -> Vec<u8> {
        let mut v = EARLY_MAGIC.to_vec();
        v.extend_from_slice(&(json.len() as u32).to_be_bytes());
        v.extend_from_slice(json.as_bytes());
        v
    }

    #[test]
    fn strips_early_payload_and_keeps_following_bytes() {
        let mut buf = early_bytes(r#"{"a":1}"#);
        buf.extend_from_slice(b"\x00\x00\x12h2");
        assert_eq!(
            take_early(&mut buf).unwrap(),
            Early::Present(serde_json::json!({"a":1}))
        );
        assert_eq!(buf, b"\x00\x00\x12h2");
    }

    #[test]
    fn non_magic_prefix_is_left_untouched() {
        let mut buf = b"\x00\x00\x06\x04\x00\x00\x00\x00\x00".to_vec();
        let before = buf.clone();
        assert_eq!(take_early(&mut buf).unwrap(), Early::Absent);
        assert_eq!(buf, before);
    }

    #[test]
    fn partial_magic_or_body_needs_more() {
        let full = early_bytes(r#"{"a":1}"#);
        for cut in [0, 3, 5, 8, full.len() - 1] {
            let mut buf = full[..cut].to_vec();
            assert_eq!(take_early(&mut buf).unwrap(), Early::NeedMore, "cut={cut}");
            assert_eq!(buf.len(), cut);
        }
    }

    #[test]
    fn short_non_magic_prefix_is_absent_early() {
        let mut buf = vec![0x00];
        assert_eq!(take_early(&mut buf).unwrap(), Early::Absent);
    }

    #[test]
    fn oversized_length_is_rejected() {
        let mut buf = EARLY_MAGIC.to_vec();
        buf.extend_from_slice(&((MAX_EARLY_JSON + 1) as u32).to_be_bytes());
        assert!(take_early(&mut buf).is_err());
    }
}
