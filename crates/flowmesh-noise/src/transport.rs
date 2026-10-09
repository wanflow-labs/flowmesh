// SPDX-License-Identifier: Apache-2.0
//! 握手完成后的加密记录层。

use crate::Error;
use crate::frame::{self, Frame, FrameType};

/// ChaChaPoly 认证标签长度。
pub const TAG_LEN: usize = 16;
/// 单帧可承载的明文上限。
pub const MAX_PLAINTEXT_PER_FRAME: usize = frame::MAX_FRAME_PAYLOAD - TAG_LEN;

pub struct Transport {
    pub(crate) state: snow::TransportState,
}

impl Transport {
    /// 加密任意长度明文，按帧上限切片后输出连续的记录帧。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(plaintext.len() + plaintext.len() / 64 + 32);
        let mut cipher = vec![0u8; frame::MAX_FRAME_PAYLOAD];
        for chunk in plaintext.chunks(MAX_PLAINTEXT_PER_FRAME) {
            let n = self.state.write_message(chunk, &mut cipher)?;
            out.extend(frame::encode(FrameType::Record, &cipher[..n])?);
        }
        Ok(out)
    }

    /// 解密一条记录帧。
    pub fn open(&mut self, frame: Frame) -> Result<Vec<u8>, Error> {
        if frame.ty != FrameType::Record {
            return Err(Error::UnexpectedFrame(frame.ty));
        }
        let mut out = vec![0u8; frame.payload.len()];
        let n = self.state.read_message(&frame.payload, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}
