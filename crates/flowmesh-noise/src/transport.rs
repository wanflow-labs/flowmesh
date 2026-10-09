// SPDX-License-Identifier: Apache-2.0
//! 握手完成后的加密记录层（control.md §4）。
//!
//! 密钥取自 Noise 握手的 split 结果，算法为 ChaCha20-Poly1305。nonce 为 4 字节零加上
//! **8 字节大端**计数器，而不是 Noise 规范里的小端。依据：用小端编码时，真实服务端的第 2 条
//! 记录就无法解密（nonce 0 的两种编码相同，从 1 开始才有差异），见 control.md §4 的观测记录。

use crate::Error;
use crate::frame::{self, Frame, FrameType};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// ChaChaPoly 认证标签长度。
pub const TAG_LEN: usize = 16;
/// 单帧可承载的明文上限。
pub const MAX_PLAINTEXT_PER_FRAME: usize = frame::MAX_FRAME_PAYLOAD - TAG_LEN;

/// 构造 12 字节 nonce：4 字节零 + 8 字节大端计数器。
pub fn nonce_bytes(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

struct CipherState {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl CipherState {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            counter: 0,
        }
    }

    fn next_nonce(&mut self) -> Result<[u8; 12], Error> {
        let n = nonce_bytes(self.counter);
        // 计数器用尽时拒绝继续，绝不重用 nonce。
        self.counter = self.counter.checked_add(1).ok_or(Error::NonceExhausted)?;
        Ok(n)
    }
}

pub struct Transport {
    send: CipherState,
    recv: CipherState,
}

impl Transport {
    /// 由 split 得到的两把密钥构造：`send` 用于本端发出，`recv` 用于解密对端。
    pub fn from_raw_split(send: [u8; 32], recv: [u8; 32]) -> Self {
        Self {
            send: CipherState::new(send),
            recv: CipherState::new(recv),
        }
    }

    /// 加密任意长度明文，按帧上限切片后输出连续的记录帧。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(plaintext.len() + plaintext.len() / 64 + 32);
        for chunk in plaintext.chunks(MAX_PLAINTEXT_PER_FRAME) {
            let nonce = self.send.next_nonce()?;
            let ct = self
                .send
                .cipher
                .encrypt(Nonce::from_slice(&nonce), chunk)
                .map_err(|_| Error::Decrypt)?;
            out.extend(frame::encode(FrameType::Record, &ct)?);
        }
        Ok(out)
    }

    /// 解密一条记录帧。
    pub fn open(&mut self, frame: Frame) -> Result<Vec<u8>, Error> {
        if frame.ty != FrameType::Record {
            return Err(Error::UnexpectedFrame(frame.ty));
        }
        let nonce = self.recv.next_nonce()?;
        self.recv
            .cipher
            .decrypt(Nonce::from_slice(&nonce), frame.payload.as_slice())
            .map_err(|_| Error::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_layout_is_big_endian_counter() {
        assert_eq!(nonce_bytes(0), [0; 12]);
        assert_eq!(nonce_bytes(1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            nonce_bytes(0x0102),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02]
        );
    }

    /// 第二条记录必须用计数器 1 的大端 nonce 才能解开：直接用独立构造的 nonce 加密，
    /// 交给 Transport 解密，避免"两端用同一实现、同样写错也能通过"。
    #[test]
    fn second_record_uses_big_endian_nonce_one() {
        let key = [7u8; 32];
        let peer = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut t = Transport::from_raw_split([9u8; 32], key);
        for (counter, msg) in [(0u64, b"first"), (1, b"other")] {
            let mut nonce = [0u8; 12];
            nonce[11] = counter as u8;
            let ct = peer.encrypt(Nonce::from_slice(&nonce), &msg[..]).unwrap();
            let f = Frame {
                ty: FrameType::Record,
                payload: ct,
            };
            assert_eq!(t.open(f).unwrap(), msg);
        }
    }
}
