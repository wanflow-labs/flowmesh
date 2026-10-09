// SPDX-License-Identifier: Apache-2.0
//! 控制通道的 Noise 握手与帧编解码，sans-IO：只处理字节，不碰 socket（设计稿 §3.2）。
//! 协议细节见 docs/protocol/control.md §3–§4。

pub mod frame;
pub mod handshake;
pub mod transport;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("frame payload of {0} bytes exceeds the limit")]
    FrameTooLarge(usize),
    #[error("unexpected frame type {0:?}")]
    UnexpectedFrame(frame::FrameType),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("record decryption failed")]
    Decrypt,
    #[error("nonce counter exhausted")]
    NonceExhausted,
    #[error("protocol: {0}")]
    Protocol(&'static str),
}
