// SPDX-License-Identifier: Apache-2.0
//! Noise handshake and frame codec for the control channel, sans-IO: it only handles bytes and never touches a socket.
//! Protocol details are in docs/protocol/control.md §3–§4.

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
