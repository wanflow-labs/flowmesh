// SPDX-License-Identifier: Apache-2.0
//! DERP relay client. Frame codec and handshake are sans-IO; `client` is a thin layer of TLS + HTTP upgrade.
//! Protocol in docs/protocol/derp.md.

pub mod client;
pub mod frame;
pub mod handshake;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("frame payload of {0} bytes exceeds the limit")]
    FrameTooLarge(usize),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("crypto box failed")]
    Crypto,
}
