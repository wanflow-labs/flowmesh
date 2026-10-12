// SPDX-License-Identifier: Apache-2.0
//! Control channel client: fetch server public key → protocol upgrade → Noise handshake → HTTP/2 → registration and map stream.
//! The protocol is described in docs/protocol/control.md.

pub mod client;
pub mod conn;
pub mod dial;
pub mod early;
pub mod mapstream;
pub mod netmap;
pub mod upgrade;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] hyper::Error),
    #[error("noise: {0}")]
    Noise(#[from] flowmesh_noise::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("server returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}
