// SPDX-License-Identifier: Apache-2.0
//! disco: path discovery messages between peers (docs/protocol/disco.md). sans-IO.

pub mod envelope;
pub mod message;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("not a disco message")]
    NotDisco,
    #[error("disco message truncated")]
    Truncated,
    #[error("disco box failed to open")]
    Crypto,
}
