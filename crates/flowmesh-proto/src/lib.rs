// SPDX-License-Identifier: Apache-2.0
//! Wire data types of the flowmesh protocols: keys and control messages. This crate does no IO.
//!
//! Every protocol field corresponds to a statement in `docs/protocol/`, which cites its source.

pub mod capver;
pub mod control;
pub mod derp;
pub mod filter;
pub mod key;
