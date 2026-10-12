// SPDX-License-Identifier: Apache-2.0
//! Packet filter. Pure function: rules + packet → verdict, no IO.
//! The semantics of every judgment are in docs/protocol/filter.md, each with an observation source.

pub mod caps;
pub mod compile;
pub mod matcher;
pub mod packet;
