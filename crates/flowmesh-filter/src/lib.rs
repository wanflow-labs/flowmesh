// SPDX-License-Identifier: Apache-2.0
//! Packet filter. Pure function: rules + packet → verdict, no IO (design doc §3.2).
//! The semantics of every judgment are in docs/protocol/filter.md, each with an observation source.

pub mod compile;
pub mod matcher;
pub mod packet;
