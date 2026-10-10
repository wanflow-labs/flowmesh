// SPDX-License-Identifier: Apache-2.0
//! Userspace data plane: one WireGuard session (boringtun `Tunn`) per peer, selecting peers by AllowedIPs,
//! running every packet through the filter in both directions. Pure logic: input bytes, output what to send and what to write to TUN; no IO.

pub mod ippkt;
pub mod plane;
