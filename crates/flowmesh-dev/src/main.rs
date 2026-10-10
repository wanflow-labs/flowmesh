// SPDX-License-Identifier: Apache-2.0
//! flowmesh development daemon (M4): control → network map → DERP → userspace WireGuard → TUN.
//! Linux only, not a release artifact; the real daemon flowmeshd comes in M7.
//!
//! Usage: flowmesh-dev --login-server <url> --authkey-file <path> --state <path> --hostname <name> [--tun <name>]

#[cfg(target_os = "linux")]
mod linux;

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux::main()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("flowmesh-dev only runs on Linux");
        std::process::ExitCode::from(2)
    }
}
