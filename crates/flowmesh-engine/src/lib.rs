// SPDX-License-Identifier: Apache-2.0
//! flowmesh network engine. Linux-only implementation; on other platforms it only exposes types (so the workspace still builds on the dev machine).

pub mod status;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::run;

/// Engine startup configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub login_server: String,
    /// Pre-auth key used for the first registration; may be omitted once the node key is registered.
    pub authkey: Option<String>,
    pub state_file: std::path::PathBuf,
    pub hostname: String,
    pub tun: String,
    pub port: u16,
    pub tap_dir: Option<std::path::PathBuf>,
    pub accept_dns: bool,
    pub accept_routes: bool,
}
