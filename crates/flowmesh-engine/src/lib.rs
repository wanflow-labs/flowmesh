// SPDX-License-Identifier: Apache-2.0
//! flowmesh network engine. Linux-only implementation; on other platforms it only exposes types (so the workspace still builds on the dev machine).

pub mod status;

use flowmesh_control::client::ControlClient;
use flowmesh_proto::capver::CAPABILITY_VERSION;
use flowmesh_proto::control::{Hostinfo, RegisterRequest};

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

/// Why the engine stopped with an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// The control server did not authorize this node key (no or bad auth key, or interactive login needed).
    NotAuthorized { auth_url: String, error: String },
    /// Anything else (network, TUN, …); the daemon retries.
    Other(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::NotAuthorized { auth_url, error } => {
                write!(f, "not authorized")?;
                if !error.is_empty() {
                    write!(f, ": {error}")?;
                }
                if !auth_url.is_empty() {
                    write!(f, " (log in at {auth_url})")?;
                }
                Ok(())
            }
            EngineError::Other(s) => f.write_str(s),
        }
    }
}

impl From<String> for EngineError {
    fn from(s: String) -> Self {
        EngineError::Other(s)
    }
}

impl From<&str> for EngineError {
    fn from(s: &str) -> Self {
        EngineError::Other(s.to_string())
    }
}

/// An expiry time in the past: the control server treats a register request carrying it as a logout.
/// (The zero time means "no expiry requested", so it must be a real past instant.)
pub const LOGOUT_EXPIRY: &str = "1970-01-01T00:00:01Z";

/// Log out: ask the control server to expire the current node key, then replace the node key locally.
/// The local part always happens; `Err` means only the server could not be told.
pub async fn logout(login_server: &str, state_file: &std::path::Path) -> Result<(), String> {
    let keys = flowmesh_state::load_or_create(state_file).map_err(|e| e.to_string())?;
    let told = async {
        let client = ControlClient::connect(login_server, &keys.machine)
            .await
            .map_err(|e| format!("control connect: {e}"))?;
        client
            .register(&RegisterRequest {
                version: CAPABILITY_VERSION,
                node_key: keys.node.public(),
                expiry: Some(LOGOUT_EXPIRY.into()),
                hostinfo: Hostinfo {
                    os: "linux".into(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .map(|_| ())
            .map_err(|e| format!("register: {e}"))
    }
    .await;
    flowmesh_state::rotate_node_key(state_file).map_err(|e| e.to_string())?;
    told
}
