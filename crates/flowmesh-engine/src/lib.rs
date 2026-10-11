// SPDX-License-Identifier: Apache-2.0
//! flowmesh network engine. Linux-only implementation; on other platforms it only exposes types (so the workspace still builds on the dev machine).

pub mod command;
pub mod control_loop;
pub mod debug;
mod logic;
pub mod metrics;
mod peerapi;
pub mod relay_plan;
pub mod status;
mod udpio;

use flowmesh_control::client::ControlClient;
use flowmesh_proto::capver::CAPABILITY_VERSION;
use flowmesh_proto::control::{Hostinfo, RegisterRequest};

#[cfg(target_os = "linux")]
mod features;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod tunio;
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
    /// Subnets this node routes for (`--advertise-routes`), sent as Hostinfo.RoutableIPs.
    pub advertise_routes: Vec<ipnet::IpNet>,
    /// Masquerade traffic forwarded from the mesh into those subnets (`--snat-subnet-routes`).
    pub snat_subnet_routes: bool,
    /// ACL tags to request (`--advertise-tags`), sent as Hostinfo.RequestTags.
    pub advertise_tags: Vec<String>,
    /// Refuse all inbound connections (`--shields-up`).
    pub shields_up: bool,
    /// Offer to be an exit node (`--advertise-exit-node`).
    pub advertise_exit_node: bool,
    /// Drop new connections forwarded into the mesh (`--stateful-filtering`).
    pub stateful_filtering: bool,
    /// The exit node to use (`--exit-node`: an address or a unique node name; empty: none).
    pub exit_node: String,
    /// Keep the host's own networks off the exit node (`--exit-node-allow-lan-access`).
    pub exit_node_allow_lan_access: bool,
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

/// How long logout waits for the control server. The official client waits until it answers or the
/// caller gives up; a bound gives scripts a definite exit code with the same end state (deviation #7).
pub const LOGOUT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Log out: ask the control server to expire the current node key, then replace the node key locally.
/// Like the official client, nothing changes locally when the server cannot be told (cli.md §1).
pub async fn logout(login_server: &str, state_file: &std::path::Path) -> Result<(), String> {
    let keys = flowmesh_state::load_or_create(state_file).map_err(|e| e.to_string())?;
    tokio::time::timeout(LOGOUT_TIMEOUT, tell_logout(login_server, &keys))
        .await
        .map_err(|_| format!("control server did not answer within {LOGOUT_TIMEOUT:?}"))??;
    flowmesh_state::rotate_node_key(state_file).map_err(|e| e.to_string())?;
    Ok(())
}

async fn tell_logout(login_server: &str, keys: &flowmesh_state::NodeState) -> Result<(), String> {
    let client = ControlClient::connect(login_server, &keys.machine)
        .await
        .map_err(|e| format!("control connect: {e}"))?;
    client
        .register(&logout_request(keys))
        .await
        .map_err(|e| format!("register: {e}"))?;
    Ok(())
}

/// A register request carrying an expiry in the past for the current node key (control.md).
fn logout_request(keys: &flowmesh_state::NodeState) -> RegisterRequest {
    RegisterRequest {
        version: CAPABILITY_VERSION,
        node_key: keys.node.public(),
        expiry: Some(LOGOUT_EXPIRY.into()),
        hostinfo: Hostinfo {
            os: "linux".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_error_text() {
        let e = |auth_url: &str, error: &str| {
            EngineError::NotAuthorized {
                auth_url: auth_url.into(),
                error: error.into(),
            }
            .to_string()
        };
        assert_eq!(e("", ""), "not authorized");
        assert_eq!(e("", "key expired"), "not authorized: key expired");
        assert_eq!(
            e("http://h/r/1", ""),
            "not authorized (log in at http://h/r/1)"
        );
        assert_eq!(
            e("http://h/r/1", "key expired"),
            "not authorized: key expired (log in at http://h/r/1)"
        );
        assert_eq!(
            EngineError::Other("tun: busy".into()).to_string(),
            "tun: busy"
        );
        assert_eq!(EngineError::from("x"), EngineError::Other("x".into()));
        assert_eq!(
            EngineError::from("y".to_string()),
            EngineError::Other("y".into())
        );
    }

    #[test]
    fn logout_request_expires_the_current_node_key() {
        let keys = flowmesh_state::NodeState {
            machine: flowmesh_proto::key::MachinePrivate::generate().unwrap(),
            node: flowmesh_proto::key::NodePrivate::generate().unwrap(),
        };
        let r = logout_request(&keys);
        assert_eq!(r.version, CAPABILITY_VERSION);
        assert_eq!(r.node_key, keys.node.public());
        assert_eq!(r.expiry.as_deref(), Some("1970-01-01T00:00:01Z"));
        assert_eq!(r.hostinfo.os, "linux");
        assert!(r.auth.is_none(), "logout never carries an auth key");
    }

    /// The server cannot be told: logout fails and the node key stays (cli.md §1).
    #[tokio::test]
    async fn logout_without_the_server_changes_nothing() {
        let dir = std::env::temp_dir().join(format!("fm-engine-logout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("node.json");
        let before = flowmesh_state::load_or_create(&state).unwrap();
        // Port 1 on loopback: connection refused at once.
        assert!(logout("http://127.0.0.1:1", &state).await.is_err());
        assert_eq!(flowmesh_state::load_or_create(&state).unwrap(), before);
    }
}
