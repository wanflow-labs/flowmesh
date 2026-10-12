// SPDX-License-Identifier: Apache-2.0
//! Engine status snapshot, published to the daemon/CLI (cli.md §2).

use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerStatus {
    pub id: i64,
    pub public_key: String,
    pub host_name: String,
    pub dns_name: String,
    pub os: String,
    pub tailscale_ips: Vec<IpAddr>,
    pub online: bool,
    pub last_seen: Option<String>,
    /// Region code of the home relay (e.g. `wanflow-relay-1000`); empty when unknown.
    pub relay: String,
    /// Current direct address; None when going through a relay.
    pub cur_addr: Option<SocketAddr>,
    /// Current peer relay path as `ip:port:vni:N`; empty otherwise (peer-relay.md §1).
    pub peer_relay: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub active: bool,
    pub exit_node_option: bool,
    /// This peer is the exit node in use.
    pub exit_node: bool,
    /// ACL tags the control server gave the node.
    pub tags: Vec<String>,
    /// The node's SSH host keys while it runs an SSH server.
    pub ssh_host_keys: Vec<String>,
    /// RFC 3339, when the server set one.
    pub key_expiry: Option<String>,
    /// The node key has expired (the peer is listed but not reachable).
    pub expired: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineStatus {
    pub self_node: Option<PeerStatus>,
    pub peers: Vec<PeerStatus>,
    pub magic_dns_suffix: String,
    pub tailnet_name: String,
    pub health: Vec<String>,
    /// `auto`, `prefer` or `strict`; empty before the first netmap.
    pub relay_mode: String,
}
