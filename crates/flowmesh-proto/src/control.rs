// SPDX-License-Identifier: Apache-2.0
//! 控制通道消息（docs/protocol/control.md）。
//!
//! 所有类型都按"宽容解析"处理：未知字段一律忽略，缺失字段取默认值（设计稿 §3.2）。
//! 字段名全部显式写出，因为协议里有 `DERPMap`、`IPProto` 这类非常规大小写。

use crate::derp::DerpMap;
use crate::filter::FilterRule;
use crate::key::{DiscoPublic, MachinePublic, NodePublic};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;

/// `GET /key?v=<能力版本>` 的响应（control.md §1，已观测）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerKeyResponse {
    #[serde(rename = "legacyPublicKey")]
    pub legacy_public_key: MachinePublic,
    #[serde(rename = "publicKey")]
    pub public_key: MachinePublic,
}

/// One entry of `Hostinfo.Services`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Service {
    #[serde(rename = "Proto")]
    pub proto: String,
    #[serde(rename = "Port")]
    pub port: u16,
    #[serde(
        rename = "Description",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub description: String,
}

/// Service protocol names in `Hostinfo.Services` (tailcfg.ServiceProto).
pub const PEERAPI4: &str = "peerapi4";
pub const PEERAPI6: &str = "peerapi6";
/// The exit node DNS proxy over peerapi; its Port is a version number (1).
pub const PEERAPI_DNS: &str = "peerapi-dns-proxy";

/// 节点自报的主机信息。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hostinfo {
    #[serde(rename = "IPNVersion", skip_serializing_if = "String::is_empty")]
    pub ipn_version: String,
    #[serde(rename = "OS", skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(rename = "OSVersion", skip_serializing_if = "String::is_empty")]
    pub os_version: String,
    #[serde(rename = "Hostname", skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(rename = "Machine", skip_serializing_if = "String::is_empty")]
    pub machine: String,
    #[serde(rename = "RoutableIPs", skip_serializing_if = "Vec::is_empty")]
    pub routable_ips: Vec<IpNet>,
    #[serde(rename = "RequestTags", skip_serializing_if = "Vec::is_empty")]
    pub request_tags: Vec<String>,
    #[serde(rename = "ShieldsUp", skip_serializing_if = "std::ops::Not::not")]
    pub shields_up: bool,
    /// Services the node offers to peers; flowmesh lists its peerapi ports and the exit node DNS
    /// proxy (Proto `peerapi4`, `peerapi6`, `peerapi-dns-proxy`).
    #[serde(rename = "Services", skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<Service>,
    /// SSH host keys in authorized_keys form (`ssh-ed25519 AAAA…`), while the node runs the SSH
    /// server. Lower-case key, as the official client sends it (OBS-20261012-ssh-official).
    #[serde(rename = "sshHostKeys", skip_serializing_if = "Vec::is_empty")]
    pub ssh_host_keys: Vec<String>,
    #[serde(rename = "NetInfo", skip_serializing_if = "Option::is_none")]
    pub net_info: Option<NetInfo>,
}

/// This node's network conditions. The control server derives this node's `HomeDERP` from `PreferredDERP`,
/// and peers use it to find the DERP relay that reaches us (observed: the self node's DERP stays 127.3.3.40:0 when this is unset).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetInfo {
    #[serde(rename = "PreferredDERP")]
    pub preferred_derp: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegisterAuth {
    #[serde(rename = "AuthKey", skip_serializing_if = "String::is_empty")]
    pub auth_key: String,
}

/// `POST /machine/register` 的请求体。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegisterRequest {
    #[serde(rename = "Version")]
    pub version: u16,
    #[serde(rename = "NodeKey")]
    pub node_key: NodePublic,
    #[serde(rename = "OldNodeKey")]
    pub old_node_key: NodePublic,
    #[serde(rename = "Auth", skip_serializing_if = "Option::is_none")]
    pub auth: Option<RegisterAuth>,
    #[serde(rename = "Hostinfo")]
    pub hostinfo: Hostinfo,
    #[serde(rename = "Ephemeral", skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
    /// RFC 3339. A time in the past asks the server to expire (log out) this node key (control.md).
    #[serde(rename = "Expiry", skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
}

/// 用户信息。headscale 回送的字段远多于此，未建模的字段在 control.md "未建模字段"中列出。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserProfile {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "LoginName")]
    pub login_name: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
}

/// 注册响应中的登录身份。用户名在这里，而不在 `User` 中（OBS-20261010-flowmesh-probe）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Login {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "LoginName")]
    pub login_name: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
    #[serde(rename = "Provider")]
    pub provider: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegisterResponse {
    #[serde(rename = "User")]
    pub user: UserProfile,
    #[serde(rename = "Login")]
    pub login: Login,
    #[serde(rename = "NodeKeyExpired")]
    pub node_key_expired: bool,
    #[serde(rename = "MachineAuthorized")]
    pub machine_authorized: bool,
    #[serde(rename = "AuthURL")]
    pub auth_url: String,
    #[serde(rename = "Error")]
    pub error: String,
}

/// `POST /machine/map` 的请求体。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MapRequest {
    #[serde(rename = "Version")]
    pub version: u16,
    /// `"zstd"` 或空字符串。
    #[serde(rename = "Compress", skip_serializing_if = "String::is_empty")]
    pub compress: String,
    #[serde(rename = "KeepAlive")]
    pub keep_alive: bool,
    #[serde(rename = "NodeKey")]
    pub node_key: NodePublic,
    #[serde(rename = "DiscoKey")]
    pub disco_key: DiscoPublic,
    #[serde(rename = "Endpoints")]
    pub endpoints: Vec<SocketAddr>,
    #[serde(rename = "Hostinfo")]
    pub hostinfo: Hostinfo,
    #[serde(rename = "Stream")]
    pub stream: bool,
    #[serde(rename = "OmitPeers", skip_serializing_if = "std::ops::Not::not")]
    pub omit_peers: bool,
}

/// 网络地图中的一个节点（自身或对端）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "StableID")]
    pub stable_id: String,
    /// 完整的 MagicDNS 名，以点结尾。
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "User")]
    pub user: i64,
    #[serde(rename = "Key")]
    pub key: NodePublic,
    #[serde(rename = "KeyExpiry", skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<String>,
    #[serde(rename = "Machine")]
    pub machine: MachinePublic,
    #[serde(rename = "DiscoKey")]
    pub disco_key: DiscoPublic,
    #[serde(rename = "Addresses")]
    pub addresses: Vec<IpNet>,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Vec<IpNet>,
    #[serde(rename = "Endpoints")]
    pub endpoints: Vec<SocketAddr>,
    #[serde(rename = "HomeDERP")]
    pub home_derp: u32,
    /// 旧格式的 home 区域，形如 `127.3.3.40:<区域号>`；新版本服务端使用 `HomeDERP`。
    #[serde(rename = "DERP", skip_serializing_if = "String::is_empty")]
    pub legacy_derp: String,
    #[serde(rename = "Hostinfo")]
    pub hostinfo: Hostinfo,
    #[serde(rename = "Online", skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(rename = "LastSeen", skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(rename = "MachineAuthorized")]
    pub machine_authorized: bool,
    #[serde(rename = "Tags", skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(rename = "PrimaryRoutes", skip_serializing_if = "Vec::is_empty")]
    pub primary_routes: Vec<IpNet>,
    #[serde(rename = "CapMap", skip_serializing_if = "Option::is_none")]
    pub cap_map: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "Expired", skip_serializing_if = "std::ops::Not::not")]
    pub expired: bool,
    /// 该节点的能力版本。
    #[serde(rename = "Cap")]
    pub cap: u32,
    #[serde(rename = "Created", skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
}

/// 对已有对端的增量修改，只携带变化的字段（`PeersChangedPatch`）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerChange {
    #[serde(rename = "NodeID")]
    pub node_id: i64,
    #[serde(rename = "DERPRegion", skip_serializing_if = "Option::is_none")]
    pub derp_region: Option<u32>,
    #[serde(rename = "Endpoints", skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<SocketAddr>>,
    #[serde(rename = "Key", skip_serializing_if = "Option::is_none")]
    pub key: Option<NodePublic>,
    #[serde(rename = "DiscoKey", skip_serializing_if = "Option::is_none")]
    pub disco_key: Option<DiscoPublic>,
    #[serde(rename = "Online", skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(rename = "LastSeen", skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(rename = "KeyExpiry", skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<String>,
    #[serde(rename = "Cap", skip_serializing_if = "Option::is_none")]
    pub cap: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsResolver {
    #[serde(rename = "Addr")]
    pub addr: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsRecord {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Type", skip_serializing_if = "String::is_empty")]
    pub record_type: String,
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    #[serde(rename = "Resolvers")]
    pub resolvers: Vec<DnsResolver>,
    #[serde(rename = "Routes")]
    pub routes: BTreeMap<String, Vec<DnsResolver>>,
    #[serde(rename = "FallbackResolvers")]
    pub fallback_resolvers: Vec<DnsResolver>,
    #[serde(rename = "Domains")]
    pub domains: Vec<String>,
    #[serde(rename = "Proxied")]
    pub proxied: bool,
    #[serde(rename = "ExtraRecords")]
    pub extra_records: Vec<DnsRecord>,
}

/// The control server's SSH access rules for this node, evaluated in order (docs/protocol/ssh.md).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SshPolicy {
    #[serde(rename = "rules")]
    pub rules: Vec<SshRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SshRule {
    /// RFC 3339; a rule past this time is ignored.
    #[serde(rename = "ruleExpires", skip_serializing_if = "Option::is_none")]
    pub rule_expires: Option<String>,
    #[serde(rename = "principals")]
    pub principals: Vec<SshPrincipal>,
    /// Requested user -> local user: `=` keeps the name, `""` refuses it; key `*` matches any user
    /// not listed.
    #[serde(rename = "sshUsers")]
    pub ssh_users: std::collections::BTreeMap<String, String>,
    #[serde(rename = "action", skip_serializing_if = "Option::is_none")]
    pub action: Option<SshAction>,
}

/// Who a rule applies to; one field set per principal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SshPrincipal {
    /// Stable node ID.
    #[serde(rename = "node", skip_serializing_if = "String::is_empty")]
    pub node: String,
    #[serde(rename = "nodeIP", skip_serializing_if = "String::is_empty")]
    pub node_ip: String,
    /// The connecting node's user's login name.
    #[serde(rename = "userLogin", skip_serializing_if = "String::is_empty")]
    pub user_login: String,
    #[serde(rename = "any", skip_serializing_if = "std::ops::Not::not")]
    pub any: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SshAction {
    /// Shown to the user (accept or reject).
    #[serde(rename = "message", skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(rename = "reject", skip_serializing_if = "std::ops::Not::not")]
    pub reject: bool,
    #[serde(rename = "accept", skip_serializing_if = "std::ops::Not::not")]
    pub accept: bool,
    /// Nanoseconds a session may last; 0 for no limit.
    #[serde(rename = "sessionDuration", skip_serializing_if = "is_zero")]
    pub session_duration: i64,
    #[serde(
        rename = "allowAgentForwarding",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub allow_agent_forwarding: bool,
    /// Ask a URL whether to accept (the official client's "check" mode); flowmesh refuses.
    #[serde(rename = "holdAndDelegate", skip_serializing_if = "String::is_empty")]
    pub hold_and_delegate: String,
    #[serde(
        rename = "allowLocalPortForwarding",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub allow_local_port_forwarding: bool,
    #[serde(
        rename = "allowRemotePortForwarding",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub allow_remote_port_forwarding: bool,
    /// Session recorders; flowmesh records nothing and refuses rules that require recording.
    #[serde(rename = "recorders", skip_serializing_if = "Vec::is_empty")]
    pub recorders: Vec<String>,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// 网络地图流中的一条消息。除 `keep_alive` 外，其余字段只在本条消息带有对应变更时才出现。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MapResponse {
    #[serde(rename = "KeepAlive")]
    pub keep_alive: bool,
    #[serde(rename = "Node", skip_serializing_if = "Option::is_none")]
    pub node: Option<Node>,
    #[serde(rename = "DERPMap", skip_serializing_if = "Option::is_none")]
    pub derp_map: Option<DerpMap>,
    /// 存在时为对端的完整列表（替换此前全部对端）。
    #[serde(rename = "Peers", skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<Node>>,
    #[serde(rename = "PeersChanged", skip_serializing_if = "Vec::is_empty")]
    pub peers_changed: Vec<Node>,
    #[serde(rename = "PeersRemoved", skip_serializing_if = "Vec::is_empty")]
    pub peers_removed: Vec<i64>,
    #[serde(rename = "PeersChangedPatch", skip_serializing_if = "Vec::is_empty")]
    pub peers_changed_patch: Vec<PeerChange>,
    #[serde(rename = "DNSConfig", skip_serializing_if = "Option::is_none")]
    pub dns_config: Option<DnsConfig>,
    /// Who may SSH to this node as whom; present when it changed (docs/protocol/ssh.md).
    #[serde(rename = "SSHPolicy", skip_serializing_if = "Option::is_none")]
    pub ssh_policy: Option<SshPolicy>,
    #[serde(rename = "Domain", skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// 旧式的单一规则表；headscale 0.26 不发送，改用 `PacketFilters`。
    #[serde(rename = "PacketFilter", skip_serializing_if = "Option::is_none")]
    pub packet_filter: Option<Vec<FilterRule>>,
    /// 按名称分组的规则表，headscale 只使用 `"base"` 一组（OBS-20261010-flowmesh-probe）。
    /// 跨消息的合并语义（整体替换还是逐键更新、null 的含义）待 M3 用差分测试确认（control.md §6）。
    #[serde(rename = "PacketFilters", skip_serializing_if = "Option::is_none")]
    pub packet_filters: Option<BTreeMap<String, Option<Vec<FilterRule>>>>,
    #[serde(rename = "UserProfiles", skip_serializing_if = "Vec::is_empty")]
    pub user_profiles: Vec<UserProfile>,
    #[serde(rename = "Health", skip_serializing_if = "Vec::is_empty")]
    pub health: Vec<String>,
    #[serde(rename = "ControlTime", skip_serializing_if = "Option::is_none")]
    pub control_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_key_response_parses_observed_sample() {
        let raw =
            include_str!("../../../fixtures/observed/20261010-control-handshake/key-response.json");
        let r: ServerKeyResponse = serde_json::from_str(raw).unwrap();
        assert!(r.legacy_public_key.is_zero());
        assert!(!r.public_key.is_zero());
    }

    #[test]
    fn map_response_ignores_unknown_fields() {
        let r: MapResponse =
            serde_json::from_str(r#"{"KeepAlive":true,"SomethingNew":{"x":1}}"#).unwrap();
        assert!(r.keep_alive);
        assert!(r.peers.is_none());
    }

    #[test]
    fn register_request_field_names() {
        let req = RegisterRequest {
            version: 131,
            auth: Some(RegisterAuth {
                auth_key: "k".into(),
            }),
            hostinfo: Hostinfo {
                hostname: "fm1".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let v = serde_json::to_value(&req).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["Auth", "Hostinfo", "NodeKey", "OldNodeKey", "Version"]
        );
        assert_eq!(v["Auth"]["AuthKey"], "k");
        assert_eq!(v["Hostinfo"]["Hostname"], "fm1");
        assert_eq!(v["OldNodeKey"], format!("nodekey:{}", "0".repeat(64)));
    }

    const PROBE: &str = "../../../fixtures/observed/20261010-flowmesh-probe";

    #[test]
    fn observed_register_response_has_login_name() {
        let r: RegisterResponse = serde_json::from_str(include_str!(
            "../../../fixtures/observed/20261010-flowmesh-probe/register-response.json"
        ))
        .unwrap();
        assert!(r.machine_authorized);
        assert!(r.error.is_empty());
        assert_eq!(r.login.login_name, "lab");
        let _ = PROBE;
    }

    #[test]
    fn observed_initial_map_response() {
        let m: MapResponse = serde_json::from_str(include_str!(
            "../../../fixtures/observed/20261010-flowmesh-probe/map-0000.json"
        ))
        .unwrap();
        let me = m.node.as_ref().unwrap();
        assert_eq!(me.name, "fm1.mesh.lab.internal.");
        assert_eq!(me.cap, 131);
        let peers = m.peers.as_ref().unwrap();
        assert_eq!(peers.len(), 2);
        assert!(
            peers
                .iter()
                .all(|p| p.home_derp == 1000 && !p.endpoints.is_empty())
        );
        assert!(peers.iter().all(|p| p.online == Some(true)));

        let base = m.packet_filters.as_ref().unwrap()["base"].as_ref().unwrap();
        assert_eq!(base.len(), 2);
        assert_eq!(base[0].src_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!(
            base[0].dst_ports[0].ports,
            crate::filter::PortRange {
                first: 0,
                last: 65535
            }
        );
        assert_eq!(
            base[1].cap_grant[0].caps,
            ["tailscale.com/cap/relay", "tailscale.com/cap/relay-target"]
        );
        let derp = m.derp_map.as_ref().unwrap();
        assert_eq!(derp.regions[&1000].nodes[0].host_name, "derp.lab");
        assert!(m.dns_config.is_some());
    }

    #[test]
    fn observed_peer_patch() {
        let m: MapResponse = serde_json::from_str(include_str!(
            "../../../fixtures/observed/20261010-flowmesh-probe/map-0001.json"
        ))
        .unwrap();
        assert_eq!(m.peers_changed_patch.len(), 1);
        assert_eq!(m.peers_changed_patch[0].node_id, 3);
        assert_eq!(m.peers_changed_patch[0].online, Some(true));
    }

    #[test]
    fn packet_filters_null_entry_means_delete() {
        let m: MapResponse =
            serde_json::from_str(r#"{"PacketFilters":{"base":null,"*":null}}"#).unwrap();
        let pf = m.packet_filters.unwrap();
        assert_eq!(pf.get("base"), Some(&None));
        assert_eq!(pf.get("*"), Some(&None));
    }

    #[test]
    fn hostinfo_netinfo_preferred_derp_field_name() {
        let h = Hostinfo {
            net_info: Some(NetInfo {
                preferred_derp: 1000,
            }),
            ..Default::default()
        };
        let v = serde_json::to_value(&h).unwrap();
        assert_eq!(v["NetInfo"]["PreferredDERP"], 1000);
        assert!(
            serde_json::to_value(Hostinfo::default())
                .unwrap()
                .get("NetInfo")
                .is_none()
        );
    }

    #[test]
    fn peers_absent_differs_from_peers_empty() {
        let absent: MapResponse = serde_json::from_str("{}").unwrap();
        let empty: MapResponse = serde_json::from_str(r#"{"Peers":[]}"#).unwrap();
        assert_eq!(absent.peers, None);
        assert_eq!(empty.peers, Some(vec![]));
    }
}
