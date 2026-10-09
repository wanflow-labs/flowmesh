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

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegisterResponse {
    #[serde(rename = "User")]
    pub user: UserProfile,
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
    #[serde(rename = "DNSConfig", skip_serializing_if = "Option::is_none")]
    pub dns_config: Option<DnsConfig>,
    #[serde(rename = "Domain", skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(rename = "PacketFilter", skip_serializing_if = "Option::is_none")]
    pub packet_filter: Option<Vec<FilterRule>>,
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

    #[test]
    fn peers_absent_differs_from_peers_empty() {
        let absent: MapResponse = serde_json::from_str("{}").unwrap();
        let empty: MapResponse = serde_json::from_str(r#"{"Peers":[]}"#).unwrap();
        assert_eq!(absent.peers, None);
        assert_eq!(empty.peers, Some(vec![]));
    }
}
