// SPDX-License-Identifier: Apache-2.0
//! 包过滤规则的线上格式。判定语义在 M3 的 flowmesh-filter 中实现（docs/protocol/filter.md）。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterRule {
    #[serde(rename = "SrcIPs")]
    pub src_ips: Vec<String>,
    #[serde(rename = "DstPorts")]
    pub dst_ports: Vec<NetPortRange>,
    /// 为空表示默认协议集合（M3 中确认具体语义）。
    #[serde(rename = "IPProto", skip_serializing_if = "Vec::is_empty")]
    pub ip_proto: Vec<i32>,
    #[serde(rename = "CapGrant", skip_serializing_if = "Vec::is_empty")]
    pub cap_grant: Vec<CapGrant>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetPortRange {
    #[serde(rename = "IP")]
    pub ip: String,
    #[serde(rename = "Ports")]
    pub ports: PortRange,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PortRange {
    #[serde(rename = "First")]
    pub first: u16,
    #[serde(rename = "Last")]
    pub last: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CapGrant {
    #[serde(rename = "Dsts")]
    pub dsts: Vec<ipnet::IpNet>,
    #[serde(rename = "Caps", skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    #[serde(rename = "CapMap", skip_serializing_if = "Option::is_none")]
    pub cap_map: Option<serde_json::Map<String, serde_json::Value>>,
}
