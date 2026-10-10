// SPDX-License-Identifier: Apache-2.0
//! 中继地图（DERP map）。字段名与控制服务器的 derp-map.yaml 一一对应
//! （lab/headscale/derp-map.yaml 中使用的是小写形式），线上 JSON 采用 PascalCase。

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DerpMap {
    #[serde(rename = "Regions")]
    pub regions: BTreeMap<u32, DerpRegion>,
    #[serde(rename = "OmitDefaultRegions")]
    pub omit_default_regions: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DerpRegion {
    #[serde(rename = "RegionID")]
    pub region_id: u32,
    #[serde(rename = "RegionCode")]
    pub region_code: String,
    #[serde(rename = "RegionName")]
    pub region_name: String,
    #[serde(rename = "Avoid")]
    pub avoid: bool,
    /// 该区域只用于中继，不参与延迟测量，也不能被选作 home（wanflow relay-region 标签语义）。
    #[serde(rename = "NoMeasureNoHome")]
    pub no_measure_no_home: bool,
    #[serde(rename = "Nodes")]
    pub nodes: Vec<DerpNode>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DerpNode {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: u32,
    #[serde(rename = "HostName")]
    pub host_name: String,
    #[serde(rename = "IPv4", skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    #[serde(rename = "IPv6", skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
    /// 0 表示默认端口 3478；-1 表示该节点不提供 STUN（wanflow relay-only 语义，偏差清单 #1）。
    #[serde(rename = "STUNPort")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly")]
    pub stun_only: bool,
    /// 0 表示默认端口 443。
    #[serde(rename = "DERPPort")]
    pub derp_port: u16,
    #[serde(rename = "InsecureForTests")]
    pub insecure_for_tests: bool,
}
