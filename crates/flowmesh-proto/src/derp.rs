// SPDX-License-Identifier: Apache-2.0
//! Relay map (DERP map). Field names map one to one onto the control server's derp-map.yaml
//! (lab/headscale/derp-map.yaml uses the lowercase form); the JSON on the wire uses PascalCase.

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
    /// The region is for relaying only: it is not latency-measured and cannot be chosen as home (relay-region tag semantics).
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
    /// 0 means the default port 3478; -1 means the node offers no STUN (relay-only semantics, deviation #1).
    #[serde(rename = "STUNPort")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly")]
    pub stun_only: bool,
    /// 0 means the default port 443.
    #[serde(rename = "DERPPort")]
    pub derp_port: u16,
    #[serde(rename = "InsecureForTests")]
    pub insecure_for_tests: bool,
}
