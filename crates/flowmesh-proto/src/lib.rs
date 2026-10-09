// SPDX-License-Identifier: Apache-2.0
//! flowmesh 协议的线上数据类型：密钥与控制消息。本 crate 不做任何 IO。
//!
//! 每个协议字段都对应 `docs/protocol/` 中的一条规范，规范里写明了出处。

pub mod capver;
pub mod control;
pub mod derp;
pub mod filter;
pub mod key;
