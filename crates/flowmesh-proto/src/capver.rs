// SPDX-License-Identifier: Apache-2.0
//! 能力版本。

/// flowmesh 向控制服务器声明的能力版本，与参照物官方客户端 1.94.2 相同。
///
/// 出处：docs/protocol/control.md §1（OBS-20261010-control-handshake）。
pub const CAPABILITY_VERSION: u16 = 131;
