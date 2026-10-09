// SPDX-License-Identifier: Apache-2.0
//! flowmesh 的开发辅助任务，用法：`cargo xtask <子命令>`。

use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask similarity --reference <dir>... \
[--allowlist <file>] [--min-tokens <n>] <scan-dir>...";

fn main() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}
