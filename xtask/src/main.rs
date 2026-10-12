// SPDX-License-Identifier: Apache-2.0
//! Development helper tasks for flowmesh. Usage: `cargo xtask <subcommand>`.

mod extract;
mod similarity;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask similarity --reference <dir>... \
[--allowlist <file>] [--min-tokens <n>] <scan-dir>...";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("similarity") => similarity::run(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
