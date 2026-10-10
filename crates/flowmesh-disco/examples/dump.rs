// SPDX-License-Identifier: Apache-2.0
//! Observation tool: decrypt tapped disco messages with this node's disco private key and print the payload (hex).
//! Usage: cargo run -p flowmesh-disco --example dump -- <state.json> <tap-dir>
#![allow(clippy::unwrap_used, clippy::expect_used)]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let state = flowmesh_state::load_or_create(std::path::Path::new(&args[1])).unwrap();
    let mut files: Vec<_> = std::fs::read_dir(&args[2])
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    for f in files {
        let raw = std::fs::read(&f).unwrap();
        match flowmesh_disco::envelope::open(&state.disco, &raw) {
            Ok((from, plain)) => {
                let hex: String = plain.iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "{}\tfrom={from}\tlen={}\tpayload={hex}",
                    f.file_name().unwrap().to_string_lossy(),
                    plain.len()
                );
            }
            Err(e) => println!("{}\t{e}", f.display()),
        }
    }
}
