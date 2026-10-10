// SPDX-License-Identifier: Apache-2.0
//! Observation tool: decrypt tapped disco messages with this node's disco private key and print the payload (hex).
//! Usage: cargo run -p flowmesh-disco --example dump -- <tap-dir>
//! The tap directory is produced by flowmesh-dev --tap-dir and includes that run's disco private key, disco.key.
#![allow(clippy::unwrap_used, clippy::expect_used)]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::Path::new(&args[1]);
    let key_hex = std::fs::read_to_string(dir.join("disco.key")).unwrap();
    let disco = flowmesh_proto::key::DiscoPrivate::from_hex(key_hex.trim()).unwrap();
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "bin"))
        .collect();
    files.sort();
    for f in files {
        let raw = std::fs::read(&f).unwrap();
        match flowmesh_disco::envelope::open(&disco, &raw) {
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
