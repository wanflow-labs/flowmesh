// SPDX-License-Identifier: Apache-2.0
//! Interop with the lab derper's STUN port. Docker Desktop on macOS doesn't forward UDP reliably, so run it inside the fm1 container:
//! `docker compose -f lab/compose.yaml exec fm1 cargo test -p flowmesh-stun -- --ignored`
//! The target address comes from `FLOWMESH_LAB_STUN`, default `derp.lab:3478`.
#![allow(clippy::unwrap_used)]

use flowmesh_stun::{binding_request, parse_response};
use std::net::UdpSocket;
use std::time::Duration;

#[test]
#[ignore = "needs the lab derper (make lab-up)"]
fn lab_derper_answers_binding_request() {
    let target = std::env::var("FLOWMESH_LAB_STUN").unwrap_or_else(|_| "derp.lab:3478".into());
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let tx = [0x42; 12];
    sock.send_to(&binding_request(tx), target.as_str()).unwrap();
    let mut buf = [0u8; 1500];
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    let (got_tx, mapped) = parse_response(&buf[..n]).unwrap();
    assert_eq!(got_tx, tx);
    println!("mapped address as seen by derper: {mapped}");
    assert!(
        mapped.is_ipv4(),
        "v4-mapped address must be normalized: {mapped}"
    );
    assert_ne!(mapped.port(), 0);
}
