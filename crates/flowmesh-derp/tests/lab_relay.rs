// SPDX-License-Identifier: Apache-2.0
//! Interop with the lab derper (needs `make lab-up`; run with `cargo test -p flowmesh-derp -- --ignored`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use flowmesh_derp::client::{DerpClient, Event};
use flowmesh_proto::derp::DerpNode;
use flowmesh_proto::key::NodePrivate;
use std::time::Duration;

fn lab_node() -> DerpNode {
    DerpNode {
        name: "lab-1".into(),
        region_id: 1000,
        host_name: "derp.lab".into(),
        ipv4: "127.0.0.1".into(),
        derp_port: 18443,
        insecure_for_tests: true,
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "needs the lab derper (make lab-up)"]
async fn two_clients_relay_a_packet_through_lab_derper() {
    let (a_key, b_key) = (
        NodePrivate::generate().unwrap(),
        NodePrivate::generate().unwrap(),
    );
    let a = DerpClient::connect(&lab_node(), &a_key).await.unwrap();
    let mut b = DerpClient::connect(&lab_node(), &b_key).await.unwrap();
    assert_eq!(a.server_key(), b.server_key());
    println!("server info: {}", a.server_info());
    a.note_preferred(true).await.unwrap();
    a.send(b_key.public(), b"flowmesh-derp-probe")
        .await
        .unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(5), b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ev,
        Event::Packet {
            src: a_key.public(),
            data: b"flowmesh-derp-probe".to_vec()
        }
    );
}
