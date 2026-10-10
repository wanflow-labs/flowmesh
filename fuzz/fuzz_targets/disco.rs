// SPDX-License-Identifier: Apache-2.0
//! Untrusted input: disco packets from any UDP sender or relay.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static KEY: OnceLock<flowmesh_proto::key::DiscoPrivate> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let key = KEY.get_or_init(|| flowmesh_proto::key::DiscoPrivate::generate().expect("random"));
    let _ = flowmesh_disco::envelope::is_disco(data);
    let _ = flowmesh_disco::envelope::sender(data);
    let _ = flowmesh_disco::envelope::open(key, data);
    if let Ok(m) = flowmesh_disco::message::decode(data) {
        // Whatever decodes must encode again without panicking.
        let _ = flowmesh_disco::message::encode(&m);
    }
    let _ = flowmesh_disco::message::parse_addr(data);
});
