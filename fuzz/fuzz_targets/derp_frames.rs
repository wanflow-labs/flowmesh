// SPDX-License-Identifier: Apache-2.0
//! Untrusted input: the byte stream from a DERP server.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut dec = flowmesh_derp::frame::FrameDecoder::default();
    // Feed in two pieces to exercise partial frames.
    let cut = data.len() / 2;
    dec.push(&data[..cut]);
    while let Ok(Some(_)) = dec.next_frame() {}
    dec.push(&data[cut..]);
    while let Ok(Some(f)) = dec.next_frame() {
        let _ = flowmesh_derp::handshake::parse_server_key(&f.payload);
    }
    let _ = flowmesh_derp::handshake::parse_server_key(data);
});
