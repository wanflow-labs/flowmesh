// SPDX-License-Identifier: Apache-2.0
//! Untrusted input: the byte stream of the control connection's outer framing.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut dec = flowmesh_noise::frame::FrameDecoder::default();
    let cut = data.len() / 3;
    dec.push(&data[..cut]);
    while let Ok(Some(_)) = dec.next_frame() {}
    dec.push(&data[cut..]);
    while let Ok(Some(_)) = dec.next_frame() {}
    let _ = dec.buffered();
});
