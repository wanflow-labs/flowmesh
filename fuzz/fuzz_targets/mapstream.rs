// SPDX-License-Identifier: Apache-2.0
//! Untrusted input: the netmap stream framing, compressed (zstd, with the decompression bomb limit)
//! and not.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for compressed in [true, false] {
        let mut buf = bytes::BytesMut::from(data);
        while let Ok(Some(_)) = flowmesh_control::mapstream::decode_frame(&mut buf, compressed) {}
    }
});
