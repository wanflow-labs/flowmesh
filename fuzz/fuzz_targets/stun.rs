// SPDX-License-Identifier: Apache-2.0
//! Untrusted input: STUN responses (any UDP sender can reach the socket).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = flowmesh_stun::is_stun(data);
    let _ = flowmesh_stun::parse_response(data);
});
