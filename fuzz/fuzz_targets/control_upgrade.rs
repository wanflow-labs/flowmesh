// SPDX-License-Identifier: Apache-2.0
//! Untrusted input: the control server's HTTP upgrade response and early payload.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = flowmesh_control::upgrade::parse_response(data);
    let mut buf = data.to_vec();
    let _ = flowmesh_control::early::take_early(&mut buf);
});
