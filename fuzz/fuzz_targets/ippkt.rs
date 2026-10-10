// SPDX-License-Identifier: Apache-2.0
//! Untrusted input: IP packets from the TUN device and, decrypted, from peers.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = flowmesh_dataplane::ippkt::parse(data);
    let _ = flowmesh_dataplane::ippkt::udp4_payload(data);
});
