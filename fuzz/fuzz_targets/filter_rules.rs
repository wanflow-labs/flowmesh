// SPDX-License-Identifier: Apache-2.0
//! Untrusted input: packet filter rules (compile must reject, never panic).
#![no_main]
use flowmesh_proto::filter::FilterRule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(rules) = serde_json::from_slice::<Vec<FilterRule>>(data) {
        let _ = flowmesh_filter::compile::compile(&rules);
        let _ = flowmesh_filter::caps::peer_caps(
            &rules,
            std::net::IpAddr::from([100, 64, 0, 1]),
            &[std::net::IpAddr::from([100, 64, 0, 2])],
        );
    }
});
