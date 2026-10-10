// SPDX-License-Identifier: Apache-2.0
//! Untrusted input: DNS queries sent to 100.100.100.100 by anything on the host.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static VIEW: OnceLock<flowmesh_dns::DnsView> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let view = VIEW.get_or_init(|| {
        flowmesh_dns::DnsView::new(
            &["mesh.lab.internal".into()],
            &[("64.100.in-addr.arpa".into(), true), ("0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa".into(), true)],
            &[flowmesh_dns::HostEntry {
                fqdn: "ts1.mesh.lab.internal.".into(),
                addrs: vec!["100.64.0.1".parse().expect("ip"), "fd7a:115c:a1e0::1".parse().expect("ip")],
            }],
            &[],
            true,
        )
    });
    let _ = flowmesh_dns::handle(view, data);
});
