// SPDX-License-Identifier: Apache-2.0
//! Untrusted input: netmap messages from the control server, and everything derived from them.
#![no_main]
use flowmesh_control::netmap::NetMap;
use flowmesh_proto::control::MapResponse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(m) = serde_json::from_slice::<MapResponse>(data) else {
        return;
    };
    let mut nm = NetMap::default();
    nm.apply(&m);
    nm.apply(&m);
    let rules = nm.filter_rules();
    let _ = flowmesh_filter::compile::compile(&rules);
    let me: Vec<std::net::IpAddr> = nm
        .self_node
        .iter()
        .flat_map(|n| n.addresses.iter().map(|a| a.addr()))
        .collect();
    for n in nm.peers.values() {
        for a in &n.addresses {
            let _ = flowmesh_filter::caps::peer_caps(&rules, a.addr(), &me);
        }
    }
    if let Some(dns) = &nm.dns {
        let routes: Vec<(String, bool)> = dns.routes.iter().map(|(k, v)| (k.clone(), v.is_empty())).collect();
        let hosts: Vec<flowmesh_dns::HostEntry> = nm
            .peers
            .values()
            .map(|n| flowmesh_dns::HostEntry {
                fqdn: n.name.clone(),
                addrs: n.addresses.iter().map(|a| a.addr()).collect(),
            })
            .collect();
        let _ = flowmesh_dns::DnsView::new(&dns.domains, &routes, &hosts, &dns.extra_records, true);
    }
});
