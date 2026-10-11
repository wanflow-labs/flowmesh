// SPDX-License-Identifier: Apache-2.0
//! `flowmesh netcheck`: what the network allows, measured from this process like the official
//! client does (OBS-20261012-cli-more-official/netcheck*.txt): STUN to every relay region in the
//! map flowmeshd has, giving UDP reachability, the external address(es) and per-region latency.
//! Regions that do not answer STUN (STUN off, UDP blocked) are timed by a TCP connect to the relay
//! instead. Unlike the official client, nothing is fetched from anywhere when the daemon has no
//! map (deviations.md #13).

use flowmesh_proto::derp::{DerpMap, DerpRegion};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const DEFAULT_STUN_PORT: u16 = 3478;
/// STUN requests per target, spaced this far apart (lost requests are common on busy links).
const ATTEMPTS: u32 = 3;
const ATTEMPT_GAP: Duration = Duration::from_millis(300);
/// How long to wait for answers after the last request.
const ANSWER_WAIT: Duration = Duration::from_secs(2);
const TCP_TIMEOUT: Duration = Duration::from_secs(2);

/// One STUN answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub region: u32,
    pub rtt: Duration,
    /// This host's address as the STUN server saw it.
    pub mapped: SocketAddr,
}

/// The measurements, with the official report's fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub now: Duration,
    pub udp: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub ipv4_can_send: bool,
    pub ipv6_can_send: bool,
    pub os_has_ipv6: bool,
    pub mapping_varies_by_dest_ip: bool,
    pub preferred_derp: u32,
    pub region_latency: BTreeMap<u32, Duration>,
    pub region_v4_latency: BTreeMap<u32, Duration>,
    pub region_v6_latency: BTreeMap<u32, Duration>,
    pub global_v4_counters: BTreeMap<SocketAddr, u32>,
    pub global_v6_counters: BTreeMap<SocketAddr, u32>,
    pub global_v4: Option<SocketAddr>,
    pub global_v6: Option<SocketAddr>,
}

/// What the probes saw, before it is summarized.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub samples: Vec<Sample>,
    /// Regions timed by TCP connect (no STUN answer).
    pub tcp: Vec<(u32, Duration)>,
    pub ipv4_can_send: bool,
    pub ipv6_can_send: bool,
    pub os_has_ipv6: bool,
}

fn measured(r: &DerpRegion) -> bool {
    !r.no_measure_no_home
}

fn most_seen(counts: &BTreeMap<SocketAddr, u32>) -> Option<SocketAddr> {
    // Highest count; among equals the first in address order, so the result is stable.
    counts
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .map(|(a, _)| *a)
}

fn keep_min(m: &mut BTreeMap<u32, Duration>, region: u32, d: Duration) {
    m.entry(region)
        .and_modify(|x| *x = (*x).min(d))
        .or_insert(d);
}

/// Summarize probe results the way the official report does.
pub fn summarize(dm: &DerpMap, o: &Observed, now: Duration) -> Report {
    let mut r = Report {
        now,
        udp: !o.samples.is_empty(),
        ipv4_can_send: o.ipv4_can_send,
        ipv6_can_send: o.ipv6_can_send,
        os_has_ipv6: o.os_has_ipv6,
        ..Default::default()
    };
    for s in &o.samples {
        let v6 = s.mapped.ip().to_canonical().is_ipv6();
        let (per_family, counters) = if v6 {
            (&mut r.region_v6_latency, &mut r.global_v6_counters)
        } else {
            (&mut r.region_v4_latency, &mut r.global_v4_counters)
        };
        keep_min(per_family, s.region, s.rtt);
        *counters.entry(s.mapped).or_default() += 1;
        keep_min(&mut r.region_latency, s.region, s.rtt);
    }
    for (region, d) in &o.tcp {
        if !r.region_latency.contains_key(region) {
            r.region_latency.insert(*region, *d);
        }
    }
    r.ipv4 = !r.global_v4_counters.is_empty();
    r.ipv6 = !r.global_v6_counters.is_empty();
    r.global_v4 = most_seen(&r.global_v4_counters);
    r.global_v6 = most_seen(&r.global_v6_counters);
    // Different servers saw different source ports: the NAT maps per destination.
    r.mapping_varies_by_dest_ip = r.global_v4_counters.len() > 1;
    r.preferred_derp = r
        .region_latency
        .iter()
        .filter(|(id, _)| dm.regions.get(id).is_some_and(|g| !g.avoid && measured(g)))
        .min_by_key(|(id, d)| (**d, **id))
        .map_or(0, |(id, _)| *id);
    r
}

/// Go's `time.Duration.String` for a value rounded to 100µs (the official report rounds so).
pub fn go_duration(d: Duration) -> String {
    let step = 100_000u128;
    let ns = (d.as_nanos() + step / 2) / step * step;
    if ns == 0 {
        return "0s".into();
    }
    let (unit, suffix) = if ns < 1_000_000 {
        (1_000, "µs")
    } else if ns < 1_000_000_000 {
        (1_000_000, "ms")
    } else {
        (1_000_000_000, "s")
    };
    let whole = ns / unit;
    let frac = ns % unit;
    if frac == 0 {
        return format!("{whole}{suffix}");
    }
    let digits = unit.ilog10() as usize;
    let f = format!("{frac:0digits$}");
    format!("{whole}.{}{suffix}", f.trim_end_matches('0'))
}

/// RFC 3339 with nanoseconds, trailing zeros trimmed, UTC (Go's `time.RFC3339Nano`).
pub fn rfc3339_nano(since_epoch: Duration) -> String {
    let secs = since_epoch.as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let mut s = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    );
    let nanos = since_epoch.subsec_nanos();
    if nanos != 0 {
        let f = format!("{nanos:09}");
        s.push('.');
        s.push_str(f.trim_end_matches('0'));
    }
    s.push('Z');
    s
}

/// The human-readable report, laid out like the official one.
pub fn text(dm: &DerpMap, r: &Report) -> String {
    let mut o = String::from("\nReport:\n");
    let _ = writeln!(o, "\t* Time: {}", rfc3339_nano(r.now));
    let _ = writeln!(o, "\t* UDP: {}", r.udp);
    match r.global_v4 {
        Some(a) => _ = writeln!(o, "\t* IPv4: yes, {a}"),
        None => _ = writeln!(o, "\t* IPv4: (no addr found)"),
    }
    match r.global_v6 {
        Some(a) => _ = writeln!(o, "\t* IPv6: yes, {a}"),
        None if r.ipv6 => _ = writeln!(o, "\t* IPv6: (no addr found)"),
        None if r.os_has_ipv6 => _ = writeln!(o, "\t* IPv6: no, but OS has support"),
        None => _ = writeln!(o, "\t* IPv6: no, unavailable in OS"),
    }
    let _ = writeln!(
        o,
        "\t* MappingVariesByDestIP: {}",
        r.mapping_varies_by_dest_ip
    );
    // flowmesh does not use UPnP, NAT-PMP or PCP.
    let _ = writeln!(o, "\t* PortMapping: ");
    match dm.regions.get(&r.preferred_derp) {
        Some(g) => _ = writeln!(o, "\t* Nearest DERP: {}", g.region_name),
        None => _ = writeln!(o, "\t* Nearest DERP: [none]"),
    }
    let _ = writeln!(o, "\t* DERP latency:");
    let mut regions: Vec<&DerpRegion> = dm.regions.values().collect();
    regions.sort_by_key(|g| {
        (
            r.region_latency
                .get(&g.region_id)
                .copied()
                .unwrap_or(Duration::MAX),
            g.region_id,
        )
    });
    for g in regions {
        let latency = r
            .region_latency
            .get(&g.region_id)
            .map(|d| go_duration(*d))
            .unwrap_or_default();
        // Go pads by characters (runes), not bytes: "µ" is one.
        let pad = 7usize.saturating_sub(latency.chars().count());
        let _ = writeln!(
            o,
            "\t\t- {:>3}: {latency}{} ({})",
            g.region_code,
            " ".repeat(pad),
            g.region_name
        );
    }
    o
}

/// The `--format=json` report: the official field names and order, tab-indented, latencies in
/// nanoseconds.
pub fn json(r: &Report) -> String {
    use serde_json::{Value, json};
    let lat = |m: &BTreeMap<u32, Duration>| {
        // Keys sort as strings, like Go's encoder does for map keys.
        let sorted: BTreeMap<String, u128> = m
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_nanos()))
            .collect();
        json!(sorted)
    };
    let counters = |m: &BTreeMap<SocketAddr, u32>| {
        if m.is_empty() {
            return Value::Null;
        }
        let sorted: BTreeMap<String, u32> = m.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        json!(sorted)
    };
    let addr = |a: Option<SocketAddr>| a.map(|a| a.to_string()).unwrap_or_default();
    let fields: [(&str, Value); 21] = [
        ("Now", json!(rfc3339_nano(r.now))),
        ("UDP", json!(r.udp)),
        ("IPv6", json!(r.ipv6)),
        ("IPv4", json!(r.ipv4)),
        ("IPv6CanSend", json!(r.ipv6_can_send)),
        ("IPv4CanSend", json!(r.ipv4_can_send)),
        ("OSHasIPv6", json!(r.os_has_ipv6)),
        ("ICMPv4", json!(false)),
        ("MappingVariesByDestIP", json!(r.mapping_varies_by_dest_ip)),
        ("UPnP", json!(false)),
        ("PMP", json!(false)),
        ("PCP", json!(false)),
        ("PreferredDERP", json!(r.preferred_derp)),
        ("RegionLatency", lat(&r.region_latency)),
        ("RegionV4Latency", lat(&r.region_v4_latency)),
        ("RegionV6Latency", lat(&r.region_v6_latency)),
        ("GlobalV4Counters", counters(&r.global_v4_counters)),
        ("GlobalV6Counters", counters(&r.global_v6_counters)),
        ("GlobalV4", json!(addr(r.global_v4))),
        ("GlobalV6", json!(addr(r.global_v6))),
        ("CaptivePortal", Value::Null),
    ];
    // serde_json's map sorts keys; write the top level by hand to keep the official order.
    let mut out = String::from("{\n");
    for (i, (k, v)) in fields.iter().enumerate() {
        let mut buf = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(
            &mut buf,
            serde_json::ser::PrettyFormatter::with_indent(b"\t"),
        );
        let _ = serde::Serialize::serialize(v, &mut ser);
        let body = String::from_utf8_lossy(&buf).replace('\n', "\n\t");
        let comma = if i + 1 < fields.len() { "," } else { "" };
        let _ = writeln!(out, "\t{}: {body}{comma}", Value::String((*k).into()));
    }
    out.push('}');
    out
}

/// One STUN target: a relay node's address and port.
#[derive(Debug, Clone, Copy)]
struct Target {
    region: u32,
    addr: SocketAddr,
}

async fn targets(dm: &DerpMap) -> Vec<Target> {
    let mut out = Vec::new();
    for g in dm.regions.values().filter(|g| measured(g)) {
        for n in &g.nodes {
            if n.stun_port == -1 {
                continue;
            }
            let port = u16::try_from(n.stun_port)
                .ok()
                .filter(|p| *p != 0)
                .unwrap_or(DEFAULT_STUN_PORT);
            let mut ips: Vec<IpAddr> = [&n.ipv4, &n.ipv6]
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            if ips.is_empty() && n.ipv4.is_empty() && n.ipv6.is_empty() {
                if let Ok(found) = tokio::net::lookup_host((n.host_name.as_str(), port)).await {
                    ips = found.map(|a| a.ip()).collect();
                }
            }
            out.extend(ips.into_iter().map(|ip| Target {
                region: g.region_id,
                addr: SocketAddr::new(ip, port),
            }));
        }
    }
    out
}

/// Time a TCP connect to each region's relay (for regions STUN did not reach).
async fn tcp_latency(dm: &DerpMap, skip: &[u32]) -> Vec<(u32, Duration)> {
    let mut set = tokio::task::JoinSet::new();
    for g in dm
        .regions
        .values()
        .filter(|g| measured(g) && !skip.contains(&g.region_id))
    {
        let Some(n) = g.nodes.iter().find(|n| !n.stun_only) else {
            continue;
        };
        let host = if n.ipv4.is_empty() {
            n.host_name.clone()
        } else {
            n.ipv4.clone()
        };
        let port = if n.derp_port == 0 { 443 } else { n.derp_port };
        let id = g.region_id;
        set.spawn(async move {
            let t = Instant::now();
            let ok = tokio::time::timeout(
                TCP_TIMEOUT,
                tokio::net::TcpStream::connect((host.as_str(), port)),
            )
            .await
            .is_ok_and(|r| r.is_ok());
            ok.then(|| (id, t.elapsed()))
        });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some(m)) = r {
            out.push(m);
        }
    }
    out
}

async fn recv(
    sock: Option<&tokio::net::UdpSocket>,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match sock {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

/// Probe every region of `dm`.
pub async fn probe(dm: &DerpMap) -> Observed {
    let v4 = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok();
    let v6 = tokio::net::UdpSocket::bind("[::]:0").await.ok();
    let mut o = Observed {
        os_has_ipv6: v6.is_some(),
        ..Default::default()
    };
    let targets = targets(dm).await;
    // Transaction id -> (target index, sent at).
    let mut sent: BTreeMap<[u8; flowmesh_stun::TX_ID_LEN], (usize, Instant)> = BTreeMap::new();
    let mut answered = vec![false; targets.len()];
    let (mut buf4, mut buf6) = ([0u8; 1500], [0u8; 1500]);
    let mut next_round = Instant::now();
    let mut round = 0;
    let mut deadline = Instant::now() + ANSWER_WAIT;
    loop {
        if round < ATTEMPTS && Instant::now() >= next_round {
            for (i, t) in targets.iter().enumerate().filter(|(i, _)| !answered[*i]) {
                let sock = if t.addr.is_ipv4() { &v4 } else { &v6 };
                let Some(sock) = sock else { continue };
                let mut tx = [0u8; flowmesh_stun::TX_ID_LEN];
                if getrandom::fill(&mut tx).is_err() {
                    continue;
                }
                if sock
                    .send_to(&flowmesh_stun::binding_request(tx), t.addr)
                    .await
                    .is_ok()
                {
                    if t.addr.is_ipv4() {
                        o.ipv4_can_send = true;
                    } else {
                        o.ipv6_can_send = true;
                    }
                    sent.insert(tx, (i, Instant::now()));
                }
            }
            round += 1;
            next_round = Instant::now() + ATTEMPT_GAP;
            deadline = Instant::now() + ANSWER_WAIT;
        }
        if answered.iter().all(|a| *a) || (round >= ATTEMPTS && Instant::now() >= deadline) {
            break;
        }
        let wake = if round < ATTEMPTS {
            next_round
        } else {
            deadline
        };
        let got = tokio::time::timeout_at(wake.into(), async {
            tokio::select! {
                Ok((n, _)) = recv(v4.as_ref(), &mut buf4) => Some(&buf4[..n]),
                Ok((n, _)) = recv(v6.as_ref(), &mut buf6) => Some(&buf6[..n]),
                else => None,
            }
        })
        .await;
        let Ok(Some(answer)) = got else { continue };
        let Ok((tx, mapped)) = flowmesh_stun::parse_response(answer) else {
            continue;
        };
        if let Some((i, at)) = sent.remove(&tx) {
            if !answered[i] {
                answered[i] = true;
                o.samples.push(Sample {
                    region: targets[i].region,
                    rtt: at.elapsed(),
                    mapped,
                });
            }
        }
    }
    let reached: Vec<u32> = o.samples.iter().map(|s| s.region).collect();
    o.tcp = tcp_latency(dm, &reached).await;
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmesh_proto::derp::{DerpNode, DerpRegion};

    fn dm() -> DerpMap {
        let mut dm = DerpMap::default();
        for (id, code, name) in [
            (1000, "wanflow-relay-1000", "Lab Relay"),
            (1001, "wanflow-relay-1001", "Lab Relay 2"),
        ] {
            dm.regions.insert(
                id,
                DerpRegion {
                    region_id: id,
                    region_code: code.into(),
                    region_name: name.into(),
                    nodes: vec![DerpNode {
                        region_id: id,
                        host_name: "relay.lab".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
        }
        dm
    }

    fn sample(region: u32, us: u64, mapped: &str) -> Sample {
        Sample {
            region,
            rtt: Duration::from_micros(us),
            mapped: mapped.parse().unwrap(),
        }
    }

    #[test]
    fn go_durations() {
        assert_eq!(go_duration(Duration::from_micros(130)), "100µs");
        assert_eq!(go_duration(Duration::from_micros(274)), "300µs");
        assert_eq!(go_duration(Duration::from_micros(57_812)), "57.8ms");
        assert_eq!(go_duration(Duration::from_micros(220_040)), "220ms");
        assert_eq!(go_duration(Duration::from_micros(1_234_567)), "1.2346s");
        assert_eq!(go_duration(Duration::from_micros(20)), "0s");
    }

    #[test]
    fn rfc3339() {
        assert_eq!(
            rfc3339_nano(Duration::new(1_791_736_561, 763_324_210)),
            "2026-10-11T16:36:01.76332421Z"
        );
        assert_eq!(
            rfc3339_nano(Duration::from_secs(951_782_400)),
            "2000-02-29T00:00:00Z"
        );
    }

    /// Same report as the official one for the same measurements (netcheck.txt).
    #[test]
    fn text_like_the_official_report() {
        let o = Observed {
            samples: vec![
                sample(1001, 130, "172.29.0.111:53142"),
                sample(1000, 290, "172.29.0.111:53142"),
            ],
            ipv4_can_send: true,
            os_has_ipv6: true,
            ..Default::default()
        };
        let r = summarize(&dm(), &o, Duration::new(1_791_736_561, 763_324_210));
        assert_eq!(r.preferred_derp, 1001);
        assert!(!r.mapping_varies_by_dest_ip);
        let official =
            include_str!("../../../fixtures/observed/20261012-cli-more-official/netcheck.txt");
        let want: String = official
            .lines()
            .filter(|l| !l.starts_with('$') && !l.starts_with("[exit") && !l.starts_with("2026/"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(text(&dm(), &r), want);
    }

    #[test]
    fn json_like_the_official_report() {
        let o = Observed {
            samples: vec![
                sample(1000, 274, "172.29.0.111:51570"),
                sample(1001, 365, "172.29.0.111:51570"),
            ],
            ipv4_can_send: true,
            os_has_ipv6: true,
            ..Default::default()
        };
        let mut r = summarize(&dm(), &o, Duration::new(1_791_736_562, 101_115_002));
        // The official report keeps nanoseconds; ours too.
        r.region_latency.insert(1000, Duration::from_nanos(274_208));
        r.region_v4_latency
            .insert(1000, Duration::from_nanos(274_208));
        r.region_latency.insert(1001, Duration::from_nanos(365_334));
        r.region_v4_latency
            .insert(1001, Duration::from_nanos(365_334));
        r.global_v4_counters
            .insert("172.29.0.111:51570".parse().unwrap(), 2);
        let official =
            include_str!("../../../fixtures/observed/20261012-cli-more-official/netcheck-json.txt");
        let want: String = official
            .lines()
            .filter(|l| {
                !l.starts_with('$')
                    && !l.starts_with("[exit")
                    && !l.starts_with("2026/")
                    && !l.starts_with('#')
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(json(&r), want);
    }

    #[test]
    fn mapping_that_varies_and_tcp_fallback() {
        let o = Observed {
            samples: vec![
                sample(1000, 500, "198.51.100.7:1000"),
                sample(1001, 900, "198.51.100.7:2000"),
            ],
            ..Default::default()
        };
        let r = summarize(&dm(), &o, Duration::ZERO);
        assert!(r.mapping_varies_by_dest_ip);
        // No STUN at all: latency from TCP, no address, UDP false.
        let o = Observed {
            tcp: vec![
                (1000, Duration::from_millis(9)),
                (1001, Duration::from_millis(4)),
            ],
            ..Default::default()
        };
        let r = summarize(&dm(), &o, Duration::ZERO);
        assert!(!r.udp && r.global_v4.is_none());
        assert_eq!(r.preferred_derp, 1001);
        assert!(text(&dm(), &r).contains("\t* IPv4: (no addr found)\n"));
        assert!(text(&dm(), &r).contains("\t* IPv6: no, unavailable in OS\n"));
    }
}
