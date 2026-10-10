// SPDX-License-Identifier: Apache-2.0
//! `flowmesh ping`: output lines, messages and exit codes follow the official client
//! (observed in OBS-20261010-ping): pong and "timed out" lines on stdout, the final verdict on stderr.

use serde_json::Value;
use std::future::Future;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Maximum number of pings (official default 10).
    pub count: u32,
    /// Stop at the first direct pong; fail if none came (official default true).
    pub until_direct: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            count: 10,
            until_direct: true,
        }
    }
}

/// One answer from `/localapi/v0/ping`.
#[derive(Debug, Clone, PartialEq)]
pub enum Attempt {
    Pong { line: String, direct: bool },
    Timeout,
    NoPeer,
}

/// Map an API answer to an attempt; unknown errors are passed through as text.
pub fn parse_attempt(v: &Value) -> Result<Attempt, String> {
    match v["Err"].as_str().unwrap_or("") {
        "" => {}
        "timed out" => return Ok(Attempt::Timeout),
        "no matching peer" => return Ok(Attempt::NoPeer),
        other => return Err(other.to_string()),
    }
    let endpoint = v["Endpoint"].as_str().unwrap_or("");
    let (via, direct) = if endpoint.is_empty() {
        (
            format!("DERP({})", v["DERPRegionCode"].as_str().unwrap_or("")),
            false,
        )
    } else {
        (endpoint.to_string(), true)
    };
    let line = format!(
        "pong from {} ({}) via {via} in {}",
        v["NodeName"].as_str().unwrap_or(""),
        v["NodeIP"].as_str().unwrap_or(""),
        go_duration(v["LatencySeconds"].as_f64().unwrap_or(0.0)),
    );
    Ok(Attempt::Pong { line, direct })
}

/// Latency as Go prints a duration rounded to the millisecond: `0s`, `7ms`, `1.5s`.
pub fn go_duration(secs: f64) -> String {
    let ms = (secs * 1000.0).round();
    if ms < 1.0 {
        "0s".to_string()
    } else if ms < 1000.0 {
        format!("{ms}ms")
    } else {
        let s = format!("{:.3}", ms / 1000.0);
        format!("{}s", s.trim_end_matches('0').trim_end_matches('.'))
    }
}

/// Find the mesh IP for a peer given as an IP, a short name, a host name or a full DNS name.
pub fn resolve(status: &Value, target: &str) -> Option<String> {
    if target.parse::<std::net::IpAddr>().is_ok() {
        return Some(target.to_string());
    }
    let wanted = target.trim_end_matches('.');
    status["Peer"].as_object()?.values().find_map(|p| {
        let dns = p["DNSName"].as_str().unwrap_or("").trim_end_matches('.');
        let short = dns.split('.').next().unwrap_or("");
        let host = p["HostName"].as_str().unwrap_or("");
        let hit = !wanted.is_empty() && (dns == wanted || short == wanted || host == wanted);
        hit.then(|| p["TailscaleIPs"][0].as_str().map(str::to_string))
            .flatten()
    })
}

/// Run the ping loop; `ping` performs one attempt. Returns the exit code.
pub async fn run<F, Fut>(
    target_ip: &str,
    opts: Options,
    out: &mut dyn Write,
    err: &mut dyn Write,
    mut ping: F,
) -> u8
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Attempt, String>>,
{
    let mut answered = false;
    for _ in 0..opts.count {
        match ping().await {
            Ok(Attempt::Pong { line, direct }) => {
                let _ = writeln!(out, "{line}");
                answered = true;
                if direct && opts.until_direct {
                    return 0;
                }
            }
            Ok(Attempt::Timeout) => {
                let _ = writeln!(out, "ping {target_ip:?} timed out");
            }
            Ok(Attempt::NoPeer) => {
                let _ = writeln!(err, "no matching peer");
                return 1;
            }
            Err(e) => {
                let _ = writeln!(err, "{e}");
                return 1;
            }
        }
    }
    if !answered {
        let _ = writeln!(err, "no reply");
        return 1;
    }
    if opts.until_direct {
        let _ = writeln!(err, "direct connection not established");
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;

    fn direct() -> Value {
        json!({ "Err": "", "NodeName": "ts1", "NodeIP": "100.64.0.1", "Endpoint": "172.29.0.21:59419",
                "DERPRegionID": 0, "DERPRegionCode": "", "LatencySeconds": 0.0021 })
    }

    fn relay() -> Value {
        json!({ "Err": "", "NodeName": "fm-a", "NodeIP": "100.64.0.9", "Endpoint": "",
                "DERPRegionID": 1000, "DERPRegionCode": "wanflow-relay-1000", "LatencySeconds": 0.0059 })
    }

    #[test]
    fn pong_lines_match_the_official_format() {
        assert_eq!(
            parse_attempt(&direct()),
            Ok(Attempt::Pong {
                line: "pong from ts1 (100.64.0.1) via 172.29.0.21:59419 in 2ms".into(),
                direct: true
            })
        );
        assert_eq!(
            parse_attempt(&relay()),
            Ok(Attempt::Pong {
                line: "pong from fm-a (100.64.0.9) via DERP(wanflow-relay-1000) in 6ms".into(),
                direct: false
            })
        );
        assert_eq!(
            parse_attempt(&json!({ "Err": "timed out" })),
            Ok(Attempt::Timeout)
        );
        assert_eq!(
            parse_attempt(&json!({ "Err": "no matching peer" })),
            Ok(Attempt::NoPeer)
        );
        assert_eq!(
            parse_attempt(&json!({ "Err": "boom" })),
            Err("boom".to_string())
        );
    }

    #[test]
    fn durations_like_go() {
        assert_eq!(go_duration(0.0004), "0s");
        assert_eq!(go_duration(0.001), "1ms");
        assert_eq!(go_duration(0.0021), "2ms");
        assert_eq!(go_duration(0.999), "999ms");
        assert_eq!(go_duration(1.0), "1s", "exactly a second switches unit");
        assert_eq!(go_duration(1.5), "1.5s");
        assert_eq!(go_duration(2.0), "2s");
        assert_eq!(go_duration(1.2346), "1.235s");
    }

    #[test]
    fn resolve_by_ip_and_names() {
        let s = json!({ "Peer": {
            "nodekey:a": { "DNSName": "ts-a-e2zlhu95.mesh.lab.internal.", "HostName": "ts-a",
                           "TailscaleIPs": ["100.64.0.10", "fd7a:115c:a1e0::a"] },
            "nodekey:b": { "DNSName": "", "HostName": "", "TailscaleIPs": ["100.64.0.11"] }
        }});
        assert_eq!(resolve(&s, "100.64.0.99").as_deref(), Some("100.64.0.99"));
        for t in [
            "ts-a-e2zlhu95",
            "ts-a",
            "ts-a-e2zlhu95.mesh.lab.internal",
            "ts-a-e2zlhu95.mesh.lab.internal.",
        ] {
            assert_eq!(resolve(&s, t).as_deref(), Some("100.64.0.10"), "{t}");
        }
        assert_eq!(resolve(&s, "nosuch"), None);
        assert_eq!(
            resolve(&s, ""),
            None,
            "an empty name must not match unnamed peers"
        );
        assert_eq!(resolve(&json!({ "Peer": null }), "ts-a"), None);
    }

    /// Feed a scripted sequence of attempts; return (exit, stdout, stderr, attempts used).
    async fn script(
        opts: Options,
        seq: Vec<Result<Attempt, String>>,
    ) -> (u8, String, String, usize) {
        let mut q: VecDeque<_> = seq.into();
        let mut used = 0;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run("100.64.0.9", opts, &mut out, &mut err, || {
            used += 1;
            let next = q.pop_front().unwrap_or(Ok(Attempt::Timeout));
            async move { next }
        })
        .await;
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
            used,
        )
    }

    fn pong(direct: bool) -> Result<Attempt, String> {
        Ok(Attempt::Pong {
            line: format!("pong direct={direct}"),
            direct,
        })
    }

    #[tokio::test]
    async fn stops_at_first_direct_pong() {
        let (code, out, err, used) = script(
            Options::default(),
            vec![pong(false), pong(true), pong(true)],
        )
        .await;
        assert_eq!((code, used), (0, 2));
        assert_eq!(out, "pong direct=false\npong direct=true\n");
        assert_eq!(err, "");
    }

    #[tokio::test]
    async fn relay_only_fails_after_count() {
        let opts = Options {
            count: 3,
            until_direct: true,
        };
        let (code, out, err, used) =
            script(opts, vec![pong(false), pong(false), pong(false)]).await;
        assert_eq!((code, used), (1, 3));
        assert_eq!(out.lines().count(), 3);
        assert_eq!(err, "direct connection not established\n");
    }

    #[tokio::test]
    async fn without_until_direct_relay_pongs_succeed() {
        let opts = Options {
            count: 2,
            until_direct: false,
        };
        let (code, _, err, used) = script(opts, vec![pong(false), pong(true)]).await;
        assert_eq!((code, used, err.as_str()), (0, 2, ""));
    }

    #[tokio::test]
    async fn timeouts_then_no_reply() {
        let opts = Options {
            count: 3,
            until_direct: true,
        };
        let (code, out, err, _) = script(opts, vec![]).await;
        assert_eq!(code, 1);
        assert_eq!(out, "ping \"100.64.0.9\" timed out\n".repeat(3));
        assert_eq!(err, "no reply\n");
    }

    #[tokio::test]
    async fn a_late_pong_after_timeouts_counts_as_answered() {
        let opts = Options {
            count: 2,
            until_direct: false,
        };
        let (code, _, err, _) = script(opts, vec![Ok(Attempt::Timeout), pong(false)]).await;
        assert_eq!((code, err.as_str()), (0, ""));
    }

    #[tokio::test]
    async fn no_peer_and_errors_stop_immediately() {
        let (code, _, err, used) = script(Options::default(), vec![Ok(Attempt::NoPeer)]).await;
        assert_eq!((code, used, err.as_str()), (1, 1, "no matching peer\n"));
        let (code, _, err, used) = script(
            Options::default(),
            vec![Err("flowmesh is not running".into())],
        )
        .await;
        assert_eq!(
            (code, used, err.as_str()),
            (1, 1, "flowmesh is not running\n")
        );
    }

    #[test]
    fn defaults_are_official() {
        assert_eq!(
            Options::default(),
            Options {
                count: 10,
                until_direct: true
            }
        );
    }
}
