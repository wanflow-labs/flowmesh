// SPDX-License-Identifier: Apache-2.0
//! The exit node's DNS proxy, reached by peers over the mesh ("peerapi"): RFC 8484 DNS-over-HTTP
//! (plain HTTP inside WireGuard) at `/dns-query`, as the official client serves it. Official
//! clients send their DNS through any exit node whose capability version is 26 or more, which
//! includes flowmesh, so a flowmesh exit node must answer here or their DNS breaks
//! (OBS-20261011-exit-node-official).
//!
//! The official handler bypasses the packet filter and decides itself: it answers only while
//! offering an exit node, and only peers whose ACL lets them reach the internet's port 53 (TCP to
//! 0.0.0.0, or to 2000:: from an IPv6 address). flowmesh does the same, and serves nothing else on
//! these ports (deviation #11).

// Only the Linux engine serves it; elsewhere the module exists for its tests.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use base64::Engine as _;
use bytes::Bytes;
use flowmesh_filter::matcher::{Filter, Verdict};
use flowmesh_filter::packet::{IpProto, Packet, TCP_SYN};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Largest DNS message accepted in a request.
const MAX_QUERY: usize = 64 * 1024;
/// How long to wait for the upstream resolver (the official handler's timeout).
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// The DNS message a DoH request carries: GET `?dns=` (base64url, no padding) or POST with
/// `application/dns-message`. The error is the public reason, sent as 400.
pub(crate) fn dns_query(
    method: &Method,
    query: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let q = match *method {
        Method::GET => {
            let b64 = query
                .into_iter()
                .flat_map(|q| q.split('&'))
                .find_map(|kv| kv.strip_prefix("dns="))
                .ok_or("missing 'dns' parameter")?;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(b64.trim_end_matches('='))
                .map_err(|_| "invalid 'dns' base64 encoding")?
        }
        Method::POST => {
            if content_type != Some("application/dns-message") {
                return Err("unexpected Content-Type");
            }
            body.to_vec()
        }
        _ => return Err("bad HTTP method"),
    };
    if q.len() < 12 || q.len() > MAX_QUERY {
        return Err("invalid DNS query");
    }
    Ok(q)
}

/// Whether `remote` may use this exit node's DNS: the ACL must let it reach the internet's port 53.
pub(crate) fn allows_internet_dns(filter: &Filter, remote: IpAddr) -> bool {
    let internet: IpAddr = if remote.is_ipv4() {
        IpAddr::from([0, 0, 0, 0])
    } else {
        "2000::".parse().unwrap_or(IpAddr::from([0u16; 8]))
    };
    let probe = Packet {
        proto: IpProto::Tcp,
        src: remote,
        dst: internet,
        src_port: 0,
        dst_port: 53,
        tcp_flags: TCP_SYN,
        icmp_type: 0,
    };
    filter.check_in(&probe, Duration::ZERO) == Verdict::Accept
}

/// What the handler needs: the current filter rules and the host's resolvers.
pub(crate) struct State {
    pub filter: RwLock<Filter>,
    pub upstreams: Vec<IpAddr>,
}

/// Send `query` to the first upstream over UDP (a socket marked as flowmesh's own) and return the
/// answer.
pub(crate) async fn resolve_udp(upstreams: &[IpAddr], query: &[u8]) -> Option<Vec<u8>> {
    let up = *upstreams.first()?;
    let bind = if up.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = tokio::net::UdpSocket::bind(bind)
        .await
        .inspect(flowmesh_net::mark)
        .ok()?;
    sock.send_to(query, (up, 53)).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(RESOLVE_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.truncate(n);
    Some(buf)
}

fn reply(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    if let Ok(v) = content_type.parse() {
        r.headers_mut().insert(hyper::header::CONTENT_TYPE, v);
    }
    r
}

async fn handle(
    req: Request<Incoming>,
    remote: SocketAddr,
    state: Arc<State>,
) -> Response<Full<Bytes>> {
    if !req.uri().path().starts_with("/dns-query") {
        return reply(StatusCode::NOT_FOUND, "text/plain", "not found\n");
    }
    let allowed = state
        .filter
        .read()
        .is_ok_and(|f| allows_internet_dns(&f, remote.ip()));
    if !allowed {
        return reply(StatusCode::FORBIDDEN, "text/plain", "DNS access denied\n");
    }
    let method = req.method().clone();
    let query = req.uri().query().map(str::to_string);
    let content_type = req
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = match Limited::new(req.into_body(), MAX_QUERY).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return reply(StatusCode::BAD_REQUEST, "text/plain", "invalid DNS query\n"),
    };
    let q = match dns_query(&method, query.as_deref(), content_type.as_deref(), &body) {
        Ok(q) => q,
        Err(e) => return reply(StatusCode::BAD_REQUEST, "text/plain", format!("{e}\n")),
    };
    match resolve_udp(&state.upstreams, &q).await {
        Some(answer) => reply(StatusCode::OK, "application/dns-message", answer),
        None => reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            "text/plain",
            "DNS forwarding error\n",
        ),
    }
}

/// Serve the DNS proxy on `listener` until the task is dropped.
pub(crate) async fn serve(listener: tokio::net::TcpListener, state: Arc<State>) {
    loop {
        let Ok((stream, remote)) = listener.accept().await else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, std::convert::Infallible>(handle(req, remote, state).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowmesh_filter::compile::compile;
    use flowmesh_proto::filter::{FilterRule, NetPortRange, PortRange};

    /// A DNS query for example.com A (id 0xabcd).
    fn query() -> Vec<u8> {
        let mut q = vec![0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    #[test]
    fn doh_get_and_post_carry_the_query() {
        let q = query();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&q);
        assert_eq!(
            dns_query(&Method::GET, Some(&format!("ct=x&dns={b64}")), None, &[]),
            Ok(q.clone())
        );
        assert_eq!(
            dns_query(&Method::POST, None, Some("application/dns-message"), &q),
            Ok(q.clone())
        );
        assert_eq!(
            dns_query(&Method::POST, None, Some("text/plain"), &q),
            Err("unexpected Content-Type")
        );
        assert_eq!(
            dns_query(&Method::GET, Some("q=example.com"), None, &[]),
            Err("missing 'dns' parameter")
        );
        assert_eq!(
            dns_query(&Method::GET, Some("dns=***"), None, &[]),
            Err("invalid 'dns' base64 encoding")
        );
        assert_eq!(
            dns_query(&Method::PUT, None, None, &q),
            Err("bad HTTP method")
        );
        assert_eq!(
            dns_query(
                &Method::POST,
                None,
                Some("application/dns-message"),
                &[1, 2]
            ),
            Err("invalid DNS query")
        );
    }

    fn rules(src: &str, dst: &str) -> Filter {
        Filter::new(
            compile(&[FilterRule {
                src_ips: vec![src.into()],
                dst_ports: vec![NetPortRange {
                    ip: dst.into(),
                    ports: PortRange {
                        first: 0,
                        last: 65535,
                    },
                }],
                ..Default::default()
            }])
            .unwrap(),
        )
    }

    #[test]
    fn dns_only_for_peers_the_acl_lets_reach_the_internet() {
        let open = rules("*", "*");
        assert!(allows_internet_dns(&open, "100.64.0.5".parse().unwrap()));
        assert!(allows_internet_dns(
            &open,
            "fd7a:115c:a1e0::5".parse().unwrap()
        ));
        let mesh_only = rules("*", "100.64.0.0/10");
        assert!(
            !allows_internet_dns(&mesh_only, "100.64.0.5".parse().unwrap()),
            "no internet in the ACL"
        );
        let one = rules("100.64.0.5", "0.0.0.0/0");
        assert!(allows_internet_dns(&one, "100.64.0.5".parse().unwrap()));
        assert!(!allows_internet_dns(&one, "100.64.0.6".parse().unwrap()));
        assert!(!allows_internet_dns(
            &Filter::new(vec![]),
            "100.64.0.5".parse().unwrap()
        ));
    }

    /// End to end on loopback: other paths are 404; an allowed, valid query reaches forwarding (no
    /// upstream here, so 500); a peer the ACL does not let reach the internet gets 403. Answers from
    /// a real resolver are checked in the lab (exit_node_check.sh).
    #[tokio::test]
    async fn serves_doh_through_the_upstream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(State {
            filter: RwLock::new(rules("127.0.0.1", "0.0.0.0/0")),
            upstreams: vec![],
        });
        tokio::spawn(serve(listener, state.clone()));
        let post = |path: &'static str| async move {
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp))
                    .await
                    .unwrap();
            tokio::spawn(conn);
            let req = Request::post(path)
                .header(hyper::header::CONTENT_TYPE, "application/dns-message")
                .body(Full::new(Bytes::from(query())))
                .unwrap();
            sender.send_request(req).await.unwrap().status()
        };
        assert_eq!(post("/other").await, StatusCode::NOT_FOUND);
        // No upstream configured: the query is valid and allowed, forwarding fails.
        assert_eq!(post("/dns-query").await, StatusCode::INTERNAL_SERVER_ERROR);
        *state.filter.write().unwrap() = rules("100.64.0.0/10", "0.0.0.0/0");
        assert_eq!(
            post("/dns-query").await,
            StatusCode::FORBIDDEN,
            "127.0.0.1 is not allowed now"
        );
    }
}
