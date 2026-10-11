// SPDX-License-Identifier: Apache-2.0
//! Serving what the configuration says on this node's mesh addresses (docs/protocol/serve.md):
//! HTTP (reverse proxy with WebSocket upgrades, text, files and directories) and raw TCP
//! forwarding with an optional PROXY protocol header. Connections reach the listeners through the
//! dataplane's port redirect; a connection is served only if the dataplane admitted it and its
//! source is a peer, whose identity goes to the backend in the official headers.

use crate::config::{Handler, ServeConfig};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;

pub type Body = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
pub type Logger = Arc<dyn Fn(String) + Send + Sync>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Who a peer is, for the identity headers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    pub login: String,
    pub name: String,
    pub profile_pic: String,
    /// Tagged nodes act for no user: no identity headers.
    pub tagged: bool,
}

/// What the listeners need from the engine; replaced as the netmap and the configuration change.
#[derive(Debug, Clone, Default)]
pub struct View {
    /// This node's DNS name, no trailing dot.
    pub name: String,
    pub peers: HashMap<IpAddr, Identity>,
    pub config: ServeConfig,
}

pub struct Shared {
    pub view: Arc<RwLock<View>>,
    /// Whether a connection from this address came through the mesh (dataplane admission).
    pub admitted: Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>,
    pub log: Logger,
}

/// What one listener does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Http,
    Tcp { target: String, proxy_protocol: u8 },
}

fn view(shared: &Shared) -> std::sync::RwLockReadGuard<'_, View> {
    shared
        .view
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Serve `listener`, which peers reach as `port`, until the task is aborted.
pub async fn serve(listener: TcpListener, port: u16, kind: Kind, shared: Arc<Shared>) {
    loop {
        let (stream, from) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                (shared.log)(format!("serve: accept on port {port}: {e}"));
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let from = SocketAddr::new(from.ip().to_canonical(), from.port());
        if !(shared.admitted)(from) {
            (shared.log)(format!(
                "serve: refused connection from {from} to port {port}: did not come through the mesh"
            ));
            continue;
        }
        let Some(who) = view(&shared).peers.get(&from.ip()).cloned() else {
            (shared.log)(format!("serve: refused connection from {from}: not a peer"));
            continue;
        };
        let local = stream
            .local_addr()
            .map(|a| SocketAddr::new(a.ip().to_canonical(), port))
            .unwrap_or(from);
        let shared = shared.clone();
        let kind = kind.clone();
        tokio::spawn(async move {
            match kind {
                Kind::Tcp {
                    target,
                    proxy_protocol,
                } => forward_tcp(stream, from, local, &target, proxy_protocol, &shared).await,
                Kind::Http => {
                    let svc = hyper::service::service_fn(move |req| {
                        let shared = shared.clone();
                        let who = who.clone();
                        async move { Ok::<_, Infallible>(handle(req, port, from, &who, &shared).await) }
                    });
                    // Header names in the usual capitalization, as Go writes them.
                    let _ = hyper::server::conn::http1::Builder::new()
                        .title_case_headers(true)
                        .serve_connection(TokioIo::new(stream), svc)
                        .with_upgrades()
                        .await;
                }
            }
        });
    }
}

/// A PROXY protocol header (v1 text or v2 binary) for a connection from `src` to `dst`.
pub fn proxy_header(version: u8, src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let (src, dst) = (
        SocketAddr::new(src.ip().to_canonical(), src.port()),
        SocketAddr::new(dst.ip().to_canonical(), dst.port()),
    );
    if version == 2 {
        let mut h = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        h.push(0x21); // version 2, PROXY command
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                h.push(0x11);
                h.extend_from_slice(&12u16.to_be_bytes());
                h.extend_from_slice(&s.octets());
                h.extend_from_slice(&d.octets());
            }
            (s, d) => {
                let v6 = |a: IpAddr| match a {
                    IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                    IpAddr::V6(v6) => v6.octets(),
                };
                h.push(0x21);
                h.extend_from_slice(&36u16.to_be_bytes());
                h.extend_from_slice(&v6(s));
                h.extend_from_slice(&v6(d));
            }
        }
        h.extend_from_slice(&src.port().to_be_bytes());
        h.extend_from_slice(&dst.port().to_be_bytes());
        return h;
    }
    let fam = if src.is_ipv4() && dst.is_ipv4() {
        "TCP4"
    } else {
        "TCP6"
    };
    format!(
        "PROXY {fam} {} {} {} {}\r\n",
        src.ip(),
        dst.ip(),
        src.port(),
        dst.port()
    )
    .into_bytes()
}

async fn forward_tcp(
    mut client: tokio::net::TcpStream,
    from: SocketAddr,
    local: SocketAddr,
    target: &str,
    proxy_protocol: u8,
    shared: &Shared,
) {
    let mut backend =
        match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(target)).await {
            Ok(Ok(s)) => s,
            other => {
                let e = match other {
                    Ok(Err(e)) => e.to_string(),
                    _ => "timed out".into(),
                };
                (shared.log)(format!("serve: TCP forward to {target}: {e}"));
                return;
            }
        };
    if proxy_protocol != 0 {
        // The destination is this node's address with the backend's port, as observed.
        let dport = backend.peer_addr().map_or(0, |a| a.port());
        let h = proxy_header(proxy_protocol, from, SocketAddr::new(local.ip(), dport));
        if tokio::io::AsyncWriteExt::write_all(&mut backend, &h)
            .await
            .is_err()
        {
            return;
        }
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
}

fn full(status: StatusCode, headers: &[(&str, &str)], body: impl Into<Bytes>) -> Response<Body> {
    let mut r = Response::new(
        Full::new(body.into())
            .map_err(|e: Infallible| match e {})
            .boxed(),
    );
    *r.status_mut() = status;
    for (k, v) in headers {
        if let (Ok(k), Ok(v)) = (HeaderName::try_from(*k), HeaderValue::try_from(*v)) {
            r.headers_mut().insert(k, v);
        }
    }
    r
}

/// Go's `http.NotFound`, which the official server answers with.
pub fn not_found() -> Response<Body> {
    full(
        StatusCode::NOT_FOUND,
        &[
            ("content-type", "text/plain; charset=utf-8"),
            ("x-content-type-options", "nosniff"),
        ],
        "404 page not found\n",
    )
}

fn bad_gateway() -> Response<Body> {
    full(StatusCode::BAD_GATEWAY, &[], Bytes::new())
}

/// The host part of a Host header (no port, no trailing dot), lower case.
fn host_only(h: &str) -> String {
    let h = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        h.rsplit_once(':').map_or(h, |(a, p)| {
            if p.chars().all(|c| c.is_ascii_digit()) {
                a
            } else {
                h
            }
        })
    };
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// The handler for `path` among `handlers`: the longest mount that is `path` or a parent of it.
pub fn pick<'a>(
    handlers: &'a std::collections::BTreeMap<String, Handler>,
    path: &str,
) -> Option<(&'a str, &'a Handler)> {
    handlers
        .iter()
        .filter(|(m, _)| {
            m.as_str() == "/"
                || path == m.as_str()
                || path
                    .strip_prefix(m.as_str())
                    .is_some_and(|r| r.starts_with('/'))
        })
        .max_by_key(|(m, _)| m.len())
        .map(|(m, h)| (m.as_str(), h))
}

/// The request path below the mount (`/api/v1` under `/api` is `/v1`; the mount itself is `/`).
pub fn below(mount: &str, path: &str) -> String {
    if mount == "/" {
        return path.to_string();
    }
    let rest = path.strip_prefix(mount).unwrap_or(path);
    if rest.is_empty() {
        "/".into()
    } else {
        rest.to_string()
    }
}

async fn handle(
    req: Request<Incoming>,
    port: u16,
    from: SocketAddr,
    who: &Identity,
    shared: &Shared,
) -> Response<Body> {
    let (name, handlers) = {
        let v = view(shared);
        (
            v.name.clone(),
            v.config.web_for_port(port).map(|w| w.handlers.clone()),
        )
    };
    let host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .or_else(|| req.uri().authority().map(|a| a.to_string()))
        .unwrap_or_default();
    let host = host_only(&host_header);
    let short = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    // Served under this node's names only, as the official server does (an address gets 404).
    if host != name.to_ascii_lowercase() && host != short {
        return not_found();
    }
    let Some(handlers) = handlers else {
        return not_found();
    };
    let path = req.uri().path().to_string();
    let Some((mount, h)) = pick(&handlers, &path) else {
        return not_found();
    };
    if !h.text.is_empty() {
        return full(
            StatusCode::OK,
            &[("content-type", "text/plain; charset=utf-8")],
            h.text.clone(),
        );
    }
    if !h.path.is_empty() {
        return crate::files::serve(&req, std::path::Path::new(&h.path), &below(mount, &path))
            .await;
    }
    match proxy(req, &h.proxy, mount, from, &host_header, who).await {
        Ok(r) => r,
        Err(e) => {
            (shared.log)(format!("serve: proxy error: {e}"));
            bad_gateway()
        }
    }
}

/// Headers that belong to one hop (RFC 9110 §7.6.1), never passed on.
const HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
];

/// A header value for a name that may not be ASCII (RFC 2047 Q encoding, as Go's mime package).
pub fn header_text(v: &str) -> String {
    if v.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return v.to_string();
    }
    let mut o = String::from("=?utf-8?q?");
    for b in v.bytes() {
        match b {
            b' ' => o.push('_'),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'!' | b'*' | b'+' | b'/' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("={b:02X}")),
        }
    }
    o.push_str("?=");
    o
}

/// The request headers the backend gets: the client's, minus per-hop ones and anything that would
/// claim an identity or a forwarding path, plus the forwarding headers and the peer's identity.
pub fn backend_headers(
    client: &HeaderMap,
    from: IpAddr,
    host: &str,
    who: &Identity,
    upgrade: bool,
) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in client {
        let n = k.as_str();
        let identity =
            n.starts_with("tailscale-") || n == "x-forwarded-for" || n == "x-forwarded-host";
        let per_hop = HOP.contains(&n) || (n == "upgrade" && !upgrade);
        if !identity && !per_hop {
            h.append(k.clone(), v.clone());
        }
    }
    if upgrade {
        h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    }
    if !who.tagged {
        for (k, v) in [
            ("tailscale-user-login", &who.login),
            ("tailscale-user-name", &who.name),
            ("tailscale-user-profile-pic", &who.profile_pic),
        ] {
            if let Ok(v) = HeaderValue::try_from(header_text(v)) {
                h.insert(HeaderName::from_static(k), v);
            }
        }
    }
    if let Ok(v) = HeaderValue::try_from(from.to_string()) {
        h.insert(HeaderName::from_static("x-forwarded-for"), v);
    }
    if let Ok(v) = HeaderValue::try_from(host) {
        h.insert(HeaderName::from_static("x-forwarded-host"), v);
    }
    h
}

/// Where a proxy target points.
enum Backend {
    Tcp {
        host: String,
        port: u16,
        tls: Option<bool>,
    },
    Unix(std::path::PathBuf),
}

fn parse_target(url: &str) -> Result<(Backend, String), String> {
    if let Some(p) = url.strip_prefix("unix:") {
        return Ok((Backend::Unix(p.into()), String::new()));
    }
    let (scheme, rest) = url.split_once("://").ok_or("bad proxy target")?;
    let tls = match scheme {
        "http" => None,
        "https" => Some(true),
        "https+insecure" => Some(false),
        other => return Err(format!("unsupported scheme {other}")),
    };
    let (hostport, base) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].trim_end_matches('/').to_string()),
        None => (rest, String::new()),
    };
    let default = if tls.is_some() { 443 } else { 80 };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => match p.parse() {
            Ok(p) => (h, p),
            Err(_) => (hostport, default),
        },
        _ => (hostport, default),
    };
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    Ok((Backend::Tcp { host, port, tls }, base))
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

async fn connect(b: &Backend) -> Result<Box<dyn Io>, String> {
    let fut = async {
        match b {
            Backend::Unix(p) => tokio::net::UnixStream::connect(p)
                .await
                .map(|s| Box::new(s) as Box<dyn Io>)
                .map_err(|e| format!("dial unix {}: {e}", p.display())),
            Backend::Tcp { host, port, tls } => {
                let s = tokio::net::TcpStream::connect((host.as_str(), *port))
                    .await
                    .map_err(|e| format!("dial tcp {host}:{port}: {e}"))?;
                match tls {
                    None => Ok(Box::new(s) as Box<dyn Io>),
                    Some(verify) => {
                        let s = crate::tls::connect(s, host, *verify).await?;
                        Ok(Box::new(s) as Box<dyn Io>)
                    }
                }
            }
        }
    };
    tokio::time::timeout(CONNECT_TIMEOUT, fut)
        .await
        .map_err(|_| "dial timed out".to_string())?
}

async fn proxy(
    mut req: Request<Incoming>,
    target: &str,
    mount: &str,
    from: SocketAddr,
    host: &str,
    who: &Identity,
) -> Result<Response<Body>, String> {
    let (backend, base) = parse_target(target)?;
    let rest = below(mount, req.uri().path());
    let mut path = if base.is_empty() {
        rest
    } else if rest == "/" {
        base.clone()
    } else {
        format!("{base}{rest}")
    };
    if let Some(q) = req.uri().query() {
        path.push('?');
        path.push_str(q);
    }
    let upgrade = req.headers().contains_key(header::UPGRADE)
        && req
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.to_ascii_lowercase()
                    .split(',')
                    .any(|t| t.trim() == "upgrade")
            });
    let mut out = Request::builder()
        .method(req.method().clone())
        .uri(&path)
        .body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
        .map_err(|e| e.to_string())?;
    *out.headers_mut() = backend_headers(req.headers(), from.ip(), host, who, upgrade);
    if matches!(backend, Backend::Unix(_)) {
        out.headers_mut()
            .insert(header::HOST, HeaderValue::from_static("localhost"));
    }
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));
    *out.body_mut() = req.into_body().map_err(|e| Box::new(e) as _).boxed();

    let io = connect(&backend).await?;
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .title_case_headers(true)
        .handshake::<_, Body>(TokioIo::new(io))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn.with_upgrades());
    let mut resp = sender.send_request(out).await.map_err(|e| e.to_string())?;

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            let backend_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(c), Ok(b)) = (client_upgrade.await, backend_upgrade.await) {
                    let _ =
                        tokio::io::copy_bidirectional(&mut TokioIo::new(c), &mut TokioIo::new(b))
                            .await;
                }
            });
        }
        let (parts, _) = resp.into_parts();
        return Ok(Response::from_parts(
            parts,
            Empty::new().map_err(|e| match e {}).boxed(),
        ));
    }
    let (mut parts, body) = resp.into_parts();
    for h in HOP {
        parts.headers.remove(h);
    }
    // The client gets HTTP/1.1 whatever the backend spoke (as from the official server).
    parts.version = hyper::Version::HTTP_11;
    Ok(Response::from_parts(
        parts,
        body.map_err(|e| Box::new(e) as _).boxed(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn mounts() {
        let mut h = BTreeMap::new();
        for m in ["/", "/api", "/text"] {
            h.insert(m.to_string(), Handler::default());
        }
        assert_eq!(pick(&h, "/api/v1/items").unwrap().0, "/api");
        assert_eq!(pick(&h, "/api").unwrap().0, "/api");
        assert_eq!(pick(&h, "/apix").unwrap().0, "/");
        assert_eq!(pick(&h, "/other").unwrap().0, "/");
        h.remove("/");
        assert!(pick(&h, "/other").is_none());
        // Observed: /api/v1/items reaches the backend as /v1/items, /api as /.
        assert_eq!(below("/api", "/api/v1/items"), "/v1/items");
        assert_eq!(below("/api", "/api"), "/");
        assert_eq!(below("/", "/a/b"), "/a/b");
    }

    #[test]
    fn hosts() {
        assert_eq!(
            host_only("svs.mesh.lab.internal:8080"),
            "svs.mesh.lab.internal"
        );
        assert_eq!(host_only("SVS."), "svs");
        assert_eq!(host_only("[fd7a::1]:80"), "fd7a::1");
    }

    /// The backend sees what the official server sends (get-root.txt, get-spoofed-headers.txt):
    /// the client's headers, the peer's identity instead of any claimed one, and X-Forwarded-For
    /// replaced by the peer's address.
    #[test]
    fn identity_and_forwarding_headers() {
        let mut c = HeaderMap::new();
        c.insert("host", HeaderValue::from_static("svs.mesh.lab.internal"));
        c.insert("user-agent", HeaderValue::from_static("curl/8.14.1"));
        c.insert(
            "tailscale-user-login",
            HeaderValue::from_static("evil@example.com"),
        );
        c.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
        c.insert("connection", HeaderValue::from_static("keep-alive"));
        let who = Identity {
            login: "lab".into(),
            name: "lab".into(),
            ..Default::default()
        };
        let ip: IpAddr = "100.64.0.76".parse().unwrap();
        let h = backend_headers(&c, ip, "svs.mesh.lab.internal", &who, false);
        assert_eq!(h["tailscale-user-login"], "lab");
        assert_eq!(h["tailscale-user-name"], "lab");
        assert_eq!(h["tailscale-user-profile-pic"], "");
        assert_eq!(
            h.get_all("x-forwarded-for").iter().collect::<Vec<_>>(),
            ["100.64.0.76"]
        );
        assert_eq!(h["x-forwarded-host"], "svs.mesh.lab.internal");
        assert_eq!(h["host"], "svs.mesh.lab.internal");
        assert_eq!(h["user-agent"], "curl/8.14.1");
        assert!(h.get("connection").is_none());
        // Tagged peers: no identity, and a claimed one is still removed.
        let tagged = Identity {
            tagged: true,
            ..who
        };
        let h = backend_headers(&c, ip, "x", &tagged, false);
        assert!(
            h.keys().all(|k| !k.as_str().starts_with("tailscale-")),
            "{h:?}"
        );
        assert_eq!(header_text("Zoë Li"), "=?utf-8?q?Zo=C3=AB_Li?=");
    }

    /// PROXY v1 as the official forwarder writes it (tcp-echo-proxy-protocol.txt), and v2.
    #[test]
    fn proxy_headers() {
        let src: SocketAddr = "100.64.0.76:33615".parse().unwrap();
        let dst: SocketAddr = "100.64.0.75:7000".parse().unwrap();
        assert_eq!(
            proxy_header(1, src, dst),
            b"PROXY TCP4 100.64.0.76 100.64.0.75 33615 7000\r\n"
        );
        let v2 = proxy_header(2, src, dst);
        assert_eq!(&v2[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(&v2[12..16], [0x21, 0x11, 0, 12]);
        assert_eq!(&v2[16..20], [100, 64, 0, 76]);
        assert_eq!(&v2[24..28], [0x83, 0x4f, 0x1b, 0x58]);
        let s6: SocketAddr = "[fd7a::1]:1".parse().unwrap();
        assert!(
            String::from_utf8(proxy_header(1, s6, dst))
                .unwrap()
                .starts_with("PROXY TCP6 fd7a::1 ")
        );
    }

    #[test]
    fn targets() {
        let (b, base) = parse_target("http://127.0.0.1:3000").unwrap();
        assert!(
            matches!(b, Backend::Tcp { ref host, port: 3000, tls: None } if host == "127.0.0.1")
        );
        assert_eq!(base, "");
        let (b, base) = parse_target("https+insecure://localhost:8443/foo/").unwrap();
        assert!(matches!(
            b,
            Backend::Tcp {
                port: 8443,
                tls: Some(false),
                ..
            }
        ));
        assert_eq!(base, "/foo");
        let (b, _) = parse_target("https://[::1]/").unwrap();
        assert!(
            matches!(b, Backend::Tcp { ref host, port: 443, tls: Some(true) } if host == "::1")
        );
        assert!(matches!(
            parse_target("unix:/tmp/s").unwrap().0,
            Backend::Unix(_)
        ));
    }
}
