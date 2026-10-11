// SPDX-License-Identifier: Apache-2.0
//! Local API: HTTP/1.1 + JSON over a unix socket, versioned under `/localapi/v0/`.
//! Reads are open to every local user; changes need root or the daemon's own uid (checked with SO_PEERCRED).

use crate::daemon::{Daemon, DaemonError, Launcher, UpRequest};
use crate::prefs::PrefsUpdate;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::convert::Infallible;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::watch;

pub const PREFIX: &str = "/localapi/v0/";
pub const MAX_BODY: usize = 64 * 1024;

/// Bind the socket (replacing a stale one), open it to all local users, and return the owner uid.
pub fn bind(path: &Path) -> std::io::Result<(UnixListener, u32)> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Only a leftover socket is replaced; anything else at that path is someone else's file.
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if !m.file_type().is_socket() {
            return Err(std::io::Error::other(format!(
                "{} exists and is not a socket",
                path.display()
            )));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    let uid = std::fs::metadata(path)?.uid();
    Ok((listener, uid))
}

pub async fn serve<L: Launcher>(
    daemon: Arc<Daemon<L>>,
    listener: UnixListener,
    owner_uid: u32,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let stream = tokio::select! {
            r = listener.accept() => match r {
                Ok((s, _)) => s,
                Err(_) => continue,
            },
            _ = stop.changed() => return,
        };
        let uid = stream.peer_cred().ok().map(|c| c.uid());
        let caller = Caller {
            root: is_privileged(uid, owner_uid),
            uid,
        };
        let d = daemon.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let d = d.clone();
                async move { Ok::<_, Infallible>(handle(&d, req, caller).await) }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

/// Changes are allowed for root and for the user the daemon runs as; unknown peers are not trusted.
pub fn is_privileged(peer_uid: Option<u32>, owner_uid: u32) -> bool {
    peer_uid == Some(0) || peer_uid == Some(owner_uid)
}

/// Who is on the other end of a local API connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    /// Root, or the user the daemon runs as.
    pub root: bool,
    pub uid: Option<u32>,
}

impl From<bool> for Caller {
    fn from(root: bool) -> Self {
        Self { root, uid: None }
    }
}

/// Whether `uid` is the operator named in the preferences (`--operator`). The name is looked up
/// on every request, so a user created or renamed later is matched without a restart.
pub fn is_operator(uid: Option<u32>, operator: &str) -> bool {
    let (Some(uid), false) = (uid, operator.is_empty()) else {
        return false;
    };
    matches!(nix::unistd::User::from_name(operator), Ok(Some(u)) if u.uid.as_raw() == uid)
}

/// Whether a change names a different operator (repeating the current one, as `up` requires for
/// every non-default setting, is not a change; `up --reset` without it clears it).
pub fn changes_operator(current: &str, given: Option<&str>, reset: bool) -> bool {
    match given {
        Some(v) => v != current,
        None => reset && !current.is_empty(),
    }
}

const OPERATOR_ROOT_ONLY: &str = "access denied: only root can change the operator";

fn reply(code: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(body.to_string())));
    *r.status_mut() = code;
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    r
}

fn error(code: StatusCode, msg: impl std::fmt::Display) -> Response<Full<Bytes>> {
    reply(code, &json!({ "error": msg.to_string() }))
}

fn daemon_error(e: &DaemonError) -> Response<Full<Bytes>> {
    let code = match e {
        DaemonError::Prefs(_) => StatusCode::BAD_REQUEST,
        DaemonError::Persist(_) => StatusCode::INTERNAL_SERVER_ERROR,
        DaemonError::Logout(_) => StatusCode::BAD_GATEWAY,
        DaemonError::NotRunning => StatusCode::SERVICE_UNAVAILABLE,
        DaemonError::Serve(_) => StatusCode::BAD_REQUEST,
        DaemonError::Denied(_) => StatusCode::FORBIDDEN,
    };
    error(code, e)
}

/// The `addr` query parameter of `whois`: an IP, `ip:port`, or `[v6]:port` (official accepts all three).
pub fn query_addr(query: Option<&str>) -> Option<std::net::IpAddr> {
    let raw = query?.split('&').find_map(|kv| kv.strip_prefix("addr="))?;
    let value = percent_decode(raw)?;
    value
        .parse::<std::net::IpAddr>()
        .ok()
        .or_else(|| value.parse::<std::net::SocketAddr>().ok().map(|s| s.ip()))
}

/// Minimal percent-decoding for query values (`%3A` in IPv6 addresses, `%5B`/`%5D` brackets).
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Ping result with the official field names (`/localapi/v0/ping`), so existing tools can read it.
pub fn ping_json(
    ip: std::net::IpAddr,
    r: &Result<flowmesh_engine::command::PingReply, flowmesh_engine::command::PingError>,
) -> Value {
    use flowmesh_engine::command::PingPath;
    match r {
        Ok(p) => {
            let (endpoint, peer_relay, region, code) = match &p.via {
                PingPath::Direct(a) => (a.to_string(), String::new(), 0, String::new()),
                PingPath::PeerRelay { server, vni } => (
                    String::new(),
                    format!("{server}:vni:{vni}"),
                    0,
                    String::new(),
                ),
                PingPath::Derp { region, code } => {
                    (String::new(), String::new(), *region, code.clone())
                }
            };
            json!({
                "IP": ip.to_string(),
                "NodeIP": p.node_ip.to_string(),
                "NodeName": p.node_name,
                "Err": "",
                "LatencySeconds": p.latency.as_secs_f64(),
                "Endpoint": endpoint,
                "PeerRelay": peer_relay,
                "DERPRegionID": region,
                "DERPRegionCode": code,
            })
        }
        Err(e) => json!({ "IP": ip.to_string(), "Err": e.to_string() }),
    }
}

/// Empty body = all defaults.
fn parse<T: serde::de::DeserializeOwned + Default>(body: &[u8]) -> Result<T, String> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    serde_json::from_slice(body).map_err(|e| format!("bad request body: {e}"))
}

pub async fn handle<L: Launcher, B>(
    d: &Daemon<L>,
    req: Request<B>,
    caller: impl Into<Caller>,
) -> Response<Full<Bytes>>
where
    B: hyper::body::Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let caller = caller.into();
    // The operator may do what root may, except name another operator.
    let privileged = caller.root || is_operator(caller.uid, &d.prefs().await.operator_user);
    let method = req.method().clone();
    let req_query = req.uri().query().map(str::to_owned);
    let Some(name) = req.uri().path().strip_prefix(PREFIX).map(str::to_owned) else {
        return error(StatusCode::NOT_FOUND, "not found");
    };
    let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return error(StatusCode::BAD_REQUEST, format!("read body: {e}")),
    };
    match (&method, name.as_str()) {
        (&Method::GET, "status") => reply(StatusCode::OK, &d.status_json().await),
        // Read-only views for `dns status`, `netcheck` and `metrics`: open to every local user like
        // status (no keys or peer endpoints in them).
        (&Method::GET, "dns" | "derpmap" | "metrics") => {
            use flowmesh_engine::debug::DebugTopic;
            let topic = match name.as_str() {
                "dns" => DebugTopic::Dns,
                "derpmap" => DebugTopic::DerpMap,
                _ => DebugTopic::Metrics,
            };
            match d.debug(topic).await {
                Ok(v) => reply(StatusCode::OK, &v),
                Err(e) => daemon_error(&e),
            }
        }
        // Peers' keys and endpoints: root (or the daemon's user) only.
        (&Method::GET, "debug") if !privileged => error(
            StatusCode::FORBIDDEN,
            "access denied: debug views require root or the operator",
        ),
        (&Method::GET, "debug") => {
            let topic = req_query
                .as_deref()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("topic=")))
                .unwrap_or("");
            match topic.parse::<flowmesh_engine::debug::DebugTopic>() {
                Ok(t) => match d.debug(t).await {
                    Ok(v) => reply(StatusCode::OK, &v),
                    Err(e) => daemon_error(&e),
                },
                Err(e) => error(StatusCode::BAD_REQUEST, e),
            }
        }
        (&Method::GET, "whois") => {
            let Some(ip) = query_addr(req_query.as_deref()) else {
                return error(StatusCode::BAD_REQUEST, "invalid 'addr' parameter");
            };
            match d.whois(ip).await {
                Ok(Some(w)) => reply(
                    StatusCode::OK,
                    &json!({ "Node": w.node, "UserProfile": w.user_profile, "CapMap": w.cap_map }),
                ),
                Ok(None) => error(StatusCode::NOT_FOUND, "peer not found"),
                Err(e) => daemon_error(&e),
            }
        }
        (&Method::GET, "prefs") => match serde_json::to_value(d.prefs().await) {
            Ok(v) => reply(StatusCode::OK, &v),
            Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        // Diagnostic only, open to every local user like status.
        (&Method::POST, "ping") => {
            #[derive(serde::Deserialize)]
            struct PingRequest {
                ip: std::net::IpAddr,
                #[serde(default)]
                timeout_ms: Option<u64>,
            }
            let req: PingRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => return error(StatusCode::BAD_REQUEST, format!("bad request body: {e}")),
            };
            match d
                .ping(req.ip, req.timeout_ms.map(std::time::Duration::from_millis))
                .await
            {
                Ok(r) => reply(StatusCode::OK, &ping_json(req.ip, &r)),
                Err(e) => daemon_error(&e),
            }
        }
        // The background serve configuration: open to read like status, root/operator to change.
        (&Method::GET, "serve") => match serde_json::to_value(d.serve_config().await) {
            Ok(v) => reply(StatusCode::OK, &v),
            Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        (&Method::POST, "serve" | "serve-foreground" | "serve-foreground-stop") if !privileged => {
            error(
                StatusCode::FORBIDDEN,
                "access denied: changing flowmesh requires root or the operator",
            )
        }
        (&Method::POST, "serve") => {
            let cfg: flowmesh_serve::config::ServeConfig = match parse(&body) {
                Ok(c) => c,
                Err(e) => return error(StatusCode::BAD_REQUEST, e),
            };
            match d.set_serve(cfg, caller.root).await {
                Ok(()) => reply(StatusCode::OK, &json!({})),
                Err(e) => daemon_error(&e),
            }
        }
        (&Method::POST, "serve-foreground" | "serve-foreground-stop") => {
            #[derive(serde::Deserialize, Default)]
            #[serde(default)]
            struct Fg {
                id: String,
                config: flowmesh_serve::config::ServeConfig,
            }
            let fg: Fg = match parse(&body) {
                Ok(f) => f,
                Err(e) => return error(StatusCode::BAD_REQUEST, e),
            };
            if fg.id.is_empty() {
                return error(StatusCode::BAD_REQUEST, "missing id");
            }
            if name == "serve-foreground-stop" {
                d.serve_foreground_stop(&fg.id).await;
                return reply(StatusCode::OK, &json!({}));
            }
            match d.serve_foreground(fg.id, fg.config, caller.root).await {
                Ok(()) => reply(StatusCode::OK, &json!({})),
                Err(e) => daemon_error(&e),
            }
        }
        (&Method::POST, "up" | "down" | "logout" | "set") if !privileged => error(
            StatusCode::FORBIDDEN,
            "access denied: changing flowmesh requires root or the operator",
        ),
        (&Method::POST, "up") => {
            let req: UpRequest = match parse(&body) {
                Ok(r) => r,
                Err(e) => return error(StatusCode::BAD_REQUEST, e),
            };
            let cur = d.prefs().await.operator_user;
            if !caller.root
                && changes_operator(&cur, req.update.operator_user.as_deref(), req.reset)
            {
                return error(StatusCode::FORBIDDEN, OPERATOR_ROOT_ONLY);
            }
            match d.up(req).await {
                Ok(()) => reply(StatusCode::OK, &json!({})),
                Err(e) => daemon_error(&e),
            }
        }
        (&Method::POST, "set") => {
            let update: PrefsUpdate = match parse(&body) {
                Ok(r) => r,
                Err(e) => return error(StatusCode::BAD_REQUEST, e),
            };
            let cur = d.prefs().await.operator_user;
            if !caller.root && changes_operator(&cur, update.operator_user.as_deref(), false) {
                return error(StatusCode::FORBIDDEN, OPERATOR_ROOT_ONLY);
            }
            match d.set(update).await {
                Ok(()) => reply(StatusCode::OK, &json!({})),
                Err(e) => daemon_error(&e),
            }
        }
        (&Method::POST, "down") => match d.down().await {
            Ok(()) => reply(StatusCode::OK, &json!({})),
            Err(e) => daemon_error(&e),
        },
        (&Method::POST, "logout") => match d.logout().await {
            Ok(()) => reply(StatusCode::OK, &json!({})),
            Err(e) => daemon_error(&e),
        },
        _ => error(StatusCode::NOT_FOUND, "not found"),
    }
}
