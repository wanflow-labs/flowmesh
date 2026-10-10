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
        let privileged = is_privileged(stream.peer_cred().ok().map(|c| c.uid()), owner_uid);
        let d = daemon.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let d = d.clone();
                async move { Ok::<_, Infallible>(handle(&d, req, privileged).await) }
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
        DaemonError::Prefs(_) | DaemonError::Unsupported(_) => StatusCode::BAD_REQUEST,
        DaemonError::Persist(_) => StatusCode::INTERNAL_SERVER_ERROR,
        DaemonError::Logout(_) => StatusCode::BAD_GATEWAY,
        DaemonError::NotRunning => StatusCode::SERVICE_UNAVAILABLE,
    };
    error(code, e)
}

/// Ping result with the official field names (`/localapi/v0/ping`), so existing tools can read it.
pub fn ping_json(
    ip: std::net::IpAddr,
    r: &Result<flowmesh_engine::command::PingReply, flowmesh_engine::command::PingError>,
) -> Value {
    use flowmesh_engine::command::PingPath;
    match r {
        Ok(p) => {
            let (endpoint, region, code) = match &p.via {
                PingPath::Direct(a) => (a.to_string(), 0, String::new()),
                PingPath::Derp { region, code } => (String::new(), *region, code.clone()),
            };
            json!({
                "IP": ip.to_string(),
                "NodeIP": p.node_ip.to_string(),
                "NodeName": p.node_name,
                "Err": "",
                "LatencySeconds": p.latency.as_secs_f64(),
                "Endpoint": endpoint,
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
    privileged: bool,
) -> Response<Full<Bytes>>
where
    B: hyper::body::Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let method = req.method().clone();
    let Some(name) = req.uri().path().strip_prefix(PREFIX).map(str::to_owned) else {
        return error(StatusCode::NOT_FOUND, "not found");
    };
    let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return error(StatusCode::BAD_REQUEST, format!("read body: {e}")),
    };
    match (&method, name.as_str()) {
        (&Method::GET, "status") => reply(StatusCode::OK, &d.status_json().await),
        (&Method::GET, "prefs") => match serde_json::to_value(d.prefs().await) {
            Ok(v) => reply(StatusCode::OK, &v),
            Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        // Diagnostic only, open to every local user like status.
        (&Method::POST, "ping") => {
            #[derive(serde::Deserialize)]
            struct PingRequest {
                ip: std::net::IpAddr,
            }
            let req: PingRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => return error(StatusCode::BAD_REQUEST, format!("bad request body: {e}")),
            };
            match d.ping(req.ip).await {
                Ok(r) => reply(StatusCode::OK, &ping_json(req.ip, &r)),
                Err(e) => daemon_error(&e),
            }
        }
        (&Method::POST, "up" | "down" | "logout" | "set") if !privileged => error(
            StatusCode::FORBIDDEN,
            "access denied: changing flowmesh requires root",
        ),
        (&Method::POST, "up") => {
            let req: UpRequest = match parse(&body) {
                Ok(r) => r,
                Err(e) => return error(StatusCode::BAD_REQUEST, e),
            };
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
