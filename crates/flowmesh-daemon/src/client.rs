// SPDX-License-Identifier: Apache-2.0
//! Local API client, used by the `flowmesh` CLI.

use crate::api::PREFIX;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const DEFAULT_SOCKET: &str = "/var/run/flowmesh/flowmeshd.sock";

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach flowmeshd at {path}: {source} (is the daemon running?)")]
    Connect {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("local api: {0}")]
    Http(String),
    /// The daemon answered with an error message.
    #[error("{message}")]
    Api { status: StatusCode, message: String },
}

pub struct LocalClient {
    socket: PathBuf,
}

impl LocalClient {
    pub fn new(socket: impl AsRef<Path>) -> Self {
        Self {
            socket: socket.as_ref().to_path_buf(),
        }
    }

    pub async fn get(&self, name: &str) -> Result<Value, ClientError> {
        self.call(Method::GET, name, Bytes::new()).await
    }

    pub async fn post(&self, name: &str, body: &Value) -> Result<Value, ClientError> {
        self.call(Method::POST, name, Bytes::from(body.to_string()))
            .await
    }

    async fn call(&self, method: Method, name: &str, body: Bytes) -> Result<Value, ClientError> {
        let stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|source| ClientError::Connect {
                path: self.socket.clone(),
                source,
            })?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        tokio::spawn(conn);
        let req = Request::builder()
            .method(method)
            .uri(format!("{PREFIX}{name}"))
            // HTTP/1.1 requires a Host header; the value is meaningless over a unix socket.
            .header(hyper::header::HOST, "local-flowmeshd")
            .body(Full::new(body))
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ClientError::Http(e.to_string()))?
            .to_bytes();
        let v: Value =
            serde_json::from_slice(&bytes).map_err(|e| ClientError::Http(e.to_string()))?;
        if status.is_success() {
            Ok(v)
        } else {
            Err(ClientError::Api {
                status,
                message: v["error"].as_str().unwrap_or("unknown error").to_string(),
            })
        }
    }
}
