// SPDX-License-Identifier: Apache-2.0
//! 控制客户端：取服务端公钥 → 协议升级 → 握手 → 前置载荷 → HTTP/2。

use crate::Error;
use crate::conn::NoiseStream;
use crate::early::{Early, take_early};
use crate::mapstream::decode_frame;
use crate::upgrade;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use flowmesh_noise::frame::FrameDecoder;
use flowmesh_noise::handshake::Initiator;
use flowmesh_proto::capver::CAPABILITY_VERSION;
use flowmesh_proto::control::{
    MapRequest, MapResponse, RegisterRequest, RegisterResponse, ServerKeyResponse,
};
use flowmesh_proto::key::{MachinePrivate, MachinePublic};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 等待服务端前置载荷的时间上限；超时则认为服务端不发送前置载荷。
const EARLY_WAIT: Duration = Duration::from_secs(3);
/// 升级响应头的长度上限。
const MAX_UPGRADE_HEAD: usize = 16 * 1024;

/// 控制服务器地址。v1 只支持 `http://`（任何端口都走明文，偏差清单 #2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl {
    pub host: String,
    pub port: u16,
    /// 用于 Host 头和请求 URI 的 authority，保持用户给定的写法。
    pub authority: String,
}

impl ServerUrl {
    pub fn parse(s: &str) -> Result<Self, Error> {
        let uri: http::Uri = s
            .parse()
            .map_err(|e| Error::Protocol(format!("bad control URL {s:?}: {e}")))?;
        match uri.scheme_str() {
            Some("http") => {}
            Some("https") => {
                return Err(Error::Unsupported(
                    "https control URLs are not supported yet".into(),
                ));
            }
            _ => return Err(Error::Protocol(format!("control URL must be http://: {s}"))),
        }
        let authority = uri
            .authority()
            .ok_or_else(|| Error::Protocol(format!("control URL has no host: {s}")))?;
        Ok(Self {
            host: authority.host().trim_matches(['[', ']']).to_string(),
            port: authority.port_u16().unwrap_or(80),
            authority: authority.as_str().to_string(),
        })
    }
}

pub struct ControlClient {
    sender: hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    url: ServerUrl,
    server_key: MachinePublic,
    early: Option<serde_json::Value>,
}

/// 网络地图流中的一条消息：解压后的原始 JSON 和解析结果。
pub struct RawMapMessage {
    pub json: Vec<u8>,
    pub parsed: MapResponse,
}

pub struct MapStream {
    body: Incoming,
    buf: BytesMut,
    compressed: bool,
}

impl MapStream {
    pub async fn next(&mut self) -> Result<Option<RawMapMessage>, Error> {
        loop {
            if let Some(json) = decode_frame(&mut self.buf, self.compressed)? {
                let parsed = serde_json::from_slice(&json)?;
                return Ok(Some(RawMapMessage { json, parsed }));
            }
            match self.body.frame().await {
                None => return Ok(None),
                Some(frame) => {
                    if let Ok(data) = frame?.into_data() {
                        self.buf.extend_from_slice(&data);
                    }
                }
            }
        }
    }
}

async fn fetch_server_key(url: &ServerUrl) -> Result<MachinePublic, Error> {
    let tcp = TcpStream::connect((url.host.as_str(), url.port)).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    let conn_task = tokio::spawn(conn);
    let req = http::Request::get(format!("/key?v={CAPABILITY_VERSION}"))
        .header(http::header::HOST, &url.authority)
        .body(Full::new(Bytes::new()))
        .map_err(|e| Error::Protocol(e.to_string()))?;
    let resp = sender.send_request(req).await?;
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await?.to_bytes();
    conn_task.abort();
    if status != 200 {
        return Err(Error::Status {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }
    let key: ServerKeyResponse = serde_json::from_slice(&body)?;
    if key.public_key.is_zero() {
        return Err(Error::Protocol("server returned a zero public key".into()));
    }
    Ok(key.public_key)
}

async fn upgrade_and_handshake(
    url: &ServerUrl,
    machine: &MachinePrivate,
    server_key: &MachinePublic,
) -> Result<NoiseStream, Error> {
    let mut tcp = TcpStream::connect((url.host.as_str(), url.port)).await?;
    let (initiator, msg) = Initiator::new(machine, server_key, CAPABILITY_VERSION)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&msg);
    tcp.write_all(upgrade::build_request(&url.authority, &b64).as_bytes())
        .await?;

    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_len = loop {
        let n = tcp.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Protocol("connection closed during upgrade".into()));
        }
        head.extend_from_slice(&chunk[..n]);
        if let Some(len) = upgrade::parse_response(&head)? {
            break len;
        }
        if head.len() > MAX_UPGRADE_HEAD {
            return Err(Error::Protocol("upgrade response header too large".into()));
        }
    };

    let mut decoder = FrameDecoder::default();
    decoder.push(&head[header_len..]);
    let response = loop {
        if let Some(frame) = decoder.next_frame()? {
            break frame;
        }
        let n = tcp.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Protocol("connection closed during handshake".into()));
        }
        decoder.push(&chunk[..n]);
    };
    let transport = initiator.finish(response)?;
    Ok(NoiseStream::new(tcp, transport, decoder)?)
}

async fn read_early(stream: &mut NoiseStream) -> Result<Option<serde_json::Value>, Error> {
    let wait = async {
        loop {
            match take_early(stream.plain_mut())? {
                Early::Present(v) => return Ok(Some(v)),
                Early::Absent => return Ok(None),
                Early::NeedMore => {
                    if !stream.read_more().await? {
                        return Err(Error::Protocol(
                            "connection closed before HTTP/2 started".into(),
                        ));
                    }
                }
            }
        }
    };
    match tokio::time::timeout(EARLY_WAIT, wait).await {
        Ok(r) => r,
        Err(_) => Ok(None),
    }
}

impl ControlClient {
    pub async fn connect(server: &str, machine: &MachinePrivate) -> Result<Self, Error> {
        let url = ServerUrl::parse(server)?;
        let server_key = fetch_server_key(&url).await?;
        let mut stream = upgrade_and_handshake(&url, machine, &server_key).await?;
        let early = read_early(&mut stream).await?;
        let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(stream))
            .await?;
        tokio::spawn(conn);
        Ok(Self {
            sender,
            url,
            server_key,
            early,
        })
    }

    pub fn server_key(&self) -> MachinePublic {
        self.server_key
    }

    pub fn early_payload(&self) -> Option<&serde_json::Value> {
        self.early.as_ref()
    }

    async fn post(&self, path: &str, body: Vec<u8>) -> Result<http::Response<Incoming>, Error> {
        let req = http::Request::post(format!("http://{}{path}", self.url.authority))
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| Error::Protocol(e.to_string()))?;
        let mut sender = self.sender.clone();
        sender.ready().await?;
        let resp = sender.send_request(req).await?;
        let status = resp.status().as_u16();
        if status != 200 {
            let body = resp.into_body().collect().await?.to_bytes();
            return Err(Error::Status {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        Ok(resp)
    }

    /// 注册；返回解析结果和原始响应 JSON。
    pub async fn register(
        &self,
        req: &RegisterRequest,
    ) -> Result<(RegisterResponse, Vec<u8>), Error> {
        let resp = self
            .post("/machine/register", serde_json::to_vec(req)?)
            .await?;
        let body = resp.into_body().collect().await?.to_bytes().to_vec();
        Ok((serde_json::from_slice(&body)?, body))
    }

    pub async fn map(&self, req: &MapRequest) -> Result<MapStream, Error> {
        let resp = self.post("/machine/map", serde_json::to_vec(req)?).await?;
        Ok(MapStream {
            body: resp.into_body(),
            buf: BytesMut::new(),
            compressed: req.compress == "zstd",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_defaults_and_rejections() {
        let u = ServerUrl::parse("http://headscale.lab").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("headscale.lab", 80));
        let u = ServerUrl::parse("http://10.0.0.1:18080/").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.authority.as_str()),
            ("10.0.0.1", 18080, "10.0.0.1:18080")
        );
        let u = ServerUrl::parse("http://[fd00::1]:8080").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("fd00::1", 8080));
        assert!(matches!(
            ServerUrl::parse("https://x"),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            ServerUrl::parse("ftp://x"),
            Err(Error::Protocol(_))
        ));
    }
}
