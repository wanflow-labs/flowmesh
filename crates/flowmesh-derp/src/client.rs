// SPDX-License-Identifier: Apache-2.0
//! DERP client: TLS → `GET /derp` upgrade → handshake → independent read/write tasks (derp.md §1–§4).

use crate::Error;
use crate::frame::{Frame, FrameDecoder, FrameType, encode};
use crate::handshake::{self, NONCE_LEN};
use flowmesh_proto::derp::DerpNode;
use flowmesh_proto::key::{NodePrivate, NodePublic};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

const DEFAULT_DERP_PORT: u16 = 443;
const MAX_UPGRADE_HEAD: usize = 16 * 1024;
const QUEUE: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Packet {
        src: NodePublic,
        data: Vec<u8>,
    },
    PeerGone(NodePublic),
    Health(String),
    /// The server echoed one of our pings.
    Pong([u8; 8]),
    /// Connection closed; the payload is the reason.
    Closed(String),
}

pub struct DerpClient {
    server_key: NodePublic,
    server_info: serde_json::Value,
    sender: DerpSender,
    events: mpsc::Receiver<Event>,
}

/// Sending half: cheap to clone, can be held by multiple tasks.
#[derive(Clone)]
pub struct DerpSender {
    tx: mpsc::Sender<Vec<u8>>,
}

impl DerpSender {
    /// Ask the server to echo `payload` back (Ping frame); the answer arrives as `Event::Pong`.
    pub async fn ping(&self, payload: [u8; 8]) -> Result<(), Error> {
        self.enqueue(encode(FrameType::Ping, &payload)?).await
    }

    pub async fn send(&self, dst: NodePublic, packet: &[u8]) -> Result<(), Error> {
        let mut payload = Vec::with_capacity(32 + packet.len());
        payload.extend_from_slice(&dst.0);
        payload.extend_from_slice(packet);
        self.enqueue(encode(FrameType::SendPacket, &payload)?).await
    }

    pub async fn note_preferred(&self, preferred: bool) -> Result<(), Error> {
        self.enqueue(encode(FrameType::NotePreferred, &[u8::from(preferred)])?)
            .await
    }

    async fn enqueue(&self, frame: Vec<u8>) -> Result<(), Error> {
        self.tx
            .send(frame)
            .await
            .map_err(|_| Error::Protocol("DERP connection closed".into()))
    }
}

/// TLS certificate verification used only when `InsecureForTests` is set: accepts any certificate (lab self-signed only).
#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config(insecure: bool) -> Result<rustls::ClientConfig, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    if insecure {
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth());
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        // A single unparseable system certificate should not block the others.
        let _ = roots.add(cert);
    }
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

/// Read the HTTP 101 response headers; return the bytes after the headers that were already read.
async fn read_upgrade<S: AsyncRead + Unpin>(s: &mut S) -> Result<Vec<u8>, Error> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Protocol(
                "connection closed during DERP upgrade".into(),
            ));
        }
        head.extend_from_slice(&chunk[..n]);
        if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            let status = String::from_utf8_lossy(&head[..end]);
            let line = status.lines().next().unwrap_or_default().to_string();
            if line.split_whitespace().nth(1) != Some("101") {
                return Err(Error::Protocol(format!("DERP upgrade rejected: {line}")));
            }
            return Ok(head[end + 4..].to_vec());
        }
        if head.len() > MAX_UPGRADE_HEAD {
            return Err(Error::Protocol("DERP upgrade header too large".into()));
        }
    }
}

async fn read_frame<S: AsyncRead + Unpin>(
    s: &mut S,
    dec: &mut FrameDecoder,
) -> Result<Frame, Error> {
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(f) = dec.next_frame()? {
            return Ok(f);
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Protocol("DERP connection closed".into()));
        }
        dec.push(&chunk[..n]);
    }
}

impl DerpClient {
    pub async fn connect(node: &DerpNode, me: &NodePrivate) -> Result<Self, Error> {
        let port = if node.derp_port == 0 {
            DEFAULT_DERP_PORT
        } else {
            node.derp_port
        };
        let addr = if node.ipv4.is_empty() {
            node.host_name.clone()
        } else {
            node.ipv4.clone()
        };
        let tcp = flowmesh_net::tcp_connect(&addr, port).await?;
        tcp.set_nodelay(true)?;
        let name = rustls::pki_types::ServerName::try_from(node.host_name.clone())
            .map_err(|e| Error::Protocol(format!("bad DERP host name: {e}")))?;
        let connector =
            tokio_rustls::TlsConnector::from(Arc::new(tls_config(node.insecure_for_tests)?));
        let mut tls = connector.connect(name, tcp).await?;

        let req = format!(
            "GET /derp HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n",
            node.host_name
        );
        tls.write_all(req.as_bytes()).await?;
        let leftover = read_upgrade(&mut tls).await?;
        let mut dec = FrameDecoder::default();
        dec.push(&leftover);

        let first = read_frame(&mut tls, &mut dec).await?;
        if first.ty != FrameType::ServerKey {
            return Err(Error::Protocol(format!(
                "expected server key frame, got {:?}",
                first.ty
            )));
        }
        let server_key = handshake::parse_server_key(&first.payload)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| Error::Crypto)?;
        let info =
            handshake::client_info(me, &server_key, &handshake::default_client_info(), nonce)?;
        tls.write_all(&encode(FrameType::ClientInfo, &info)?)
            .await?;
        let second = read_frame(&mut tls, &mut dec).await?;
        if second.ty != FrameType::ServerInfo {
            return Err(Error::Protocol(format!(
                "expected server info frame, got {:?}",
                second.ty
            )));
        }
        let server_info = handshake::open_server_info(me, &server_key, &second.payload)?;

        let (reader, writer) = tokio::io::split(tls);
        let (tx, wrx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let (etx, events) = mpsc::channel::<Event>(QUEUE);
        tokio::spawn(write_loop(writer, wrx));
        let frames = Arc::new(AtomicU64::new(0));
        let reader_task = tokio::spawn(read_loop(
            reader,
            dec,
            tx.clone(),
            etx.clone(),
            frames.clone(),
        ));
        tokio::spawn(watch_liveness(reader_task, frames, tx.clone(), etx));
        Ok(Self {
            server_key,
            server_info,
            sender: DerpSender { tx },
            events,
        })
    }

    pub fn server_key(&self) -> NodePublic {
        self.server_key
    }

    pub fn server_info(&self) -> &serde_json::Value {
        &self.server_info
    }

    pub async fn send(&self, dst: NodePublic, packet: &[u8]) -> Result<(), Error> {
        self.sender.send(dst, packet).await
    }

    pub async fn note_preferred(&self, preferred: bool) -> Result<(), Error> {
        self.sender.note_preferred(preferred).await
    }

    /// Split into the sending half and the event receiver.
    pub fn split(self) -> (DerpSender, mpsc::Receiver<Event>) {
        (self.sender, self.events)
    }

    pub async fn recv(&mut self) -> Option<Event> {
        self.events.recv().await
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(mut w: W, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if w.write_all(&frame).await.is_err() || w.flush().await.is_err() {
            return;
        }
    }
}

/// Ping a quiet server and declare the connection dead if nothing comes back (`liveness`). The
/// reader is aborted rather than raced: cancelling a read mid-frame would corrupt the stream.
async fn watch_liveness(
    reader: tokio::task::JoinHandle<()>,
    frames: Arc<AtomicU64>,
    tx: mpsc::Sender<Vec<u8>>,
    events: mpsc::Sender<Event>,
) {
    use crate::liveness::{Liveness, Verdict};
    let start = tokio::time::Instant::now();
    let mut live = Liveness::new(std::time::Duration::ZERO);
    let mut seen = frames.load(Ordering::Relaxed);
    let mut pings: u64 = 0;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tick.tick().await;
        if reader.is_finished() || events.is_closed() {
            return;
        }
        let now = start.elapsed();
        let n = frames.load(Ordering::Relaxed);
        if n != seen {
            seen = n;
            live.on_frame(now);
        }
        match live.tick(now) {
            Verdict::Quiet => {}
            Verdict::SendPing => {
                pings += 1;
                if let Ok(frame) = encode(FrameType::Ping, &pings.to_be_bytes()) {
                    let _ = tx.send(frame).await;
                }
            }
            Verdict::Dead => {
                reader.abort();
                let _ = events
                    .send(Event::Closed(
                        "no reply from the relay; connection presumed dead".into(),
                    ))
                    .await;
                return;
            }
        }
    }
}

async fn read_loop<R: AsyncRead + Unpin>(
    mut r: R,
    mut dec: FrameDecoder,
    tx: mpsc::Sender<Vec<u8>>,
    events: mpsc::Sender<Event>,
    frames: Arc<AtomicU64>,
) {
    // Lab observation only: FLOWMESH_DERP_TRACE prints each frame type with its arrival time.
    let trace = std::env::var_os("FLOWMESH_DERP_TRACE").map(|_| std::time::Instant::now());
    let reason = loop {
        let frame = match read_frame(&mut r, &mut dec).await {
            Ok(f) => f,
            Err(e) => break e.to_string(),
        };
        frames.fetch_add(1, Ordering::Relaxed);
        if let Some(t0) = trace {
            eprintln!(
                "derp-trace {:.1}s {:?} len={}",
                t0.elapsed().as_secs_f64(),
                frame.ty,
                frame.payload.len()
            );
        }
        let event = match frame.ty {
            FrameType::RecvPacket if frame.payload.len() >= 32 => {
                let mut src = [0u8; 32];
                src.copy_from_slice(&frame.payload[..32]);
                Some(Event::Packet {
                    src: NodePublic(src),
                    data: frame.payload[32..].to_vec(),
                })
            }
            FrameType::PeerGone if frame.payload.len() >= 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&frame.payload[..32]);
                Some(Event::PeerGone(NodePublic(k)))
            }
            FrameType::Health => Some(Event::Health(
                String::from_utf8_lossy(&frame.payload).into_owned(),
            )),
            FrameType::Pong if frame.payload.len() == 8 => {
                let mut p = [0u8; 8];
                p.copy_from_slice(&frame.payload);
                Some(Event::Pong(p))
            }
            FrameType::Ping => {
                // Echo the 8-byte payload back as-is.
                match encode(FrameType::Pong, &frame.payload) {
                    Ok(pong) => {
                        if tx.send(pong).await.is_err() {
                            break "writer closed".into();
                        }
                    }
                    Err(e) => break e.to_string(),
                }
                None
            }
            _ => None,
        };
        if let Some(ev) = event {
            if events.send(ev).await.is_err() {
                return;
            }
        }
    };
    let _ = events.send(Event::Closed(reason)).await;
}
