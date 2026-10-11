// SPDX-License-Identifier: Apache-2.0
//! The byte stream to the control server: plain TCP for `http://`, TLS for `https://`. The `/key`
//! fetch and the protocol upgrade both run over it; after the upgrade the Noise record layer wraps
//! it either way (control.md §1).

use crate::Error;
use crate::client::ServerUrl;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// A connected stream, plain or TLS.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub type BoxIo = Box<dyn Io>;

/// Connect to the control server; for `https://` complete a TLS handshake that verifies the
/// server's certificate against the system roots (`SSL_CERT_FILE`/`SSL_CERT_DIR` are honored).
pub async fn dial(url: &ServerUrl) -> Result<BoxIo, Error> {
    let tcp = TcpStream::connect((url.host.as_str(), url.port)).await?;
    if !url.tls {
        return Ok(Box::new(tcp));
    }
    let name = rustls::pki_types::ServerName::try_from(url.host.clone())
        .map_err(|e| Error::Protocol(format!("bad TLS server name {:?}: {e}", url.host)))?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls_config()?))
        .connect(name, tcp)
        .await
        .map_err(|e| Error::Protocol(format!("TLS to {}: {e}", url.authority)))?;
    Ok(Box::new(tls))
}

fn tls_config() -> Result<rustls::ClientConfig, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        // One unparseable system certificate must not block the others.
        let _ = roots.add(cert);
    }
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Protocol(format!("TLS setup: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // The key fetch and the upgrade request are HTTP/1.1.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}
