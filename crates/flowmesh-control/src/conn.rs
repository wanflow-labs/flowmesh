// SPDX-License-Identifier: Apache-2.0
//! Adapts "TCP (or TLS) + Noise record layer" to `AsyncRead`/`AsyncWrite` for HTTP/2.
//! All protocol logic lives in the sans-IO flowmesh-noise crate; this module only moves bytes.

use crate::dial::BoxIo;
use flowmesh_noise::frame::FrameDecoder;
use flowmesh_noise::transport::Transport;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

const READ_CHUNK: usize = 16 * 1024;

pub struct NoiseStream {
    tcp: BoxIo,
    transport: Transport,
    decoder: FrameDecoder,
    /// Decrypted plaintext not yet read by the upper layer.
    plain: Vec<u8>,
    /// Encrypted ciphertext not yet written to the socket.
    pending: Vec<u8>,
    scratch: Vec<u8>,
}

fn io_err(e: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl NoiseStream {
    /// `decoder` may already hold record frames that were read past the handshake.
    pub fn new(tcp: BoxIo, transport: Transport, decoder: FrameDecoder) -> io::Result<Self> {
        let mut s = Self {
            tcp,
            transport,
            decoder,
            plain: Vec::new(),
            pending: Vec::new(),
            scratch: vec![0u8; READ_CHUNK],
        };
        s.pump()?;
        Ok(s)
    }

    pub fn plain_mut(&mut self) -> &mut Vec<u8> {
        &mut self.plain
    }

    /// Reads once from the socket and decrypts; returns false when the peer has closed. Cancel-safe.
    pub async fn read_more(&mut self) -> io::Result<bool> {
        let n = self.tcp.read(&mut self.scratch).await?;
        if n == 0 {
            return Ok(false);
        }
        self.decoder.push(&self.scratch[..n]);
        self.pump()?;
        Ok(true)
    }

    fn pump(&mut self) -> io::Result<()> {
        while let Some(frame) = self.decoder.next_frame().map_err(io_err)? {
            let p = self.transport.open(frame).map_err(io_err)?;
            self.plain.extend_from_slice(&p);
        }
        Ok(())
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.tcp).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.drain(..n);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for NoiseStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.plain.is_empty() {
                let n = this.plain.len().min(buf.remaining());
                buf.put_slice(&this.plain[..n]);
                this.plain.drain(..n);
                return Poll::Ready(Ok(()));
            }
            let mut tmp = ReadBuf::new(&mut this.scratch);
            ready!(Pin::new(&mut this.tcp).poll_read(cx, &mut tmp))?;
            let filled = tmp.filled().len();
            if filled == 0 {
                return Poll::Ready(Ok(()));
            }
            this.decoder.push(&this.scratch[..filled]);
            this.pump()?;
        }
    }
}

impl AsyncWrite for NoiseStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        this.pending = this.transport.seal(buf).map_err(io_err)?;
        // Write out immediately if possible; whatever is left is continued by the next write/flush.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.tcp).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.tcp).poll_shutdown(cx)
    }
}
