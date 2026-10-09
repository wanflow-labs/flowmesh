// SPDX-License-Identifier: Apache-2.0
//! 把"TCP + Noise 记录层"适配成 `AsyncRead`/`AsyncWrite`，供 HTTP/2 使用。
//! 协议逻辑都在 sans-IO 的 flowmesh-noise 里，这里只搬运字节。

use flowmesh_noise::frame::FrameDecoder;
use flowmesh_noise::transport::Transport;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

const READ_CHUNK: usize = 16 * 1024;

pub struct NoiseStream {
    tcp: TcpStream,
    transport: Transport,
    decoder: FrameDecoder,
    /// 已解密、尚未被上层读走的明文。
    plain: Vec<u8>,
    /// 已加密、尚未写进 socket 的密文。
    pending: Vec<u8>,
    scratch: Vec<u8>,
}

fn io_err(e: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl NoiseStream {
    /// `decoder` 中可能已有握手时多读到的记录帧。
    pub fn new(tcp: TcpStream, transport: Transport, decoder: FrameDecoder) -> io::Result<Self> {
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

    /// 从 socket 读一次并解密；返回 false 表示对端已关闭。可安全取消。
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
        // 尽量立即写出；没写完的部分由下一次 write/flush 继续。
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
