// SPDX-License-Identifier: Apache-2.0
//! flowmesh's own sockets (control, DERP, the WireGuard/disco UDP socket, DNS forwarding) carry a
//! firewall mark. When an exit node is in use, policy routing sends everything else through the
//! mesh interface and marked packets through the main table, so the tunnel never carries itself.
//! The mark and the rule priorities are the official client's (OBS-20261011-exit-node-official);
//! on CPEs the agent reserves this bit for the mesh.
//!
//! On Linux the mark is set with SO_MARK (needs CAP_NET_ADMIN; without it the socket works
//! unmarked); elsewhere these functions open plain sockets.

use std::io;
use tokio::net::{TcpSocket, TcpStream};

/// The fwmark on flowmesh's own packets, and the mask it lives in.
pub const BYPASS_MARK: u32 = 0x80000;
pub const BYPASS_MASK: u32 = 0xff0000;

/// Mark a socket as flowmesh's own (best effort).
#[cfg(target_os = "linux")]
pub fn mark<S: std::os::fd::AsFd>(sock: &S) {
    let _ = nix::sys::socket::setsockopt(sock, nix::sys::socket::sockopt::Mark, &BYPASS_MARK);
}

#[cfg(not(target_os = "linux"))]
pub fn mark<S>(_sock: &S) {}

/// `TcpStream::connect` with the mark set before connecting: the addresses of `host` are tried in
/// order, the first that connects wins.
pub async fn tcp_connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = None;
    for addr in tokio::net::lookup_host((host, port)).await? {
        let sock = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        mark(&sock);
        match sock.connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{host}: no address"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connects_like_tcp_stream_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.map(|(_, a)| a) });
        let s = tcp_connect("localhost", port).await.unwrap();
        assert_eq!(accept.await.unwrap().unwrap(), s.local_addr().unwrap());
        assert!(
            tcp_connect("127.0.0.1", 1).await.is_err(),
            "refused port: an error, not a hang"
        );
    }
}
