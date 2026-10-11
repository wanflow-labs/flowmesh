// SPDX-License-Identifier: Apache-2.0
//! The serve listeners end to end in one process: a backend, a listener serving the configuration,
//! and raw HTTP requests as a peer would send them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use flowmesh_serve::config::{Change, ServeConfig, apply, mount, tcp_target, web_handler};
use flowmesh_serve::server::{Identity, Kind, Shared, View, serve};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const NAME: &str = "svs.mesh.lab.internal";

/// An HTTP/1.1 backend that answers with the request it got (and switches protocols on
/// `Upgrade: echo`, then echoes bytes).
async fn backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let req = String::from_utf8_lossy(&buf).to_string();
                if req.to_ascii_lowercase().contains("upgrade: echo") {
                    s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: echo\r\n\r\n")
                        .await
                        .unwrap();
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    return;
                }
                let body = req.replace("\r\n", "\n");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

async fn tcp_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// A listener serving `cfg` for `port`, admitting everything from 127.0.0.1 as user `lab`.
async fn listener(cfg: ServeConfig, port: u16, kind: Kind, tagged: bool) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let mut peers = HashMap::new();
    peers.insert(
        "127.0.0.1".parse().unwrap(),
        Identity {
            login: "lab@example.com".into(),
            name: "Lab User".into(),
            profile_pic: String::new(),
            tagged,
        },
    );
    let shared = Arc::new(Shared {
        view: Arc::new(RwLock::new(View {
            name: NAME.into(),
            peers,
            config: cfg,
        })),
        admitted: Arc::new(|_| true),
        log: Arc::new(|s| eprintln!("{s}")),
    });
    tokio::spawn(serve(l, port, kind, shared));
    addr
}

async fn request(addr: SocketAddr, raw: &str) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(raw.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).to_string()
}

fn get(path: &str, host: &str, extra: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n")
}

#[tokio::test]
async fn http_serving() {
    let b = backend().await;
    let dir = std::env::temp_dir().join(format!("fm-serve-e2e-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/a.txt"), "hello-file\n").unwrap();
    let mut cfg = ServeConfig::default();
    for (m, t) in [
        (None, b.to_string()),
        (Some("/api"), format!("http://127.0.0.1:{b}/base")),
        (Some("/text"), "text:hello-text".into()),
        (Some("/files"), dir.display().to_string()),
        (Some("/down"), "1".into()),
    ] {
        let change = Change::Web {
            port: 80,
            mount: mount(m),
            handler: web_handler(&t).unwrap(),
        };
        apply(&mut cfg, NAME, change).unwrap();
    }
    let addr = listener(cfg, 80, Kind::Http, false).await;

    // Proxied with the identity and forwarding headers; claimed ones are replaced.
    let r = request(
        addr,
        &get(
            "/a?x=1",
            NAME,
            "Tailscale-User-Login: evil\r\nX-Forwarded-For: 6.6.6.6\r\n",
        ),
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
    assert!(r.contains("GET /a?x=1 HTTP/1.1"), "{r}");
    assert!(
        r.to_ascii_lowercase()
            .contains("tailscale-user-login: lab@example.com"),
        "{r}"
    );
    assert!(
        r.to_ascii_lowercase()
            .contains("tailscale-user-name: lab user"),
        "{r}"
    );
    assert!(
        r.to_ascii_lowercase()
            .contains("x-forwarded-for: 127.0.0.1"),
        "{r}"
    );
    assert!(!r.contains("evil") && !r.contains("6.6.6.6"), "{r}");
    // The short name works; an address does not (observed).
    assert!(
        request(addr, &get("/", "svs", ""))
            .await
            .starts_with("HTTP/1.1 200")
    );
    let r = request(addr, &get("/", "100.64.0.75", "")).await;
    assert!(
        r.starts_with("HTTP/1.1 404") && r.ends_with("404 page not found\n"),
        "{r}"
    );
    // Mount with a base path on the backend.
    let r = request(addr, &get("/api/v1/items", NAME, "")).await;
    assert!(r.contains("GET /base/v1/items HTTP/1.1"), "{r}");
    let r = request(addr, &get("/api", NAME, "")).await;
    assert!(r.contains("GET /base HTTP/1.1"), "{r}");
    // Text, files, a directory without its slash, a missing file, a backend that is down.
    let r = request(addr, &get("/text", NAME, "")).await;
    assert!(
        r.contains("text/plain; charset=utf-8") && r.ends_with("hello-text"),
        "{r}"
    );
    let r = request(addr, &get("/files/sub/a.txt", NAME, "")).await;
    assert!(
        r.starts_with("HTTP/1.1 200") && r.ends_with("hello-file\n"),
        "{r}"
    );
    let r = request(addr, &get("/files/sub", NAME, "")).await;
    assert!(
        r.starts_with("HTTP/1.1 301") && r.to_ascii_lowercase().contains("location: sub/"),
        "{r}"
    );
    let r = request(addr, &get("/files/sub/", NAME, "")).await;
    assert!(r.contains("<a href=\"a.txt\">a.txt</a>"), "{r}");
    let r = request(addr, &get("/files/../../../etc/passwd", NAME, "")).await;
    assert!(r.starts_with("HTTP/1.1 404"), "{r}");
    let r = request(addr, &get("/files/sub/a.txt", NAME, "Range: bytes=0-4\r\n")).await;
    assert!(r.starts_with("HTTP/1.1 206") && r.ends_with("hello"), "{r}");
    assert!(
        request(addr, &get("/down", NAME, ""))
            .await
            .starts_with("HTTP/1.1 502")
    );
    // POST body passes through.
    let r = request(
        addr,
        &format!("POST /p HTTP/1.1\r\nHost: {NAME}\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello-body"),
    )
    .await;
    assert!(r.contains("hello-body"), "{r}");
    // Protocol upgrade (WebSockets work this way): after 101 the bytes flow both ways.
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!("GET /ws HTTP/1.1\r\nHost: {NAME}\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = s.read(&mut buf).await.unwrap();
    assert!(
        String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&buf[..n])
    );
    s.write_all(b"ping-upgraded").await.unwrap();
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"ping-upgraded");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn tagged_peers_get_no_identity() {
    let b = backend().await;
    let mut cfg = ServeConfig::default();
    apply(
        &mut cfg,
        NAME,
        Change::Web {
            port: 80,
            mount: "/".into(),
            handler: web_handler(&b.to_string()).unwrap(),
        },
    )
    .unwrap();
    let addr = listener(cfg, 80, Kind::Http, true).await;
    let r = request(addr, &get("/", NAME, "Tailscale-User-Login: evil\r\n")).await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(!r.to_ascii_lowercase().contains("tailscale-"), "{r}");
}

#[tokio::test]
async fn tcp_forwarding_with_proxy_protocol() {
    let e = tcp_echo().await;
    let target = tcp_target(&e.to_string()).unwrap();
    let addr = listener(
        ServeConfig::default(),
        2225,
        Kind::Tcp {
            target,
            proxy_protocol: 1,
        },
        true,
    )
    .await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"ping\n").await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    while !String::from_utf8_lossy(&got).contains("ping\n") {
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&got);
    let local = s.local_addr().unwrap();
    assert!(
        text.starts_with(&format!(
            "PROXY TCP4 127.0.0.1 127.0.0.1 {} {e}\r\n",
            local.port()
        )),
        "{text}"
    );
}
