// SPDX-License-Identifier: Apache-2.0
//! What `flowmesh serve` serves, in the official configuration's shape (`serve status --json`,
//! OBS-20261012-serve-official): `TCP` per port (an HTTP server, or a TCP forwarder), `Web` per
//! `<name>:<port>` with handlers per mount path. Parsing targets, applying a command, and the texts
//! the CLI prints are pure functions here.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServeConfig {
    /// Port (as a string, the JSON key) -> what listens there.
    #[serde(rename = "TCP", skip_serializing_if = "BTreeMap::is_empty")]
    pub tcp: BTreeMap<String, TcpHandler>,
    /// `<DNS name>:<port>` -> its HTTP handlers.
    #[serde(rename = "Web", skip_serializing_if = "BTreeMap::is_empty")]
    pub web: BTreeMap<String, WebServer>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TcpHandler {
    #[serde(rename = "HTTP", skip_serializing_if = "std::ops::Not::not")]
    pub http: bool,
    #[serde(rename = "HTTPS", skip_serializing_if = "std::ops::Not::not")]
    pub https: bool,
    /// `host:port` to forward raw TCP to.
    #[serde(rename = "TCPForward", skip_serializing_if = "String::is_empty")]
    pub tcp_forward: String,
    #[serde(rename = "TerminateTLS", skip_serializing_if = "String::is_empty")]
    pub terminate_tls: String,
    /// PROXY protocol version sent to the backend (1 or 2); 0 for none.
    #[serde(rename = "ProxyProtocol", skip_serializing_if = "is_zero")]
    pub proxy_protocol: u8,
}

fn is_zero(v: &u8) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WebServer {
    #[serde(rename = "Handlers")]
    pub handlers: BTreeMap<String, Handler>,
}

/// One mount: exactly one of the three is set.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default)]
pub struct Handler {
    /// `http://…`, `https://…`, `https+insecure://…` or `unix:/path`.
    #[serde(rename = "Proxy", skip_serializing_if = "String::is_empty")]
    pub proxy: String,
    #[serde(rename = "Text", skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// A file or directory on this host.
    #[serde(rename = "Path", skip_serializing_if = "String::is_empty")]
    pub path: String,
}

impl ServeConfig {
    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.web.is_empty()
    }

    /// Ports to listen on, with what each does.
    pub fn ports(&self) -> Vec<(u16, &TcpHandler)> {
        let mut v: Vec<(u16, &TcpHandler)> = self
            .tcp
            .iter()
            .filter_map(|(p, h)| Some((p.parse().ok()?, h)))
            .collect();
        v.sort_by_key(|(p, _)| *p);
        v
    }

    /// The handlers for `port`, whatever name they were configured under.
    pub fn web_for_port(&self, port: u16) -> Option<&WebServer> {
        self.web
            .iter()
            .find(|(k, _)| key_port(k) == Some(port))
            .map(|(_, w)| w)
    }

    /// Both configurations together (the background one and a foreground one).
    pub fn merged(&self, other: &ServeConfig) -> ServeConfig {
        let mut c = self.clone();
        for (p, h) in &other.tcp {
            c.tcp.insert(p.clone(), h.clone());
        }
        for (k, w) in &other.web {
            c.web
                .entry(k.clone())
                .or_default()
                .handlers
                .extend(w.handlers.clone());
        }
        c
    }
}

fn key_port(key: &str) -> Option<u16> {
    key.rsplit_once(':')?.1.parse().ok()
}

/// What a command asks to listen as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Http(u16),
    Https(u16),
    Tcp(u16),
    TlsTerminatedTcp(u16),
}

impl Mode {
    pub fn port(self) -> u16 {
        match self {
            Mode::Http(p) | Mode::Https(p) | Mode::Tcp(p) | Mode::TlsTerminatedTcp(p) => p,
        }
    }

    /// The flag that names this mode, for messages (`--http=80`).
    pub fn flag(self) -> String {
        match self {
            Mode::Http(p) => format!("--http={p}"),
            Mode::Https(p) => format!("--https={p}"),
            Mode::Tcp(p) => format!("--tcp={p}"),
            Mode::TlsTerminatedTcp(p) => format!("--tls-terminated-tcp={p}"),
        }
    }
}

const SCHEMES: &str = "[http https https+insecure unix]";

fn local_host(h: &str) -> bool {
    matches!(h, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

/// A web target: a port, `host:port`, a URL, `unix:/path`, `text:…`, or a file or directory.
pub fn web_handler(target: &str) -> Result<Handler, String> {
    if let Some(t) = target.strip_prefix("text:") {
        return Ok(Handler {
            text: t.to_string(),
            ..Default::default()
        });
    }
    if let Some(p) = target.strip_prefix("unix:") {
        if !p.starts_with('/') {
            return Err(format!("unix socket path must be absolute: {p:?}"));
        }
        return Ok(Handler {
            proxy: target.to_string(),
            ..Default::default()
        });
    }
    if target.starts_with('/') || target.starts_with("./") || target.starts_with("../") {
        let abs =
            std::fs::canonicalize(target).map_err(|e| format!("invalid path {target:?}: {e}"))?;
        return Ok(Handler {
            path: abs.display().to_string(),
            ..Default::default()
        });
    }
    if let Ok(port) = target.parse::<u32>() {
        let port = check_port(port, "proxy target")?;
        return Ok(Handler {
            proxy: format!("http://127.0.0.1:{port}"),
            ..Default::default()
        });
    }
    let url = if target.contains("://") {
        target.to_string()
    } else {
        format!("http://{target}")
    };
    let (scheme, rest) = url.split_once("://").unwrap_or(("", ""));
    if !matches!(scheme, "http" | "https" | "https+insecure") {
        return Err(format!(
            "failed apply web serve: must be a URL starting with one of the supported schemes: {SCHEMES}"
        ));
    }
    let hostport = rest.split('/').next().unwrap_or_default();
    let host = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() => h,
        _ => hostport,
    };
    if !local_host(host) {
        return Err(format!(
            "failed apply web serve: only a server on this machine can be served (localhost, 127.0.0.1 or [::1]), not {host:?}"
        ));
    }
    Ok(Handler {
        proxy: url,
        ..Default::default()
    })
}

/// A TCP forwarding target: a port, `host:port` or `tcp://host:port`, on this machine.
pub fn tcp_target(target: &str) -> Result<String, String> {
    if let Ok(port) = target.parse::<u32>() {
        return Ok(format!("127.0.0.1:{}", check_port(port, "TCP target")?));
    }
    let hp = target.strip_prefix("tcp://").unwrap_or(target);
    let (host, port) = hp
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid TCP target {target:?}: expected host:port"))?;
    port.parse::<u16>()
        .map_err(|_| format!("invalid TCP target {target:?}: bad port"))?;
    if !local_host(host) {
        return Err(format!(
            "only a server on this machine can be forwarded to (localhost, 127.0.0.1 or [::1]), not {host:?}"
        ));
    }
    Ok(hp.to_string())
}

fn check_port(port: u32, what: &str) -> Result<u16, String> {
    u16::try_from(port)
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("invalid {what} port {port}"))
}

/// A listen port flag's value, with the official message for one past 65535.
pub fn listen_port(v: &str, flag: &str) -> Result<u16, String> {
    let n: u64 = v
        .parse()
        .map_err(|_| format!("invalid value {v:?} for flag -{flag}"))?;
    if n > 65535 {
        // The official CLI names the https flag whatever the flag was (observed: bad-port.txt).
        return Err(format!("port number {n} is too high for https flag"));
    }
    u16::try_from(n)
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("invalid port {n}"))
}

/// A mount path from `--set-path`: leading slash, no trailing one (except `/`).
pub fn mount(set_path: Option<&str>) -> String {
    let p = set_path.unwrap_or("/").trim();
    let p = format!("/{}", p.trim_matches('/'));
    if p.len() > 1 { p } else { "/".into() }
}

/// What one `serve` command does to the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Web {
        port: u16,
        mount: String,
        handler: Handler,
    },
    Tcp {
        port: u16,
        target: String,
        proxy_protocol: u8,
    },
    WebOff {
        port: u16,
        mount: String,
    },
    TcpOff {
        port: u16,
    },
}

/// Apply `change`; `name` is this node's DNS name (no trailing dot), the key of `Web` entries.
pub fn apply(cfg: &mut ServeConfig, name: &str, change: Change) -> Result<(), String> {
    match change {
        Change::Web {
            port,
            mount,
            handler,
        } => {
            if let Some(t) = cfg.tcp.get(&port.to_string()) {
                if !t.http {
                    return Err(format!(
                        "port {port} is already serving TCP; turn it off first (--tcp={port} off)"
                    ));
                }
            }
            cfg.tcp.insert(
                port.to_string(),
                TcpHandler {
                    http: true,
                    ..Default::default()
                },
            );
            // Entries made under an earlier name of this node move to the current one.
            let old: Vec<String> = cfg
                .web
                .keys()
                .filter(|k| key_port(k) == Some(port))
                .cloned()
                .collect();
            let mut server = WebServer::default();
            for k in old {
                if let Some(w) = cfg.web.remove(&k) {
                    server.handlers.extend(w.handlers);
                }
            }
            server.handlers.insert(mount, handler);
            cfg.web.insert(format!("{name}:{port}"), server);
        }
        Change::Tcp {
            port,
            target,
            proxy_protocol,
        } => {
            if cfg.tcp.get(&port.to_string()).is_some_and(|t| t.http) {
                return Err(format!(
                    "port {port} is already serving HTTP; turn it off first (--http={port} off)"
                ));
            }
            cfg.tcp.insert(
                port.to_string(),
                TcpHandler {
                    tcp_forward: target,
                    proxy_protocol,
                    ..Default::default()
                },
            );
        }
        Change::WebOff { port, mount } => {
            let key = cfg
                .web
                .keys()
                .find(|k| key_port(k) == Some(port))
                .cloned()
                .ok_or_else(|| format!("nothing is served over HTTP on port {port}"))?;
            let server = cfg.web.get_mut(&key).ok_or("unreachable")?;
            if server.handlers.remove(&mount).is_none() {
                return Err(format!("nothing is served at {mount} on port {port}"));
            }
            if server.handlers.is_empty() {
                cfg.web.remove(&key);
                cfg.tcp.remove(&port.to_string());
            }
        }
        Change::TcpOff { port } => {
            match cfg.tcp.get(&port.to_string()) {
                Some(t) if !t.http => {}
                _ => return Err(format!("nothing is forwarded from TCP port {port}")),
            }
            cfg.tcp.remove(&port.to_string());
        }
    }
    Ok(())
}

/// Check every handler as the CLI checks what it builds: a configuration can reach the daemon
/// over the local API without the CLI. Proxy and forward targets must be on this machine.
pub fn validate(cfg: &ServeConfig) -> Result<(), String> {
    for (port, t) in &cfg.tcp {
        port.parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("invalid port {port:?}"))?;
        if !t.tcp_forward.is_empty() {
            tcp_target(&t.tcp_forward)?;
            if t.http {
                return Err(format!("port {port}: both HTTP and TCP forwarding"));
            }
        }
        if t.proxy_protocol > 2 {
            return Err(format!(
                "port {port}: PROXY protocol version {}",
                t.proxy_protocol
            ));
        }
    }
    for (key, w) in &cfg.web {
        let port = key_port(key).ok_or_else(|| format!("invalid web key {key:?}"))?;
        if !cfg.tcp.get(&port.to_string()).is_some_and(|t| t.http) {
            return Err(format!("{key}: port {port} is not an HTTP port"));
        }
        for (m, h) in &w.handlers {
            if !m.starts_with('/') {
                return Err(format!("{key}: invalid mount {m:?}"));
            }
            let set = [!h.proxy.is_empty(), !h.text.is_empty(), !h.path.is_empty()];
            if set.iter().filter(|x| **x).count() != 1 {
                return Err(format!(
                    "{key}{m}: a handler needs exactly one of Proxy, Text, Path"
                ));
            }
            if !h.proxy.is_empty() {
                web_handler(&h.proxy)?;
            }
            if !h.path.is_empty() && !h.path.starts_with('/') {
                return Err(format!("{key}{m}: path must be absolute"));
            }
        }
    }
    Ok(())
}

/// Handlers the daemon serves with its own rights: files, directories and Unix sockets (by port
/// and mount). Only root may add or change them; anyone allowed to change settings may keep them.
pub fn privileged_handlers(
    cfg: &ServeConfig,
) -> std::collections::BTreeSet<(u16, String, Handler)> {
    cfg.web
        .iter()
        .filter_map(|(k, w)| Some((key_port(k)?, w)))
        .flat_map(|(port, w)| {
            w.handlers
                .iter()
                .filter(|(_, h)| !h.path.is_empty() || h.proxy.starts_with("unix:"))
                .map(move |(m, h)| (port, m.clone(), h.clone()))
        })
        .collect()
}

/// `kind target` of a handler as listed: `proxy http://…`, `text  "…"`, `path  /dir`.
fn handler_line(h: &Handler) -> String {
    if !h.proxy.is_empty() {
        format!("proxy {}", h.proxy)
    } else if !h.text.is_empty() {
        format!("text  {:?}", h.text)
    } else {
        format!("path  {}", h.path)
    }
}

fn web_url(name: &str, port: u16) -> String {
    if port == 80 {
        format!("http://{name}")
    } else {
        format!("http://{name}:{port}")
    }
}

fn tcp_kind(t: &TcpHandler) -> &'static str {
    if t.terminate_tls.is_empty() {
        "TLS over TCP"
    } else {
        "TLS terminated"
    }
}

fn tcp_lines(o: &mut String, name: &str, ips: &[IpAddr], port: u16, t: &TcpHandler, note: &str) {
    o.push_str(&format!(
        "|-- tcp://{name}:{port} ({}{note})\n",
        tcp_kind(t)
    ));
    for ip in ips {
        match ip {
            IpAddr::V4(v4) => o.push_str(&format!("|-- tcp://{v4}:{port}\n")),
            IpAddr::V6(v6) => o.push_str(&format!("|-- tcp://[{v6}]:{port}\n")),
        }
    }
    o.push_str(&format!("|--> tcp://{}\n", t.tcp_forward));
}

/// What a `serve` command prints about the port it changed (`Available within your tailnet:`),
/// as the official CLI does (OBS-20261012-serve-official/http-port.txt, tcp.txt …).
pub fn available(cfg: &ServeConfig, name: &str, ips: &[IpAddr], port: u16) -> String {
    let mut o = String::from("Available within your tailnet:\n\n");
    let Some(t) = cfg.tcp.get(&port.to_string()) else {
        return o;
    };
    if t.http {
        if let Some(w) = cfg.web_for_port(port) {
            for (m, h) in &w.handlers {
                let path = if m == "/" { "/" } else { m.as_str() };
                o.push_str(&format!(
                    "{}{path}\n|-- {}\n\n",
                    web_url(name, port),
                    handler_line(h)
                ));
            }
        }
    } else {
        let note = match t.proxy_protocol {
            0 => String::new(),
            v => format!(", PROXY protocol v{v}"),
        };
        tcp_lines(&mut o, name, ips, port, t, &note);
        o.push('\n');
    }
    o
}

/// The closing lines of a `--bg` command.
pub fn background_footer(off: &str) -> String {
    format!(
        "Serve started and running in the background.\nTo disable the proxy, run: flowmesh serve {off} off\n"
    )
}

/// `serve status`: TCP forwarders, then each HTTP server under both of this node's names, as the
/// official CLI prints it (status-all.txt).
pub fn status(cfg: &ServeConfig, name: &str, ips: &[IpAddr]) -> String {
    if cfg.is_empty() {
        return "No serve config\n".into();
    }
    let short = name.split('.').next().unwrap_or(name);
    let mut o = String::new();
    let mut any_tcp = false;
    for (port, t) in cfg.ports() {
        if !t.http && !t.https {
            tcp_lines(&mut o, name, ips, port, t, ", tailnet only");
            any_tcp = true;
        }
    }
    if any_tcp {
        o.push('\n');
    }
    let mut webs: Vec<(u16, &WebServer)> = cfg
        .web
        .iter()
        .filter_map(|(k, w)| Some((key_port(k)?, w)))
        .collect();
    webs.sort_by_key(|(p, _)| *p);
    for (port, w) in webs {
        o.push_str(&format!("{} (tailnet only)\n", web_url(short, port)));
        o.push_str(&format!("{} (tailnet only)\n", web_url(name, port)));
        let width = w
            .handlers
            .keys()
            .map(|m| m.chars().count())
            .max()
            .unwrap_or(1);
        for (m, h) in &w.handlers {
            o.push_str(&format!("|-- {m:<width$} {}\n", handler_line(h)));
        }
        o.push('\n');
    }
    o
}

/// `serve status --json`: the configuration with the official field names, two-space indent.
pub fn status_json(cfg: &ServeConfig) -> String {
    serde_json::to_string_pretty(cfg).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_raw(f: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/../../fixtures/observed/20261012-serve-official/{f}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    /// The observed server's name (nodes.txt).
    static NAME: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        fixture_raw("nodes.txt")
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_string()
    });

    /// Its addresses: IPv4 from nodes.txt, IPv6 from the TCP listing (tcp.txt).
    fn ips() -> Vec<IpAddr> {
        let v4 = fixture_raw("nodes.txt")
            .split_whitespace()
            .nth(2)
            .unwrap()
            .parse()
            .unwrap();
        let v6 = fixture_raw("tcp.txt")
            .lines()
            .find_map(|l| {
                l.strip_prefix("|-- tcp://[")?
                    .split(']')
                    .next()?
                    .parse()
                    .ok()
            })
            .unwrap();
        vec![v4, v6]
    }

    fn fixture(f: &str) -> String {
        let p = format!(
            "{}/../../fixtures/observed/20261012-serve-official/{f}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .skip(1)
            .filter(|l| !l.starts_with("[exit"))
            .map(|l| format!("{l}\n"))
            .collect::<String>()
            .replace("tailscale serve", "flowmesh serve")
    }

    /// The status text with its TCP forwarder blocks (4 lines each) and HTTP server blocks each put
    /// in a fixed order: the official output lists them in Go's random map order.
    fn tcp_blocks_sorted(text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();
        let n = lines.iter().take_while(|l| l.starts_with("|-")).count();
        let mut blocks: Vec<String> = lines[..n].chunks(4).map(|c| c.join("\n")).collect();
        blocks.sort();
        // The HTTP servers too (blank-line separated), also in Go's map order there.
        let rest = lines[n..].join("\n");
        let mut webs: Vec<&str> = rest
            .split("\n\n")
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .collect();
        webs.sort();
        format!("{}\n{}", blocks.join("\n"), webs.join("\n\n"))
    }

    fn web(c: &mut ServeConfig, port: u16, set_path: Option<&str>, target: &str) {
        let change = Change::Web {
            port,
            mount: mount(set_path),
            handler: web_handler(target).unwrap(),
        };
        apply(c, &NAME, change).unwrap();
    }

    fn tcp(c: &mut ServeConfig, port: u16, target: &str, pp: u8) {
        let change = Change::Tcp {
            port,
            target: tcp_target(target).unwrap(),
            proxy_protocol: pp,
        };
        apply(c, &NAME, change).unwrap();
    }

    /// The observed sequence of commands, checked against the official output at each step.
    #[test]
    fn like_the_official_cli() {
        let mut c = ServeConfig::default();
        assert_eq!(status(&c, &NAME, &ips()), fixture("status-empty.txt"));
        assert_eq!(status_json(&c) + "\n", fixture("status-empty-json.txt"));

        web(&mut c, 80, None, "3000");
        assert_eq!(
            available(&c, &NAME, &ips(), 80) + &background_footer("--http=80"),
            fixture("http-port.txt")
        );
        assert_eq!(status_json(&c) + "\n", fixture("status-http-json.txt"));

        web(&mut c, 80, Some("/api"), "http://127.0.0.1:4000");
        assert_eq!(
            available(&c, &NAME, &ips(), 80) + &background_footer("--http=80"),
            fixture("set-path.txt")
        );
        web(&mut c, 80, Some("/text"), "text:hello-text");
        assert_eq!(status(&c, &NAME, &ips()), fixture("status-paths.txt"));

        web(&mut c, 8080, None, "/tmp");
        c.web
            .get_mut(&format!("{}:8080", *NAME))
            .unwrap()
            .handlers
            .get_mut("/")
            .unwrap()
            .path = "/tmp/site".into();
        assert_eq!(
            available(&c, &NAME, &ips(), 8080) + &background_footer("--http=8080"),
            fixture("dir.txt")
        );
        web(&mut c, 8081, None, "unix:/tmp/echo.sock");
        assert_eq!(
            available(&c, &NAME, &ips(), 8081) + &background_footer("--http=8081"),
            fixture("unix.txt")
        );
        web(&mut c, 8082, None, "3999");
        tcp(&mut c, 2222, "tcp://localhost:7000", 0);
        assert_eq!(
            available(&c, &NAME, &ips(), 2222) + &background_footer("--tcp=2222"),
            fixture("tcp.txt")
        );
        tcp(&mut c, 2223, "7000", 0);
        assert_eq!(
            available(&c, &NAME, &ips(), 2223) + &background_footer("--tcp=2223"),
            fixture("tcp-port-only.txt")
        );
        // TLS-terminated forwarding is refused by flowmesh (no certificates); as the official
        // configuration it would read:
        c.tcp.insert(
            "2224".into(),
            TcpHandler {
                tcp_forward: "127.0.0.1:7000".into(),
                terminate_tls: NAME.to_string(),
                ..Default::default()
            },
        );
        tcp(&mut c, 2225, "tcp://localhost:7000", 1);
        assert_eq!(
            available(&c, &NAME, &ips(), 2225) + &background_footer("--tcp=2225"),
            fixture("proxy-protocol.txt")
        );
        // The official order of TCP forwarders is Go's random map order; flowmesh sorts by port.
        assert_eq!(
            tcp_blocks_sorted(&status(&c, &NAME, &ips())),
            tcp_blocks_sorted(&fixture("status-all.txt"))
        );
        assert_eq!(status_json(&c) + "\n", fixture("status-all-json.txt"));

        apply(
            &mut c,
            &NAME,
            Change::WebOff {
                port: 8082,
                mount: "/".into(),
            },
        )
        .unwrap();
        apply(
            &mut c,
            &NAME,
            Change::WebOff {
                port: 80,
                mount: mount(Some("/api")),
            },
        )
        .unwrap();
        assert_eq!(
            tcp_blocks_sorted(&status(&c, &NAME, &ips())),
            tcp_blocks_sorted(&fixture("status-after-off.txt"))
        );
    }

    /// A configuration sent straight to the daemon is held to the CLI's rules.
    #[test]
    fn validation() {
        let ok: ServeConfig = serde_json::from_value(serde_json::json!({
            "TCP": {"80": {"HTTP": true}, "2222": {"TCPForward": "localhost:22"}},
            "Web": {"n.mesh:80": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:3000"}, "/f": {"Path": "/srv"}, "/u": {"Proxy": "unix:/run/s.sock"}}}}
        }))
        .unwrap();
        validate(&ok).unwrap();
        assert_eq!(privileged_handlers(&ok).len(), 2);
        let bad = |v: serde_json::Value| validate(&serde_json::from_value(v).unwrap()).unwrap_err();
        assert!(bad(serde_json::json!({"TCP": {"80": {"HTTP": true}}, "Web": {"n:80": {"Handlers": {"/": {"Proxy": "http://10.0.0.5:80"}}}}})).contains("this machine"));
        assert!(
            bad(serde_json::json!({"TCP": {"22": {"TCPForward": "192.168.1.1:22"}}}))
                .contains("this machine")
        );
        assert!(bad(serde_json::json!({"TCP": {"80": {"HTTP": true}}, "Web": {"n:80": {"Handlers": {"/": {"Path": "etc"}}}}})).contains("absolute"));
        assert!(
            bad(serde_json::json!({"Web": {"n:81": {"Handlers": {"/": {"Text": "x"}}}}}))
                .contains("not an HTTP port")
        );
        assert!(bad(serde_json::json!({"TCP": {"80": {"HTTP": true}}, "Web": {"n:80": {"Handlers": {"/": {"Text": "x", "Path": "/a"}}}}})).contains("exactly one"));
    }

    #[test]
    fn targets_and_errors() {
        assert_eq!(web_handler("3000").unwrap().proxy, "http://127.0.0.1:3000");
        assert_eq!(
            web_handler("localhost:3000").unwrap().proxy,
            "http://localhost:3000"
        );
        assert_eq!(
            web_handler("https+insecure://localhost:8443/x")
                .unwrap()
                .proxy,
            "https+insecure://localhost:8443/x"
        );
        assert_eq!(web_handler("text:hi").unwrap().text, "hi");
        assert_eq!(
            web_handler("ftp://x").unwrap_err(),
            "failed apply web serve: must be a URL starting with one of the supported schemes: [http https https+insecure unix]"
        );
        assert!(
            web_handler("http://10.0.0.5:80")
                .unwrap_err()
                .contains("only a server on this machine")
        );
        assert!(web_handler("/nonexistent/dir/x").is_err());
        assert!(web_handler("70000").is_err());
        assert_eq!(
            tcp_target("tcp://localhost:7000").unwrap(),
            "localhost:7000"
        );
        assert_eq!(tcp_target("7000").unwrap(), "127.0.0.1:7000");
        assert!(tcp_target("tcp://192.168.1.1:22").is_err());
        assert_eq!(
            listen_port("70000", "http").unwrap_err(),
            "port number 70000 is too high for https flag"
        );
        assert_eq!(mount(Some("api/")), "/api");
        assert_eq!(mount(None), "/");
        // HTTP and TCP cannot share a port.
        let mut c = ServeConfig::default();
        web(&mut c, 80, None, "3000");
        assert!(
            apply(
                &mut c,
                &NAME,
                Change::Tcp {
                    port: 80,
                    target: "127.0.0.1:1".into(),
                    proxy_protocol: 0
                }
            )
            .is_err()
        );
        tcp(&mut c, 81, "7000", 0);
        assert!(
            apply(
                &mut c,
                &NAME,
                Change::Web {
                    port: 81,
                    mount: "/".into(),
                    handler: web_handler("1").unwrap()
                }
            )
            .is_err()
        );
        assert!(apply(&mut c, &NAME, Change::TcpOff { port: 80 }).is_err());
        assert!(
            apply(
                &mut c,
                &NAME,
                Change::WebOff {
                    port: 81,
                    mount: "/".into()
                }
            )
            .is_err()
        );
        // A renamed node keeps its handlers under the new name.
        apply(
            &mut c,
            "new.mesh",
            Change::Web {
                port: 80,
                mount: "/x".into(),
                handler: web_handler("2").unwrap(),
            },
        )
        .unwrap();
        assert_eq!(
            c.web
                .keys()
                .filter(|k| k.ends_with(":80"))
                .collect::<Vec<_>>(),
            ["new.mesh:80"]
        );
        assert_eq!(c.web["new.mesh:80"].handlers.len(), 2);
    }
}
