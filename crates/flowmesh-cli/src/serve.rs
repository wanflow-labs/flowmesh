// SPDX-License-Identifier: Apache-2.0
//! `flowmesh serve` arguments (docs/protocol/serve.md). Flags follow Go's flag syntax like the
//! rest of the CLI; the target comes after them.

use flowmesh_serve::config::{self, Change, Mode};

pub const USAGE: &str = "usage: flowmesh serve [--bg] [--http=<port> | --tcp=<port>] [--set-path=<path>] [--proxy-protocol=1|2] <target> | off\n       flowmesh serve status [--json]\n       flowmesh serve reset";

pub const HELP: &str = "Share a local server, files or text with the mesh

usage: flowmesh serve [--bg] [--http=<port> | --tcp=<port>] [--set-path=<path>] [--proxy-protocol=1|2] <target> | off
       flowmesh serve status [--json]
       flowmesh serve reset

<target> for --http: a port (3000), host:port or a URL on this machine (http://, https://,
https+insecure://), unix:/path/to.sock, text:<text>, or a file or directory.
<target> for --tcp: a port, host:port or tcp://host:port on this machine.

Peers reach it as http://<this node's name>[:port]/ (--http) or <name or address>:<port> (--tcp).
Without --bg it is served until this command is interrupted; `off` with the same flags removes it.
HTTPS (--https, --tls-terminated-tcp) needs certificates from the control server and is not
available.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeArgs {
    Help,
    Status {
        json: bool,
    },
    Reset,
    Apply {
        bg: bool,
        mode: Mode,
        change: Change,
    },
}

const NO_HTTPS: &str = "HTTPS serving needs certificates from the control server, which it does not issue; serve over HTTP instead (--http=<port>) or forward TCP (--tcp=<port>)";

fn bool_flag(name: &str, inline: Option<&str>) -> Result<bool, String> {
    match inline {
        None | Some("true") | Some("1") => Ok(true),
        Some("false") | Some("0") => Ok(false),
        Some(v) => Err(format!("invalid boolean value {v:?} for -{name}")),
    }
}

/// Parse the arguments after `serve`.
pub fn parse(rest: &[String]) -> Result<ServeArgs, String> {
    if rest
        .iter()
        .any(|a| matches!(a.as_str(), "-h" | "--help" | "-help"))
    {
        return Ok(ServeArgs::Help);
    }
    match rest.first().map(String::as_str) {
        Some("status") => {
            let mut json = false;
            for a in &rest[1..] {
                let (name, inline) = split(a)?;
                match name {
                    "json" => json = bool_flag(name, inline)?,
                    _ => return Err(format!("serve status: unknown flag -{name}")),
                }
            }
            return Ok(ServeArgs::Status { json });
        }
        Some("reset") if rest.len() == 1 => return Ok(ServeArgs::Reset),
        Some(s @ ("drain" | "clear" | "advertise" | "get-config" | "set-config")) => {
            return Err(format!(
                "serve {s}: services (a name of their own in the tailnet) need control server support that flowmesh's control server does not have"
            ));
        }
        _ => {}
    }
    let (mut bg, mut set_path, mut pp) = (false, None, 0u8);
    let mut modes = Vec::new();
    let mut i = 0;
    while let Some(a) = rest.get(i).filter(|a| a.starts_with('-')) {
        let (name, inline) = split(a)?;
        let mut value = || take(rest, &mut i, name, inline);
        match name {
            "bg" => bg = bool_flag(name, inline)?,
            "yes" => {
                bool_flag(name, inline)?;
            }
            "http" => modes.push(Mode::Http(config::listen_port(&value()?, name)?)),
            "https" => modes.push(Mode::Https(config::listen_port(&value()?, name)?)),
            "tcp" => modes.push(Mode::Tcp(config::listen_port(&value()?, name)?)),
            "tls-terminated-tcp" => modes.push(Mode::TlsTerminatedTcp(config::listen_port(
                &value()?,
                name,
            )?)),
            "set-path" => set_path = Some(value()?),
            "proxy-protocol" => {
                pp = match value()?.as_str() {
                    "1" => 1,
                    "2" => 2,
                    v => return Err(format!("invalid PROXY protocol version {v:?}: 1 or 2")),
                }
            }
            "service" | "tun" | "accept-app-caps" => {
                return Err(format!(
                    "-{name}: services and app capabilities need control server support that flowmesh's control server does not have"
                ));
            }
            _ => return Err(format!("serve: unknown flag -{name}\n{USAGE}")),
        }
        i += 1;
    }
    let target = match &rest[i.min(rest.len())..] {
        [t] => t.clone(),
        [] => return Err(USAGE.into()),
        _ => return Err(format!("too many arguments\n{USAGE}")),
    };
    let mode = match modes.as_slice() {
        [] => return Err(NO_HTTPS.into()),
        [m] => *m,
        _ => return Err("cannot serve multiple types for a single mount point".into()),
    };
    let off = target == "off";
    let change = match mode {
        Mode::Https(_) | Mode::TlsTerminatedTcp(_) => return Err(NO_HTTPS.into()),
        Mode::Http(port) => {
            if pp != 0 {
                return Err("--proxy-protocol is for TCP forwarding (--tcp)".into());
            }
            let mount = config::mount(set_path.as_deref());
            if off {
                Change::WebOff { port, mount }
            } else {
                Change::Web {
                    port,
                    mount,
                    handler: config::web_handler(&target)?,
                }
            }
        }
        Mode::Tcp(port) => {
            if set_path.is_some() {
                return Err("--set-path is for HTTP (--http)".into());
            }
            if off {
                Change::TcpOff { port }
            } else {
                Change::Tcp {
                    port,
                    target: config::tcp_target(&target)?,
                    proxy_protocol: pp,
                }
            }
        }
    };
    Ok(ServeArgs::Apply { bg, mode, change })
}

fn take(
    rest: &[String],
    i: &mut usize,
    name: &str,
    inline: Option<&str>,
) -> Result<String, String> {
    match inline {
        Some(v) => Ok(v.to_string()),
        None => {
            *i += 1;
            rest.get(*i)
                .cloned()
                .ok_or_else(|| format!("flag needs an argument: -{name}"))
        }
    }
}

fn split(a: &str) -> Result<(&str, Option<&str>), String> {
    let s = a
        .strip_prefix("--")
        .or_else(|| a.strip_prefix('-'))
        .ok_or_else(|| format!("not a flag: {a}"))?;
    Ok(match s.split_once('=') {
        Some((n, v)) => (n, Some(v)),
        None => (s, None),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Result<ServeArgs, String> {
        parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn commands() {
        assert_eq!(p(&["status"]), Ok(ServeArgs::Status { json: false }));
        assert_eq!(
            p(&["status", "--json"]),
            Ok(ServeArgs::Status { json: true })
        );
        assert_eq!(p(&["reset"]), Ok(ServeArgs::Reset));
        assert_eq!(p(&["--help"]), Ok(ServeArgs::Help));
        let ServeArgs::Apply { bg, mode, change } =
            p(&["--bg", "--http=80", "--set-path", "/api", "4000"]).unwrap()
        else {
            panic!()
        };
        assert!(bg);
        assert_eq!(mode, Mode::Http(80));
        assert!(
            matches!(change, Change::Web { port: 80, ref mount, ref handler } if mount == "/api" && handler.proxy == "http://127.0.0.1:4000")
        );
        assert!(matches!(
            p(&["--tcp=2225", "--proxy-protocol=1", "tcp://localhost:7000"]).unwrap(),
            ServeArgs::Apply {
                bg: false,
                change: Change::Tcp {
                    port: 2225,
                    proxy_protocol: 1,
                    ..
                },
                ..
            }
        ));
        assert!(matches!(
            p(&["--http=80", "--set-path=/api", "off"]).unwrap(),
            ServeArgs::Apply { change: Change::WebOff { port: 80, ref mount }, .. } if mount == "/api"
        ));
        assert!(matches!(
            p(&["--tcp=2222", "off"]).unwrap(),
            ServeArgs::Apply {
                change: Change::TcpOff { port: 2222 },
                ..
            }
        ));
    }

    #[test]
    fn refusals() {
        // Default mode is HTTPS, as official; flowmesh has no certificates.
        assert!(p(&["3000"]).unwrap_err().contains("certificates"));
        assert!(
            p(&["--https=443", "3000"])
                .unwrap_err()
                .contains("certificates")
        );
        assert!(
            p(&["--tls-terminated-tcp=2224", "7000"])
                .unwrap_err()
                .contains("certificates")
        );
        // Official messages (two-modes.txt, bad-port.txt, bad-target.txt).
        assert_eq!(
            p(&["--bg", "--http=80", "--tcp=81", "3000"]).unwrap_err(),
            "cannot serve multiple types for a single mount point"
        );
        assert_eq!(
            p(&["--bg", "--http=70000", "3000"]).unwrap_err(),
            "port number 70000 is too high for https flag"
        );
        assert!(
            p(&["--bg", "--http=80", "ftp://x"])
                .unwrap_err()
                .contains("supported schemes")
        );
        assert!(
            p(&["--service=svc:web", "--http=80", "3000"])
                .unwrap_err()
                .contains("services")
        );
        assert!(
            p(&["advertise", "svc:web"])
                .unwrap_err()
                .contains("services")
        );
        assert!(p(&["--http=80", "--proxy-protocol=1", "3000"]).is_err());
        assert!(p(&["--tcp=81", "--set-path=/x", "3000"]).is_err());
        assert!(p(&["--http=80"]).is_err());
    }
}
