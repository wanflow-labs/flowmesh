// SPDX-License-Identifier: Apache-2.0
//! Command-line parsing. Flag syntax follows Go's `flag` package, which the official client uses, so
//! existing scripts keep working: `-x` and `--x` are the same; a boolean is `--x` or `--x=false`
//! (never `--x false`); other flags take `--x value` or `--x=value`.

use flowmesh_daemon::prefs::PrefsUpdate;
use ipnet::IpNet;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Up {
        update: PrefsUpdate,
        reset: bool,
        authkey: Option<AuthKey>,
        /// None = wait forever (official default).
        timeout: Option<Duration>,
    },
    Down,
    Logout,
    Set(PrefsUpdate),
    Status {
        json: bool,
    },
    Ping {
        target: String,
        opts: crate::ping::Options,
    },
    Whois {
        addr: String,
        json: bool,
    },
    /// `debug prefs`
    DebugPrefs,
    /// `debug netmap|paths|filter|derp`, served by the engine.
    Debug(String),
    Bugreport {
        output: Option<PathBuf>,
    },
    Version,
    /// `ip [-4|-6|-1] [peer]`
    Ip {
        family: crate::query::IpFamily,
        peer: Option<String>,
    },
    /// `exit-node list [--filter=country]`
    ExitNodeList {
        filter: Option<String>,
    },
    /// `dns status [--all] [--json]` (`--json` is flowmesh only, see docs/deviations.md #20).
    DnsStatus {
        all: bool,
        json: bool,
    },
    /// `dns query <name> [type]`; no name prints the usage (exit 0, as official).
    DnsQuery {
        name: Option<String>,
        rtype: Option<String>,
    },
    /// `netcheck [--format=json]`
    Netcheck {
        json: bool,
    },
    /// `metrics print`, or `metrics write <file>`
    Metrics {
        write: Option<PathBuf>,
    },
    /// `ssh [user@]<host> [args...]`: the system ssh, checking the peer's advertised host keys.
    Ssh {
        target: String,
        args: Vec<String>,
    },
    /// `nc <host> <port>`: connect stdin/stdout to a peer's TCP port (ssh's ProxyCommand).
    Nc {
        host: String,
        port: u16,
    },
    /// `serve …`
    Serve(crate::serve::ServeArgs),
    /// `serve …` that cannot be done.
    ServeError(String),
}

/// `--auth-key` value; `file:<path>` reads the key from a file (official syntax).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthKey {
    Literal(String),
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub socket: Option<PathBuf>,
    pub command: Command,
}

pub const USAGE: &str = "usage: flowmesh [--socket=PATH] <up|down|logout|set|status|ip|ping|ssh|nc|serve|whois|exit-node|netcheck|dns|metrics|debug|bugreport|version> [flags]";

/// Parse the arguments after the program name.
pub fn parse(args: &[String]) -> Result<Invocation, String> {
    let mut i = 0;
    let mut socket = None;
    while let Some(a) = args.get(i).filter(|a| a.starts_with('-')) {
        let (name, inline) = split_flag(a)?;
        match name {
            "socket" => socket = Some(PathBuf::from(take_value(name, inline, args, &mut i)?)),
            _ => return Err(format!("unknown flag -{name}\n{USAGE}")),
        }
        i += 1;
    }
    let sub = args.get(i).ok_or(USAGE)?;
    let rest = &args[i + 1..];
    let command = match sub.as_str() {
        "up" => prefs_command(rest, true)?,
        "set" => prefs_command(rest, false)?,
        "down" => plain(rest, Command::Down)?,
        "logout" => plain(rest, Command::Logout)?,
        "version" => plain(rest, Command::Version)?,
        "status" => {
            let mut json = false;
            let mut j = 0;
            while let Some(a) = rest.get(j) {
                let (name, inline) = split_flag(a)?;
                match name {
                    "json" => json = bool_value(name, inline)?,
                    _ => return Err(format!("status: unknown flag -{name}")),
                }
                j += 1;
            }
            Command::Status { json }
        }
        "ping" => ping_command(rest)?,
        "ip" => ip_command(rest)?,
        "exit-node" => exit_node_command(rest)?,
        "dns" => match rest {
            [s, flags @ ..] if s == "status" => {
                let (mut all, mut json) = (false, false);
                for f in flags {
                    match split_flag(f)? {
                        ("all", inline) => all = bool_value("all", inline)?,
                        ("json", inline) => json = bool_value("json", inline)?,
                        (name, _) => return Err(format!("dns status: unknown flag -{name}")),
                    }
                }
                Command::DnsStatus { all, json }
            }
            // Arguments past the type are ignored, as by the official command.
            [q, rest @ ..] if q == "query" => Command::DnsQuery {
                name: rest.first().cloned(),
                rtype: rest.get(1).cloned(),
            },
            _ => {
                return Err(
                    "usage: flowmesh dns status [--all]\n       flowmesh dns query <name> [type]  (type: a, aaaa, cname, mx, ns, opt, ptr, srv or txt)".into(),
                );
            }
        },
        "netcheck" => {
            let mut json = false;
            let mut j = 0;
            while let Some(a) = rest.get(j) {
                let (name, inline) = split_flag(a)?;
                match name {
                    "format" => match take_value(name, inline, rest, &mut j)?.as_str() {
                        "" => json = false,
                        "json" | "json-line" => json = true,
                        other => return Err(format!("unknown output format {other:?}")),
                    },
                    "every" | "verbose" => {
                        return Err(format!("netcheck: -{name} is not supported by flowmesh"));
                    }
                    _ => return Err(format!("netcheck: unknown flag -{name}")),
                }
                j += 1;
            }
            Command::Netcheck { json }
        }
        // Errors are reported like the official command's (exit 1), not as usage errors.
        "serve" => match crate::serve::parse(rest) {
            Ok(a) => Command::Serve(a),
            Err(e) => Command::ServeError(e),
        },
        "ssh" => match rest {
            [target, args @ ..] if !target.starts_with('-') => Command::Ssh {
                target: target.clone(),
                args: args.to_vec(),
            },
            _ => return Err("usage: flowmesh ssh [user@]<host> [args...]".into()),
        },
        "nc" => match rest {
            [host, port] => Command::Nc {
                host: host.clone(),
                port: port.parse().map_err(|_| format!("invalid port {port:?}"))?,
            },
            _ => return Err("usage: flowmesh nc <hostname-or-IP> <port>".into()),
        },
        "metrics" => match rest {
            [s] if s == "print" => Command::Metrics { write: None },
            [s, path] if s == "write" => Command::Metrics {
                write: Some(PathBuf::from(path)),
            },
            [s] if s == "write" => return Err("usage: flowmesh metrics write <path>".into()),
            _ => return Err("usage: flowmesh metrics print|write <path>".into()),
        },
        "whois" => {
            let mut json = false;
            let mut i = 0;
            while let Some(a) = rest.get(i).filter(|a| a.starts_with('-')) {
                let (name, inline) = split_flag(a)?;
                match name {
                    "json" => json = bool_value(name, inline)?,
                    _ => return Err(format!("whois: unknown flag -{name}")),
                }
                i += 1;
            }
            match &rest[i.min(rest.len())..] {
                [addr] => Command::Whois {
                    addr: addr.clone(),
                    json,
                },
                [] => return Err("missing argument, expected one peer".into()),
                _ => return Err("too many arguments, expected one peer".into()),
            }
        }
        "debug" => match rest {
            [what] if what == "prefs" => Command::DebugPrefs,
            [what] if ["netmap", "paths", "filter", "derp"].contains(&what.as_str()) => {
                Command::Debug(what.clone())
            }
            _ => return Err("usage: flowmesh debug prefs|netmap|paths|filter|derp".into()),
        },
        "bugreport" => {
            let mut output = None;
            let mut j = 0;
            while let Some(a) = rest.get(j) {
                let (name, inline) = split_flag(a)?;
                match name {
                    "output" | "o" => {
                        output = Some(PathBuf::from(take_value(name, inline, rest, &mut j)?))
                    }
                    _ => return Err(format!("bugreport: unknown flag -{name}")),
                }
                j += 1;
            }
            Command::Bugreport { output }
        }
        other => return Err(format!("unknown command {other:?}\n{USAGE}")),
    };
    Ok(Invocation { socket, command })
}

/// `ping [-c N] [--until-direct[=bool]] <peer>`; flags come before the peer (Go flag parsing stops at
/// the first non-flag argument).
fn ping_command(rest: &[String]) -> Result<Command, String> {
    let mut opts = crate::ping::Options::default();
    let mut i = 0;
    while let Some(a) = rest.get(i).filter(|a| a.starts_with('-')) {
        let (name, inline) = split_flag(a)?;
        match name {
            "c" => {
                let v = take_value(name, inline, rest, &mut i)?;
                opts.count = v
                    .parse()
                    .map_err(|_| format!("invalid value {v:?} for -c"))?;
            }
            "until-direct" => opts.until_direct = bool_value(name, inline)?,
            "timeout" => {
                let d = parse_duration(&take_value(name, inline, rest, &mut i)?)?;
                opts.timeout = (!d.is_zero()).then_some(d);
            }
            _ => return Err(format!("ping: unknown flag -{name}")),
        }
        i += 1;
    }
    match &rest[i.min(rest.len())..] {
        [target] => Ok(Command::Ping {
            target: target.clone(),
            opts,
        }),
        [] => Err("usage: flowmesh ping [flags] <hostname-or-IP>".into()),
        _ => Err("too many non-flag arguments".into()),
    }
}

/// `ip [-4|-6|-1] [peer]`, with the official CLI's messages.
fn ip_command(rest: &[String]) -> Result<Command, String> {
    use crate::query::IpFamily;
    let (mut v4, mut v6, mut one) = (false, false, false);
    let mut i = 0;
    while let Some(a) = rest.get(i).filter(|a| a.starts_with('-')) {
        let (name, inline) = split_flag(a)?;
        match name {
            "4" => v4 = bool_value(name, inline)?,
            "6" => v6 = bool_value(name, inline)?,
            "1" => one = bool_value(name, inline)?,
            _ => return Err(format!("ip: unknown flag -{name}")),
        }
        i += 1;
    }
    let family = match (v4, v6, one) {
        (false, false, false) => IpFamily::All,
        (true, false, false) => IpFamily::V4,
        (false, true, false) => IpFamily::V6,
        (false, false, true) => IpFamily::One,
        _ => return Err("flowmesh ip -1, -4, and -6 are mutually exclusive".into()),
    };
    match &rest[i.min(rest.len())..] {
        [] => Ok(Command::Ip { family, peer: None }),
        [peer] => Ok(Command::Ip {
            family,
            peer: Some(peer.clone()),
        }),
        _ => Err("too many arguments, expected at most one peer".into()),
    }
}

/// `exit-node list [--filter=country]`.
fn exit_node_command(rest: &[String]) -> Result<Command, String> {
    const USE: &str = "usage: flowmesh exit-node list [--filter=country]";
    match rest.first().map(String::as_str) {
        Some("list") => {
            let mut filter = None;
            let mut i = 1;
            while let Some(a) = rest.get(i) {
                let (name, inline) = split_flag(a)?;
                match name {
                    "filter" => {
                        let v = take_value(name, inline, rest, &mut i)?;
                        filter = (!v.is_empty()).then_some(v);
                    }
                    _ => return Err(format!("exit-node list: unknown flag -{name}")),
                }
                i += 1;
            }
            Ok(Command::ExitNodeList { filter })
        }
        _ => Err(USE.into()),
    }
}

fn plain(rest: &[String], c: Command) -> Result<Command, String> {
    match rest.first() {
        None => Ok(c),
        Some(a) => Err(format!("unexpected argument {a:?}")),
    }
}

/// `--name=value` / `-name` → (name, inline value).
/// One `--advertise-routes` entry, checked the way the official client checks it (same messages); a
/// bare address is a single-host route. A default route would make this node an exit node, which
/// flowmesh does not offer yet.
fn parse_route(r: &str) -> Result<IpNet, String> {
    let net = match r.parse::<IpNet>() {
        Ok(n) => n,
        Err(_) => r
            .parse::<std::net::IpAddr>()
            .map(IpNet::from)
            .map_err(|_| format!("{r:?} is not a valid IP address or CIDR prefix"))?,
    };
    if net.trunc() != net {
        return Err(format!(
            "{r} has non-address bits set; expected {}",
            net.trunc()
        ));
    }
    Ok(net)
}

/// The default routes in `--advertise-routes` mean an exit node, as in the official client: both
/// must be given (same messages), and they become `--advertise-exit-node`.
fn split_exit_routes(routes: Vec<IpNet>, update: &mut PrefsUpdate) -> Result<Vec<IpNet>, String> {
    let v4 = routes
        .iter()
        .any(|r| matches!(r, IpNet::V4(_)) && r.prefix_len() == 0);
    let v6 = routes
        .iter()
        .any(|r| matches!(r, IpNet::V6(_)) && r.prefix_len() == 0);
    match (v4, v6) {
        (true, false) => Err(
            "0.0.0.0/0 advertised without its IPv6 counterpart, please also advertise ::/0".into(),
        ),
        (false, true) => Err(
            "::/0 advertised without its IPv4 counterpart, please also advertise 0.0.0.0/0".into(),
        ),
        (true, true) => {
            update.advertise_exit_node.get_or_insert(true);
            Ok(routes.into_iter().filter(|r| r.prefix_len() != 0).collect())
        }
        (false, false) => Ok(routes),
    }
}

/// One `--advertise-tags` entry, checked like the official client (same messages): `tag:` and a
/// name that starts with a letter and holds only letters, digits and dashes.
fn check_tag(t: &str) -> Result<String, String> {
    let name = t
        .strip_prefix("tag:")
        .ok_or_else(|| format!("tag: {t:?}: tags must start with 'tag:'"))?;
    if name.is_empty() {
        return Err(format!("tag: {t:?}: tag names must not be empty"));
    }
    if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return Err(format!(
            "tag: {t:?}: tag names must start with a letter, after 'tag:'"
        ));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!(
            "tag: {t:?}: tag names can only contain numbers, letters, or dashes"
        ));
    }
    Ok(t.to_string())
}

fn split_flag(a: &str) -> Result<(&str, Option<&str>), String> {
    let body = a
        .strip_prefix("--")
        .or_else(|| a.strip_prefix('-'))
        .ok_or_else(|| format!("unexpected argument {a:?}"))?;
    Ok(match body.split_once('=') {
        Some((n, v)) => (n, Some(v)),
        None => (body, None),
    })
}

fn take_value(
    name: &str,
    inline: Option<&str>,
    args: &[String],
    i: &mut usize,
) -> Result<String, String> {
    if let Some(v) = inline {
        return Ok(v.to_string());
    }
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("flag needs an argument: -{name}"))
}

/// Accepted spellings are those of Go's strconv.ParseBool.
fn bool_value(name: &str, inline: Option<&str>) -> Result<bool, String> {
    match inline {
        None | Some("1" | "t" | "T" | "true" | "TRUE" | "True") => Ok(true),
        Some("0" | "f" | "F" | "false" | "FALSE" | "False") => Ok(false),
        Some(v) => Err(format!("invalid boolean value {v:?} for -{name}")),
    }
}

/// `up` (with `is_up`) and `set` share the preference flags; `up` adds registration/waiting flags.
fn prefs_command(rest: &[String], is_up: bool) -> Result<Command, String> {
    let mut update = PrefsUpdate::default();
    let mut reset = false;
    let mut authkey = None;
    let mut timeout = None;
    let mut i = 0;
    while let Some(a) = rest.get(i) {
        if a == "--" {
            if let Some(extra) = rest.get(i + 1) {
                return Err(format!("unexpected argument {extra:?}"));
            }
            break;
        }
        let (name, inline) = split_flag(a)?;
        match name {
            "login-server" => update.control_url = Some(take_value(name, inline, rest, &mut i)?),
            "hostname" => update.hostname = Some(take_value(name, inline, rest, &mut i)?),
            "accept-dns" => update.accept_dns = Some(bool_value(name, inline)?),
            "accept-routes" => update.accept_routes = Some(bool_value(name, inline)?),
            "advertise-routes" => {
                let v = take_value(name, inline, rest, &mut i)?;
                let routes = if v.is_empty() {
                    Vec::new()
                } else {
                    v.split(',')
                        .map(|r| parse_route(r.trim()))
                        .collect::<Result<_, _>>()?
                };
                update.advertise_routes = Some(split_exit_routes(routes, &mut update)?);
            }
            "snat-subnet-routes" => update.snat_subnet_routes = Some(bool_value(name, inline)?),
            "shields-up" => update.shields_up = Some(bool_value(name, inline)?),
            "advertise-exit-node" => update.advertise_exit_node = Some(bool_value(name, inline)?),
            "stateful-filtering" => update.stateful_filtering = Some(bool_value(name, inline)?),
            "exit-node" => {
                let v = take_value(name, inline, rest, &mut i)?;
                if v.starts_with("auto:") {
                    return Err(format!(
                        "--exit-node={v}: automatic exit node selection is not supported yet; name an exit node"
                    ));
                }
                update.exit_node = Some(v);
            }
            "exit-node-allow-lan-access" => {
                update.exit_node_allow_lan_access = Some(bool_value(name, inline)?)
            }
            "exit-node-forwarded-only" => {
                update.exit_node_forwarded_only = Some(bool_value(name, inline)?)
            }
            "ssh" => update.run_ssh = Some(bool_value(name, inline)?),
            // Accepted as given, like the official client (an unknown user simply matches nobody).
            "operator" => update.operator_user = Some(take_value(name, inline, rest, &mut i)?),
            "advertise-tags" => {
                let v = take_value(name, inline, rest, &mut i)?;
                let tags = if v.is_empty() {
                    Vec::new()
                } else {
                    v.split(',')
                        .map(|t| check_tag(t.trim()))
                        .collect::<Result<_, _>>()?
                };
                update.advertise_tags = Some(tags);
            }
            "auth-key" | "authkey" if is_up => {
                let v = take_value(name, inline, rest, &mut i)?;
                authkey = Some(match v.strip_prefix("file:") {
                    Some(path) => AuthKey::File(PathBuf::from(path)),
                    None => AuthKey::Literal(v),
                });
            }
            "reset" if is_up => reset = bool_value(name, inline)?,
            "timeout" if is_up => {
                let d = parse_duration(&take_value(name, inline, rest, &mut i)?)?;
                timeout = (!d.is_zero()).then_some(d);
            }
            _ => {
                let cmd = if is_up { "up" } else { "set" };
                return Err(format!("{cmd}: unknown flag -{name}"));
            }
        }
        i += 1;
    }
    Ok(if is_up {
        Command::Up {
            update,
            reset,
            authkey,
            timeout,
        }
    } else {
        Command::Set(update)
    })
}

/// Go-style duration: a whole number followed by `ms`, `s`, `m` or `h`; `0` alone means zero.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| format!("invalid duration {s:?}"))?;
    let secs = |k: u64| Duration::from_secs(n.saturating_mul(k));
    match unit {
        "ms" => Ok(Duration::from_millis(n)),
        "s" => Ok(secs(1)),
        "m" => Ok(secs(60)),
        "h" => Ok(secs(3600)),
        _ => Err(format!("invalid duration {s:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Invocation, String> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    fn cmd(args: &[&str]) -> Command {
        p(args).unwrap().command
    }

    #[test]
    fn up_with_official_flag_spellings() {
        let c = cmd(&[
            "up",
            "--login-server=http://h",
            "-hostname",
            "fm1",
            "--accept-dns=false",
            "--accept-routes",
            "--advertise-routes=10.0.0.0/24,10.1.0.0/24",
            "--auth-key",
            "tskey-x",
            "--reset",
        ]);
        let Command::Up {
            update,
            reset,
            authkey,
            timeout,
        } = c
        else {
            panic!("{c:?}")
        };
        assert_eq!(update.control_url.as_deref(), Some("http://h"));
        assert_eq!(update.hostname.as_deref(), Some("fm1"));
        assert_eq!(update.accept_dns, Some(false));
        assert_eq!(update.accept_routes, Some(true));
        assert_eq!(
            update.advertise_routes,
            Some(vec![
                "10.0.0.0/24".parse().unwrap(),
                "10.1.0.0/24".parse().unwrap()
            ])
        );
        assert!(reset);
        assert_eq!(authkey, Some(AuthKey::Literal("tskey-x".into())));
        assert_eq!(timeout, None);
    }

    #[test]
    fn authkey_alias_and_file_form() {
        let Command::Up { authkey, .. } = cmd(&["up", "--authkey=file:/etc/k"]) else {
            panic!()
        };
        assert_eq!(authkey, Some(AuthKey::File("/etc/k".into())));
    }

    #[test]
    fn bare_up_mentions_nothing() {
        assert_eq!(
            cmd(&["up"]),
            Command::Up {
                update: PrefsUpdate::default(),
                reset: false,
                authkey: None,
                timeout: None
            }
        );
    }

    /// The official client's messages for bad routes (observed against tailscaled 1.94.2).
    #[test]
    fn advertise_routes_are_checked_like_the_official_client() {
        assert_eq!(
            p(&["up", "--advertise-routes=10.0.0.1/24"]).unwrap_err(),
            "10.0.0.1/24 has non-address bits set; expected 10.0.0.0/24"
        );
        assert_eq!(
            p(&["up", "--advertise-routes=10.0.0.0/24,fd00::1/64"]).unwrap_err(),
            "fd00::1/64 has non-address bits set; expected fd00::/64"
        );
        assert_eq!(
            p(&["up", "--advertise-routes=banana"]).unwrap_err(),
            "\"banana\" is not a valid IP address or CIDR prefix"
        );
        assert_eq!(
            p(&["up", "--advertise-routes=0.0.0.0/0"]).unwrap_err(),
            "0.0.0.0/0 advertised without its IPv6 counterpart, please also advertise ::/0"
        );
        assert_eq!(
            p(&["up", "--advertise-routes=::/0"]).unwrap_err(),
            "::/0 advertised without its IPv4 counterpart, please also advertise 0.0.0.0/0"
        );
        let Command::Up { update, .. } =
            cmd(&["up", "--advertise-routes=0.0.0.0/0,::/0,10.0.0.0/24"])
        else {
            panic!()
        };
        assert_eq!(
            update.advertise_exit_node,
            Some(true),
            "both default routes = exit node"
        );
        assert_eq!(
            update.advertise_routes,
            Some(vec!["10.0.0.0/24".parse().unwrap()])
        );
        let Command::Set(update) = cmd(&["set", "--advertise-exit-node", "--stateful-filtering"])
        else {
            panic!()
        };
        assert_eq!(
            (update.advertise_exit_node, update.stateful_filtering),
            (Some(true), Some(true))
        );
        let Command::Up { update, .. } = cmd(&["up", "--advertise-routes=192.168.1.10"]) else {
            panic!()
        };
        assert_eq!(
            update.advertise_routes,
            Some(vec!["192.168.1.10/32".parse().unwrap()])
        );
    }

    /// The official client's messages for bad tags (observed against tailscaled 1.94.2).
    #[test]
    fn advertise_tags_are_checked_like_the_official_client() {
        for (arg, msg) in [
            ("eng", "tag: \"eng\": tags must start with 'tag:'"),
            ("tag:", "tag: \"tag:\": tag names must not be empty"),
            (
                "tag:bad_name",
                "tag: \"tag:bad_name\": tag names can only contain numbers, letters, or dashes",
            ),
            (
                "tag:9lives",
                "tag: \"tag:9lives\": tag names must start with a letter, after 'tag:'",
            ),
        ] {
            assert_eq!(
                p(&["up", &format!("--advertise-tags={arg}")]).unwrap_err(),
                msg
            );
        }
        let Command::Up { update, .. } = cmd(&["up", "--advertise-tags=tag:Upper,tag:ok-1"]) else {
            panic!()
        };
        assert_eq!(
            update.advertise_tags,
            Some(vec!["tag:Upper".into(), "tag:ok-1".into()])
        );
        let Command::Set(update) = cmd(&["set", "--shields-up"]) else {
            panic!()
        };
        assert_eq!(update.shields_up, Some(true));
    }

    #[test]
    fn exit_node_flags() {
        let Command::Up { update, .. } = cmd(&[
            "up",
            "--exit-node=100.64.0.9",
            "--exit-node-allow-lan-access",
        ]) else {
            panic!()
        };
        assert_eq!(update.exit_node.as_deref(), Some("100.64.0.9"));
        assert_eq!(update.exit_node_allow_lan_access, Some(true));
        let Command::Up { update, .. } = cmd(&["up", "--exit-node-forwarded-only"]) else {
            panic!()
        };
        assert_eq!(update.exit_node_forwarded_only, Some(true));
        let Command::Set(update) = cmd(&["set", "--exit-node-forwarded-only=false"]) else {
            panic!()
        };
        assert_eq!(update.exit_node_forwarded_only, Some(false));
        let Command::Set(update) = cmd(&["set", "--exit-node-forwarded-only=true"]) else {
            panic!()
        };
        assert_eq!(update.exit_node_forwarded_only, Some(true));
        assert!(p(&["set", "--exit-node-forwarded-only=maybe"]).is_err());
        let Command::Set(update) = cmd(&["set", "--exit-node="]) else {
            panic!()
        };
        assert_eq!(
            update.exit_node.as_deref(),
            Some(""),
            "empty: stop using an exit node"
        );
        assert!(
            p(&["up", "--exit-node=auto:any"])
                .unwrap_err()
                .contains("not supported yet")
        );
    }

    #[test]
    fn snat_subnet_routes_flag() {
        let Command::Up { update, .. } = cmd(&["up", "--snat-subnet-routes=false"]) else {
            panic!()
        };
        assert_eq!(update.snat_subnet_routes, Some(false));
        let Command::Set(update) = cmd(&["set", "--snat-subnet-routes"]) else {
            panic!()
        };
        assert_eq!(update.snat_subnet_routes, Some(true));
    }

    #[test]
    fn empty_advertise_routes_clears() {
        let Command::Up { update, .. } = cmd(&["up", "--advertise-routes="]) else {
            panic!()
        };
        assert_eq!(update.advertise_routes, Some(Vec::new()));
    }

    #[test]
    fn boolean_takes_no_separate_value() {
        // Go flag semantics: "false" is not consumed by the boolean, so it is an unexpected argument.
        assert!(p(&["up", "--accept-dns", "false"]).is_err());
        let Command::Up { update, .. } = cmd(&["up", "--accept-dns=true"]) else {
            panic!()
        };
        assert_eq!(update.accept_dns, Some(true));
        assert!(p(&["up", "--accept-dns=maybe"]).is_err());
    }

    #[test]
    fn malformed_flags_are_errors() {
        for bad in ["-", "---x", "-=x", "--=x"] {
            assert!(p(&["up", bad]).is_err(), "{bad}");
        }
    }

    #[test]
    fn double_dash_ends_flags_and_allows_nothing_after() {
        assert!(p(&["up", "--hostname=a", "--"]).is_ok());
        assert!(p(&["up", "--", "extra"]).is_err());
        assert!(p(&["up", "stray"]).is_err());
    }

    #[test]
    fn value_flag_needs_a_value() {
        assert!(p(&["up", "--hostname"]).is_err());
    }

    #[test]
    fn unknown_flag_and_command_are_errors() {
        assert!(p(&["up", "--bogus"]).is_err());
        assert!(p(&["frobnicate"]).is_err());
        assert!(p(&[]).is_err());
        assert!(p(&["up", "--advertise-routes=not-a-prefix"]).is_err());
    }

    #[test]
    fn set_rejects_up_only_flags() {
        assert!(p(&["set", "--reset"]).is_err());
        assert!(p(&["set", "--auth-key=k"]).is_err());
        assert!(p(&["set", "--timeout=5s"]).is_err());
        let c = cmd(&["set", "--accept-routes=false"]);
        assert_eq!(
            c,
            Command::Set(PrefsUpdate {
                accept_routes: Some(false),
                ..Default::default()
            })
        );
    }

    #[test]
    fn simple_commands() {
        assert_eq!(cmd(&["down"]), Command::Down);
        assert_eq!(cmd(&["logout"]), Command::Logout);
        assert_eq!(cmd(&["version"]), Command::Version);
        assert_eq!(cmd(&["status"]), Command::Status { json: false });
        assert_eq!(cmd(&["status", "--json"]), Command::Status { json: true });
        assert!(p(&["down", "--json"]).is_err());
        assert!(p(&["down", "extra"]).is_err());
    }

    #[test]
    fn ip_and_exit_node_commands() {
        use crate::query::IpFamily;
        assert_eq!(
            cmd(&["ip"]),
            Command::Ip {
                family: IpFamily::All,
                peer: None
            }
        );
        assert_eq!(
            cmd(&["ip", "-4"]),
            Command::Ip {
                family: IpFamily::V4,
                peer: None
            }
        );
        assert_eq!(
            cmd(&["ip", "--6", "toe"]),
            Command::Ip {
                family: IpFamily::V6,
                peer: Some("toe".into())
            }
        );
        assert_eq!(
            cmd(&["ip", "-1"]),
            Command::Ip {
                family: IpFamily::One,
                peer: None
            }
        );
        // Official messages (OBS-20261012-cli-more-official/ip-4-6.txt, ip-too-many.txt).
        assert_eq!(
            p(&["ip", "-4", "-6"]).unwrap_err(),
            "flowmesh ip -1, -4, and -6 are mutually exclusive"
        );
        assert_eq!(
            p(&["ip", "a", "b"]).unwrap_err(),
            "too many arguments, expected at most one peer"
        );
        assert_eq!(
            cmd(&["exit-node", "list"]),
            Command::ExitNodeList { filter: None }
        );
        assert_eq!(
            cmd(&["exit-node", "list", "--filter=Korea"]),
            Command::ExitNodeList {
                filter: Some("Korea".into())
            }
        );
        assert_eq!(
            cmd(&["exit-node", "list", "-filter", "Korea"]),
            Command::ExitNodeList {
                filter: Some("Korea".into())
            }
        );
        assert!(p(&["exit-node"]).is_err());
        assert!(p(&["exit-node", "list", "--json"]).is_err());
    }

    #[test]
    fn ssh_and_nc_commands() {
        assert_eq!(
            cmd(&["ssh", "root@tss", "-tt", "id"]),
            Command::Ssh {
                target: "root@tss".into(),
                args: vec!["-tt".into(), "id".into()]
            }
        );
        assert_eq!(
            cmd(&["ssh", "tss"]),
            Command::Ssh {
                target: "tss".into(),
                args: vec![]
            }
        );
        assert!(p(&["ssh"]).is_err());
        assert!(p(&["ssh", "-v", "tss"]).is_err());
        assert_eq!(
            cmd(&["nc", "tss", "22"]),
            Command::Nc {
                host: "tss".into(),
                port: 22
            }
        );
        assert!(p(&["nc", "tss", "x"]).is_err());
        assert!(p(&["nc", "tss"]).is_err());
        let Command::Set(u) = cmd(&["set", "--ssh"]) else {
            panic!()
        };
        assert_eq!(u.run_ssh, Some(true));
    }

    #[test]
    fn dns_netcheck_metrics_commands() {
        let dns = |all, json| Command::DnsStatus { all, json };
        assert_eq!(cmd(&["dns", "status"]), dns(false, false));
        assert_eq!(cmd(&["dns", "status", "--all"]), dns(true, false));
        assert_eq!(cmd(&["dns", "status", "--json"]), dns(false, true));
        assert_eq!(cmd(&["dns", "status", "--json", "--all"]), dns(true, true));
        assert_eq!(
            cmd(&["dns", "status", "--all=false", "-json"]),
            dns(false, true)
        );
        assert!(p(&["dns", "status", "--bogus"]).is_err());
        assert!(p(&["dns"]).is_err());
        assert_eq!(
            cmd(&["dns", "query", "a", "b", "c"]),
            Command::DnsQuery {
                name: Some("a".into()),
                rtype: Some("b".into())
            }
        );
        assert_eq!(
            cmd(&["dns", "query"]),
            Command::DnsQuery {
                name: None,
                rtype: None
            }
        );
        assert_eq!(cmd(&["netcheck"]), Command::Netcheck { json: false });
        assert_eq!(
            cmd(&["netcheck", "--format=json"]),
            Command::Netcheck { json: true }
        );
        // Official message (netcheck-bad-format.txt).
        assert_eq!(
            p(&["netcheck", "--format=xml"]).unwrap_err(),
            "unknown output format \"xml\""
        );
        assert_eq!(cmd(&["metrics", "print"]), Command::Metrics { write: None });
        assert_eq!(
            cmd(&["metrics", "write", "/var/lib/node_exporter/flowmesh.prom"]),
            Command::Metrics {
                write: Some("/var/lib/node_exporter/flowmesh.prom".into())
            }
        );
        assert!(p(&["metrics"]).is_err());
        assert!(p(&["metrics", "write"]).is_err());
    }

    #[test]
    fn global_socket_flag() {
        let inv = p(&["--socket=/tmp/x.sock", "status"]).unwrap();
        assert_eq!(inv.socket, Some("/tmp/x.sock".into()));
        let inv = p(&["--socket", "/tmp/y.sock", "down"]).unwrap();
        assert_eq!(inv.socket, Some("/tmp/y.sock".into()));
        assert_eq!(p(&["down"]).unwrap().socket, None);
    }

    #[test]
    fn up_timeout() {
        let Command::Up { timeout, .. } = cmd(&["up", "--timeout=30s"]) else {
            panic!()
        };
        assert_eq!(timeout, Some(Duration::from_secs(30)));
        let Command::Up { timeout, .. } = cmd(&["up", "--timeout", "0s"]) else {
            panic!()
        };
        assert_eq!(
            timeout, None,
            "0 means wait forever, as in the official client"
        );
    }

    #[test]
    fn ping_arguments() {
        use crate::ping::Options;
        assert_eq!(
            cmd(&["ping", "ts1"]),
            Command::Ping {
                target: "ts1".into(),
                opts: Options::default()
            }
        );
        assert_eq!(
            cmd(&["ping", "-c", "3", "--until-direct=false", "100.64.0.1"]),
            Command::Ping {
                target: "100.64.0.1".into(),
                opts: Options {
                    count: 3,
                    until_direct: false,
                    timeout: None
                }
            }
        );
        assert!(
            p(&["ping"])
                .unwrap_err()
                .starts_with("usage: flowmesh ping")
        );
        assert_eq!(
            p(&["ping", "a", "b"]).unwrap_err(),
            "too many non-flag arguments"
        );
        assert!(
            p(&["ping", "a", "-c", "3"]).is_err(),
            "flags after the peer are not flags"
        );
        assert!(p(&["ping", "-c", "x", "a"]).is_err());
        assert!(p(&["ping", "--bogus", "a"]).is_err());
        let Command::Ping { opts, .. } = cmd(&["ping", "--timeout=2s", "a"]) else {
            panic!()
        };
        assert_eq!(opts.timeout, Some(Duration::from_secs(2)));
        let Command::Ping { opts, .. } = cmd(&["ping", "--timeout", "0", "a"]) else {
            panic!()
        };
        assert_eq!(opts.timeout, None, "0 means the default");
    }

    #[test]
    fn whois_arguments() {
        assert_eq!(
            cmd(&["whois", "100.64.0.1:22"]),
            Command::Whois {
                addr: "100.64.0.1:22".into(),
                json: false
            }
        );
        assert_eq!(
            cmd(&["whois", "--json", "100.64.0.1"]),
            Command::Whois {
                addr: "100.64.0.1".into(),
                json: true
            }
        );
        assert_eq!(
            p(&["whois"]).unwrap_err(),
            "missing argument, expected one peer"
        );
        assert!(p(&["whois", "a", "b"]).is_err());
        assert!(p(&["whois", "--bogus", "a"]).is_err());
    }

    #[test]
    fn debug_and_bugreport() {
        assert_eq!(cmd(&["debug", "prefs"]), Command::DebugPrefs);
        assert!(p(&["debug"]).is_err());
        assert_eq!(cmd(&["debug", "paths"]), Command::Debug("paths".into()));
        assert_eq!(cmd(&["debug", "derp"]), Command::Debug("derp".into()));
        assert!(p(&["debug", "bogus"]).is_err());
        assert!(p(&["debug", "netmap", "extra"]).is_err());
        assert_eq!(cmd(&["bugreport"]), Command::Bugreport { output: None });
        assert_eq!(
            cmd(&["bugreport", "--output", "/tmp/r.json"]),
            Command::Bugreport {
                output: Some("/tmp/r.json".into())
            }
        );
        assert_eq!(
            cmd(&["bugreport", "-o=/tmp/r.json"]),
            Command::Bugreport {
                output: Some("/tmp/r.json".into())
            }
        );
        assert!(p(&["bugreport", "--upload"]).is_err());
        assert!(p(&["bugreport", "stray"]).is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("2s"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_duration("3m"), Ok(Duration::from_secs(180)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse_duration("0"), Ok(Duration::ZERO));
        assert!(parse_duration("5").is_err());
        assert!(parse_duration("s").is_err());
        assert!(parse_duration("-1s").is_err());
        assert!(parse_duration("1d").is_err());
    }
}
