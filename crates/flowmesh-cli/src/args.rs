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

pub const USAGE: &str = "usage: flowmesh [--socket=PATH] <up|down|logout|set|status|ping|whois|debug|bugreport|version> [flags]";

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
    if net.prefix_len() == 0 {
        return Err(format!(
            "{r} would make this node an exit node, which flowmesh does not support yet"
        ));
    }
    Ok(net)
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
                update.advertise_routes = Some(routes);
            }
            "snat-subnet-routes" => update.snat_subnet_routes = Some(bool_value(name, inline)?),
            "shields-up" => update.shields_up = Some(bool_value(name, inline)?),
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
        assert!(
            p(&["up", "--advertise-routes=0.0.0.0/0"])
                .unwrap_err()
                .contains("exit node")
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
