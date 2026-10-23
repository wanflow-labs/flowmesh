// SPDX-License-Identifier: Apache-2.0
//! Policy routing while an exit node is in use, laid out as the official client does it
//! (OBS-20261011-exit-node-official): table 52 holds the default route through the mesh
//! interface, rule 5270 sends everything to it, and packets carrying flowmesh's own mark are
//! sent to the main table first (5210), then the default table (5230), and are never routed
//! through the mesh (5250 unreachable). With LAN access allowed, the host's own networks are
//! `throw` routes in table 52, so they fall through to the main table.
//!
//! Router mode (`--exit-node-forwarded-only`, not in the official client): rule 5260 sends the
//! host's own traffic (`iif lo`) to the main table before 5270, so only forwarded traffic (the
//! LAN behind a router) goes through the exit node. Its throw routes follow the host's networks:
//! `throw_update_cmds` moves them in place when `needs_refresh` says the set changed.
//!
//! The builders are pure (tested anywhere); `install` and `remove` run `ip`.

use std::process::Command;

pub const TABLE: &str = "52";
const PRIORITIES: [&str; 4] = ["5210", "5230", "5250", "5270"];
/// Router mode: the host's own traffic goes by the main table (after the mark rules, before 5270).
pub const LOCAL_PREF: &str = "5260";

/// `ip` argument lists that install the rules and table 52; with `forwarded_only` also the rule
/// that keeps the host's own traffic off the exit node.
pub fn install_cmds(
    tun: &str,
    mark: u32,
    mask: u32,
    lan: &[ipnet::IpNet],
    ipv6: bool,
    forwarded_only: bool,
) -> Vec<Vec<String>> {
    let fwmark = format!("{mark:#x}/{mask:#x}");
    let mut out = Vec::new();
    let families: &[&str] = if ipv6 { &["-4", "-6"] } else { &["-4"] };
    for fam in families {
        let v = |args: &[&str]| -> Vec<String> {
            std::iter::once(fam.to_string())
                .chain(args.iter().map(|s| s.to_string()))
                .collect()
        };
        out.push(v(&[
            "rule", "add", "pref", "5210", "fwmark", &fwmark, "table", "main",
        ]));
        out.push(v(&[
            "rule", "add", "pref", "5230", "fwmark", &fwmark, "table", "default",
        ]));
        out.push(v(&[
            "rule",
            "add",
            "pref",
            "5250",
            "fwmark",
            &fwmark,
            "unreachable",
        ]));
        if forwarded_only {
            out.push(v(&[
                "rule", "add", "pref", LOCAL_PREF, "iif", "lo", "table", "main",
            ]));
        }
        out.push(v(&["rule", "add", "pref", "5270", "table", TABLE]));
        out.push(v(&[
            "route", "replace", "default", "dev", tun, "table", TABLE,
        ]));
        let loopback = if *fam == "-4" {
            "127.0.0.0/8"
        } else {
            "::1/128"
        };
        out.push(v(&["route", "replace", "throw", loopback, "table", TABLE]));
        for net in lan {
            if family(net) == *fam {
                out.push(v(&[
                    "route",
                    "replace",
                    "throw",
                    &net.to_string(),
                    "table",
                    TABLE,
                ]));
            }
        }
    }
    out
}

fn family(net: &ipnet::IpNet) -> &'static str {
    match net {
        ipnet::IpNet::V4(_) => "-4",
        ipnet::IpNet::V6(_) => "-6",
    }
}

fn set(nets: &[ipnet::IpNet]) -> std::collections::BTreeSet<ipnet::IpNet> {
    nets.iter().copied().collect()
}

/// Whether the host's networks changed as a set (order and repeats do not count), so the throw
/// routes need to follow.
pub fn needs_refresh(old: &[ipnet::IpNet], new: &[ipnet::IpNet]) -> bool {
    set(old) != set(new)
}

/// `ip` argument lists that move table 52's throw routes from `old` to `new` networks: new ones
/// are added first, then gone ones deleted; the rules and the default route are not touched, so
/// forwarded traffic never finds the exit routing missing. IPv6 entries only with `ipv6`.
pub fn throw_update_cmds(
    old: &[ipnet::IpNet],
    new: &[ipnet::IpNet],
    ipv6: bool,
) -> Vec<Vec<String>> {
    let (old, new) = (set(old), set(new));
    let cmd = |op: &str, net: &ipnet::IpNet| -> Vec<String> {
        [
            family(net),
            "route",
            op,
            "throw",
            &net.to_string(),
            "table",
            TABLE,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    };
    let wanted = |net: &&ipnet::IpNet| ipv6 || net.addr().is_ipv4();
    let mut out: Vec<Vec<String>> = new
        .difference(&old)
        .filter(wanted)
        .map(|n| cmd("replace", n))
        .collect();
    out.extend(old.difference(&new).filter(wanted).map(|n| cmd("del", n)));
    out
}

/// `ip` argument lists that remove what `install_cmds` added (both families; missing entries are
/// fine, so this also cleans up after an unclean exit).
pub fn remove_cmds() -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for fam in ["-4", "-6"] {
        for pref in PRIORITIES.iter().chain([&LOCAL_PREF]) {
            out.push(vec![
                fam.into(),
                "rule".into(),
                "del".into(),
                "pref".into(),
                (*pref).into(),
            ]);
        }
        out.push(vec![
            fam.into(),
            "route".into(),
            "flush".into(),
            "table".into(),
            TABLE.into(),
        ]);
    }
    out
}

fn ip(args: &[String]) -> Result<(), String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Install the exit node routing. Leftovers from an unclean exit are removed first. An IPv6
/// failure (host without IPv6) is a warning: IPv4 still goes through the exit node.
pub fn install(
    tun: &str,
    mark: u32,
    mask: u32,
    lan: &[ipnet::IpNet],
    ipv6: bool,
    forwarded_only: bool,
) -> Result<Option<String>, String> {
    remove();
    let mut warning = None;
    for args in install_cmds(tun, mark, mask, lan, ipv6, forwarded_only) {
        match ip(&args) {
            Ok(()) => {}
            Err(e) if args[0] == "-6" => {
                warning.get_or_insert(format!("IPv6 exit node routing: {e}"));
            }
            Err(e) => {
                remove();
                return Err(e);
            }
        }
    }
    Ok(warning)
}

/// Move the throw routes from `old` to `new` networks (see `throw_update_cmds`). A failed IPv4
/// add is returned (the caller keeps `old` and tries again); a failed delete (already gone) or
/// IPv6 add (host without IPv6 routing, as in `install`) is not.
pub fn update_throws(old: &[ipnet::IpNet], new: &[ipnet::IpNet], ipv6: bool) -> Result<(), String> {
    let mut first_err = None;
    for args in throw_update_cmds(old, new, ipv6) {
        if let Err(e) = ip(&args)
            && args[0] == "-4"
            && args[2] == "replace"
        {
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Remove the exit node routing (errors ignored: entries may already be gone).
pub fn remove() {
    for args in remove_cmds() {
        // A rule may have been added twice; delete until none is left.
        for _ in 0..4 {
            if ip(&args).is_err() || args[1] == "route" {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(cmds: &[Vec<String>]) -> Vec<String> {
        cmds.iter().map(|a| format!("ip {}", a.join(" "))).collect()
    }

    #[test]
    fn rules_and_table_like_the_official_client() {
        let l = lines(&install_cmds(
            "flowmesh0",
            0x80000,
            0xff0000,
            &[],
            true,
            false,
        ));
        for fam in ["-4", "-6"] {
            for want in [
                format!("ip {fam} rule add pref 5210 fwmark 0x80000/0xff0000 table main"),
                format!("ip {fam} rule add pref 5230 fwmark 0x80000/0xff0000 table default"),
                format!("ip {fam} rule add pref 5250 fwmark 0x80000/0xff0000 unreachable"),
                format!("ip {fam} rule add pref 5270 table 52"),
                format!("ip {fam} route replace default dev flowmesh0 table 52"),
            ] {
                assert!(l.contains(&want), "missing {want}");
            }
        }
        assert!(l.contains(&"ip -4 route replace throw 127.0.0.0/8 table 52".to_string()));
        assert!(
            !l.iter().any(|x| x.contains("throw 172.")),
            "no LAN access by default"
        );
        let v4only = lines(&install_cmds(
            "flowmesh0",
            0x80000,
            0xff0000,
            &[],
            false,
            false,
        ));
        assert!(v4only.iter().all(|x| x.starts_with("ip -4")));
    }

    #[test]
    fn lan_access_throws_the_host_networks_per_family() {
        let lan: Vec<ipnet::IpNet> = vec![
            "172.29.0.0/24".parse().unwrap(),
            "fd00:1::/64".parse().unwrap(),
        ];
        let l = lines(&install_cmds(
            "flowmesh0",
            0x80000,
            0xff0000,
            &lan,
            true,
            false,
        ));
        assert!(l.contains(&"ip -4 route replace throw 172.29.0.0/24 table 52".to_string()));
        assert!(l.contains(&"ip -6 route replace throw fd00:1::/64 table 52".to_string()));
        assert!(!l.contains(&"ip -6 route replace throw 172.29.0.0/24 table 52".to_string()));
    }

    fn nets(v: &[&str]) -> Vec<ipnet::IpNet> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    /// Without --exit-node-forwarded-only the commands are exactly what they were before it existed.
    #[test]
    fn not_forwarded_only_is_the_previous_command_list() {
        let lan = nets(&["172.29.0.0/24", "fd00:1::/64"]);
        let l = lines(&install_cmds(
            "flowmesh0",
            0x80000,
            0xff0000,
            &lan,
            true,
            false,
        ));
        let want: Vec<String> = [
            "ip -4 rule add pref 5210 fwmark 0x80000/0xff0000 table main",
            "ip -4 rule add pref 5230 fwmark 0x80000/0xff0000 table default",
            "ip -4 rule add pref 5250 fwmark 0x80000/0xff0000 unreachable",
            "ip -4 rule add pref 5270 table 52",
            "ip -4 route replace default dev flowmesh0 table 52",
            "ip -4 route replace throw 127.0.0.0/8 table 52",
            "ip -4 route replace throw 172.29.0.0/24 table 52",
            "ip -6 rule add pref 5210 fwmark 0x80000/0xff0000 table main",
            "ip -6 rule add pref 5230 fwmark 0x80000/0xff0000 table default",
            "ip -6 rule add pref 5250 fwmark 0x80000/0xff0000 unreachable",
            "ip -6 rule add pref 5270 table 52",
            "ip -6 route replace default dev flowmesh0 table 52",
            "ip -6 route replace throw ::1/128 table 52",
            "ip -6 route replace throw fd00:1::/64 table 52",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(l, want);
    }

    /// Router mode: the host's own traffic (iif lo) is routed by the main table before rule 5270
    /// can send it to the exit node; only forwarded traffic reaches table 52.
    #[test]
    fn forwarded_only_keeps_the_host_own_traffic_off_the_exit_node() {
        let l = lines(&install_cmds(
            "flowmesh0",
            0x80000,
            0xff0000,
            &[],
            true,
            true,
        ));
        for fam in ["-4", "-6"] {
            let bypass = format!("ip {fam} rule add pref {LOCAL_PREF} iif lo table main");
            let exit = format!("ip {fam} rule add pref 5270 table 52");
            let b = l.iter().position(|x| *x == bypass).expect("bypass rule");
            let e = l.iter().position(|x| *x == exit).expect("exit rule");
            assert!(b < e, "the bypass rule is added before 5270");
        }
        let pref: u32 = LOCAL_PREF.parse().unwrap();
        assert!(
            pref > 5250 && pref < 5270,
            "between the mark rules and 5270"
        );
        let v4only = lines(&install_cmds(
            "flowmesh0",
            0x80000,
            0xff0000,
            &[],
            false,
            true,
        ));
        assert!(v4only.contains(&format!(
            "ip -4 rule add pref {LOCAL_PREF} iif lo table main"
        )));
        assert!(v4only.iter().all(|x| x.starts_with("ip -4")));
    }

    #[test]
    fn refresh_only_when_the_set_of_networks_changed() {
        let a = nets(&["192.168.1.0/24", "10.0.0.0/24"]);
        let b = nets(&["10.0.0.0/24", "192.168.1.0/24"]);
        assert!(!needs_refresh(&a, &b), "order does not matter");
        assert!(!needs_refresh(
            &a,
            &nets(&["10.0.0.0/24", "192.168.1.0/24", "10.0.0.0/24"])
        ));
        assert!(needs_refresh(&a, &nets(&["10.0.0.0/24"])));
        assert!(needs_refresh(&a, &nets(&["10.0.0.0/24", "192.168.2.0/24"])));
        assert!(needs_refresh(&[], &a));
        assert!(!needs_refresh(&[], &[]));
    }

    /// The throw routes move in place: new networks are added, gone ones deleted, nothing else
    /// touched (no window in which the exit routing is missing).
    #[test]
    fn throw_update_adds_new_and_deletes_gone_networks() {
        let old = nets(&["192.168.1.0/24", "10.0.0.0/24", "fd00:1::/64"]);
        let new = nets(&["10.0.0.0/24", "192.168.2.0/24", "fd00:2::/64"]);
        let l = lines(&throw_update_cmds(&old, &new, true));
        assert_eq!(
            l,
            vec![
                "ip -4 route replace throw 192.168.2.0/24 table 52",
                "ip -6 route replace throw fd00:2::/64 table 52",
                "ip -4 route del throw 192.168.1.0/24 table 52",
                "ip -6 route del throw fd00:1::/64 table 52",
            ]
        );
        let v4 = lines(&throw_update_cmds(&old, &new, false));
        assert_eq!(
            v4,
            vec![
                "ip -4 route replace throw 192.168.2.0/24 table 52",
                "ip -4 route del throw 192.168.1.0/24 table 52",
            ]
        );
        assert!(throw_update_cmds(&old, &old, true).is_empty());
    }

    #[test]
    fn removal_covers_every_rule_and_the_table() {
        let l = lines(&remove_cmds());
        for fam in ["-4", "-6"] {
            for pref in PRIORITIES {
                assert!(l.contains(&format!("ip {fam} rule del pref {pref}")));
            }
            assert!(l.contains(&format!("ip {fam} rule del pref {LOCAL_PREF}")));
            assert!(l.contains(&format!("ip {fam} route flush table 52")));
        }
    }
}
