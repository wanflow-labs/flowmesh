// SPDX-License-Identifier: Apache-2.0
//! Policy routing while an exit node is in use, laid out as the official client does it
//! (OBS-20261011-exit-node-official): table 52 holds the default route through the mesh
//! interface, rule 5270 sends everything to it, and packets carrying flowmesh's own mark are
//! sent to the main table first (5210), then the default table (5230), and are never routed
//! through the mesh (5250 unreachable). With LAN access allowed, the host's own networks are
//! `throw` routes in table 52, so they fall through to the main table.
//!
//! The builders are pure (tested anywhere); `install` and `remove` run `ip`.

use std::process::Command;

pub const TABLE: &str = "52";
const PRIORITIES: [&str; 4] = ["5210", "5230", "5250", "5270"];

/// `ip` argument lists that install the rules and table 52.
pub fn install_cmds(
    tun: &str,
    mark: u32,
    mask: u32,
    lan: &[ipnet::IpNet],
    ipv6: bool,
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
            let same = matches!(
                (fam, net),
                (&"-4", ipnet::IpNet::V4(_)) | (&"-6", ipnet::IpNet::V6(_))
            );
            if same {
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

/// `ip` argument lists that remove what `install_cmds` added (both families; missing entries are
/// fine, so this also cleans up after an unclean exit).
pub fn remove_cmds() -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for fam in ["-4", "-6"] {
        for pref in PRIORITIES {
            out.push(vec![
                fam.into(),
                "rule".into(),
                "del".into(),
                "pref".into(),
                pref.into(),
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
) -> Result<Option<String>, String> {
    remove();
    let mut warning = None;
    for args in install_cmds(tun, mark, mask, lan, ipv6) {
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
        let l = lines(&install_cmds("flowmesh0", 0x80000, 0xff0000, &[], true));
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
        let v4only = lines(&install_cmds("flowmesh0", 0x80000, 0xff0000, &[], false));
        assert!(v4only.iter().all(|x| x.starts_with("ip -4")));
    }

    #[test]
    fn lan_access_throws_the_host_networks_per_family() {
        let lan: Vec<ipnet::IpNet> = vec![
            "172.29.0.0/24".parse().unwrap(),
            "fd00:1::/64".parse().unwrap(),
        ];
        let l = lines(&install_cmds("flowmesh0", 0x80000, 0xff0000, &lan, true));
        assert!(l.contains(&"ip -4 route replace throw 172.29.0.0/24 table 52".to_string()));
        assert!(l.contains(&"ip -6 route replace throw fd00:1::/64 table 52".to_string()));
        assert!(!l.contains(&"ip -6 route replace throw 172.29.0.0/24 table 52".to_string()));
    }

    #[test]
    fn removal_covers_every_rule_and_the_table() {
        let l = lines(&remove_cmds());
        for fam in ["-4", "-6"] {
            for pref in PRIORITIES {
                assert!(l.contains(&format!("ip {fam} rule del pref {pref}")));
            }
            assert!(l.contains(&format!("ip {fam} route flush table 52")));
        }
    }
}
