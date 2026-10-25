// SPDX-License-Identifier: Apache-2.0
//! Netfilter rules for a subnet router (`--advertise-routes`): accept forwarding to and from the
//! mesh interface, and masquerade what the mesh sends into the routed subnets (`--snat-subnet-routes`,
//! on by default like the official client, which does the same with a fwmark set in FORWARD; see
//! OBS-20261011-subnet-router-official). flowmesh matches the mesh's source range instead of a mark,
//! so no fwmark bits are taken (deviations.md #10).
//!
//! With `iptables` present the rules go into the host's own iptables variant (legacy or nft), the
//! same one Docker and firewalld-iptables use, so a FORWARD policy of DROP set there is overridden by
//! our accept rules. Without it, an `inet flowmesh` nftables table does the same.
//!
//! Router exit mode (`--exit-node-forwarded-only`, not in the official client) adds its own SNAT:
//! forwarded IPv4 traffic leaving through the mesh interface towards the exit node is masqueraded
//! to this node's mesh address, except traffic to the mesh range or to a peer's approved subnet
//! route (those keep their real source, as without an exit node). It lives in chain
//! `fm-exit-snat` (or an `ip flowmesh_exit` nftables table), apart from the subnet router rules.
//!
//! The builders are pure (tested anywhere); `install` and `remove` run the commands.

use std::process::Command;

/// The mesh's IPv4 range (CGNAT) and IPv6 ULA prefix: forwarded traffic from the mesh has these sources.
pub const MESH_V4: &str = "100.64.0.0/10";
pub const MESH_V6: &str = "fd7a:115c:a1e0::/48";

const FORWARD_CHAIN: &str = "fm-forward";
const NAT_CHAIN: &str = "fm-postrouting";
const NFT_TABLE: &str = "flowmesh";
const EXIT_NAT_CHAIN: &str = "fm-exit-snat";
const EXIT_NFT_TABLE: &str = "flowmesh_exit";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Iptables,
    Nft,
}

/// One command: program and arguments.
pub type Cmd = (&'static str, Vec<String>);

fn ipt(prog: &'static str, args: &[&str]) -> Cmd {
    // -w: wait for the xtables lock instead of failing when another tool holds it.
    let mut v = vec!["-w".to_string()];
    v.extend(args.iter().map(|s| s.to_string()));
    (prog, v)
}

/// The iptables/ip6tables commands that install the rules, in order. Creating a chain that already
/// exists fails harmlessly (the next command flushes it), so the list can run again after a crash.
pub fn iptables_install(tun: &str, snat: bool, stateful: bool) -> Vec<Cmd> {
    let mut out = Vec::new();
    for (prog, mesh) in [("iptables", MESH_V4), ("ip6tables", MESH_V6)] {
        out.push(ipt(prog, &["-N", FORWARD_CHAIN]));
        out.push(ipt(prog, &["-F", FORWARD_CHAIN]));
        out.push(ipt(prog, &["-A", FORWARD_CHAIN, "-i", tun, "-j", "ACCEPT"]));
        if stateful {
            // --stateful-filtering: from the routed networks into the mesh, only replies.
            out.push(ipt(
                prog,
                &[
                    "-A",
                    FORWARD_CHAIN,
                    "-o",
                    tun,
                    "-m",
                    "conntrack",
                    "!",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "DROP",
                ],
            ));
        }
        out.push(ipt(prog, &["-A", FORWARD_CHAIN, "-o", tun, "-j", "ACCEPT"]));
        out.push(ipt(prog, &["-I", "FORWARD", "1", "-j", FORWARD_CHAIN]));
        out.push(ipt(prog, &["-t", "nat", "-N", NAT_CHAIN]));
        out.push(ipt(prog, &["-t", "nat", "-F", NAT_CHAIN]));
        if snat {
            out.push(ipt(
                prog,
                &[
                    "-t",
                    "nat",
                    "-A",
                    NAT_CHAIN,
                    "-s",
                    mesh,
                    "!",
                    "-o",
                    tun,
                    "-j",
                    "MASQUERADE",
                ],
            ));
        }
        out.push(ipt(
            prog,
            &["-t", "nat", "-I", "POSTROUTING", "1", "-j", NAT_CHAIN],
        ));
    }
    out
}

/// The commands that remove everything `iptables_install` added. A jump inserted twice (install
/// after an unclean exit) is removed by repeating its delete, which `remove` does until it fails.
pub fn iptables_remove() -> Vec<Cmd> {
    let mut out = Vec::new();
    for prog in ["iptables", "ip6tables"] {
        out.push(ipt(prog, &["-D", "FORWARD", "-j", FORWARD_CHAIN]));
        out.push(ipt(prog, &["-F", FORWARD_CHAIN]));
        out.push(ipt(prog, &["-X", FORWARD_CHAIN]));
        out.push(ipt(
            prog,
            &["-t", "nat", "-D", "POSTROUTING", "-j", NAT_CHAIN],
        ));
        out.push(ipt(prog, &["-t", "nat", "-F", NAT_CHAIN]));
        out.push(ipt(prog, &["-t", "nat", "-X", NAT_CHAIN]));
    }
    out
}

/// An nft script that replaces the `inet flowmesh` table in one transaction.
pub fn nft_install(tun: &str, snat: bool, stateful: bool) -> String {
    let masquerade = if snat {
        format!("\t\tiifname \"{tun}\" oifname != \"{tun}\" masquerade\n")
    } else {
        String::new()
    };
    let stateful = if stateful {
        format!("\t\toifname \"{tun}\" ct state != {{ established, related }} drop\n")
    } else {
        String::new()
    };
    format!(
        "add table inet {NFT_TABLE}\n\
         delete table inet {NFT_TABLE}\n\
         table inet {NFT_TABLE} {{\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority filter; policy accept;\n\
         \t\tiifname \"{tun}\" accept\n\
         {stateful}\
         \t\toifname \"{tun}\" accept\n\
         \t}}\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         {masquerade}\
         \t}}\n\
         }}\n"
    )
}

/// The destinations router-mode exit SNAT leaves alone, or None when there is no exit SNAT (it
/// exists only while an exit node is used with `forwarded_only`): the mesh's IPv4 range and every
/// IPv4 subnet route approved for a peer, merged (an nftables interval set refuses overlaps).
/// Exit routes (/0) are not subnets; IPv6 is not translated (no NAT66).
pub fn exit_snat_plan(
    using_exit: bool,
    forwarded_only: bool,
    approved: &[ipnet::IpNet],
) -> Option<Vec<ipnet::Ipv4Net>> {
    if !(using_exit && forwarded_only) {
        return None;
    }
    let mesh = ipnet::Ipv4Net::new(std::net::Ipv4Addr::new(100, 64, 0, 0), 10).ok()?;
    let mut nets: Vec<ipnet::Ipv4Net> = approved
        .iter()
        .filter_map(|n| match n {
            ipnet::IpNet::V4(n) if n.prefix_len() != 0 => Some(n.trunc()),
            _ => None,
        })
        .collect();
    nets.push(mesh);
    Some(ipnet::Ipv4Net::aggregate(&nets))
}

/// The iptables commands that install router-mode exit SNAT (see `exit_snat_plan`).
pub fn exit_snat_iptables_install(tun: &str, excluded: &[ipnet::Ipv4Net]) -> Vec<Cmd> {
    let p = "iptables";
    let mut out = vec![
        ipt(p, &["-t", "nat", "-N", EXIT_NAT_CHAIN]),
        ipt(p, &["-t", "nat", "-F", EXIT_NAT_CHAIN]),
        ipt(
            p,
            &[
                "-t",
                "nat",
                "-A",
                EXIT_NAT_CHAIN,
                "-s",
                MESH_V4,
                "-j",
                "RETURN",
            ],
        ),
    ];
    for net in excluded {
        out.push(ipt(
            p,
            &[
                "-t",
                "nat",
                "-A",
                EXIT_NAT_CHAIN,
                "-d",
                &net.to_string(),
                "-j",
                "RETURN",
            ],
        ));
    }
    out.push(ipt(
        p,
        &["-t", "nat", "-A", EXIT_NAT_CHAIN, "-j", "MASQUERADE"],
    ));
    out.push(ipt(
        p,
        &[
            "-t",
            "nat",
            "-I",
            "POSTROUTING",
            "1",
            "-o",
            tun,
            "-j",
            EXIT_NAT_CHAIN,
        ],
    ));
    out
}

/// The commands that remove what `exit_snat_iptables_install` added.
pub fn exit_snat_iptables_remove(tun: &str) -> Vec<Cmd> {
    let p = "iptables";
    vec![
        ipt(
            p,
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-o",
                tun,
                "-j",
                EXIT_NAT_CHAIN,
            ],
        ),
        ipt(p, &["-t", "nat", "-F", EXIT_NAT_CHAIN]),
        ipt(p, &["-t", "nat", "-X", EXIT_NAT_CHAIN]),
    ]
}

/// An nft script that replaces the `ip flowmesh_exit` table (router-mode exit SNAT) in one
/// transaction. Masquerade on the mesh interface takes its IPv4 address: this node's mesh address.
pub fn exit_snat_nft_install(tun: &str, excluded: &[ipnet::Ipv4Net]) -> String {
    let set: Vec<String> = excluded.iter().map(ToString::to_string).collect();
    format!(
        "add table ip {EXIT_NFT_TABLE}\n\
         delete table ip {EXIT_NFT_TABLE}\n\
         table ip {EXIT_NFT_TABLE} {{\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\toifname \"{tun}\" ip saddr != {MESH_V4} ip daddr != {{ {} }} masquerade\n\
         \t}}\n\
         }}\n",
        set.join(", ")
    )
}

fn have(prog: &str) -> bool {
    Command::new(prog)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn run(cmd: &Cmd) -> Result<(), String> {
    let out = Command::new(cmd.0)
        .args(&cmd.1)
        .output()
        .map_err(|e| format!("{}: {e}", cmd.0))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} {}: {}",
            cmd.0,
            cmd.1.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// What `install` did: the tool used, and a warning when only the IPv4 rules could be installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub backend: Backend,
    pub warning: Option<String>,
}

/// Install the rules with whichever tool the host has. A host without IPv6 netfilter still routes
/// IPv4 (the IPv6 failure becomes a warning); an IPv4 failure is an error.
pub fn install(tun: &str, snat: bool, stateful: bool) -> Result<Installed, String> {
    if have("iptables") {
        let mut warning = None;
        for cmd in iptables_install(tun, snat, stateful) {
            if cmd.0 == "ip6tables" && warning.is_some() {
                continue;
            }
            let creates_chain = cmd.1.iter().any(|a| a == "-N");
            match run(&cmd) {
                Ok(()) => {}
                // The chain is left over from an unclean exit; the next command flushes it.
                Err(_) if creates_chain => {}
                Err(e) if cmd.0 == "ip6tables" => {
                    warning = Some(format!("IPv6 forwarding rules: {e}"))
                }
                Err(e) => return Err(e),
            }
        }
        return Ok(Installed {
            backend: Backend::Iptables,
            warning,
        });
    }
    if have("nft") {
        nft_script(&nft_install(tun, snat, stateful))?;
        return Ok(Installed {
            backend: Backend::Nft,
            warning: None,
        });
    }
    Err("neither iptables nor nft is installed".into())
}

fn nft_script(script: &str) -> Result<(), String> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("nft: {e}"))?;
    }
    let out = child.wait_with_output().map_err(|e| format!("nft: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nft: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Install router-mode exit SNAT (`exit_snat_plan`'s exclusions) with whichever tool the host has,
/// replacing an earlier install. Returns the tool used, for `exit_snat_remove`.
pub fn exit_snat_install(tun: &str, excluded: &[ipnet::Ipv4Net]) -> Result<Backend, String> {
    if have("iptables") {
        exit_snat_remove(Backend::Iptables, tun);
        for cmd in exit_snat_iptables_install(tun, excluded) {
            match run(&cmd) {
                Ok(()) => {}
                // Left over from an unclean exit; the next command flushes it.
                Err(_) if cmd.1.iter().any(|a| a == "-N") => {}
                Err(e) => {
                    exit_snat_remove(Backend::Iptables, tun);
                    return Err(e);
                }
            }
        }
        return Ok(Backend::Iptables);
    }
    if have("nft") {
        nft_script(&exit_snat_nft_install(tun, excluded))?;
        return Ok(Backend::Nft);
    }
    Err("neither iptables nor nft is installed".into())
}

/// Commands that all succeed only while router-mode exit SNAT is in place: with iptables the jump
/// from POSTROUTING and the chain's closing MASQUERADE (`-C` of what the install appended), with nft
/// its chain. Someone else can remove them under us: OpenWrt's fw3 flushes the whole nat table on
/// every firewall restart or reload, an `nft flush ruleset` drops the table.
pub fn exit_snat_check_cmds(backend: Backend, tun: &str) -> Vec<Cmd> {
    match backend {
        Backend::Iptables => vec![
            ipt(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-C",
                    "POSTROUTING",
                    "-o",
                    tun,
                    "-j",
                    EXIT_NAT_CHAIN,
                ],
            ),
            ipt(
                "iptables",
                &["-t", "nat", "-C", EXIT_NAT_CHAIN, "-j", "MASQUERADE"],
            ),
        ],
        Backend::Nft => vec![(
            "nft",
            ["list", "chain", "ip", EXIT_NFT_TABLE, "postrouting"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )],
    }
}

/// Whether router-mode exit SNAT installed with `backend` is still in place (one or two short
/// commands; cheap enough to ask every few seconds).
pub fn exit_snat_present(backend: Backend, tun: &str) -> bool {
    exit_snat_check_cmds(backend, tun)
        .iter()
        .all(|cmd| run(cmd).is_ok())
}

/// Remove router-mode exit SNAT; errors are ignored (it may already be gone).
pub fn exit_snat_remove(backend: Backend, tun: &str) {
    match backend {
        Backend::Iptables => {
            for cmd in exit_snat_iptables_remove(tun) {
                // A jump inserted more than once is deleted until none is left.
                let tries = if cmd.1.iter().any(|a| a == "-D") {
                    8
                } else {
                    1
                };
                for _ in 0..tries {
                    if run(&cmd).is_err() {
                        break;
                    }
                }
            }
        }
        Backend::Nft => {
            let _ = run(&(
                "nft",
                vec![
                    "delete".into(),
                    "table".into(),
                    "ip".into(),
                    EXIT_NFT_TABLE.into(),
                ],
            ));
        }
    }
}

/// Remove what `install` added; errors are ignored (the rules may already be gone).
pub fn remove(backend: Backend) {
    match backend {
        Backend::Iptables => {
            for cmd in iptables_remove() {
                let is_jump_delete = cmd.1.iter().any(|a| a == "-D");
                if is_jump_delete {
                    // A jump inserted more than once is deleted until none is left.
                    for _ in 0..8 {
                        if run(&cmd).is_err() {
                            break;
                        }
                    }
                } else {
                    let _ = run(&cmd);
                }
            }
        }
        Backend::Nft => {
            let _ = run(&(
                "nft",
                vec![
                    "delete".into(),
                    "table".into(),
                    "inet".into(),
                    NFT_TABLE.into(),
                ],
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(cmds: &[Cmd]) -> Vec<String> {
        cmds.iter()
            .map(|(p, a)| format!("{p} {}", a.join(" ")))
            .collect()
    }

    #[test]
    fn iptables_rules_accept_forwarding_and_masquerade_mesh_sources() {
        let l = lines(&iptables_install("flowmesh0", true, false));
        assert!(l.contains(&"iptables -w -A fm-forward -i flowmesh0 -j ACCEPT".to_string()));
        assert!(l.contains(&"iptables -w -A fm-forward -o flowmesh0 -j ACCEPT".to_string()));
        assert!(l.contains(&"iptables -w -I FORWARD 1 -j fm-forward".to_string()));
        assert!(l.contains(
            &"iptables -w -t nat -A fm-postrouting -s 100.64.0.0/10 ! -o flowmesh0 -j MASQUERADE"
                .to_string()
        ));
        assert!(l.contains(
            &"ip6tables -w -t nat -A fm-postrouting -s fd7a:115c:a1e0::/48 ! -o flowmesh0 -j MASQUERADE"
                .to_string()
        ));
        // Each chain is flushed after creation and before it is filled: reinstalling is idempotent.
        let flush = l
            .iter()
            .position(|x| x == "iptables -w -F fm-forward")
            .unwrap();
        let fill = l
            .iter()
            .position(|x| x == "iptables -w -A fm-forward -i flowmesh0 -j ACCEPT")
            .unwrap();
        assert!(flush < fill);
        assert!(
            l.iter().all(|x| !x.contains("mark")),
            "no fwmark bits are used"
        );
    }

    #[test]
    fn snat_off_keeps_forwarding_but_no_masquerade() {
        let l = lines(&iptables_install("flowmesh0", false, false));
        assert!(l.iter().all(|x| !x.contains("MASQUERADE")));
        assert!(l.contains(&"iptables -w -A fm-forward -i flowmesh0 -j ACCEPT".to_string()));
        assert!(!nft_install("flowmesh0", false, false).contains("masquerade"));
    }

    /// Stateful filtering: new connections from the routed networks into the mesh are dropped,
    /// before the accept rule (the official client's conntrack rule, OBS-20261011-exit-node-official).
    #[test]
    fn stateful_filtering_drops_new_connections_into_the_mesh() {
        let l = lines(&iptables_install("flowmesh0", true, true));
        let drop = "iptables -w -A fm-forward -o flowmesh0 -m conntrack ! --ctstate RELATED,ESTABLISHED -j DROP";
        let accept = "iptables -w -A fm-forward -o flowmesh0 -j ACCEPT";
        let (d, a) = (
            l.iter().position(|x| x == drop).unwrap(),
            l.iter().position(|x| x == accept).unwrap(),
        );
        assert!(d < a, "the drop must come before the accept");
        assert!(!lines(&iptables_install("flowmesh0", true, false)).contains(&drop.to_string()));
        let n = nft_install("flowmesh0", true, true);
        let (d, a) = (
            n.find("ct state != { established, related } drop").unwrap(),
            n.find("oifname \"flowmesh0\" accept").unwrap(),
        );
        assert!(d < a);
    }

    #[test]
    fn removal_undoes_every_jump_and_chain() {
        let l = lines(&iptables_remove());
        for prog in ["iptables", "ip6tables"] {
            assert!(l.contains(&format!("{prog} -w -D FORWARD -j fm-forward")));
            assert!(l.contains(&format!("{prog} -w -X fm-forward")));
            assert!(l.contains(&format!(
                "{prog} -w -t nat -D POSTROUTING -j fm-postrouting"
            )));
            assert!(l.contains(&format!("{prog} -w -t nat -X fm-postrouting")));
        }
    }

    fn nets(v: &[&str]) -> Vec<ipnet::IpNet> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    /// Exit SNAT exists only when an exit node is used in router mode; it never covers the mesh
    /// range or a peer's approved subnet route, and exit routes (/0) are not exclusions.
    #[test]
    fn exit_snat_only_with_an_exit_node_in_forwarded_only_mode() {
        let approved = nets(&["10.99.0.0/24", "fd00:1::/64", "0.0.0.0/0", "::/0"]);
        assert_eq!(exit_snat_plan(false, false, &approved), None);
        assert_eq!(exit_snat_plan(true, false, &approved), None);
        assert_eq!(exit_snat_plan(false, true, &approved), None);
        let got: Vec<String> = exit_snat_plan(true, true, &approved)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(got, ["10.99.0.0/24", "100.64.0.0/10"]);
    }

    /// Overlapping approved routes are merged (an nft interval set refuses overlaps), and a
    /// subnet inside the mesh range adds nothing.
    #[test]
    fn exit_snat_exclusions_are_merged() {
        let got: Vec<String> = exit_snat_plan(
            true,
            true,
            &nets(&["10.0.0.0/8", "10.1.0.0/24", "100.100.0.0/16", "10.1.2.3/24"]),
        )
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(got, ["10.0.0.0/8", "100.64.0.0/10"]);
    }

    #[test]
    fn exit_snat_iptables_masquerades_only_what_goes_to_the_internet() {
        let ex = exit_snat_plan(true, true, &nets(&["10.99.0.0/24"])).unwrap();
        let l = lines(&exit_snat_iptables_install("flowmesh0", &ex));
        assert_eq!(
            l,
            vec![
                "iptables -w -t nat -N fm-exit-snat",
                "iptables -w -t nat -F fm-exit-snat",
                "iptables -w -t nat -A fm-exit-snat -s 100.64.0.0/10 -j RETURN",
                "iptables -w -t nat -A fm-exit-snat -d 10.99.0.0/24 -j RETURN",
                "iptables -w -t nat -A fm-exit-snat -d 100.64.0.0/10 -j RETURN",
                "iptables -w -t nat -A fm-exit-snat -j MASQUERADE",
                "iptables -w -t nat -I POSTROUTING 1 -o flowmesh0 -j fm-exit-snat",
            ]
        );
        assert!(l.iter().all(|x| x.starts_with("iptables ")), "IPv4 only");
        let r = lines(&exit_snat_iptables_remove("flowmesh0"));
        assert_eq!(
            r,
            vec![
                "iptables -w -t nat -D POSTROUTING -o flowmesh0 -j fm-exit-snat",
                "iptables -w -t nat -F fm-exit-snat",
                "iptables -w -t nat -X fm-exit-snat",
            ]
        );
    }

    #[test]
    fn exit_snat_check_matches_what_the_install_adds() {
        let ex = exit_snat_plan(true, true, &nets(&["10.99.0.0/24"])).unwrap();
        let installed = lines(&exit_snat_iptables_install("flowmesh0", &ex));
        let checks = lines(&exit_snat_check_cmds(Backend::Iptables, "flowmesh0"));
        assert_eq!(
            checks,
            [
                "iptables -w -t nat -C POSTROUTING -o flowmesh0 -j fm-exit-snat",
                "iptables -w -t nat -C fm-exit-snat -j MASQUERADE",
            ]
        );
        // Each check is an installed rule, asked for with -C instead of added: the jump (inserted
        // first in POSTROUTING) and the chain's last rule, so a half-flushed chain counts as gone.
        assert!(installed.contains(
            &"iptables -w -t nat -I POSTROUTING 1 -o flowmesh0 -j fm-exit-snat".to_string()
        ));
        assert_eq!(
            installed.last().map(String::as_str),
            Some("iptables -w -t nat -I POSTROUTING 1 -o flowmesh0 -j fm-exit-snat")
        );
        assert_eq!(
            installed[installed.len() - 2],
            "iptables -w -t nat -A fm-exit-snat -j MASQUERADE"
        );
        // nft: the chain the install script creates.
        let script = exit_snat_nft_install("flowmesh0", &ex);
        assert!(script.contains("table ip flowmesh_exit {\n\tchain postrouting {"));
        assert_eq!(
            lines(&exit_snat_check_cmds(Backend::Nft, "flowmesh0")),
            ["nft list chain ip flowmesh_exit postrouting"]
        );
    }

    #[test]
    fn exit_snat_nft_table_is_separate_and_ipv4_only() {
        let ex = exit_snat_plan(true, true, &nets(&["10.99.0.0/24"])).unwrap();
        let s = exit_snat_nft_install("flowmesh0", &ex);
        assert_eq!(
            s,
            "add table ip flowmesh_exit\n\
             delete table ip flowmesh_exit\n\
             table ip flowmesh_exit {\n\
             \tchain postrouting {\n\
             \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
             \t\toifname \"flowmesh0\" ip saddr != 100.64.0.0/10 ip daddr != { 10.99.0.0/24, 100.64.0.0/10 } masquerade\n\
             \t}\n\
             }\n"
        );
        // The subnet router's own table is untouched by it.
        assert!(!s.contains("inet flowmesh"));
    }

    #[test]
    fn nft_script_replaces_the_table_atomically() {
        let s = nft_install("flowmesh0", true, false);
        assert!(s.starts_with("add table inet flowmesh\ndelete table inet flowmesh\n"));
        assert!(s.contains("iifname \"flowmesh0\" accept"));
        assert!(s.contains("oifname \"flowmesh0\" accept"));
        assert!(s.contains("iifname \"flowmesh0\" oifname != \"flowmesh0\" masquerade"));
        assert!(s.contains("type nat hook postrouting priority srcnat"));
    }
}
