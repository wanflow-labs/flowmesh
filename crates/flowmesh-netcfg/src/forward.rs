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
//! The builders are pure (tested anywhere); `install` and `remove` run the commands.

use std::process::Command;

/// The mesh's IPv4 range (CGNAT) and IPv6 ULA prefix: forwarded traffic from the mesh has these sources.
pub const MESH_V4: &str = "100.64.0.0/10";
pub const MESH_V6: &str = "fd7a:115c:a1e0::/48";

const FORWARD_CHAIN: &str = "fm-forward";
const NAT_CHAIN: &str = "fm-postrouting";
const NFT_TABLE: &str = "flowmesh";

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
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("nft: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(nft_install(tun, snat, stateful).as_bytes())
                .map_err(|e| format!("nft: {e}"))?;
        }
        let out = child.wait_with_output().map_err(|e| format!("nft: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "nft: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        return Ok(Installed {
            backend: Backend::Nft,
            warning: None,
        });
    }
    Err("neither iptables nor nft is installed".into())
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
