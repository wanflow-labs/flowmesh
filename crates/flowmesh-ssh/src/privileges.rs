// SPDX-License-Identifier: Apache-2.0
//! Can this process start sessions as other users? Judged from `/proc/self/status`: switching
//! users needs CAP_SETUID and CAP_SETGID. A sandboxed service (the default flowmeshd unit) has
//! neither, and its sessions would inherit the rest of the sandbox too, so the server does not
//! start and says which unit to use instead.

/// Capability numbers from linux/capability.h.
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;

/// What to do about it, for Health.
pub const SANDBOXED: &str = "SSH sessions would inherit flowmeshd's sandbox; run flowmeshd with the unit made for the SSH server: sudo install -m 0644 /usr/share/flowmesh/flowmeshd-ssh.service /etc/systemd/system/flowmeshd.service && sudo systemctl daemon-reload && sudo systemctl restart flowmeshd";

/// `Err` with the reason when `status` (the text of `/proc/self/status`) shows that sessions cannot
/// switch users. A status without a readable `CapEff` passes: starting a session reports its own
/// error then.
pub fn check(status: &str) -> Result<(), String> {
    let Some(bits) = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
    else {
        return Ok(());
    };
    let missing: Vec<&str> = [(CAP_SETUID, "CAP_SETUID"), (CAP_SETGID, "CAP_SETGID")]
        .into_iter()
        .filter(|(n, _)| bits & (1 << n) == 0)
        .map(|(_, name)| name)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "no privileges to switch users ({}). {SANDBOXED}",
            missing.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(cap_eff: &str) -> String {
        format!("Name:\tflowmeshd\nNoNewPrivs:\t0\nCapEff:\t{cap_eff}\nCapBnd:\t000001ffffffffff\n")
    }

    #[test]
    fn root_and_docker_defaults_pass() {
        assert_eq!(check(&status("000001ffffffffff")), Ok(()));
        // Docker's default capability set includes both.
        assert_eq!(check(&status("00000000a80425fb")), Ok(()));
    }

    #[test]
    fn the_sandboxed_unit_is_refused_with_the_way_out() {
        // flowmeshd.service: CAP_NET_ADMIN and CAP_NET_RAW only.
        let e = check(&status("0000000000003000")).unwrap_err();
        assert!(e.contains("CAP_SETUID, CAP_SETGID"), "{e}");
        assert!(e.contains("flowmeshd-ssh.service"), "{e}");
    }

    #[test]
    fn each_capability_counts() {
        let only_setgid = check(&status("0000000000000040")).unwrap_err();
        assert!(only_setgid.contains("(CAP_SETUID)"), "{only_setgid}");
        let only_setuid = check(&status("0000000000000080")).unwrap_err();
        assert!(only_setuid.contains("(CAP_SETGID)"), "{only_setuid}");
    }

    #[test]
    fn unreadable_status_passes() {
        assert_eq!(check(""), Ok(()));
        assert_eq!(check(&status("not-hex")), Ok(()));
    }
}
