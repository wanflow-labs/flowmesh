// SPDX-License-Identifier: Apache-2.0
//! The node name reported to the control server.
//!
//! Without `--hostname` the official client reports the machine's host name. Reporting an empty
//! one makes headscale register a node without a name, after which it cannot build a map for it
//! ("node has no given name") and the node never comes up. So an empty setting falls back to the
//! system host name, and failing that to a stable generated name: never to "".

/// Where the system host name is read from, in order. `/proc/sys/kernel/hostname` is what
/// `uname -n` reports and exists on every Linux (distributions, BusyBox/Alpine, OpenWrt,
/// containers); `/etc/hostname` covers a missing or restricted /proc.
const HOSTNAME_FILES: [&str; 2] = ["/proc/sys/kernel/hostname", "/etc/hostname"];

/// Machine ids for the last-resort name, so it stays the same across restarts.
const MACHINE_ID_FILES: [&str; 2] = ["/etc/machine-id", "/var/lib/dbus/machine-id"];

/// The name for this node: the configured one, or the system's when none is configured.
pub fn effective_hostname(configured: &str) -> String {
    resolve(configured, &|path| std::fs::read_to_string(path).ok())
}

/// `effective_hostname` with the file reads injected.
fn resolve(configured: &str, read: &dyn Fn(&str) -> Option<String>) -> String {
    if !configured.trim().is_empty() {
        return configured.to_owned();
    }
    if let Some(name) = HOSTNAME_FILES
        .iter()
        .find_map(|path| read(path).as_deref().and_then(usable))
    {
        return name;
    }
    if let Some(id) = MACHINE_ID_FILES
        .iter()
        .find_map(|path| read(path).as_deref().and_then(machine_id_prefix))
    {
        return format!("linux-{id}");
    }
    "flowmesh".to_owned()
}

/// The first label of a host name, unless it is a placeholder for "no name set".
fn usable(raw: &str) -> Option<String> {
    let label = raw.trim().split('.').next()?.trim();
    let placeholder = label.is_empty()
        || label.eq_ignore_ascii_case("localhost")
        // the kernel's default before anything sets a name (minimal and embedded systems)
        || label == "(none)";
    (!placeholder).then(|| label.to_owned())
}

/// The first six hex digits of a machine id.
fn machine_id_prefix(raw: &str) -> Option<String> {
    let id = raw.trim();
    let prefix = id.get(..6)?;
    prefix
        .bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then(|| prefix.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn files(entries: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |path| map.get(path).cloned()
    }

    #[test]
    fn configured_name_wins() {
        let read = files(&[("/proc/sys/kernel/hostname", "box\n")]);
        assert_eq!(resolve("gw-1", &read), "gw-1");
    }

    #[test]
    fn empty_setting_uses_the_kernel_host_name() {
        let read = files(&[
            ("/proc/sys/kernel/hostname", "iZbp1fnf34r2nywxrn4cdhZ\n"),
            ("/etc/hostname", "other\n"),
        ]);
        assert_eq!(resolve("", &read), "iZbp1fnf34r2nywxrn4cdhZ");
        assert_eq!(resolve("  ", &read), "iZbp1fnf34r2nywxrn4cdhZ");
    }

    #[test]
    fn falls_back_to_etc_hostname() {
        let read = files(&[("/etc/hostname", "web1\n")]);
        assert_eq!(resolve("", &read), "web1");
    }

    #[test]
    fn keeps_only_the_first_label() {
        let read = files(&[("/proc/sys/kernel/hostname", "web1.example.com\n")]);
        assert_eq!(resolve("", &read), "web1");
    }

    #[test]
    fn placeholder_names_are_not_used() {
        for junk in [
            "",
            "\n",
            "localhost\n",
            "localhost.localdomain\n",
            "(none)\n",
            "LOCALHOST",
        ] {
            let read = files(&[
                ("/proc/sys/kernel/hostname", junk),
                ("/etc/hostname", "real\n"),
            ]);
            assert_eq!(resolve("", &read), "real", "kernel host name {junk:?}");
        }
    }

    #[test]
    fn no_usable_host_name_uses_the_machine_id() {
        let read = files(&[
            ("/proc/sys/kernel/hostname", "(none)\n"),
            ("/etc/machine-id", "3f9a6c0e2b7d4e1fa0c5b8d7e6f4a3b2\n"),
        ]);
        assert_eq!(resolve("", &read), "linux-3f9a6c");

        let dbus = files(&[(
            "/var/lib/dbus/machine-id",
            "ab12cd34ef56ab12cd34ef56ab12cd34\n",
        )]);
        assert_eq!(resolve("", &dbus), "linux-ab12cd");
    }

    #[test]
    fn last_resort_is_never_empty() {
        assert_eq!(resolve("", &files(&[])), "flowmesh");
        let bad_id = files(&[("/etc/machine-id", "zz\n")]);
        assert_eq!(resolve("", &bad_id), "flowmesh");
    }
}
