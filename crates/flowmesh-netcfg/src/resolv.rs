// SPDX-License-Identifier: Apache-2.0
//! resolv.conf takeover and restore (dns.md §1, direct mode).

use std::io;
use std::net::IpAddr;
use std::path::Path;

/// Header of the file we write (our own wording).
pub const HEADER: &str =
    "# Managed by flowmesh (MagicDNS). The original file is restored when flowmesh stops.\n";

/// Generate the takeover content: `nameserver <addr>` + `search <domains>`.
pub fn render(nameserver: IpAddr, search: &[String]) -> String {
    let mut s = format!("{HEADER}\nnameserver {nameserver}\n");
    if !search.is_empty() {
        s.push_str(&format!("search {}\n", search.join(" ")));
    }
    s
}

/// Read nameserver addresses from resolv.conf content (ignoring comments and invalid lines).
pub fn parse_nameservers(content: &str) -> Vec<IpAddr> {
    content
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next()? == "nameserver")
                .then(|| w.next()?.parse().ok())
                .flatten()
        })
        .collect()
}

/// Marker written into the backup when there was no original file, so restore deletes the file instead of writing an empty one.
const ABSENT_MARKER: &str = "# flowmesh: no resolv.conf existed before takeover\n";

/// Take over `path`: on first takeover, back up the original to `backup` (an existing backup is never overwritten, so a restart after a crash
/// still keeps the true original), then write `content`. Prefer atomic replace; if `path` is a mount point (container bind mounts, etc.)
/// rename fails, so fall back to an in-place write.
pub fn takeover(path: &Path, backup: &Path, content: &str) -> io::Result<()> {
    if !backup.exists() {
        let original = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => ABSENT_MARKER.to_string(),
            Err(e) => return Err(e),
        };
        write_atomic(backup, &original)?;
    }
    write_replace(path, content)
}

fn write_atomic(path: &Path, content: &str) -> io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("flowmesh-tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    sync_dir_of(path)
}

/// The rename lives in the directory; sync it so the swap survives a power loss.
fn sync_dir_of(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    std::fs::File::open(dir)?.sync_all()
}

/// Replace the file: prefer atomic rename; if that fails (e.g. the target is a bind mount), write in place instead.
fn write_replace(path: &Path, content: &str) -> io::Result<()> {
    match write_atomic(path, content) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = std::fs::remove_file(path.with_extension("flowmesh-tmp"));
            std::fs::write(path, content)
        }
    }
}

/// When `path` is a symbolic link, another service (systemd-resolved, resolvconf, NetworkManager) owns
/// the system resolver configuration; returns the link target. Writing through the link would edit
/// that service's own file, so flowmesh leaves it alone.
pub fn managed_elsewhere(path: &Path) -> Option<std::path::PathBuf> {
    std::fs::read_link(path).ok()
}

/// Restore the backup (if any) to `path` and delete it. Returns whether anything was restored.
pub fn restore(path: &Path, backup: &Path) -> io::Result<bool> {
    let original = match std::fs::read_to_string(backup) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if original == ABSENT_MARKER {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    } else {
        write_replace(path, &original)?;
    }
    std::fs::remove_file(backup)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("flowmesh-resolv-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const ORIGINAL: &str = "# from docker\nnameserver 127.0.0.11\noptions ndots:0\n";

    #[test]
    fn render_layout() {
        let s = render(
            "100.100.100.100".parse().unwrap(),
            &["mesh.lab.internal".into(), "corp".into()],
        );
        assert!(s.starts_with(HEADER));
        assert!(s.contains("\nnameserver 100.100.100.100\n"));
        assert!(s.ends_with("search mesh.lab.internal corp\n"));
        let no_search = render("100.100.100.100".parse().unwrap(), &[]);
        assert!(!no_search.contains("search"));
    }

    #[test]
    fn parse_nameservers_ignores_comments_and_garbage() {
        let c = "# nameserver 9.9.9.9\nnameserver 127.0.0.11\n  nameserver   fd00::53 \nnameserver bogus\nsearch x\n";
        assert_eq!(
            parse_nameservers(c),
            vec![
                "127.0.0.11".parse::<IpAddr>().unwrap(),
                "fd00::53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn takeover_then_restore_roundtrip() {
        let d = dir("roundtrip");
        let (path, backup) = (d.join("resolv.conf"), d.join("resolv.conf.flowmesh-backup"));
        std::fs::write(&path, ORIGINAL).unwrap();
        takeover(&path, &backup, "managed\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "managed\n");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), ORIGINAL);
        assert!(restore(&path, &backup).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ORIGINAL);
        assert!(!backup.exists());
        assert!(!restore(&path, &backup).unwrap(), "nothing left to restore");
    }

    #[test]
    fn dir_sync_targets() {
        assert!(
            sync_dir_of(Path::new("relative-name")).is_ok(),
            "a bare name means the cwd"
        );
        assert!(sync_dir_of(Path::new("/nonexistent-flowmesh-dir/x")).is_err());
    }

    #[test]
    fn symlinked_resolv_conf_is_managed_elsewhere() {
        let d = dir("symlink");
        let target = d.join("stub-resolv.conf");
        std::fs::write(&target, "nameserver 127.0.0.53\n").unwrap();
        let link = d.join("resolv.conf");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(managed_elsewhere(&link), Some(target.clone()));
        assert_eq!(
            managed_elsewhere(&target),
            None,
            "a regular file is ours to manage"
        );
        assert_eq!(managed_elsewhere(&d.join("missing")), None);
    }

    /// Restart after a crash: the second takeover must not overwrite the backup with our managed content.
    #[test]
    fn second_takeover_keeps_original_backup() {
        let d = dir("crash");
        let (path, backup) = (d.join("resolv.conf"), d.join("resolv.conf.flowmesh-backup"));
        std::fs::write(&path, ORIGINAL).unwrap();
        takeover(&path, &backup, "managed-1\n").unwrap();
        takeover(&path, &backup, "managed-2\n").unwrap();
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), ORIGINAL);
        restore(&path, &backup).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ORIGINAL);
    }

    /// Read errors other than "does not exist" (here the path is a directory) must propagate, not be treated as "no original file".
    #[test]
    fn unexpected_io_errors_propagate() {
        let d = dir("errors");
        let as_dir = d.join("resolv.conf");
        std::fs::create_dir_all(&as_dir).unwrap();
        assert!(takeover(&as_dir, &d.join("b1"), "x\n").is_err());
        assert!(!d.join("b1").exists());
        let backup_dir = d.join("b2");
        std::fs::create_dir_all(&backup_dir).unwrap();
        assert!(restore(&d.join("other"), &backup_dir).is_err());
    }

    /// No original file existed, and the managed file has already been deleted by someone else: restore still succeeds and cleans up the backup.
    #[test]
    fn restore_absent_when_file_already_gone() {
        let d = dir("gone");
        let (path, backup) = (d.join("resolv.conf"), d.join("resolv.conf.flowmesh-backup"));
        takeover(&path, &backup, "managed\n").unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(restore(&path, &backup).unwrap());
        assert!(!backup.exists());
    }

    /// No original file existed, but the path has become something that cannot be deleted as a file (a directory): the error must propagate.
    #[test]
    fn restore_absent_propagates_removal_errors() {
        let d = dir("undeletable");
        let (path, backup) = (d.join("resolv.conf"), d.join("resolv.conf.flowmesh-backup"));
        takeover(&path, &backup, "managed\n").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir_all(&path).unwrap();
        assert!(restore(&path, &backup).is_err());
        assert!(
            backup.exists(),
            "a backup that failed to restore must be kept"
        );
    }

    #[test]
    fn takeover_without_original_restores_to_absent() {
        let d = dir("absent");
        let (path, backup) = (d.join("resolv.conf"), d.join("resolv.conf.flowmesh-backup"));
        takeover(&path, &backup, "managed\n").unwrap();
        assert!(restore(&path, &backup).unwrap());
        assert!(
            !path.exists(),
            "a file that did not exist before must not exist after restore"
        );
    }
}
