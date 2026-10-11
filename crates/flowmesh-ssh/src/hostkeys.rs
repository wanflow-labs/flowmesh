// SPDX-License-Identifier: Apache-2.0
//! The server's host keys: created once in the state directory, then reused, so clients that
//! learned them (from the netmap or their known_hosts) keep trusting this node. Ed25519 and ECDSA
//! P-256; no RSA key (deviations.md #14).

use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, EcdsaCurve, PrivateKey};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const KEYS: [&str; 2] = ["ssh_host_ed25519_key", "ssh_host_ecdsa_key"];

fn algorithm(name: &str) -> Algorithm {
    if name.contains("ecdsa") {
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }
    } else {
        Algorithm::Ed25519
    }
}

/// Load the host keys from `dir`, creating any that are missing (mode 0600, directory 0700).
pub fn load_or_create(dir: &Path) -> Result<Vec<PrivateKey>, String> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("create {}: {e}", dir.display()))?;
    let mut keys = Vec::new();
    for name in KEYS {
        let path = dir.join(name);
        let key = match std::fs::read_to_string(&path) {
            Ok(pem) => PrivateKey::from_openssh(pem)
                .map_err(|e| format!("read {}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = PrivateKey::random(&mut rand::rng(), algorithm(name))
                    .map_err(|e| format!("generate {name}: {e}"))?;
                let pem = key
                    .to_openssh(LineEnding::LF)
                    .map_err(|e| format!("encode {name}: {e}"))?;
                // Written under a temporary name and renamed, so a crash never leaves half a key.
                let tmp = path.with_extension("tmp");
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|e| format!("write {}: {e}", tmp.display()))?;
                f.write_all(pem.as_bytes())
                    .and_then(|()| f.sync_all())
                    .and_then(|()| std::fs::rename(&tmp, &path))
                    .map_err(|e| format!("write {}: {e}", path.display()))?;
                key
            }
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        keys.push(key);
    }
    Ok(keys)
}

/// The public halves in authorized_keys form without a comment (`ssh-ed25519 AAAA…`), for
/// `Hostinfo.sshHostKeys`.
pub fn public_lines(keys: &[PrivateKey]) -> Vec<String> {
    keys.iter()
        .filter_map(|k| {
            let mut p = k.public_key().clone();
            p.set_comment("");
            p.to_openssh().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn created_once_then_reused() {
        let dir = std::env::temp_dir().join(format!("fm-hostkeys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = public_lines(&load_or_create(&dir).unwrap());
        assert_eq!(first.len(), 2);
        assert!(first[0].starts_with("ssh-ed25519 AAAA"), "{}", first[0]);
        assert!(
            first[1].starts_with("ecdsa-sha2-nistp256 AAAA"),
            "{}",
            first[1]
        );
        assert!(first.iter().all(|l| l.split(' ').count() == 2), "{first:?}");
        let again = public_lines(&load_or_create(&dir).unwrap());
        assert_eq!(first, again);
        for name in KEYS {
            let mode = std::fs::metadata(dir.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
