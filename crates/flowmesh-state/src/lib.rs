// SPDX-License-Identifier: Apache-2.0
//! Node key state file: generated on first run, the same keys are read back afterwards. Permissions 0600, atomic writes.

use flowmesh_proto::key::{KeyError, MachinePrivate, NodePrivate};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("state key: {0}")]
    Key(#[from] KeyError),
}

#[derive(Serialize, Deserialize)]
struct StateFile {
    machine_private: String,
    node_private: String,
}

#[derive(Debug, PartialEq, Eq)]
/// Persisted identity keys. The disco key is deliberately **not** persisted: it is regenerated on every process start, the same as
/// the official client (disco.md §3, observed), so peers can tell from the key change that this end restarted and reset the WireGuard session immediately.
pub struct NodeState {
    pub machine: MachinePrivate,
    pub node: NodePrivate,
}

pub fn load_or_create(path: &Path) -> Result<NodeState, StateError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let f: StateFile = serde_json::from_slice(&bytes)?;
            Ok(NodeState {
                machine: MachinePrivate::from_hex(&f.machine_private)?,
                node: NodePrivate::from_hex(&f.node_private)?,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let state = NodeState {
                machine: MachinePrivate::generate()?,
                node: NodePrivate::generate()?,
            };
            save(path, &state)?;
            Ok(state)
        }
        Err(e) => Err(e.into()),
    }
}

/// Logout: keep the machine key, replace the node key, so the next login registers a new node
/// (the official client behaves the same way: logout discards the node key, the machine identity stays).
pub fn rotate_node_key(path: &Path) -> Result<NodeState, StateError> {
    let old = load_or_create(path)?;
    let state = NodeState {
        machine: old.machine,
        node: NodePrivate::generate()?,
    };
    save(path, &state)?;
    Ok(state)
}

fn save(path: &Path, state: &NodeState) -> Result<(), StateError> {
    write_private(
        path,
        &serde_json::to_vec_pretty(&StateFile {
            machine_private: state.machine.to_hex(),
            node_private: state.node.to_hex(),
        })?,
    )?;
    Ok(())
}

/// Atomic write with mode 0600: temp file → fsync → rename → fsync the directory. After a power
/// loss the file holds either the old or the new content, never a mix or nothing.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    sync_dir_of(path)
}

/// Make a rename in `path`'s directory durable: the rename lives in the directory, not the file.
pub fn sync_dir_of(path: &Path) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "flowmesh-state-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("state.json")
    }

    #[test]
    fn creates_then_reloads_same_keys() {
        let path = temp_path("reload");
        let first = load_or_create(&path).unwrap();
        let second = load_or_create(&path).unwrap();
        assert_eq!(first, second);
        assert_ne!(first.machine.public().0, first.node.public().0);
    }

    /// Old state files contained disco_private; on load it is ignored rather than rejected.
    #[test]
    fn legacy_file_with_disco_key_still_loads() {
        let path = temp_path("legacy");
        let m = MachinePrivate::generate().unwrap();
        let n = NodePrivate::generate().unwrap();
        let legacy = format!(
            r#"{{"machine_private":"{}","node_private":"{}","disco_private":"{}"}}"#,
            m.to_hex(),
            n.to_hex(),
            "11".repeat(32)
        );
        std::fs::write(&path, legacy).unwrap();
        let s = load_or_create(&path).unwrap();
        assert_eq!((s.machine, s.node), (m, n));
    }

    #[test]
    fn rotate_keeps_machine_replaces_node() {
        let path = temp_path("rotate");
        let before = load_or_create(&path).unwrap();
        let rotated = rotate_node_key(&path).unwrap();
        assert_eq!(rotated.machine, before.machine);
        assert_ne!(rotated.node, before.node);
        assert_eq!(load_or_create(&path).unwrap(), rotated);
    }

    /// A state file that exists but cannot be read must never be replaced by fresh keys: that would
    /// silently give the node a new identity.
    #[test]
    fn unreadable_state_is_an_error_not_a_new_identity() {
        let path = temp_path("unreadable");
        load_or_create(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&path).is_ok() {
            // Running as root: permissions do not stop the read, so the scenario cannot be built.
            return;
        }
        assert!(load_or_create(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
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
    fn file_is_private() {
        let path = temp_path("mode");
        load_or_create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn no_temp_file_left_behind() {
        let path = temp_path("tmp");
        load_or_create(&path).unwrap();
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec!["state.json".to_string()]);
    }
}
