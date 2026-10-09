// SPDX-License-Identifier: Apache-2.0
//! 探测程序的密钥状态文件：首次运行生成，之后读回同一组密钥。

use flowmesh_proto::key::{DiscoPrivate, KeyError, MachinePrivate, NodePrivate};
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
    disco_private: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProbeState {
    pub machine: MachinePrivate,
    pub node: NodePrivate,
    pub disco: DiscoPrivate,
}

pub fn load_or_create(path: &Path) -> Result<ProbeState, StateError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let f: StateFile = serde_json::from_slice(&bytes)?;
            Ok(ProbeState {
                machine: MachinePrivate::from_hex(&f.machine_private)?,
                node: NodePrivate::from_hex(&f.node_private)?,
                disco: DiscoPrivate::from_hex(&f.disco_private)?,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let state = ProbeState {
                machine: MachinePrivate::generate()?,
                node: NodePrivate::generate()?,
                disco: DiscoPrivate::generate()?,
            };
            write_private(
                path,
                &serde_json::to_vec_pretty(&StateFile {
                    machine_private: state.machine.to_hex(),
                    node_private: state.node.to_hex(),
                    disco_private: state.disco.to_hex(),
                })?,
            )?;
            Ok(state)
        }
        Err(e) => Err(e.into()),
    }
}

/// 以 0600 权限原子写入：临时文件 → fsync → rename。
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
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
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "flowmesh-probe-state-{}-{}",
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
