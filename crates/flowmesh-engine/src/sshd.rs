// SPDX-License-Identifier: Apache-2.0
//! The SSH server's place in the engine (`--ssh`, docs/protocol/ssh.md). Built only with the
//! `ssh` feature; without it `start` refuses and nothing of the SSH stack is linked in (a CPE
//! build saves the space).

#[cfg(feature = "ssh")]
mod imp {
    use crate::EngineConfig;
    use crate::linux::{AbortOnDrop, log};
    use ipnet::IpNet;
    use std::net::SocketAddr;
    use std::sync::Arc;

    /// The SSH server (`--ssh`): listeners on the mesh addresses and what peers learn about it.
    pub(crate) struct SshServer {
        view: Arc<std::sync::RwLock<flowmesh_ssh::server::View>>,
        /// Host keys in authorized_keys form, for Hostinfo.sshHostKeys.
        host_keys: Vec<String>,
        _tasks: Vec<AbortOnDrop>,
    }

    /// What the SSH server needs from the netmap: the policy and who each peer address belongs to.
    pub(crate) fn ssh_view(nm: &flowmesh_control::netmap::NetMap) -> flowmesh_ssh::server::View {
        use flowmesh_ssh::policy::Peer;
        use flowmesh_ssh::server::PeerInfo;
        let mut peers = std::collections::HashMap::new();
        for n in nm.peers.values() {
            // Tagged nodes act for no user (a userLogin principal never matches them).
            let user_login = if n.tags.is_empty() {
                nm.user_profiles
                    .get(&n.user)
                    .map(|u| u.login_name.clone())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            for a in &n.addresses {
                peers.insert(
                    a.addr(),
                    PeerInfo {
                        peer: Peer {
                            ip: Some(a.addr()),
                            node: n.stable_id.clone(),
                            user_login: user_login.clone(),
                        },
                        name: n.name.trim_end_matches('.').to_string(),
                    },
                );
            }
        }
        flowmesh_ssh::server::View {
            policy: nm.ssh_policy.clone(),
            peers,
        }
    }

    pub(crate) fn start(
        cfg: &EngineConfig,
        own: &[IpNet],
        nm: &flowmesh_control::netmap::NetMap,
        admissions: &flowmesh_dataplane::plane::Admissions,
    ) -> Result<(SshServer, u16), String> {
        let dir = cfg
            .state_file
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("ssh");
        let keys = flowmesh_ssh::hostkeys::load_or_create(&dir)?;
        let host_keys = flowmesh_ssh::hostkeys::public_lines(&keys);
        let helper = match &cfg.ssh_helper {
            Some(p) => p.clone(),
            None => std::env::current_exe().map_err(|e| format!("own program path: {e}"))?,
        };
        let view = Arc::new(std::sync::RwLock::new(ssh_view(nm)));
        let admitted = admissions.clone();
        let shared = Arc::new(flowmesh_ssh::server::Shared {
            config: Arc::new(flowmesh_ssh::server::config(keys)),
            view: view.clone(),
            log: Arc::new(log),
            helper,
            admitted: Arc::new(move |from| admitted.take(from)),
        });
        // IPv4 first picks the port; the other addresses use the same one.
        let mut addrs: Vec<std::net::IpAddr> = own.iter().map(IpNet::addr).collect();
        addrs.sort_by_key(|a| a.is_ipv6());
        let mut port = 0u16;
        let mut tasks = Vec::new();
        for ip in addrs {
            let l = flowmesh_ssh::server::listen(SocketAddr::new(ip, port), &cfg.tun)
                .map_err(|e| format!("listen on {ip}: {e}"))?;
            if port == 0 {
                port = l.local_addr().map_err(|e| e.to_string())?.port();
            }
            tasks.push(AbortOnDrop(tokio::spawn(flowmesh_ssh::server::serve(
                l,
                shared.clone(),
            ))));
        }
        if tasks.is_empty() {
            return Err("no mesh address".into());
        }
        Ok((
            SshServer {
                view,
                host_keys,
                _tasks: tasks,
            },
            port,
        ))
    }

    impl SshServer {
        /// Bring the server's view of the netmap up to date.
        pub(crate) fn update(&self, nm: &flowmesh_control::netmap::NetMap) {
            let v = ssh_view(nm);
            *self
                .view
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = v;
        }

        pub(crate) fn host_keys(&self) -> Vec<String> {
            self.host_keys.clone()
        }
    }
}

#[cfg(not(feature = "ssh"))]
mod imp {
    use crate::EngineConfig;
    use ipnet::IpNet;

    /// Never exists in a build without SSH.
    pub(crate) enum SshServer {}

    impl SshServer {
        pub(crate) fn update(&self, _nm: &flowmesh_control::netmap::NetMap) {
            match *self {}
        }

        pub(crate) fn host_keys(&self) -> Vec<String> {
            match *self {}
        }
    }

    pub(crate) fn start(
        _cfg: &EngineConfig,
        _own: &[IpNet],
        _nm: &flowmesh_control::netmap::NetMap,
        _admissions: &flowmesh_dataplane::plane::Admissions,
    ) -> Result<(SshServer, u16), String> {
        Err("this flowmeshd was built without SSH support".into())
    }
}

pub(crate) use imp::{SshServer, start};
