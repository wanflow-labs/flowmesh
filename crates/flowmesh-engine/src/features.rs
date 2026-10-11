// SPDX-License-Identifier: Apache-2.0
//! The parts of the engine a setting switches on and off: subnet router / exit node forwarding
//! rules, exit node policy routing, and the exit node's DNS proxy (peerapi). The same functions
//! set them up at start and bring them in line when `set`/`up` change a setting while the engine
//! runs; the official client changes all of these without restarting (OBS-20261011-set-live), so
//! nothing here touches WireGuard sessions or the disco key.

use crate::EngineConfig;
use crate::linux::{AbortOnDrop, log};
use flowmesh_proto::control::Service;
use ipnet::IpNet;
use std::net::SocketAddr;
use std::sync::Arc;

/// What this node routes for the mesh: its subnets, plus both default routes as an exit node.
pub(crate) fn advertised(cfg: &EngineConfig) -> Vec<IpNet> {
    let mut v = cfg.advertise_routes.clone();
    if cfg.advertise_exit_node {
        v.extend(
            ["0.0.0.0/0", "::/0"]
                .iter()
                .filter_map(|r| r.parse::<IpNet>().ok()),
        );
    }
    v
}

/// Removes the subnet-router netfilter rules when dropped.
pub(crate) struct ForwardRules(flowmesh_netcfg::forward::Backend);

impl Drop for ForwardRules {
    fn drop(&mut self) {
        flowmesh_netcfg::forward::remove(self.0);
        log("subnet router: forwarding rules removed");
    }
}

/// Removes the exit node policy routing when dropped.
pub(crate) struct ExitRouting;

impl Drop for ExitRouting {
    fn drop(&mut self) {
        flowmesh_netcfg::exit_route::remove();
        log("exit node: policy routing removed");
    }
}

/// The exit node's DNS proxy: listeners on the mesh addresses and what they advertise.
pub(crate) struct PeerApi {
    pub state: Arc<crate::peerapi::State>,
    pub services: Vec<Service>,
    pub listeners: Vec<SocketAddr>,
    _tasks: Vec<AbortOnDrop>,
}

/// The SSH server (`--ssh`): listeners on the mesh addresses and what peers learn about it.
pub(crate) struct SshServer {
    view: Arc<std::sync::RwLock<flowmesh_ssh::server::View>>,
    /// Host keys in authorized_keys form, for Hostinfo.sshHostKeys.
    host_keys: Vec<String>,
    _tasks: Vec<AbortOnDrop>,
}

/// The switched parts and the messages their setup produced (shown in health).
#[derive(Default)]
pub(crate) struct Features {
    forward: Option<ForwardRules>,
    forward_msg: Option<String>,
    exit_routing: Option<ExitRouting>,
    exit_msg: Option<String>,
    pub peerapi: Option<PeerApi>,
    ssh: Option<SshServer>,
    ssh_msg: Option<String>,
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

impl Features {
    pub fn health(&self) -> impl Iterator<Item = String> + '_ {
        self.forward_msg
            .iter()
            .chain(self.exit_msg.iter())
            .chain(self.ssh_msg.iter())
            .cloned()
    }

    /// The SSH server runs while `--ssh` is on. Returns whether Hostinfo changed.
    pub fn sync_ssh(
        &mut self,
        cfg: &EngineConfig,
        own: &[IpNet],
        nm: &flowmesh_control::netmap::NetMap,
        dp: &mut flowmesh_dataplane::plane::Dataplane,
    ) -> bool {
        match (cfg.run_ssh, self.ssh.is_some()) {
            (true, true) | (false, false) => false,
            (false, true) => {
                self.ssh = None; // Drop stops the listeners; running sessions end with them.
                self.ssh_msg = None;
                dp.set_ssh_redirect(None);
                log("ssh: server stopped");
                true
            }
            (true, false) => match start_ssh(cfg, own, nm) {
                Ok((server, port, admissions)) => {
                    dp.set_ssh_redirect(Some((
                        port,
                        own.iter().map(IpNet::addr).collect(),
                        admissions,
                    )));
                    log(format!(
                        "ssh: server on port 22 of {:?} (listening on port {port}, mesh interface only)",
                        own.iter().map(IpNet::addr).collect::<Vec<_>>()
                    ));
                    self.ssh = Some(server);
                    self.ssh_msg = None;
                    true
                }
                Err(e) => {
                    let msg = format!("SSH server could not start: {e}");
                    log(&msg);
                    let changed = self.ssh_msg.as_ref() != Some(&msg);
                    self.ssh_msg = Some(msg);
                    changed
                }
            },
        }
    }

    /// Bring the SSH server's view of the netmap up to date.
    pub fn update_ssh_view(&self, nm: &flowmesh_control::netmap::NetMap) {
        if let Some(s) = &self.ssh {
            let v = ssh_view(nm);
            *s.view
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = v;
        }
    }

    pub fn ssh_host_keys(&self) -> Vec<String> {
        self.ssh
            .as_ref()
            .map(|s| s.host_keys.clone())
            .unwrap_or_default()
    }

    /// Forwarding rules: needed while anything is advertised; reinstalled when what they depend
    /// on changed (whether anything is advertised, SNAT, stateful filtering).
    pub fn sync_forwarding(&mut self, cfg: &EngineConfig, old: Option<&EngineConfig>) {
        let key = |c: &EngineConfig| {
            (
                !advertised(c).is_empty(),
                c.snat_subnet_routes,
                c.stateful_filtering,
            )
        };
        if old.is_some_and(|o| key(o) == key(cfg)) {
            return;
        }
        self.forward = None; // Drop removes the old rules first.
        self.forward_msg = None;
        let routes = advertised(cfg);
        if routes.is_empty() {
            return;
        }
        match flowmesh_netcfg::forward::install(
            &cfg.tun,
            cfg.snat_subnet_routes,
            cfg.stateful_filtering,
        ) {
            Ok(installed) => {
                log(format!(
                    "subnet router: advertising {routes:?}; forwarding rules via {:?}, SNAT {}, stateful filtering {}",
                    installed.backend,
                    if cfg.snat_subnet_routes { "on" } else { "off" },
                    if cfg.stateful_filtering { "on" } else { "off" }
                ));
                if let Some(w) = installed.warning {
                    log(&w);
                    self.forward_msg = Some(w);
                }
                self.forward = Some(ForwardRules(installed.backend));
            }
            Err(e) => {
                let msg = format!(
                    "subnet routes are advertised, but the forwarding rules could not be installed: {e}"
                );
                log(&msg);
                self.forward_msg = Some(msg);
            }
        }
    }

    /// Exit node policy routing: needed while an exit node is set; reinstalled when that or LAN
    /// access changed (switching from one exit node to another keeps it: only AllowedIPs move).
    pub fn sync_exit_routing(
        &mut self,
        cfg: &EngineConfig,
        old: Option<&EngineConfig>,
        ipv6: bool,
    ) {
        let key = |c: &EngineConfig| (!c.exit_node.is_empty(), c.exit_node_allow_lan_access);
        if old.is_some_and(|o| key(o) == key(cfg)) {
            return;
        }
        self.exit_routing = None;
        self.exit_msg = None;
        if cfg.exit_node.is_empty() {
            return;
        }
        let lan = if cfg.exit_node_allow_lan_access {
            crate::linux::interfaces(&cfg.tun).nets
        } else {
            Vec::new()
        };
        match flowmesh_netcfg::exit_route::install(
            &cfg.tun,
            flowmesh_net::BYPASS_MARK,
            flowmesh_net::BYPASS_MASK,
            &lan,
            ipv6,
        ) {
            Ok(warning) => {
                log(format!(
                    "exit node: using {}; LAN access {}",
                    cfg.exit_node,
                    if cfg.exit_node_allow_lan_access {
                        format!("allowed {lan:?}")
                    } else {
                        "blocked".into()
                    }
                ));
                if let Some(w) = warning {
                    log(&w);
                    self.exit_msg = Some(w);
                }
                self.exit_routing = Some(ExitRouting);
            }
            Err(e) => {
                let msg = format!(
                    "exit node {}: routing could not be installed: {e}",
                    cfg.exit_node
                );
                log(&msg);
                self.exit_msg = Some(msg);
            }
        }
    }

    /// The DNS proxy runs while offering an exit node. Returns whether the advertised services
    /// changed (the caller then sends the new host info).
    pub async fn sync_peerapi(
        &mut self,
        cfg: &EngineConfig,
        own: &[IpNet],
        rules: Vec<flowmesh_filter::compile::CompiledRule>,
        upstreams: &[std::net::IpAddr],
        dp: &mut flowmesh_dataplane::plane::Dataplane,
    ) -> bool {
        match (cfg.advertise_exit_node, self.peerapi.is_some()) {
            (true, true) | (false, false) => false,
            (false, true) => {
                self.peerapi = None; // Drop aborts the listeners.
                dp.set_peerapi(Vec::new());
                log("exit node: DNS proxy for peers stopped");
                true
            }
            (true, false) => {
                self.peerapi = start_peerapi(own, rules, upstreams).await;
                if let Some(p) = &self.peerapi {
                    dp.set_peerapi(p.listeners.clone());
                    log(format!(
                        "exit node: DNS proxy for peers on {:?}",
                        p.listeners
                    ));
                }
                self.peerapi.is_some()
            }
        }
    }

    /// The services to advertise in Hostinfo.
    pub fn services(&self) -> Vec<Service> {
        self.peerapi
            .as_ref()
            .map(|p| p.services.clone())
            .unwrap_or_default()
    }
}

fn start_ssh(
    cfg: &EngineConfig,
    own: &[IpNet],
    nm: &flowmesh_control::netmap::NetMap,
) -> Result<(SshServer, u16, flowmesh_dataplane::plane::Admissions), String> {
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
    let admissions = flowmesh_dataplane::plane::Admissions::default();
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
        admissions,
    ))
}

async fn start_peerapi(
    own: &[IpNet],
    rules: Vec<flowmesh_filter::compile::CompiledRule>,
    upstreams: &[std::net::IpAddr],
) -> Option<PeerApi> {
    use flowmesh_proto::control::{PEERAPI_DNS, PEERAPI4, PEERAPI6};
    let state = Arc::new(crate::peerapi::State {
        filter: std::sync::RwLock::new(flowmesh_filter::matcher::Filter::new(rules)),
        upstreams: upstreams.to_vec(),
    });
    let mut services = Vec::new();
    let mut listeners = Vec::new();
    let mut tasks = Vec::new();
    for a in own {
        let ip = a.addr();
        match tokio::net::TcpListener::bind((ip, 0)).await {
            Ok(l) => {
                let port = l.local_addr().map(|x| x.port()).unwrap_or(0);
                let proto = if ip.is_ipv4() { PEERAPI4 } else { PEERAPI6 };
                services.push(Service {
                    proto: proto.into(),
                    port,
                    description: String::new(),
                });
                listeners.push(SocketAddr::new(ip, port));
                tasks.push(AbortOnDrop(tokio::spawn(crate::peerapi::serve(
                    l,
                    state.clone(),
                ))));
            }
            Err(e) => log(format!("peerapi: listen on {ip}: {e}")),
        }
    }
    if services.is_empty() {
        return None;
    }
    services.push(Service {
        proto: PEERAPI_DNS.into(),
        port: 1,
        description: String::new(),
    });
    Some(PeerApi {
        state,
        services,
        listeners,
        _tasks: tasks,
    })
}

/// Host info fields that follow the settings and the running features.
pub(crate) fn apply_to_hostinfo(
    h: &mut flowmesh_proto::control::Hostinfo,
    cfg: &EngineConfig,
    features: &Features,
) {
    h.hostname.clone_from(&cfg.hostname);
    h.routable_ips = advertised(cfg);
    h.request_tags.clone_from(&cfg.advertise_tags);
    h.shields_up = cfg.shields_up;
    h.services = features.services();
    h.ssh_host_keys = features.ssh_host_keys();
}

/// Whether `new` differs from `cur` only in settings the engine can change while running.
pub(crate) fn live_changeable(cur: &EngineConfig, new: &EngineConfig) -> bool {
    cur.login_server == new.login_server
        && cur.state_file == new.state_file
        && cur.tun == new.tun
        && cur.port == new.port
        && cur.tap_dir == new.tap_dir
}
