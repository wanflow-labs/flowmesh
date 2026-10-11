// SPDX-License-Identifier: Apache-2.0
//! `flowmesh serve` in the engine: a listener per configured port on the mesh addresses (bound to
//! the mesh interface, on a port of its own that the dataplane maps the configured port to), and
//! the view the listeners read: the configuration, this node's name and who each peer is.
//! Listeners are restarted only when what a port does changes; HTTP handler changes take effect
//! at once on the running listener.

use crate::linux::{AbortOnDrop, log};
use flowmesh_control::netmap::NetMap;
use flowmesh_dataplane::plane::Admissions;
use flowmesh_serve::config::ServeConfig;
use flowmesh_serve::server::{Identity, Kind, Shared, View};
use ipnet::IpNet;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

struct PortListener {
    inner: u16,
    kind: Kind,
    _tasks: Vec<AbortOnDrop>,
}

#[derive(Default)]
pub(crate) struct Served {
    view: Arc<RwLock<View>>,
    ports: BTreeMap<u16, PortListener>,
    pub msg: Option<String>,
}

/// This node's name and every peer's identity, for the identity headers.
fn identities(nm: &NetMap) -> (String, HashMap<std::net::IpAddr, Identity>) {
    let name = nm
        .self_node
        .as_ref()
        .map(|n| n.name.trim_end_matches('.').to_string())
        .unwrap_or_default();
    let mut peers = HashMap::new();
    for n in nm.peers.values() {
        let profile = nm.user_profiles.get(&n.user);
        let who = Identity {
            login: profile.map(|p| p.login_name.clone()).unwrap_or_default(),
            name: profile.map(|p| p.display_name.clone()).unwrap_or_default(),
            profile_pic: profile
                .map(|p| p.profile_pic_url.clone())
                .unwrap_or_default(),
            tagged: !n.tags.is_empty(),
        };
        for a in &n.addresses {
            peers.insert(a.addr(), who.clone());
        }
    }
    (name, peers)
}

fn kind_of(h: &flowmesh_serve::config::TcpHandler) -> Kind {
    if h.http {
        Kind::Http
    } else {
        Kind::Tcp {
            target: h.tcp_forward.clone(),
            proxy_protocol: h.proxy_protocol,
        }
    }
}

fn start(
    port: u16,
    kind: Kind,
    own: &[IpNet],
    tun: &str,
    shared: &Arc<Shared>,
) -> Result<PortListener, String> {
    let mut addrs: Vec<std::net::IpAddr> = own.iter().map(IpNet::addr).collect();
    addrs.sort_by_key(|a| a.is_ipv6());
    let mut inner = 0u16;
    let mut tasks = Vec::new();
    for ip in addrs {
        let l = flowmesh_net::listen_on_device(SocketAddr::new(ip, inner), tun)
            .map_err(|e| format!("listen on {ip}: {e}"))?;
        if inner == 0 {
            inner = l.local_addr().map_err(|e| e.to_string())?.port();
        }
        tasks.push(AbortOnDrop(tokio::spawn(flowmesh_serve::server::serve(
            l,
            port,
            kind.clone(),
            shared.clone(),
        ))));
    }
    if tasks.is_empty() {
        return Err("no mesh address".into());
    }
    Ok(PortListener {
        inner,
        kind,
        _tasks: tasks,
    })
}

impl Served {
    /// Bring listeners and view in line with `cfg`. `taken` ports are in use by the SSH server.
    /// Returns whether the set of (port, listener port) pairs changed.
    pub fn sync(
        &mut self,
        cfg: &ServeConfig,
        own: &[IpNet],
        nm: &NetMap,
        tun: &str,
        admissions: &Admissions,
        taken: &[u16],
    ) -> bool {
        let (name, peers) = identities(nm);
        *self
            .view
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = View {
            name,
            peers,
            config: cfg.clone(),
        };
        let admitted = admissions.clone();
        let shared = Arc::new(Shared {
            view: self.view.clone(),
            admitted: Arc::new(move |from| admitted.take(from)),
            log: Arc::new(log),
        });
        let mut want: BTreeMap<u16, Kind> = BTreeMap::new();
        let mut problems = Vec::new();
        for (port, h) in cfg.ports() {
            if h.https || !h.terminate_tls.is_empty() {
                problems.push(format!(
                    "port {port}: HTTPS needs certificates, which the control server does not issue"
                ));
            } else if taken.contains(&port) {
                problems.push(format!("port {port} is used by the SSH server"));
            } else {
                want.insert(port, kind_of(h));
            }
        }
        let before: Vec<(u16, u16)> = self.redirects();
        self.ports.retain(|p, l| want.get(p) == Some(&l.kind));
        for (port, kind) in want {
            if self.ports.contains_key(&port) {
                continue;
            }
            match start(port, kind.clone(), own, tun, &shared) {
                Ok(l) => {
                    log(format!(
                        "serve: port {port} ({kind:?}) on listener port {}",
                        l.inner
                    ));
                    self.ports.insert(port, l);
                }
                Err(e) => problems.push(format!("port {port}: {e}")),
            }
        }
        self.msg = (!problems.is_empty()).then(|| format!("serve: {}", problems.join("; ")));
        if let Some(m) = &self.msg {
            log(m);
        }
        before != self.redirects()
    }

    /// Who the peers are and this node's name, after a netmap change.
    pub fn update(&self, nm: &NetMap) {
        let (name, peers) = identities(nm);
        let mut v = self
            .view
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        v.name = name;
        v.peers = peers;
    }

    /// (configured port, listener port) for the dataplane.
    pub fn redirects(&self) -> Vec<(u16, u16)> {
        self.ports.iter().map(|(p, l)| (*p, l.inner)).collect()
    }
}
