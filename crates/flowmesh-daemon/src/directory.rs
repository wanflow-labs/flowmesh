// SPDX-License-Identifier: Apache-2.0
//! Mesh services learn who is calling from the daemon's current netmap (via the engine's whois).

use crate::daemon::{Daemon, Launcher};
use flowmesh_meshsvc::{BoxFut, Caller, Directory};
use std::net::SocketAddr;
use std::sync::Arc;

pub struct DaemonDirectory<L: Launcher>(pub Arc<Daemon<L>>);

impl<L: Launcher> Directory for DaemonDirectory<L> {
    /// `None` when the address is not in the netmap, or the network is not running.
    fn caller(&self, addr: SocketAddr) -> BoxFut<Option<Caller>> {
        let daemon = self.0.clone();
        Box::pin(async move {
            let w = daemon.whois(addr.ip()).await.ok()??;
            Some(Caller::new(addr, &w.node, w.user_profile, w.cap_map))
        })
    }
}
