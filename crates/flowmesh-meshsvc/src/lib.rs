// SPDX-License-Identifier: Apache-2.0
//! Mesh services: TCP services bound to this node's mesh addresses that learn the caller's identity
//! from the netmap. This is where v4's SSH, Serve and the web client attach (design doc §3).
//!
//! Access control is not done here: the packet filter already decided whether the caller may reach
//! this port (filter.md). This layer only answers "who is it", and refuses callers it cannot name.

use flowmesh_proto::control::{Node, UserProfile};
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Who is on the other end of a connection.
#[derive(Debug, Clone, PartialEq)]
pub struct Caller {
    pub addr: SocketAddr,
    pub node_id: i64,
    /// Full DNS name without the trailing dot.
    pub node_name: String,
    pub tags: Vec<String>,
    /// The owning user; services should treat tagged nodes as owned by their tags, not the user.
    pub user: Option<UserProfile>,
    /// Capabilities the packet filter grants the caller towards this node (whois `CapMap`).
    pub caps: BTreeMap<String, Value>,
}

impl Caller {
    pub fn new(
        addr: SocketAddr,
        node: &Node,
        user: Option<UserProfile>,
        caps: BTreeMap<String, Value>,
    ) -> Self {
        Self {
            addr,
            node_id: node.id,
            node_name: node.name.trim_end_matches('.').to_string(),
            tags: node.tags.clone(),
            user,
            caps,
        }
    }

    pub fn has_cap(&self, cap: &str) -> bool {
        self.caps.contains_key(cap)
    }
}

/// Resolves a connection's source to an identity (the daemon answers from the netmap).
pub trait Directory: Send + Sync + 'static {
    fn caller(&self, addr: SocketAddr) -> BoxFut<Option<Caller>>;
}

/// A service on one TCP port of the mesh address.
pub trait Service: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn port(&self) -> u16;
    fn serve(&self, stream: TcpStream, caller: Caller) -> BoxFut<()>;
}

/// Bind every service on `ip` and serve until `stop` turns true. Binding failures are returned
/// before anything is served, so a misconfigured port does not leave half the services up.
pub async fn run(
    ip: IpAddr,
    services: Vec<Arc<dyn Service>>,
    directory: Arc<dyn Directory>,
    stop: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let mut bound = Vec::with_capacity(services.len());
    for svc in services {
        let listener = TcpListener::bind((ip, svc.port())).await.map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("{} on {ip}:{}: {e}", svc.name(), svc.port()),
            )
        })?;
        bound.push((svc, listener));
    }
    let tasks: Vec<_> = bound
        .into_iter()
        .map(|(svc, listener)| {
            tokio::spawn(accept_loop(svc, listener, directory.clone(), stop.clone()))
        })
        .collect();
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

async fn accept_loop(
    svc: Arc<dyn Service>,
    listener: TcpListener,
    directory: Arc<dyn Directory>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let (stream, addr) = tokio::select! {
            r = listener.accept() => match r {
                Ok(pair) => pair,
                Err(_) => continue,
            },
            r = stop.changed() => {
                if r.is_err() || *stop.borrow() {
                    return;
                }
                continue;
            }
        };
        let svc = svc.clone();
        let directory = directory.clone();
        tokio::spawn(async move {
            // An address the netmap cannot name is not a mesh peer: close without serving.
            if let Some(caller) = directory.caller(addr).await {
                svc.serve(stream, caller).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Knows 127.0.0.1 only.
    struct Loopback;
    impl Directory for Loopback {
        fn caller(&self, addr: SocketAddr) -> BoxFut<Option<Caller>> {
            Box::pin(async move {
                (addr.ip() == IpAddr::from([127, 0, 0, 1])).then(|| {
                    let node = Node {
                        id: 7,
                        name: "ts1.mesh.lab.internal.".into(),
                        tags: vec!["tag:relay-enabled".into()],
                        ..Default::default()
                    };
                    let caps = [("tailscale.com/cap/relay".to_string(), Value::Null)].into();
                    Caller::new(addr, &node, None, caps)
                })
            })
        }
    }

    struct Nobody;
    impl Directory for Nobody {
        fn caller(&self, _addr: SocketAddr) -> BoxFut<Option<Caller>> {
            Box::pin(async { None })
        }
    }

    /// Writes back "<name> <node> <has relay cap>" and closes.
    struct Hello {
        name: &'static str,
        port: u16,
    }
    impl Service for Hello {
        fn name(&self) -> &str {
            self.name
        }
        fn port(&self) -> u16 {
            self.port
        }
        fn serve(&self, mut stream: TcpStream, caller: Caller) -> BoxFut<()> {
            let line = format!(
                "{} {} {}",
                self.name,
                caller.node_name,
                caller.has_cap("tailscale.com/cap/relay")
            );
            Box::pin(async move {
                let _ = stream.write_all(line.as_bytes()).await;
            })
        }
    }

    async fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn read_all(port: u16) -> String {
        for _ in 0..100 {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await {
                let mut buf = String::new();
                let _ = s.read_to_string(&mut buf).await;
                return buf;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("service on {port} never came up");
    }

    fn spawn(
        services: Vec<Arc<dyn Service>>,
        dir: Arc<dyn Directory>,
    ) -> (
        watch::Sender<bool>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let (tx, rx) = watch::channel(false);
        let h = tokio::spawn(run(IpAddr::from([127, 0, 0, 1]), services, dir, rx));
        (tx, h)
    }

    #[tokio::test]
    async fn services_see_who_is_calling() {
        let (a, b) = (free_port().await, free_port().await);
        let (stop, task) = spawn(
            vec![
                Arc::new(Hello {
                    name: "one",
                    port: a,
                }),
                Arc::new(Hello {
                    name: "two",
                    port: b,
                }),
            ],
            Arc::new(Loopback),
        );
        assert_eq!(read_all(a).await, "one ts1.mesh.lab.internal true");
        assert_eq!(read_all(b).await, "two ts1.mesh.lab.internal true");
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn unknown_callers_are_closed_without_service() {
        let port = free_port().await;
        let (stop, task) = spawn(
            vec![Arc::new(Hello { name: "one", port })],
            Arc::new(Nobody),
        );
        assert_eq!(read_all(port).await, "", "closed without a word");
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_port_conflict_fails_before_serving() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let busy = taken.local_addr().unwrap().port();
        let free = free_port().await;
        let (_stop, task) = spawn(
            vec![
                Arc::new(Hello {
                    name: "ok",
                    port: free,
                }),
                Arc::new(Hello {
                    name: "clash",
                    port: busy,
                }),
            ],
            Arc::new(Loopback),
        );
        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("clash on 127.0.0.1:"), "{err}");
        assert!(
            TcpStream::connect(("127.0.0.1", free)).await.is_err(),
            "nothing left serving"
        );
    }

    #[test]
    fn caller_from_netmap_node() {
        let node = Node {
            id: 3,
            name: "laptop.mesh.lab.internal.".into(),
            ..Default::default()
        };
        let user = UserProfile {
            id: 9,
            login_name: "alice".into(),
            display_name: "Alice".into(),
            ..Default::default()
        };
        let c = Caller::new(
            "100.64.0.3:5000".parse().unwrap(),
            &node,
            Some(user.clone()),
            BTreeMap::new(),
        );
        assert_eq!(
            (c.node_id, c.node_name.as_str()),
            (3, "laptop.mesh.lab.internal")
        );
        assert_eq!(c.user, Some(user));
        assert!(c.tags.is_empty() && !c.has_cap("x"));
    }
}
