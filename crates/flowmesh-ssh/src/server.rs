// SPDX-License-Identifier: Apache-2.0
//! The SSH server (docs/protocol/ssh.md §3). A connection is identified by its source address,
//! which the netmap ties to a peer; the control server's SSH policy then decides which local user,
//! if any, it may log in as. There are no passwords or keys: authentication is the "none" method.

use crate::policy::{Decision, Peer, decide};
use crate::proc::{self, Account, Program, PtySpec, Spec};
use flowmesh_proto::control::{SshAction, SshPolicy};
use russh::keys::PrivateKey;
use russh::server::{Auth, ChannelOpenHandle, Handle, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Sig};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// The port clients connect to; the dataplane delivers it to the server's own port.
pub const SSH_PORT: u16 = 22;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_CHUNK: usize = 32 * 1024;

/// Who a peer is, by the netmap.
#[derive(Debug, Clone, Default)]
pub struct PeerInfo {
    pub peer: Peer,
    /// Its DNS name, for the log.
    pub name: String,
}

/// What the server needs from the engine; replaced on every netmap change.
#[derive(Debug, Clone, Default)]
pub struct View {
    pub policy: Option<SshPolicy>,
    /// Peers by mesh address. This node is not in it: a connection from one of its own addresses
    /// came from a local process, never through the mesh.
    pub peers: HashMap<IpAddr, PeerInfo>,
}

pub type Logger = Arc<dyn Fn(String) + Send + Sync>;

/// Server-wide settings shared by all connections.
pub struct Shared {
    pub config: Arc<russh::server::Config>,
    pub view: Arc<RwLock<View>>,
    pub log: Logger,
    /// flowmeshd itself: started as `be-child ssh …` to become the user and run the program.
    pub helper: std::path::PathBuf,
    /// Whether a connection from this address came through the mesh: the dataplane saw its SYN
    /// arrive over WireGuard (one use per SYN). Local processes can reach the listener too, and
    /// some can pick a peer's address as their source; only this tells them apart.
    pub admitted: Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>,
}

pub fn config(keys: Vec<PrivateKey>) -> russh::server::Config {
    russh::server::Config {
        server_id: russh::SshId::Standard("SSH-2.0-flowmesh".into()),
        methods: MethodSet::from(&[MethodKind::None, MethodKind::KeyboardInteractive][..]),
        // Nothing secret is checked, so there is no timing to hide.
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys,
        inactivity_timeout: None,
        nodelay: true,
        ..Default::default()
    }
}

/// Accept connections until the listener fails or the task is aborted.
pub async fn serve(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        let (stream, from) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                (shared.log)(format!("ssh: accept: {e}"));
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let local = stream.local_addr().unwrap_or(from);
        let from = SocketAddr::new(from.ip().to_canonical(), from.port());
        if !(shared.admitted)(from) {
            (shared.log)(format!(
                "ssh: refused connection from {from}: did not come through the mesh"
            ));
            continue;
        }
        let info = shared
            .view
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .peers
            .get(&from.ip())
            .cloned();
        // And only from addresses the netmap gives a peer (never this node's own).
        let Some(info) = info else {
            (shared.log)(format!("ssh: refused connection from {from}: not a peer"));
            continue;
        };
        let handler = Conn {
            shared: shared.clone(),
            info,
            from,
            server: SocketAddr::new(local.ip(), SSH_PORT),
            requested: String::new(),
            decision: None,
            account: None,
            chans: HashMap::new(),
            agent_sock: None,
            tasks: Vec::new(),
        };
        let config = shared.config.clone();
        tokio::spawn(async move {
            if let Ok(s) = russh::server::run_stream(config, stream, handler).await {
                let _ = s.await;
            }
        });
    }
}

#[derive(Default)]
struct Chan {
    pty: Option<PtySpec>,
    /// Input for the running program; dropping it closes the program's stdin.
    input: Option<mpsc::Sender<Vec<u8>>>,
    pid: Option<i32>,
    master: Option<Arc<OwnedFd>>,
    started: bool,
}

struct Conn {
    shared: Arc<Shared>,
    info: PeerInfo,
    from: SocketAddr,
    server: SocketAddr,
    requested: String,
    decision: Option<Decision>,
    account: Option<Account>,
    chans: HashMap<ChannelId, Chan>,
    /// Agent forwarding: the socket directory (removed when the connection ends).
    agent_sock: Option<std::path::PathBuf>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        if let Some(dir) = self.agent_sock.as_ref().and_then(|s| s.parent()) {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl Conn {
    fn log(&self, s: String) {
        (self.shared.log)(s);
    }

    fn action(&self) -> Option<&SshAction> {
        match &self.decision {
            Some(Decision::Accept { action, .. }) => Some(action),
            _ => None,
        }
    }

    fn decide(&mut self, user: &str) -> Decision {
        if self.decision.is_none() || self.requested != user {
            self.requested = user.to_string();
            let policy = self
                .shared
                .view
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .policy
                .clone();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            let mut d = decide(policy.as_ref(), &self.info.peer, user, now);
            if let Decision::Accept { local_user, .. } = &d {
                match proc::lookup(local_user) {
                    Ok(a) => self.account = Some(a),
                    Err(e) => {
                        d = Decision::Reject {
                            message: format!("flowmesh: {e}"),
                        }
                    }
                }
            }
            self.decision = Some(d);
        }
        self.decision.clone().unwrap_or(Decision::Reject {
            message: String::new(),
        })
    }

    /// Start the program for a session channel.
    fn start(&mut self, id: ChannelId, program: Program, handle: Handle) -> bool {
        let Some(account) = self.account.clone() else {
            return false;
        };
        let chan = self.chans.entry(id).or_default();
        if chan.started {
            return false;
        }
        let mut env = proc::login_env(&account, self.from, self.server);
        if let Some(sock) = &self.agent_sock {
            env.push(("SSH_AUTH_SOCK".into(), sock.display().to_string()));
        }
        let what = match &program {
            Program::LoginShell => "shell".to_string(),
            Program::Command(c) => format!("command {c:?}"),
            Program::Binary(b) => format!("{}", b.display()),
            Program::BuiltinSftp => "sftp".to_string(),
        };
        let spec = Spec {
            account: account.clone(),
            program,
            env,
            pty: chan.pty.clone(),
        };
        let started = match proc::spawn(&self.shared.helper, spec) {
            Ok(s) => s,
            Err(e) => {
                (self.shared.log)(format!(
                    "ssh: {} as {}: start {what}: {e}",
                    self.info.name, account.name
                ));
                return false;
            }
        };
        (self.shared.log)(format!(
            "ssh: {} ({}) as {}: {what}{}",
            self.info.name,
            self.from.ip(),
            account.name,
            if chan.pty.is_some() { " with pty" } else { "" }
        ));
        chan.started = true;
        chan.pid = started.child.id().map(|p| p as i32);
        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
        chan.input = Some(tx);
        let task = match started.pty {
            Some((master, slave)) => {
                let master = Arc::new(master);
                chan.master = Some(master.clone());
                tokio::spawn(pump_pty(started.child, master, slave, rx, handle, id))
            }
            None => tokio::spawn(pump_pipes(started.child, rx, handle, id)),
        };
        self.tasks.push(task);
        true
    }
}

/// Duplicate a pty master into a tokio file (reads and writes go through the blocking pool).
fn pty_file(master: &OwnedFd) -> Option<tokio::fs::File> {
    master
        .try_clone()
        .ok()
        .map(|fd| tokio::fs::File::from_std(std::fs::File::from(fd)))
}

async fn feed<W: tokio::io::AsyncWrite + Unpin>(mut w: W, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(buf) = rx.recv().await {
        if w.write_all(&buf).await.is_err() || w.flush().await.is_err() {
            return;
        }
    }
}

async fn forward_output<R: tokio::io::AsyncRead + Unpin>(
    mut r: R,
    handle: Handle,
    id: ChannelId,
    ext: Option<u32>,
) {
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                let sent = match ext {
                    None => handle.data(id, data).await,
                    Some(e) => handle.extended_data(id, e, data).await,
                };
                if sent.is_err() {
                    return;
                }
            }
        }
    }
}

/// Report how the program ended, then end the channel.
async fn finish(handle: &Handle, id: ChannelId, status: std::io::Result<std::process::ExitStatus>) {
    use std::os::unix::process::ExitStatusExt;
    match status {
        Ok(s) if s.signal().is_some() => {
            let sig = s.signal().unwrap_or(0);
            let name = nix::sys::signal::Signal::try_from(sig)
                .map(|s| s.as_str().trim_start_matches("SIG").to_string())
                .unwrap_or_else(|_| sig.to_string());
            let _ = handle
                .exit_signal_request(
                    id,
                    Sig::Custom(name),
                    s.core_dumped(),
                    String::new(),
                    String::new(),
                )
                .await;
        }
        Ok(s) => {
            let _ = handle
                .exit_status_request(id, s.code().unwrap_or(255) as u32)
                .await;
        }
        Err(_) => {
            let _ = handle.exit_status_request(id, 255).await;
        }
    }
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
}

async fn pump_pipes(
    mut child: tokio::process::Child,
    rx: mpsc::Receiver<Vec<u8>>,
    handle: Handle,
    id: ChannelId,
) {
    if let Some(stdin) = child.stdin.take() {
        tokio::spawn(feed(stdin, rx));
    }
    let out = child
        .stdout
        .take()
        .map(|o| tokio::spawn(forward_output(o, handle.clone(), id, None)));
    let err = child
        .stderr
        .take()
        .map(|e| tokio::spawn(forward_output(e, handle.clone(), id, Some(1))));
    for t in [out, err].into_iter().flatten() {
        let _ = t.await;
    }
    let status = child.wait().await;
    finish(&handle, id, status).await;
}

async fn pump_pty(
    mut child: tokio::process::Child,
    master: Arc<OwnedFd>,
    // Held until the program ends, so reading the master cannot see a hang-up before the
    // helper opened the terminal.
    slave: OwnedFd,
    rx: mpsc::Receiver<Vec<u8>>,
    handle: Handle,
    id: ChannelId,
) {
    if let Some(w) = pty_file(&master) {
        tokio::spawn(feed(w, rx));
    }
    // Reading the master ends with EIO once every holder of the terminal has gone.
    if let Some(r) = pty_file(&master) {
        let out = tokio::spawn(forward_output(r, handle.clone(), id, None));
        tokio::select! {
            _ = out => {}
            // The shell is gone; give the last output a moment, then stop reading.
            _ = async {
                let _ = child.wait().await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            } => {}
        }
    }
    let status = child.wait().await;
    drop(slave);
    finish(&handle, id, status).await;
}

fn sig_of(s: &Sig) -> Option<nix::sys::signal::Signal> {
    use nix::sys::signal::Signal as S;
    Some(match s {
        Sig::ABRT => S::SIGABRT,
        Sig::ALRM => S::SIGALRM,
        Sig::FPE => S::SIGFPE,
        Sig::HUP => S::SIGHUP,
        Sig::ILL => S::SIGILL,
        Sig::INT => S::SIGINT,
        Sig::KILL => S::SIGKILL,
        Sig::PIPE => S::SIGPIPE,
        Sig::QUIT => S::SIGQUIT,
        Sig::SEGV => S::SIGSEGV,
        Sig::TERM => S::SIGTERM,
        Sig::USR1 => S::SIGUSR1,
        Sig::Custom(n) => format!("SIG{n}").parse().ok()?,
    })
}

/// An SFTP server binary on this host, if there is one.
fn system_sftp_server() -> Option<std::path::PathBuf> {
    [
        "/usr/lib/openssh/sftp-server",
        "/usr/libexec/openssh/sftp-server",
        "/usr/lib/ssh/sftp-server",
        "/usr/libexec/sftp-server",
        "/usr/lib/sftp-server",
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .find(|p| p.is_file())
}

impl russh::server::Handler for Conn {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        match self.decide(user) {
            Decision::Accept { local_user, action } => {
                self.log(format!(
                    "ssh: login of {} ({}) as {local_user:?} accepted",
                    self.info.name,
                    self.from.ip()
                ));
                let _ = (local_user, action);
                Ok(Auth::Accept)
            }
            // The reason reaches the user through keyboard-interactive (see below).
            Decision::Reject { .. } => Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
                partial_success: false,
            }),
        }
    }

    /// Refusals are explained here: the "none" method cannot carry a message, so the client is
    /// sent to keyboard-interactive and shown the reason as its instructions with nothing to
    /// answer; its (empty) answer ends the connection. OpenSSH prints the reason once and then
    /// "Connection closed", as with the official server's banner.
    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        if response.is_some() {
            return Err(russh::Error::Disconnect);
        }
        match self.decide(user) {
            Decision::Reject { message } => {
                self.log(format!(
                    "ssh: login of {} ({}) as {user:?} refused: {message}",
                    self.info.name,
                    self.from.ip()
                ));
                Ok(Auth::Partial {
                    name: "".into(),
                    instructions: message.into(),
                    prompts: Vec::new().into(),
                })
            }
            Decision::Accept { .. } => Ok(Auth::reject()),
        }
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        if let Some(a) = self.action() {
            // The session ends when the rule's time is up (headscale's "check" period).
            if a.session_duration > 0 {
                let d = Duration::from_nanos(a.session_duration as u64);
                let handle = session.handle();
                self.tasks.push(tokio::spawn(async move {
                    tokio::time::sleep(d).await;
                    let _ = handle
                        .disconnect(
                            russh::Disconnect::ByApplication,
                            "flowmesh: session time limit reached".into(),
                            String::new(),
                        )
                        .await;
                }));
            }
        }
        if let (Some(a), Some(acc)) = (self.action(), &self.account) {
            if !a.message.is_empty() {
                // Accepted with a message: nothing to show it in after authentication; log it.
                self.log(format!("ssh: message for {}: {}", acc.name, a.message));
            }
            self.log(format!(
                "ssh: audit: login user={} uid={} from={} node={}",
                acc.name,
                acc.uid,
                self.from.ip(),
                self.info.name
            ));
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.account.is_none() {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        self.chans.insert(channel.id(), Chan::default());
        // Data and requests arrive through the handler; the channel object is not needed.
        drop(channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _originator: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let allowed = self.action().is_some_and(|a| a.allow_local_port_forwarding);
        let Ok(port) = u16::try_from(port) else {
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        if !allowed {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        let target = format!("{host}:{port}");
        match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&target)).await {
            Ok(Ok(mut tcp)) => {
                reply.accept().await;
                self.log(format!("ssh: {} forwards to {target}", self.info.name));
                let mut stream = channel.into_stream();
                self.tasks.push(tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                }));
            }
            _ => reply.reject(ChannelOpenFailure::ConnectFailed).await,
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.chans.get_mut(&channel) {
            Some(c) if !c.started => {
                c.pty = Some(PtySpec {
                    term: term.to_string(),
                    cols: u16::try_from(cols).unwrap_or(u16::MAX),
                    rows: u16::try_from(rows).unwrap_or(u16::MAX),
                });
                session.channel_success(channel)?;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(m) = self.chans.get(&channel).and_then(|c| c.master.as_ref()) {
            proc::resize(
                m,
                u16::try_from(cols).unwrap_or(u16::MAX),
                u16::try_from(rows).unwrap_or(u16::MAX),
            );
        }
        Ok(())
    }

    /// Environment from the client is not taken (the official server takes none by default).
    async fn env_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.start(channel, Program::LoginShell, session.handle()) {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        if self.start(channel, Program::Command(command), session.handle()) {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let program = match name {
            "sftp" => Some(system_sftp_server().map_or(Program::BuiltinSftp, Program::Binary)),
            _ => None,
        };
        let ok = match program {
            Some(p) => self.start(channel, p, session.handle()),
            None => false,
        };
        if ok {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.chans.get(&channel).and_then(|c| c.input.clone()) {
            // Waits when the program reads slowly: backpressure to the client.
            let _ = tx.send(data.to_vec()).await;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(c) = self.chans.get_mut(&channel) {
            // A pty's input has no end; a pipe's end closes the program's stdin.
            if c.pty.is_none() {
                c.input = None;
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(c) = self.chans.remove(&channel) {
            if let (Some(pid), Some(_)) = (c.pid, c.master.as_ref()) {
                // The client closed a terminal session: hang up, like closing a terminal.
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-pid),
                    nix::sys::signal::Signal::SIGHUP,
                );
            }
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let (Some(pid), Some(sig)) = (
            self.chans.get(&channel).and_then(|c| c.pid),
            sig_of(&signal),
        ) {
            let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), sig);
        }
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let allowed = self.action().is_some_and(|a| a.allow_agent_forwarding);
        let Some(account) = self.account.clone().filter(|_| allowed) else {
            session.channel_failure(channel)?;
            return Ok(false);
        };
        if self.agent_sock.is_none() {
            match agent_listener(&account) {
                Ok((path, listener)) => {
                    let handle = session.handle();
                    self.tasks.push(tokio::spawn(serve_agent(listener, handle)));
                    self.agent_sock = Some(path);
                }
                Err(e) => {
                    self.log(format!("ssh: agent forwarding for {}: {e}", account.name));
                    session.channel_failure(channel)?;
                    return Ok(false);
                }
            }
        }
        session.channel_success(channel)?;
        Ok(true)
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Remote forwarding: headscale never allows it, and flowmesh does not offer it.
        Ok(false)
    }
}

/// A socket for the user's programs to reach the forwarded agent: in a fresh directory only the
/// user can enter.
fn agent_listener(a: &Account) -> Result<(std::path::PathBuf, tokio::net::UnixListener), String> {
    use std::os::unix::fs::DirBuilderExt;
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir().join(format!(
        "flowmesh-ssh-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join("agent");
    let listener = tokio::net::UnixListener::bind(&path)
        .map_err(|e| format!("listen {}: {e}", path.display()))?;
    for p in [&dir, &path] {
        nix::unistd::chown(p.as_path(), Some(a.uid), Some(a.gid))
            .map_err(|e| format!("chown {}: {e}", p.display()))?;
    }
    Ok((path, listener))
}

async fn serve_agent(listener: tokio::net::UnixListener, handle: Handle) {
    while let Ok((mut local, _)) = listener.accept().await {
        let handle = handle.clone();
        tokio::spawn(async move {
            if let Ok(ch) = handle.channel_open_agent().await {
                let mut stream = ch.into_stream();
                let _ = tokio::io::copy_bidirectional(&mut local, &mut stream).await;
            }
        });
    }
}

/// Bind the server's listener on `addr` (a mesh address, port 0 for any), bound to interface
/// `dev`. That does not keep local processes out (the kernel delivers their connections to the
/// mesh address too, as seen in the lab); the admission check in `serve` does.
pub fn listen(addr: SocketAddr, dev: &str) -> std::io::Result<TcpListener> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, setsockopt, sockopt};
    let family = if addr.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    let fd = nix::sys::socket::socket(
        family,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    setsockopt(&fd, sockopt::BindToDevice, &std::ffi::OsString::from(dev))?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    if addr.is_ipv6() {
        setsockopt(&fd, sockopt::Ipv6V6Only, &true)?;
    }
    let sa = nix::sys::socket::SockaddrStorage::from(addr);
    nix::sys::socket::bind(fd.as_raw_fd(), &sa)?;
    nix::sys::socket::listen(
        &fd,
        nix::sys::socket::Backlog::new(128).map_err(std::io::Error::from)?,
    )?;
    TcpListener::from_std(std::net::TcpListener::from(fd))
}
