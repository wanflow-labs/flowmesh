// SPDX-License-Identifier: Apache-2.0
//! The daemon core: persisted preferences, engine supervision, and the operations behind the local API.
//! The engine is reached through [`Launcher`] so this logic is tested off-Linux with a fake engine.

use crate::prefs::{Prefs, PrefsError, PrefsUpdate};
use crate::state::{BackendState, Facts, derive};
use crate::status_json;
use flowmesh_engine::command::{EngineCommand, PingError, PingReply, WhoisReply};
use flowmesh_engine::status::EngineStatus;
use flowmesh_engine::{EngineConfig, EngineError};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// How the daemon starts the network engine and logs out.
pub trait Launcher: Send + Sync + 'static {
    fn run(
        &self,
        cfg: EngineConfig,
        status: watch::Sender<EngineStatus>,
        stop: watch::Receiver<bool>,
        commands: mpsc::Receiver<EngineCommand>,
    ) -> BoxFut<Result<(), EngineError>>;
    fn logout(&self, login_server: String, state_file: PathBuf) -> BoxFut<Result<(), String>>;
}

#[derive(Debug, Clone)]
pub struct Options {
    pub state_dir: PathBuf,
    pub tun: String,
    pub port: u16,
    /// First retry delay after an engine failure; doubles up to `retry_max`.
    pub retry_min: Duration,
    pub retry_max: Duration,
    /// How long `down`/`logout`/shutdown wait for the engine to restore the system before giving up on it.
    pub stop_timeout: Duration,
}

impl Options {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            tun: "flowmesh0".into(),
            port: 41641,
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(10),
        }
    }
    pub fn prefs_file(&self) -> PathBuf {
        self.state_dir.join("prefs.json")
    }
    pub fn node_file(&self) -> PathBuf {
        self.state_dir.join("node.json")
    }
}

/// What is written to `prefs.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Stored {
    pub prefs: Prefs,
    pub logged_in: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error(transparent)]
    Prefs(#[from] PrefsError),
    #[error("persist preferences: {0}")]
    Persist(String),
    #[error("logout failed: {0}")]
    Logout(String),
    #[error("flowmesh is not running")]
    NotRunning,
}

/// Body of `up`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpRequest {
    pub update: PrefsUpdate,
    pub reset: bool,
    /// Used only for registration; kept in memory, never written to disk.
    pub authkey: Option<String>,
}

struct Engine {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct Shared {
    stored: Stored,
    authkey: Option<String>,
    /// `Some(auth_url)` after the control server refused the node.
    refused: Option<String>,
    errors: Vec<String>,
    live: bool,
    /// Last snapshot; kept after `down` (official behavior), cleared by `logout`.
    snap: EngineStatus,
    engine: Option<Engine>,
}

/// Sender into the current engine run. Kept outside `Shared` (and behind a lock never held across an
/// await) so the supervisor can swap it without contending with operations that hold `Shared`.
type CommandSlot = Arc<std::sync::Mutex<Option<mpsc::Sender<EngineCommand>>>>;

/// Per-attempt ping timeout: official default 5 s; requests are clamped to 1–60 s.
pub const PING_TIMEOUT_DEFAULT: Duration = Duration::from_secs(5);
const PING_TIMEOUT_RANGE: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));
/// Extra wait on top of the engine's own ping timeout before giving up on the engine.
const PING_SLACK: Duration = Duration::from_secs(2);

pub struct Daemon<L: Launcher> {
    launcher: Arc<L>,
    opts: Options,
    shared: Arc<Mutex<Shared>>,
    commands: CommandSlot,
}

/// Where an unparsable prefs file is moved, so it can be inspected.
pub fn quarantine_path(prefs_file: &Path) -> PathBuf {
    prefs_file.with_extension("json.corrupt")
}

/// Read errors refuse to start; unparsable content is moved aside and defaults are used, so an
/// unattended host comes back up (the node key lives in another file, so `up` needs no auth key).
fn load(path: &Path) -> Result<Stored, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Stored::default()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    match serde_json::from_slice(&bytes) {
        Ok(s) => Ok(s),
        Err(e) => {
            let aside = quarantine_path(path);
            std::fs::rename(path, &aside)
                .map_err(|re| format!("{}: {e}; moving it aside failed: {re}", path.display()))?;
            eprintln!(
                "flowmeshd: {} could not be parsed ({e}); moved to {} and starting with default preferences",
                path.display(),
                aside.display()
            );
            Ok(Stored::default())
        }
    }
}

fn save(path: &Path, s: &Stored) -> Result<(), DaemonError> {
    let bytes = serde_json::to_vec_pretty(s).map_err(|e| DaemonError::Persist(e.to_string()))?;
    flowmesh_state::write_private(path, &bytes).map_err(|e| DaemonError::Persist(e.to_string()))
}

impl<L: Launcher> Daemon<L> {
    /// Load preferences and, if the user left the network up, bring it back.
    pub async fn start(launcher: L, opts: Options) -> Result<Self, String> {
        std::fs::create_dir_all(&opts.state_dir)
            .map_err(|e| format!("{}: {e}", opts.state_dir.display()))?;
        let stored = load(&opts.prefs_file())?;
        let d = Self {
            launcher: Arc::new(launcher),
            opts,
            commands: CommandSlot::default(),
            shared: Arc::new(Mutex::new(Shared {
                stored,
                ..Default::default()
            })),
        };
        let mut sh = d.shared.lock().await;
        if sh.stored.prefs.want_running {
            d.spawn_engine(&mut sh);
        }
        drop(sh);
        Ok(d)
    }

    pub async fn up(&self, req: UpRequest) -> Result<(), DaemonError> {
        let mut sh = self.shared.lock().await;
        let prefs = sh.stored.prefs.apply_up(&req.update, req.reset)?;
        let same_server = prefs.control_url == sh.stored.prefs.control_url;
        let mut stored = sh.stored.clone();
        if prefs.control_url != stored.prefs.control_url {
            // A different control server knows nothing about our node key.
            stored.logged_in = false;
        }
        stored.prefs = prefs;
        save(&self.opts.prefs_file(), &stored)?;
        sh.stored = stored;
        if req.authkey.is_some() {
            sh.authkey = req.authkey;
        }
        sh.refused = None;
        if same_server && self.reconfigure(&sh).await {
            return Ok(());
        }
        self.stop_engine(&mut sh).await;
        self.spawn_engine(&mut sh);
        Ok(())
    }

    pub async fn set(&self, update: PrefsUpdate) -> Result<(), DaemonError> {
        let mut sh = self.shared.lock().await;
        let prefs = sh.stored.prefs.apply_set(&update);
        if prefs == sh.stored.prefs {
            return Ok(());
        }
        let same_server = prefs.control_url == sh.stored.prefs.control_url;
        let mut stored = sh.stored.clone();
        if prefs.control_url != stored.prefs.control_url {
            stored.logged_in = false;
        }
        stored.prefs = prefs;
        save(&self.opts.prefs_file(), &stored)?;
        sh.stored = stored;
        if sh.stored.prefs.want_running && !(same_server && self.reconfigure(&sh).await) {
            self.stop_engine(&mut sh).await;
            self.spawn_engine(&mut sh);
        }
        Ok(())
    }

    /// Hand the current preferences to the running engine, which applies them without a restart
    /// (as the official client does). False when there is no running, logged-in engine, or it
    /// cannot apply the change; the caller then restarts it.
    async fn reconfigure(&self, sh: &Shared) -> bool {
        if sh.engine.is_none() || !sh.live || !sh.stored.logged_in {
            return false;
        }
        let Some(tx) = self
            .commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        else {
            return false;
        };
        let cfg = engine_config(&sh.stored.prefs, None, &self.opts);
        let (reply, rx) = oneshot::channel();
        if tx
            .send(EngineCommand::Reconfigure {
                cfg: Box::new(cfg),
                reply,
            })
            .await
            .is_err()
        {
            return false;
        }
        matches!(
            tokio::time::timeout(RECONFIGURE_TIMEOUT, rx).await,
            Ok(Ok(Ok(())))
        )
    }

    pub async fn down(&self) -> Result<(), DaemonError> {
        let mut sh = self.shared.lock().await;
        let mut stored = sh.stored.clone();
        stored.prefs.want_running = false;
        save(&self.opts.prefs_file(), &stored)?;
        sh.stored = stored;
        self.stop_engine(&mut sh).await;
        Ok(())
    }

    /// Official behavior (cli.md §1): the network is stopped first; if the control server cannot be
    /// told, the logout fails and the node stays logged in but Stopped.
    pub async fn logout(&self) -> Result<(), DaemonError> {
        let mut sh = self.shared.lock().await;
        self.stop_engine(&mut sh).await;
        if sh.stored.logged_in && !sh.stored.prefs.control_url.is_empty() {
            let mut stopped = sh.stored.clone();
            stopped.prefs.want_running = false;
            save(&self.opts.prefs_file(), &stopped)?;
            sh.stored = stopped;
            self.launcher
                .logout(sh.stored.prefs.control_url.clone(), self.opts.node_file())
                .await
                .map_err(DaemonError::Logout)?;
        }
        // Official behavior (cli.md §1): logout resets every preference to its default, so the next
        // login starts clean and is not subject to the "mention all non-default flags" rule.
        let stored = Stored::default();
        save(&self.opts.prefs_file(), &stored)?;
        sh.stored = stored;
        sh.authkey = None;
        sh.refused = None;
        sh.errors.clear();
        sh.snap = EngineStatus::default();
        Ok(())
    }

    /// Disco-ping the peer owning `ip` once. The outer error means no running network to ask.
    pub async fn ping(
        &self,
        ip: std::net::IpAddr,
        timeout: Option<Duration>,
    ) -> Result<Result<PingReply, PingError>, DaemonError> {
        let timeout = timeout
            .unwrap_or(PING_TIMEOUT_DEFAULT)
            .clamp(PING_TIMEOUT_RANGE.0, PING_TIMEOUT_RANGE.1);
        if self.backend_state().await != BackendState::Running {
            return Err(DaemonError::NotRunning);
        }
        let tx = self
            .commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(DaemonError::NotRunning)?;
        let (reply, rx) = oneshot::channel();
        tx.send(EngineCommand::Ping { ip, timeout, reply })
            .await
            .map_err(|_| DaemonError::NotRunning)?;
        match tokio::time::timeout(timeout + PING_SLACK, rx).await {
            Ok(Ok(r)) => Ok(r),
            // The engine stopped, or never answered: report it like an unanswered ping.
            Ok(Err(_)) | Err(_) => Ok(Err(PingError::Timeout)),
        }
    }

    /// A read-only engine view for `flowmesh debug <topic>`.
    pub async fn debug(
        &self,
        topic: flowmesh_engine::debug::DebugTopic,
    ) -> Result<serde_json::Value, DaemonError> {
        if self.backend_state().await != BackendState::Running {
            return Err(DaemonError::NotRunning);
        }
        let tx = self
            .commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(DaemonError::NotRunning)?;
        let (reply, rx) = oneshot::channel();
        tx.send(EngineCommand::Debug { topic, reply })
            .await
            .map_err(|_| DaemonError::NotRunning)?;
        rx.await.map_err(|_| DaemonError::NotRunning)
    }

    /// Who owns `ip` according to the current netmap (`None`: nobody).
    pub async fn whois(&self, ip: std::net::IpAddr) -> Result<Option<WhoisReply>, DaemonError> {
        if self.backend_state().await != BackendState::Running {
            return Err(DaemonError::NotRunning);
        }
        let tx = self
            .commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(DaemonError::NotRunning)?;
        let (reply, rx) = oneshot::channel();
        tx.send(EngineCommand::Whois { ip, reply })
            .await
            .map_err(|_| DaemonError::NotRunning)?;
        rx.await.map_err(|_| DaemonError::NotRunning)
    }

    pub async fn prefs(&self) -> Prefs {
        self.shared.lock().await.stored.prefs.clone()
    }

    pub async fn backend_state(&self) -> BackendState {
        let sh = self.shared.lock().await;
        derive(facts(&sh))
    }

    pub async fn status_json(&self) -> serde_json::Value {
        let sh = self.shared.lock().await;
        status_json::render(&status_json::Input {
            state: derive(facts(&sh)),
            logged_in: sh.stored.logged_in,
            auth_url: sh.refused.as_deref().unwrap_or(""),
            errors: &sh.errors,
            snap: &sh.snap,
            hostname: &sh.stored.prefs.hostname,
        })
    }

    /// Stop the engine (it restores DNS/routes on the way out). Preferences are untouched, so the
    /// next start brings the network back.
    pub async fn shutdown(&self) {
        let mut sh = self.shared.lock().await;
        self.stop_engine(&mut sh).await;
    }

    async fn stop_engine(&self, sh: &mut Shared) {
        sh.live = false;
        let Some(engine) = sh.engine.take() else {
            return;
        };
        let _ = engine.stop.send(true);
        let abort = engine.task.abort_handle();
        if tokio::time::timeout(self.opts.stop_timeout, engine.task)
            .await
            .is_err()
        {
            abort.abort();
        }
    }

    fn spawn_engine(&self, sh: &mut Shared) {
        let cfg = engine_config(&sh.stored.prefs, sh.authkey.clone(), &self.opts);
        let (stop_tx, stop_rx) = watch::channel(false);
        sh.errors.clear();
        sh.live = false;
        let task = tokio::spawn(supervise(
            self.launcher.clone(),
            self.shared.clone(),
            self.commands.clone(),
            self.opts.clone(),
            cfg,
            stop_rx,
        ));
        sh.engine = Some(Engine {
            stop: stop_tx,
            task,
        });
    }
}

fn set_commands(slot: &CommandSlot, tx: Option<mpsc::Sender<EngineCommand>>) {
    // A poisoned lock only means a panic elsewhere; the slot itself is always valid.
    *slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = tx;
}

fn facts(sh: &Shared) -> Facts {
    Facts {
        logged_in: sh.stored.logged_in,
        want_running: sh.stored.prefs.want_running,
        refused: sh.refused.is_some(),
        live: sh.live,
    }
}

/// Run the engine until stopped; retry failures with backoff; stop retrying when refused.
/// The engine configuration for these preferences.
fn engine_config(p: &Prefs, authkey: Option<String>, opts: &Options) -> EngineConfig {
    EngineConfig {
        login_server: p.control_url.clone(),
        authkey,
        state_file: opts.node_file(),
        hostname: p.hostname.clone(),
        tun: opts.tun.clone(),
        port: opts.port,
        tap_dir: None,
        accept_dns: p.accept_dns,
        accept_routes: p.accept_routes,
        advertise_routes: p.advertise_routes.clone(),
        snat_subnet_routes: p.snat_subnet_routes,
        advertise_tags: p.advertise_tags.clone(),
        shields_up: p.shields_up,
        advertise_exit_node: p.advertise_exit_node,
        stateful_filtering: p.stateful_filtering,
        exit_node: p.exit_node.clone(),
        exit_node_allow_lan_access: p.exit_node_allow_lan_access,
    }
}

/// How long `set`/`up` wait for the running engine to apply new settings before restarting it.
const RECONFIGURE_TIMEOUT: Duration = Duration::from_secs(10);

async fn supervise<L: Launcher>(
    launcher: Arc<L>,
    shared: Arc<Mutex<Shared>>,
    commands: CommandSlot,
    opts: Options,
    mut cfg: EngineConfig,
    mut stop: watch::Receiver<bool>,
) {
    let mut delay = opts.retry_min;
    loop {
        let (status_tx, status_rx) = watch::channel(EngineStatus::default());
        let watcher = tokio::spawn(follow_status(shared.clone(), opts.clone(), status_rx));
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        set_commands(&commands, Some(cmd_tx));
        let result = launcher
            .run(cfg.clone(), status_tx, stop.clone(), cmd_rx)
            .await;
        set_commands(&commands, None);
        watcher.abort();
        // A requested stop is awaited by `stop_engine` while it holds the lock: leave without taking it.
        if *stop.borrow() {
            return;
        }
        let mut sh = tokio::select! {
            g = shared.lock() => g,
            _ = stop.changed() => return,
        };
        sh.live = false;
        match result {
            Ok(()) => return,
            Err(EngineError::NotAuthorized { auth_url, error }) => {
                sh.refused = Some(auth_url);
                sh.errors = if error.is_empty() {
                    Vec::new()
                } else {
                    vec![error]
                };
                if sh.stored.logged_in {
                    sh.stored.logged_in = false;
                    let stored = sh.stored.clone();
                    if let Err(e) = save(&opts.prefs_file(), &stored) {
                        sh.errors.push(e.to_string());
                    }
                }
                return;
            }
            Err(EngineError::Other(e)) => sh.errors = vec![e],
        }
        // Restart with the current preferences (they may have changed while the engine ran, see
        // `reconfigure`); a registered node key no longer needs the auth key.
        cfg = engine_config(&sh.stored.prefs, sh.authkey.clone(), &opts);
        drop(sh);
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = stop.changed() => return,
        }
        delay = (delay * 2).min(opts.retry_max);
    }
}

/// Mirror engine snapshots into the shared state; the first netmap marks the node as logged in.
async fn follow_status(
    shared: Arc<Mutex<Shared>>,
    opts: Options,
    mut rx: watch::Receiver<EngineStatus>,
) {
    while rx.changed().await.is_ok() {
        let snap = rx.borrow_and_update().clone();
        let mut sh = shared.lock().await;
        if snap.self_node.is_some() {
            sh.live = true;
            sh.errors.clear();
            sh.authkey = None;
            if !sh.stored.logged_in {
                sh.stored.logged_in = true;
                let stored = sh.stored.clone();
                if let Err(e) = save(&opts.prefs_file(), &stored) {
                    sh.errors.push(e.to_string());
                }
            }
        }
        sh.snap = snap;
    }
}
