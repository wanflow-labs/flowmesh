// SPDX-License-Identifier: Apache-2.0
//! The daemon over its real unix-socket API, with a fake engine. The command sequences mirror what was
//! observed on the official client (cli.md §1).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use flowmesh_daemon::api;
use flowmesh_daemon::client::{ClientError, LocalClient};
use flowmesh_daemon::daemon::{BoxFut, Daemon, Launcher, Options};
use flowmesh_engine::command::{EngineCommand, PingError, PingPath, PingReply, WhoisReply};
use flowmesh_engine::status::{EngineStatus, PeerStatus};
use flowmesh_engine::{EngineConfig, EngineError};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

const GOOD_KEY: &str = "good-authkey";
const AUTH_URL: &str = "http://h/register/abc";

#[derive(Default)]
struct World {
    registered: bool,
    fail_next: u32,
    runs: u32,
    logouts: u32,
    last_cfg: Option<EngineConfig>,
    /// Runs that ended because the daemon asked them to stop.
    stops: u32,
    logout_fails: bool,
    ping_timeouts: Vec<Duration>,
    logout_state_file: Option<PathBuf>,
    /// Control servers that never answer (the engine keeps trying, no netmap).
    unreachable: Vec<String>,
    /// Settings applied by the running engine without a restart.
    reconfigures: u32,
    /// Answer Reconfigure with an error (the daemon must restart instead).
    refuse_reconfigure: bool,
    /// Make the running engine fail (the daemon's supervisor then restarts it).
    crash: Arc<tokio::sync::Notify>,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<World>>);

/// The fake engine's answers. Ping: 100.64.0.1 answers directly, 100.64.0.2 over DERP,
/// 100.64.0.3 never, anything else is not a peer. Whois: only 100.64.0.1 is known.
fn answer(cmd: EngineCommand) {
    match cmd {
        // Handled in the engine loop below (it needs the world).
        EngineCommand::Reconfigure { .. } => {}
        EngineCommand::Debug { topic, reply } => {
            let _ = reply.send(json!({ "topic": format!("{topic:?}") }));
        }
        EngineCommand::Whois { ip, reply } => {
            let found = (ip.to_string() == "100.64.0.1").then(|| WhoisReply {
                node: flowmesh_proto::control::Node {
                    id: 1,
                    name: "ts1.mesh.lab.internal.".into(),
                    ..Default::default()
                },
                user_profile: None,
                cap_map: [("tailscale.com/cap/relay".to_string(), Value::Null)].into(),
            });
            let _ = reply.send(found);
        }
        EngineCommand::Ping { ip, reply, .. } => {
            let via = match ip.to_string().as_str() {
                "100.64.0.1" => Some(PingPath::Direct("172.29.0.21:41641".parse().unwrap())),
                "100.64.0.2" => Some(PingPath::Derp {
                    region: 1000,
                    code: "r1000".into(),
                }),
                _ => None,
            };
            let result = match (ip.to_string().as_str(), via) {
                ("100.64.0.3", _) => Err(PingError::Timeout),
                (_, Some(via)) => Ok(PingReply {
                    node_ip: ip,
                    node_name: "peer".into(),
                    via,
                    latency: Duration::from_millis(3),
                }),
                (_, None) => Err(PingError::NoPeer),
            };
            let _ = reply.send(result);
        }
    }
}

impl Launcher for Fake {
    fn run(
        &self,
        cfg: EngineConfig,
        status: watch::Sender<EngineStatus>,
        mut stop: watch::Receiver<bool>,
        mut commands: tokio::sync::mpsc::Receiver<EngineCommand>,
    ) -> BoxFut<Result<(), EngineError>> {
        let world = self.0.clone();
        Box::pin(async move {
            let publish = {
                let mut w = world.lock().unwrap();
                w.runs += 1;
                w.last_cfg = Some(cfg.clone());
                if w.fail_next > 0 {
                    w.fail_next -= 1;
                    return Err(EngineError::Other("control connect: refused".into()));
                }
                if !w.unreachable.contains(&cfg.login_server) && !w.registered {
                    if cfg.authkey.as_deref() == Some(GOOD_KEY) {
                        w.registered = true;
                    } else {
                        return Err(EngineError::NotAuthorized {
                            auth_url: AUTH_URL.into(),
                            error: String::new(),
                        });
                    }
                }
                !w.unreachable.contains(&cfg.login_server)
            };
            if publish {
                let _ = status.send(EngineStatus {
                    self_node: Some(PeerStatus {
                        public_key: "nodekey:aa".into(),
                        host_name: cfg.hostname.clone(),
                        ..Default::default()
                    }),
                    peers: vec![PeerStatus {
                        public_key: "nodekey:bb".into(),
                        ..Default::default()
                    }],
                    magic_dns_suffix: "mesh.lab.internal".into(),
                    tailnet_name: "lab".into(),
                    health: Vec::new(),
                    relay_mode: "auto".into(),
                });
            }
            let crash = world.lock().unwrap().crash.clone();
            loop {
                tokio::select! {
                    r = stop.changed() => if r.is_err() || *stop.borrow() { break },
                    _ = crash.notified() => return Err(EngineError::Other("engine crashed".into())),
                    Some(cmd) = commands.recv() => {
                        if let EngineCommand::Reconfigure { cfg, reply } = cmd {
                            let mut w = world.lock().unwrap();
                            if w.refuse_reconfigure {
                                let _ = reply.send(Err("this change needs a restart".into()));
                            } else {
                                w.reconfigures += 1;
                                w.last_cfg = Some(*cfg);
                                let _ = reply.send(Ok(()));
                            }
                            continue;
                        }
                        if let EngineCommand::Ping { timeout, .. } = &cmd {
                            world.lock().unwrap().ping_timeouts.push(*timeout);
                        }
                        answer(cmd)
                    }
                }
            }
            world.lock().unwrap().stops += 1;
            Ok(())
        })
    }

    fn logout(&self, _login_server: String, state_file: PathBuf) -> BoxFut<Result<(), String>> {
        let world = self.0.clone();
        Box::pin(async move {
            let mut w = world.lock().unwrap();
            w.logout_state_file = Some(state_file);
            if w.logout_fails {
                return Err("control connect: refused".to_string());
            }
            w.logouts += 1;
            w.registered = false;
            Ok(())
        })
    }
}

struct Harness {
    dir: PathBuf,
    fake: Fake,
    daemon: Arc<Daemon<Fake>>,
    client: LocalClient,
    _stop: watch::Sender<bool>,
}

fn temp_dir(name: &str) -> PathBuf {
    // Keep it short: unix socket paths are limited to ~100 bytes.
    let dir = std::env::temp_dir().join(format!("fmd-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn start(dir: PathBuf, fake: Fake) -> Harness {
    let mut opts = Options::new(dir.clone());
    opts.retry_min = Duration::from_millis(10);
    opts.retry_max = Duration::from_millis(40);
    let daemon = Arc::new(Daemon::start(fake.clone(), opts).await.unwrap());
    let sock = dir.join("s.sock");
    let (listener, uid) = api::bind(&sock).unwrap();
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(api::serve(daemon.clone(), listener, uid, stop_rx));
    Harness {
        dir,
        fake,
        daemon,
        client: LocalClient::new(sock),
        _stop: stop_tx,
    }
}

impl Harness {
    async fn status(&self) -> Value {
        self.client.get("status").await.unwrap()
    }

    async fn wait_state(&self, want: &str) -> Value {
        let mut last = Value::Null;
        for _ in 0..300 {
            last = self.status().await;
            if last["BackendState"] == want {
                return last;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("never reached {want}; last status: {last}");
    }

    async fn up(&self, body: Value) -> Result<Value, ClientError> {
        self.client.post("up", &body).await
    }

    fn stored(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.dir.join("prefs.json")).unwrap()).unwrap()
    }
}

fn full_flags() -> Value {
    json!({ "control_url": "http://h", "hostname": "fm1", "accept_dns": false })
}

fn api_error(r: Result<Value, ClientError>) -> (u16, String) {
    match r {
        Err(ClientError::Api { status, message }) => (status.as_u16(), message),
        other => panic!("expected an API error, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_matches_official_transitions() {
    let h = start(temp_dir("life"), Fake::default()).await;
    assert_eq!(h.status().await["BackendState"], "NeedsLogin");

    let (code, msg) = api_error(h.up(json!({})).await);
    assert_eq!(code, 400);
    assert!(msg.contains("--login-server"), "{msg}");

    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    let s = h.wait_state("Running").await;
    assert_eq!(s["Self"]["PublicKey"], "nodekey:aa");
    assert_eq!(s["HaveNodeKey"], true);
    let mode = std::fs::metadata(h.dir.join("prefs.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let raw = std::fs::read_to_string(h.dir.join("prefs.json")).unwrap();
    assert!(
        !raw.contains(GOOD_KEY),
        "the auth key must never reach disk"
    );
    assert_eq!(h.stored()["logged_in"], true);

    h.client.post("down", &json!({})).await.unwrap();
    let s = h.wait_state("Stopped").await;
    assert!(s["Peer"].is_object(), "the last netmap is kept after down");
    assert_eq!(s["Health"], json!(["flowmesh is stopped."]));

    let (code, msg) = api_error(h.up(json!({})).await);
    assert_eq!(code, 400);
    assert!(
        msg.contains("flowmesh up --login-server=http://h --hostname=fm1 --accept-dns=false"),
        "{msg}"
    );
    assert_eq!(h.status().await["BackendState"], "Stopped");

    h.up(json!({ "update": full_flags() })).await.unwrap();
    h.wait_state("Running").await;

    h.client.post("logout", &json!({})).await.unwrap();
    let s = h.wait_state("NeedsLogin").await;
    assert_eq!(h.fake.0.lock().unwrap().logouts, 1);
    assert_eq!(s["Peer"], Value::Null);
    assert_eq!(
        s["Self"]["PublicKey"],
        flowmesh_daemon::status_json::ZERO_NODE_KEY
    );
    assert_eq!(h.stored()["logged_in"], false);
    assert_eq!(
        h.stored()["prefs"]["control_url"],
        "",
        "logout resets preferences"
    );
    assert_eq!(h.stored()["prefs"]["accept_dns"], true);

    // Logged out: a bare up has no control server to go to.
    let (code, msg) = api_error(h.up(json!({})).await);
    assert_eq!(code, 400);
    assert!(msg.contains("--login-server"), "{msg}");

    // Fewer flags than before are fine after logout, but the control server refuses without a key.
    h.up(json!({ "update": full_flags() })).await.unwrap();
    let s = h.wait_state("NeedsLogin").await;
    assert_eq!(s["AuthURL"], AUTH_URL);

    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    let s = h.wait_state("Running").await;
    assert_eq!(s["AuthURL"], "");
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_restores_the_wanted_state() {
    let dir = temp_dir("restart");
    let h = start(dir.clone(), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    h.daemon.shutdown().await;
    let fake = h.fake.clone();
    drop(h);

    // The node key is registered; a fresh daemon comes back up on its own, without an auth key.
    let h = start(dir.clone(), fake).await;
    h.wait_state("Running").await;
    assert_eq!(
        h.fake.0.lock().unwrap().last_cfg.as_ref().unwrap().authkey,
        None
    );
    h.client.post("down", &json!({})).await.unwrap();
    h.daemon.shutdown().await;
    let fake = h.fake.clone();
    drop(h);

    let h = start(dir, fake).await;
    assert_eq!(h.status().await["BackendState"], "Stopped");
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_failures_are_retried_and_reported() {
    let fake = Fake::default();
    fake.0.lock().unwrap().fail_next = 2;
    let h = start(temp_dir("retry"), fake).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    let s = h.wait_state("Running").await;
    assert_eq!(
        s["Health"],
        json!([]),
        "errors clear once the netmap arrives"
    );
    assert_eq!(h.fake.0.lock().unwrap().runs, 3);
    // The retries still carried the auth key (registration had not happened yet).
    assert_eq!(h.stored()["logged_in"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn failure_is_visible_while_starting() {
    let fake = Fake::default();
    fake.0.lock().unwrap().fail_next = u32::MAX;
    let h = start(temp_dir("starting"), fake).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    let mut seen = Value::Null;
    for _ in 0..300 {
        seen = h.status().await;
        if seen["Health"] == json!(["control connect: refused"]) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(seen["BackendState"], "Starting");
    assert_eq!(seen["Health"], json!(["control connect: refused"]));
    h.client.post("down", &json!({})).await.unwrap();
    // Never registered: down leads to NeedsLogin, not Stopped.
    assert_eq!(h.status().await["BackendState"], "NeedsLogin");
}

#[tokio::test(flavor = "multi_thread")]
async fn set_changes_only_given_fields_and_applies_them_live() {
    let h = start(temp_dir("set"), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    let runs = h.fake.0.lock().unwrap().runs;

    h.client
        .post("set", &json!({ "accept_routes": true }))
        .await
        .unwrap();
    let prefs = h.client.get("prefs").await.unwrap();
    assert_eq!(prefs["accept_routes"], true);
    assert_eq!(prefs["hostname"], "fm1");
    {
        let w = h.fake.0.lock().unwrap();
        assert_eq!(
            (w.runs, w.reconfigures),
            (runs, 1),
            "applied by the running engine"
        );
        assert!(w.last_cfg.as_ref().unwrap().accept_routes);
    }

    // No change: nothing sent.
    h.client
        .post("set", &json!({ "accept_routes": true }))
        .await
        .unwrap();
    assert_eq!(h.fake.0.lock().unwrap().reconfigures, 1);

    // While stopped, set only records the preference.
    h.client.post("down", &json!({})).await.unwrap();
    h.client
        .post("set", &json!({ "hostname": "fm9" }))
        .await
        .unwrap();
    {
        let w = h.fake.0.lock().unwrap();
        assert_eq!((w.runs, w.reconfigures), (runs, 1));
    }
    assert_eq!(h.status().await["BackendState"], "Stopped");
}

#[tokio::test(flavor = "multi_thread")]
async fn switching_control_server_forgets_the_login() {
    let fake = Fake::default();
    fake.0.lock().unwrap().unreachable = vec!["http://b".into(), "http://c".into()];
    let h = start(temp_dir("switch"), fake).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;

    h.up(json!({ "update": { "control_url": "http://b" }, "reset": true }))
        .await
        .unwrap();
    assert_eq!(h.stored()["logged_in"], false);
    h.client.post("down", &json!({})).await.unwrap();
    assert_eq!(h.status().await["BackendState"], "NeedsLogin");

    // Same through set.
    h.up(json!({ "update": { "control_url": "http://h" }, "reset": true, "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    h.client
        .post("set", &json!({ "control_url": "http://c" }))
        .await
        .unwrap();
    assert_eq!(h.stored()["logged_in"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn changes_need_privilege_reads_do_not() {
    use http_body_util::Full;
    use hyper::body::Bytes;
    let h = start(temp_dir("priv"), Fake::default()).await;
    for name in ["up", "down", "logout", "set"] {
        let req = hyper::Request::post(format!("/localapi/v0/{name}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = api::handle(&h.daemon, req, false).await;
        assert_eq!(resp.status(), 403, "{name}");
    }
    let req = hyper::Request::get("/localapi/v0/status")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(api::handle(&h.daemon, req, false).await.status(), 200);
    let req = hyper::Request::get("/localapi/v0/prefs")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(api::handle(&h.daemon, req, false).await.status(), 200);
    let req = hyper::Request::get("/other")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(api::handle(&h.daemon, req, true).await.status(), 404);
    let req = hyper::Request::post("/localapi/v0/up")
        .body(Full::new(Bytes::from_static(b"{not json")))
        .unwrap();
    assert_eq!(api::handle(&h.daemon, req, true).await.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_and_logout_use_the_node_key_file() {
    let h = start(temp_dir("nodefile"), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    h.client.post("logout", &json!({})).await.unwrap();
    let w = h.fake.0.lock().unwrap();
    let node = h.dir.join("node.json");
    assert_eq!(w.last_cfg.as_ref().unwrap().state_file, node);
    assert_eq!(w.logout_state_file.as_ref().unwrap(), &node);
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_stops_the_engine_but_keeps_prefs() {
    let h = start(temp_dir("shutdown"), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    h.daemon.shutdown().await;
    assert_eq!(h.fake.0.lock().unwrap().stops, 1);
    assert_eq!(h.stored()["prefs"]["want_running"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_delay_doubles() {
    let fake = Fake::default();
    fake.0.lock().unwrap().fail_next = 3;
    let dir = temp_dir("backoff");
    let mut opts = Options::new(dir.clone());
    opts.retry_min = Duration::from_millis(40);
    opts.retry_max = Duration::from_secs(5);
    let daemon = Daemon::start(fake.clone(), opts).await.unwrap();
    let t0 = std::time::Instant::now();
    daemon
        .up(serde_json::from_value(json!({ "update": full_flags(), "authkey": GOOD_KEY })).unwrap())
        .await
        .unwrap();
    for _ in 0..1000 {
        if fake.0.lock().unwrap().runs >= 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(fake.0.lock().unwrap().runs, 4);
    // 40 + 80 + 160 ms; sleeps are never shorter than asked, so this lower bound is not flaky.
    assert!(
        t0.elapsed() >= Duration::from_millis(280),
        "{:?}",
        t0.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unreadable_prefs_refuse_to_start() {
    let dir = temp_dir("badprefs");
    std::fs::create_dir_all(dir.join("prefs.json")).unwrap();
    assert!(
        Daemon::start(Fake::default(), Options::new(dir))
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_prefs_are_moved_aside_and_defaults_used() {
    let dir = temp_dir("corrupt");
    std::fs::write(dir.join("prefs.json"), b"{\"prefs\": {\"control_u").unwrap();
    let h = start(dir.clone(), Fake::default()).await;
    assert_eq!(h.status().await["BackendState"], "NeedsLogin");
    let aside = flowmesh_daemon::daemon::quarantine_path(&dir.join("prefs.json"));
    assert_eq!(std::fs::read(&aside).unwrap(), b"{\"prefs\": {\"control_u");
    assert!(!dir.join("prefs.json").exists());
    // And it is usable right away.
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
}

#[test]
fn bind_replaces_only_a_stale_socket() {
    let dir = temp_dir("bind");
    let file = dir.join("f.sock");
    std::fs::write(&file, b"keep me").unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        assert!(api::bind(&file).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
        let sock = dir.join("s.sock");
        let first = api::bind(&sock).unwrap();
        drop(first);
        let (_l, _uid) = api::bind(&sock).unwrap();
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o666);
    });
}

#[test]
fn privilege_rule() {
    assert!(api::is_privileged(Some(0), 1000));
    assert!(api::is_privileged(Some(1000), 1000));
    assert!(!api::is_privileged(Some(1001), 1000));
    assert!(!api::is_privileged(None, 1000));
}

#[tokio::test(flavor = "multi_thread")]
async fn request_body_limit() {
    use http_body_util::Full;
    use hyper::body::Bytes;
    let h = start(temp_dir("limit"), Fake::default()).await;
    let body = json!({ "update": full_flags(), "authkey": GOOD_KEY }).to_string();
    let padded = format!("{body}{}", " ".repeat(8 * 1024));
    let req = hyper::Request::post("/localapi/v0/up")
        .body(Full::new(Bytes::from(padded)))
        .unwrap();
    assert_eq!(api::handle(&h.daemon, req, true).await.status(), 200);
    let huge = format!("{body}{}", " ".repeat(api::MAX_BODY));
    let req = hyper::Request::post("/localapi/v0/up")
        .body(Full::new(Bytes::from(huge)))
        .unwrap();
    assert_eq!(api::handle(&h.daemon, req, true).await.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn advertised_routes_and_snat_reach_the_engine() {
    let h = start(temp_dir("advroutes"), Fake::default()).await;
    let mut flags = full_flags();
    flags["advertise_routes"] = json!(["10.99.0.0/24"]);
    h.up(json!({ "update": flags, "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    {
        let w = h.fake.0.lock().unwrap();
        let cfg = w.last_cfg.as_ref().unwrap();
        assert_eq!(
            cfg.advertise_routes,
            vec!["10.99.0.0/24".parse::<ipnet::IpNet>().unwrap()]
        );
        assert!(cfg.snat_subnet_routes, "SNAT is on by default");
    }
    h.client
        .post("set", &json!({ "snat_subnet_routes": false }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    let w = h.fake.0.lock().unwrap();
    assert!(!w.last_cfg.as_ref().unwrap().snat_subnet_routes);
}

/// `set` and `up` change settings in the running engine, like the official client: no restart,
/// the engine gets the new configuration (OBS-20261011-set-live).
#[tokio::test(flavor = "multi_thread")]
async fn settings_change_without_restarting_the_engine() {
    let h = start(temp_dir("liveset"), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    let runs = h.fake.0.lock().unwrap().runs;
    h.client
        .post("set", &json!({ "shields_up": true }))
        .await
        .unwrap();
    h.client
        .post("set", &json!({ "advertise_routes": ["10.99.0.0/24"] }))
        .await
        .unwrap();
    let mut flags = full_flags();
    flags["shields_up"] = json!(true);
    flags["advertise_routes"] = json!(["10.99.0.0/24"]);
    flags["accept_routes"] = json!(true);
    h.up(json!({ "update": flags })).await.unwrap();
    let w = h.fake.0.lock().unwrap();
    assert_eq!(w.runs, runs, "no restart");
    assert_eq!(w.reconfigures, 3);
    let cfg = w.last_cfg.as_ref().unwrap();
    assert!(cfg.shields_up && cfg.accept_routes);
    assert_eq!(
        cfg.advertise_routes,
        vec!["10.99.0.0/24".parse::<ipnet::IpNet>().unwrap()]
    );
}

/// When the engine cannot apply a change live, the daemon restarts it with the new settings.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_live_change_restarts_the_engine() {
    let h = start(temp_dir("liverefused"), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    let runs = {
        let mut w = h.fake.0.lock().unwrap();
        w.refuse_reconfigure = true;
        w.runs
    };
    h.client
        .post("set", &json!({ "shields_up": true }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    let w = h.fake.0.lock().unwrap();
    assert_eq!(w.runs, runs + 1, "restarted");
    assert!(w.last_cfg.as_ref().unwrap().shields_up);
}

/// A live change must survive the engine's next automatic restart: the supervisor restarts it
/// with the current preferences, not the configuration it was first started with.
#[tokio::test(flavor = "multi_thread")]
async fn a_restart_after_a_live_change_keeps_the_change() {
    let h = start(temp_dir("livekeep"), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    h.client
        .post("set", &json!({ "shields_up": true }))
        .await
        .unwrap();
    let (runs, crash) = {
        let w = h.fake.0.lock().unwrap();
        (w.runs, w.crash.clone())
    };
    crash.notify_one();
    for _ in 0..200 {
        if h.fake.0.lock().unwrap().runs > runs {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let w = h.fake.0.lock().unwrap();
    assert_eq!(w.runs, runs + 1, "the supervisor restarted the engine");
    assert!(
        w.last_cfg.as_ref().unwrap().shields_up,
        "with the live change, not the start-up settings"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_needs_the_control_server() {
    let h = start(temp_dir("logoutfail"), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    h.fake.0.lock().unwrap().logout_fails = true;
    let (code, msg) = api_error(h.client.post("logout", &json!({})).await);
    assert_eq!(code, 502);
    assert!(msg.contains("control connect: refused"), "{msg}");
    // Same as observed on the official client: stopped, still logged in, preferences kept.
    assert_eq!(h.status().await["BackendState"], "Stopped");
    assert_eq!(h.stored()["logged_in"], true);
    assert_eq!(h.stored()["prefs"]["control_url"], "http://h");

    h.fake.0.lock().unwrap().logout_fails = false;
    h.client.post("logout", &json!({})).await.unwrap();
    assert_eq!(h.status().await["BackendState"], "NeedsLogin");
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_when_never_logged_in_does_not_call_the_server() {
    let h = start(temp_dir("logoutnone"), Fake::default()).await;
    h.client.post("logout", &json!({})).await.unwrap();
    assert_eq!(h.fake.0.lock().unwrap().logouts, 0);
    assert_eq!(h.status().await["BackendState"], "NeedsLogin");

    // A control server is configured but refused the node: its key was never registered, so there
    // is nothing to expire there.
    h.up(json!({ "update": full_flags() })).await.unwrap();
    h.wait_state("NeedsLogin").await;
    assert_eq!(h.stored()["prefs"]["control_url"], "http://h");
    h.client.post("logout", &json!({})).await.unwrap();
    assert_eq!(h.fake.0.lock().unwrap().logouts, 0);
    assert_eq!(h.stored()["prefs"]["control_url"], "");
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_reports_official_fields() {
    let h = start(temp_dir("ping"), Fake::default()).await;
    let (code, msg) = api_error(h.client.post("ping", &json!({ "ip": "100.64.0.1" })).await);
    assert_eq!((code, msg.as_str()), (503, "flowmesh is not running"));

    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    let d = h
        .client
        .post("ping", &json!({ "ip": "100.64.0.1" }))
        .await
        .unwrap();
    assert_eq!(d["Err"], "");
    assert_eq!(d["Endpoint"], "172.29.0.21:41641");
    assert_eq!(d["DERPRegionID"], 0);
    assert_eq!(d["NodeName"], "peer");
    assert_eq!(d["NodeIP"], "100.64.0.1");
    assert!((d["LatencySeconds"].as_f64().unwrap() - 0.003).abs() < 1e-9);
    let r = h
        .client
        .post("ping", &json!({ "ip": "100.64.0.2" }))
        .await
        .unwrap();
    assert_eq!(
        (r["Endpoint"].as_str(), r["DERPRegionID"].as_u64()),
        (Some(""), Some(1000))
    );
    assert_eq!(r["DERPRegionCode"], "r1000");
    let t = h
        .client
        .post("ping", &json!({ "ip": "100.64.0.3" }))
        .await
        .unwrap();
    assert_eq!(t["Err"], "timed out");
    let n = h
        .client
        .post("ping", &json!({ "ip": "100.64.9.9" }))
        .await
        .unwrap();
    assert_eq!(n["Err"], "no matching peer");

    let (code, _) = api_error(h.client.post("ping", &json!({ "ip": "not-an-ip" })).await);
    assert_eq!(code, 400);
    // Like status, ping is open to every local user.
    use http_body_util::Full;
    use hyper::body::Bytes;
    let req = hyper::Request::post("/localapi/v0/ping")
        .body(Full::new(Bytes::from_static(br#"{"ip":"100.64.0.1"}"#)))
        .unwrap();
    assert_eq!(api::handle(&h.daemon, req, false).await.status(), 200);

    h.client.post("down", &json!({})).await.unwrap();
    let (code, _) = api_error(h.client.post("ping", &json!({ "ip": "100.64.0.1" })).await);
    assert_eq!(code, 503);
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_timeout_default_and_clamp() {
    let h = start(temp_dir("pingtimeout"), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    for body in [
        json!({ "ip": "100.64.0.1" }),
        json!({ "ip": "100.64.0.1", "timeout_ms": 1500 }),
        json!({ "ip": "100.64.0.1", "timeout_ms": 0 }),
        json!({ "ip": "100.64.0.1", "timeout_ms": 999_999 }),
    ] {
        h.client.post("ping", &body).await.unwrap();
    }
    let ms: Vec<u128> = h
        .fake
        .0
        .lock()
        .unwrap()
        .ping_timeouts
        .iter()
        .map(|d| d.as_millis())
        .collect();
    assert_eq!(ms, [5000, 1500, 1000, 60_000]);
}

#[tokio::test(flavor = "multi_thread")]
async fn debug_views_are_root_only() {
    use http_body_util::Full;
    use hyper::body::Bytes;
    let h = start(temp_dir("debug"), Fake::default()).await;
    let (code, _) = api_error(h.client.get("debug?topic=paths").await);
    assert_eq!(code, 503, "not running");
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    for (t, want) in [
        ("netmap", "Netmap"),
        ("paths", "Paths"),
        ("filter", "Filter"),
        ("derp", "Derp"),
    ] {
        let v = h.client.get(&format!("debug?topic={t}")).await.unwrap();
        assert_eq!(v["topic"], want);
    }
    let (code, msg) = api_error(h.client.get("debug?topic=prefs").await);
    assert_eq!(code, 400);
    assert!(msg.contains("unknown debug topic"), "{msg}");
    let (code, _) = api_error(h.client.get("debug").await);
    assert_eq!(code, 400);
    let req = hyper::Request::get("/localapi/v0/debug?topic=netmap")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(api::handle(&h.daemon, req, false).await.status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_derpmap_and_metrics_are_open_to_every_user() {
    use http_body_util::Full;
    use hyper::body::Bytes;
    let h = start(temp_dir("openviews"), Fake::default()).await;
    let (code, _) = api_error(h.client.get("metrics").await);
    assert_eq!(code, 503, "not running");
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    for (name, want) in [
        ("dns", "Dns"),
        ("derpmap", "DerpMap"),
        ("metrics", "Metrics"),
    ] {
        let req = hyper::Request::get(format!("/localapi/v0/{name}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = api::handle(&h.daemon, req, false).await;
        assert_eq!(resp.status(), 200, "{name}");
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["topic"], want);
    }
}

/// The operator (`--operator`) may change settings and read debug views without root, but not
/// name another operator; everyone else stays read-only.
#[tokio::test(flavor = "multi_thread")]
async fn operator_may_change_settings_but_not_the_operator() {
    use http_body_util::Full;
    use hyper::body::Bytes;
    let me = nix::unistd::getuid();
    let name = nix::unistd::User::from_uid(me).unwrap().unwrap().name;
    let h = start(temp_dir("operator"), Fake::default()).await;
    let mut flags = full_flags();
    flags["operator_user"] = json!(name);
    h.up(json!({ "update": flags, "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    assert_eq!(
        h.client.get("prefs").await.unwrap()["operator_user"],
        json!(name)
    );
    let call = |path: &str, body: serde_json::Value, uid: u32| {
        let req = hyper::Request::post(format!("/localapi/v0/{path}"))
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        let d = h.daemon.clone();
        async move {
            api::handle(
                &d,
                req,
                api::Caller {
                    root: false,
                    uid: Some(uid),
                },
            )
            .await
            .status()
        }
    };
    let op = me.as_raw();
    let other = op.wrapping_add(4242);
    assert_eq!(call("set", json!({ "shields_up": true }), op).await, 200);
    assert_eq!(
        call("set", json!({ "shields_up": false }), other).await,
        403
    );
    // Naming the current operator again is no change; naming someone else needs root.
    assert_eq!(call("set", json!({ "operator_user": name }), op).await, 200);
    assert_eq!(
        call("set", json!({ "operator_user": "someone-else" }), op).await,
        403
    );
    assert_eq!(call("set", json!({ "operator_user": "" }), op).await, 403);
    let mut reset = full_flags();
    reset.as_object_mut().unwrap().remove("operator_user");
    assert_eq!(
        call("up", json!({ "update": reset, "reset": true }), op).await,
        403
    );
    let req = hyper::Request::get("/localapi/v0/debug?topic=paths")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = api::handle(
        &h.daemon,
        req,
        api::Caller {
            root: false,
            uid: Some(op),
        },
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        h.client.get("prefs").await.unwrap()["shields_up"],
        json!(true)
    );
}

/// `--ssh` is stored only by a build that has the SSH server; one without refuses it instead of
/// keeping a setting that would do nothing.
#[tokio::test(flavor = "multi_thread")]
async fn ssh_setting_follows_the_build() {
    let h = start(temp_dir("sshfeature"), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    let r = h.client.post("set", &json!({ "run_ssh": true })).await;
    if cfg!(feature = "ssh") {
        r.unwrap();
        assert_eq!(h.client.get("prefs").await.unwrap()["run_ssh"], json!(true));
    } else {
        let (code, msg) = api_error(r);
        assert_eq!(code, 400);
        assert!(msg.contains("built without SSH support"), "{msg}");
        assert_eq!(
            h.client.get("prefs").await.unwrap()["run_ssh"],
            json!(false)
        );
        let (code, _) = api_error(
            h.up(json!({ "update": { "control_url": "http://h", "hostname": "fm1", "accept_dns": false, "run_ssh": true } }))
                .await,
        );
        assert_eq!(code, 400);
    }
}

/// `serve`: the background configuration is stored (and survives a restart of the daemon),
/// foreground ones live while renewed, HTTPS is refused, and only root/operator may change it.
#[tokio::test(flavor = "multi_thread")]
async fn serve_configuration() {
    use http_body_util::Full;
    use hyper::body::Bytes;
    let dir = temp_dir("serve");
    let h = start(dir.clone(), Fake::default()).await;
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    assert_eq!(h.client.get("serve").await.unwrap(), json!({}));
    let bg = json!({
        "TCP": { "80": { "HTTP": true } },
        "Web": { "fm1.mesh:80": { "Handlers": { "/": { "Proxy": "http://127.0.0.1:3000" } } } }
    });
    h.client.post("serve", &bg).await.unwrap();
    assert_eq!(h.client.get("serve").await.unwrap(), bg);
    // HTTPS needs certificates the control server does not issue.
    let (code, msg) = api_error(
        h.client
            .post("serve", &json!({ "TCP": { "443": { "HTTPS": true } } }))
            .await,
    );
    assert_eq!(code, 400);
    assert!(msg.contains("certificates"), "{msg}");
    // A foreground configuration is not part of the stored one, and goes when stopped.
    let fg =
        json!({ "id": "cli-1", "config": { "TCP": { "2222": { "TCPForward": "127.0.0.1:22" } } } });
    h.client.post("serve-foreground", &fg).await.unwrap();
    assert_eq!(h.client.get("serve").await.unwrap(), bg);
    h.client
        .post("serve-foreground-stop", &json!({ "id": "cli-1" }))
        .await
        .unwrap();
    // Not root, not the operator: refused.
    let req = hyper::Request::post("/localapi/v0/serve")
        .body(Full::new(Bytes::from("{}")))
        .unwrap();
    assert_eq!(api::handle(&h.daemon, req, false).await.status(), 403);
    let req = hyper::Request::get("/localapi/v0/serve")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(api::handle(&h.daemon, req, false).await.status(), 200);
    // The daemon holds configurations to the CLI's rules (they can arrive without the CLI), and
    // only root may make it serve files, directories or Unix sockets with its rights.
    let (code, msg) = api_error(
        h.client
            .post("serve", &json!({ "TCP": { "80": { "HTTP": true } }, "Web": { "fm1.mesh:80": { "Handlers": { "/": { "Proxy": "http://10.0.0.5:80" } } } } }))
            .await,
    );
    assert_eq!(code, 400, "{msg}");
    let me = nix::unistd::getuid();
    let name = nix::unistd::User::from_uid(me).unwrap().unwrap().name;
    h.client
        .post("set", &json!({ "operator_user": name }))
        .await
        .unwrap();
    let as_operator = |path: &'static str, body: serde_json::Value| {
        let d = h.daemon.clone();
        async move {
            let req = hyper::Request::post(format!("/localapi/v0/{path}"))
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            api::handle(
                &d,
                req,
                api::Caller {
                    root: false,
                    uid: Some(me.as_raw()),
                },
            )
            .await
            .status()
        }
    };
    let files = json!({ "TCP": { "80": { "HTTP": true } }, "Web": { "fm1.mesh:80": { "Handlers": { "/": { "Path": "/etc" } } } } });
    assert_eq!(as_operator("serve", files.clone()).await, 403);
    assert_eq!(
        as_operator(
            "serve-foreground",
            json!({ "id": "x", "config": files.clone() })
        )
        .await,
        403
    );
    let sock = json!({ "TCP": { "80": { "HTTP": true } }, "Web": { "fm1.mesh:80": { "Handlers": { "/": { "Proxy": "unix:/var/run/docker.sock" } } } } });
    assert_eq!(as_operator("serve", sock).await, 403);
    // Root adds a directory; the operator may then add a proxy beside it, keeping it.
    h.client.post("serve", &files).await.unwrap();
    let both = json!({ "TCP": { "80": { "HTTP": true } }, "Web": { "fm1.mesh:80": { "Handlers": { "/": { "Path": "/etc" }, "/app": { "Proxy": "http://127.0.0.1:3000" } } } } });
    assert_eq!(as_operator("serve", both.clone()).await, 200);
    // …but not point it elsewhere.
    let moved = json!({ "TCP": { "80": { "HTTP": true } }, "Web": { "fm1.mesh:80": { "Handlers": { "/": { "Path": "/root" } } } } });
    assert_eq!(as_operator("serve", moved).await, 403);
    h.client.post("serve", &bg).await.unwrap();
    // Persisted with the preferences.
    let stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("prefs.json")).unwrap()).unwrap();
    assert_eq!(stored["serve"], bg);
}

#[test]
fn operator_change_rule() {
    assert!(!api::changes_operator("alice", Some("alice"), false));
    assert!(api::changes_operator("alice", Some("bob"), false));
    assert!(api::changes_operator("", Some("bob"), false));
    assert!(!api::changes_operator("alice", None, false));
    assert!(api::changes_operator("alice", None, true));
    assert!(!api::changes_operator("", None, true));
    assert!(!api::is_operator(Some(0), ""));
    assert!(!api::is_operator(None, "root"));
    assert!(api::is_operator(Some(0), "root"));
}

#[tokio::test(flavor = "multi_thread")]
async fn whois_by_address_forms() {
    let h = start(temp_dir("whois"), Fake::default()).await;
    let (code, _) = api_error(h.client.get("whois?addr=100.64.0.1").await);
    assert_eq!(code, 503, "not running yet");
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    for q in ["100.64.0.1", "100.64.0.1:22", "100.64.0.1%3A22"] {
        let w = h.client.get(&format!("whois?addr={q}")).await.unwrap();
        assert_eq!(w["Node"]["ID"], 1, "{q}");
        assert_eq!(w["Node"]["Name"], "ts1.mesh.lab.internal.");
        assert_eq!(w["UserProfile"], Value::Null);
        assert_eq!(w["CapMap"], json!({ "tailscale.com/cap/relay": null }));
    }
    let (code, msg) = api_error(h.client.get("whois?addr=100.64.99.99").await);
    assert_eq!((code, msg.as_str()), (404, "peer not found"));
    for bad in [
        "whois?addr=notanip",
        "whois",
        "whois?other=1",
        "whois?addr=%zz",
    ] {
        let (code, msg) = api_error(h.client.get(bad).await);
        assert_eq!(
            (code, msg.as_str()),
            (400, "invalid 'addr' parameter"),
            "{bad}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_services_learn_callers_from_the_netmap() {
    use flowmesh_meshsvc::Directory;
    let h = start(temp_dir("directory"), Fake::default()).await;
    let dir = flowmesh_daemon::directory::DaemonDirectory(h.daemon.clone());
    let known: std::net::SocketAddr = "100.64.0.1:40000".parse().unwrap();
    assert_eq!(
        dir.caller(known).await,
        None,
        "not running: nobody can be named"
    );
    h.up(json!({ "update": full_flags(), "authkey": GOOD_KEY }))
        .await
        .unwrap();
    h.wait_state("Running").await;
    let c = dir.caller(known).await.unwrap();
    assert_eq!(
        (c.node_id, c.node_name.as_str(), c.addr),
        (1, "ts1.mesh.lab.internal", known)
    );
    assert!(c.has_cap("tailscale.com/cap/relay"));
    assert_eq!(dir.caller("100.64.99.99:1".parse().unwrap()).await, None);
}

#[test]
fn whois_addr_parsing() {
    let q = |s: &str| api::query_addr(Some(s)).map(|ip| ip.to_string());
    assert_eq!(
        q("addr=fd7a:115c:a1e0::1").as_deref(),
        Some("fd7a:115c:a1e0::1")
    );
    assert_eq!(
        q("addr=%5Bfd7a:115c:a1e0::1%5D:22").as_deref(),
        Some("fd7a:115c:a1e0::1")
    );
    assert_eq!(q("x=1&addr=100.64.0.1").as_deref(), Some("100.64.0.1"));
    assert_eq!(q("addr=100.64.0.1%"), None, "truncated escape");
    assert_eq!(api::query_addr(None), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_daemon_is_a_clear_error() {
    let c = LocalClient::new(temp_dir("nodaemon").join("s.sock"));
    let e = c.get("status").await.unwrap_err();
    assert!(e.to_string().contains("is the daemon running?"), "{e}");
}
