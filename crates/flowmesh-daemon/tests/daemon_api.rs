// SPDX-License-Identifier: Apache-2.0
//! The daemon over its real unix-socket API, with a fake engine. The command sequences mirror what was
//! observed on the official client (cli.md §1).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use flowmesh_daemon::api;
use flowmesh_daemon::client::{ClientError, LocalClient};
use flowmesh_daemon::daemon::{BoxFut, Daemon, Launcher, Options};
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
    logout_state_file: Option<PathBuf>,
    /// Control servers that never answer (the engine keeps trying, no netmap).
    unreachable: Vec<String>,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<World>>);

impl Launcher for Fake {
    fn run(
        &self,
        cfg: EngineConfig,
        status: watch::Sender<EngineStatus>,
        mut stop: watch::Receiver<bool>,
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
                });
            }
            while !*stop.borrow() {
                if stop.changed().await.is_err() {
                    break;
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

    let r = h.client.post("logout", &json!({})).await.unwrap();
    assert_eq!(r["warning"], Value::Null);
    let s = h.wait_state("NeedsLogin").await;
    assert_eq!(h.fake.0.lock().unwrap().logouts, 1);
    assert_eq!(s["Peer"], Value::Null);
    assert_eq!(
        s["Self"]["PublicKey"],
        flowmesh_daemon::status_json::ZERO_NODE_KEY
    );
    assert_eq!(h.stored()["logged_in"], false);

    // Logged out: the old flags are still the prefs, but the control server refuses without a key.
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
async fn set_changes_only_given_fields_and_restarts_the_engine() {
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
    h.wait_state("Running").await;
    {
        let w = h.fake.0.lock().unwrap();
        assert_eq!(w.runs, runs + 1);
        assert!(w.last_cfg.as_ref().unwrap().accept_routes);
    }

    // No change: no restart.
    h.client
        .post("set", &json!({ "accept_routes": true }))
        .await
        .unwrap();
    assert_eq!(h.fake.0.lock().unwrap().runs, runs + 1);

    // While stopped, set only records the preference.
    h.client.post("down", &json!({})).await.unwrap();
    h.client
        .post("set", &json!({ "hostname": "fm9" }))
        .await
        .unwrap();
    assert_eq!(h.fake.0.lock().unwrap().runs, runs + 1);
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
async fn missing_daemon_is_a_clear_error() {
    let c = LocalClient::new(temp_dir("nodaemon").join("s.sock"));
    let e = c.get("status").await.unwrap_err();
    assert!(e.to_string().contains("is the daemon running?"), "{e}");
}
