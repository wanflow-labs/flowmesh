// SPDX-License-Identifier: Apache-2.0
//! flowmeshd: the flowmesh daemon.
//!
//! Usage: flowmeshd [--state-dir <dir>] [--socket <path>] [--tun <name>] [--port <n>]

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux::main()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("flowmeshd only runs on Linux");
        std::process::ExitCode::from(2)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use flowmesh_daemon::api;
    use flowmesh_daemon::client::DEFAULT_SOCKET;
    use flowmesh_daemon::daemon::{BoxFut, Daemon, Launcher, Options};
    use flowmesh_engine::status::EngineStatus;
    use flowmesh_engine::{EngineConfig, EngineError};
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::Arc;
    use tokio::sync::watch;

    struct Engine;

    impl Launcher for Engine {
        fn run(
            &self,
            cfg: EngineConfig,
            status: watch::Sender<EngineStatus>,
            stop: watch::Receiver<bool>,
        ) -> BoxFut<Result<(), EngineError>> {
            Box::pin(flowmesh_engine::run(cfg, status, stop))
        }
        fn logout(&self, login_server: String, state_file: PathBuf) -> BoxFut<Result<(), String>> {
            Box::pin(async move { flowmesh_engine::logout(&login_server, &state_file).await })
        }
    }

    struct Args {
        state_dir: PathBuf,
        socket: PathBuf,
        tun: String,
        port: u16,
    }

    fn parse_args() -> Result<Args, String> {
        let mut a = Args {
            state_dir: PathBuf::from("/var/lib/flowmesh"),
            socket: PathBuf::from(DEFAULT_SOCKET),
            tun: "flowmesh0".into(),
            port: 41641,
        };
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut val = || it.next().ok_or(format!("{flag} needs a value"));
            match flag.as_str() {
                "--state-dir" => a.state_dir = PathBuf::from(val()?),
                "--socket" => a.socket = PathBuf::from(val()?),
                "--tun" => a.tun = val()?,
                "--port" => {
                    let v = val()?;
                    a.port = v.parse().map_err(|_| format!("bad --port {v}"))?;
                }
                "--version" => {
                    println!("flowmeshd {}", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(a)
    }

    pub fn main() -> ExitCode {
        let args = match parse_args() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("flowmeshd: {e}");
                return ExitCode::from(2);
            }
        };
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("flowmeshd: runtime: {e}");
                return ExitCode::FAILURE;
            }
        };
        match rt.block_on(run(args)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("flowmeshd: {e}");
                ExitCode::FAILURE
            }
        }
    }

    async fn run(args: Args) -> Result<(), String> {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
        let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
        let mut opts = Options::new(args.state_dir);
        opts.tun = args.tun;
        opts.port = args.port;
        let daemon = Arc::new(Daemon::start(Engine, opts).await?);
        let (listener, uid) =
            api::bind(&args.socket).map_err(|e| format!("{}: {e}", args.socket.display()))?;
        eprintln!("flowmeshd: listening on {}", args.socket.display());
        let (stop_tx, stop_rx) = watch::channel(false);
        let server = tokio::spawn(api::serve(daemon.clone(), listener, uid, stop_rx));
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        let _ = stop_tx.send(true);
        let _ = server.await;
        // Restores resolv.conf and routes; preferences stay, so the next start reconnects.
        daemon.shutdown().await;
        let _ = std::fs::remove_file(&args.socket);
        Ok(())
    }
}
