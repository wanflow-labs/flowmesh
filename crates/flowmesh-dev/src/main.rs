// SPDX-License-Identifier: Apache-2.0
//! flowmesh development entry point: a thin wrapper around flowmesh-engine, used by the lab acceptance scripts. The product daemon is flowmeshd.
//!
//! Usage: flowmesh-dev --login-server <url> --authkey-file <path> --state <path> --hostname <name>
//!        [--tun <name>] [--port <n>] [--tap-dir <dir>] [--accept-dns] [--accept-routes]

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux_main()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("flowmesh-dev only runs on Linux");
        std::process::ExitCode::from(2)
    }
}

#[cfg(target_os = "linux")]
fn parse_args() -> Result<flowmesh_engine::EngineConfig, String> {
    use std::path::PathBuf;
    let mut it = std::env::args().skip(1);
    let mut cfg = flowmesh_engine::EngineConfig {
        login_server: String::new(),
        authkey: None,
        state_file: PathBuf::new(),
        hostname: String::new(),
        tun: "flowmesh0".into(),
        port: 41641,
        tap_dir: None,
        accept_dns: false,
        accept_routes: false,
        advertise_routes: Vec::new(),
        snat_subnet_routes: true,
        advertise_tags: Vec::new(),
        shields_up: false,
        advertise_exit_node: false,
        stateful_filtering: false,
        exit_node: String::new(),
        exit_node_allow_lan_access: false,
        run_ssh: false,
        ssh_helper: None,
    };
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--login-server" => cfg.login_server = val()?,
            "--authkey-file" => {
                let path = val()?;
                let key =
                    std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
                cfg.authkey = Some(key.trim().to_string());
            }
            "--state" => cfg.state_file = PathBuf::from(val()?),
            "--hostname" => cfg.hostname = val()?,
            "--tun" => cfg.tun = val()?,
            "--port" => {
                let v = val()?;
                cfg.port = v.parse().map_err(|_| format!("bad --port {v}"))?;
            }
            "--tap-dir" => cfg.tap_dir = Some(PathBuf::from(val()?)),
            "--accept-dns" => cfg.accept_dns = true,
            "--accept-routes" => cfg.accept_routes = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if cfg.login_server.is_empty()
        || cfg.hostname.is_empty()
        || cfg.state_file.as_os_str().is_empty()
    {
        return Err("--login-server, --state and --hostname are required".into());
    }
    Ok(cfg)
}

#[cfg(target_os = "linux")]
fn linux_main() -> std::process::ExitCode {
    use std::process::ExitCode;
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("flowmesh-dev: {e}");
            return ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("flowmesh-dev: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = rt.block_on(async move {
        let (status_tx, _status_rx) =
            tokio::sync::watch::channel(flowmesh_engine::status::EngineStatus::default());
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        // flowmesh-dev takes no commands; the sender lives as long as the engine.
        let (_cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let (Ok(mut term), Ok(mut int)) = (
                signal(SignalKind::terminate()),
                signal(SignalKind::interrupt()),
            ) else {
                return;
            };
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
            let _ = stop_tx.send(true);
        });
        flowmesh_engine::run(cfg, status_tx, stop_rx, cmd_rx).await
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("flowmesh-dev: {e}");
            ExitCode::FAILURE
        }
    }
}
