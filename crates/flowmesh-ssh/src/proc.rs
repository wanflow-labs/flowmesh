// SPDX-License-Identifier: Apache-2.0
//! Running a login's programs as the local user. flowmeshd starts itself again as a helper
//! (`flowmeshd be-child ssh …`, see `child.rs`) which becomes the user and then runs the program:
//! the identity switch happens in a fresh single-threaded process, never between fork and exec
//! of the multi-threaded daemon (which would need unsafe code).

use nix::unistd::{Gid, Uid, User};
use std::ffi::{CString, OsString};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// A local account to run as.
#[derive(Debug, Clone)]
pub struct Account {
    pub name: String,
    pub uid: Uid,
    pub gid: Gid,
    pub home: PathBuf,
    pub shell: PathBuf,
    pub groups: Vec<Gid>,
}

pub fn lookup(name: &str) -> Result<Account, String> {
    let u = User::from_name(name)
        .map_err(|e| format!("look up user {name:?}: {e}"))?
        .ok_or_else(|| format!("no local user {name:?}"))?;
    let cname = CString::new(name).map_err(|_| format!("bad user name {name:?}"))?;
    let groups =
        nix::unistd::getgrouplist(&cname, u.gid).map_err(|e| format!("groups of {name:?}: {e}"))?;
    let shell = if u.shell.as_os_str().is_empty() {
        PathBuf::from("/bin/sh")
    } else {
        u.shell
    };
    Ok(Account {
        name: u.name,
        uid: u.uid,
        gid: u.gid,
        home: u.dir,
        shell,
        groups,
    })
}

/// PATH for a login: /etc/login.defs' ENV_SUPATH / ENV_PATH when set, else the usual defaults.
pub fn default_path(root: bool) -> String {
    let key = if root { "ENV_SUPATH" } else { "ENV_PATH" };
    let from_defs = std::fs::read_to_string("/etc/login.defs")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                let mut w = l.split_whitespace();
                (w.next() == Some(key))
                    .then(|| w.next())
                    .flatten()
                    .map(|v| v.strip_prefix("PATH=").unwrap_or(v).to_string())
            })
        });
    from_defs.unwrap_or_else(|| {
        // Each of /usr/local, /usr and / contributes its bin directory, preceded by its sbin
        // directory for root.
        let mut dirs = Vec::new();
        for prefix in ["/usr/local", "/usr", ""] {
            if root {
                dirs.push(format!("{prefix}/sbin"));
            }
            dirs.push(format!("{prefix}/bin"));
        }
        dirs.join(":")
    })
}

/// A requested pseudo-terminal.
#[derive(Debug, Clone, Default)]
pub struct PtySpec {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

/// What to run.
#[derive(Debug, Clone)]
pub enum Program {
    /// The user's shell as a login shell (`shell` request).
    LoginShell,
    /// `shell -c <command>` (`exec` request).
    Command(String),
    /// A program run directly with no arguments (an SFTP server binary).
    Binary(PathBuf),
    /// flowmesh's own SFTP server, run by the helper once it is the user.
    BuiltinSftp,
}

pub struct Spec {
    pub account: Account,
    pub program: Program,
    pub env: Vec<(String, String)>,
    pub pty: Option<PtySpec>,
}

/// A started program: a pty master (pty sessions; the slave is held until the program ends so the
/// master does not see a hang-up before the program opened it) or three pipes.
pub struct Started {
    pub child: tokio::process::Child,
    pub pty: Option<(OwnedFd, OwnedFd)>,
}

fn winsize(cols: u16, rows: u16) -> rustix::termios::Winsize {
    rustix::termios::Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// Resize a pty (window-change request).
pub fn resize(master: &OwnedFd, cols: u16, rows: u16) {
    let _ = rustix::termios::tcsetwinsize(master, winsize(cols, rows));
}

/// The helper's command line for `spec`.
fn helper_args(spec: &Spec, tty: Option<&Path>) -> Vec<OsString> {
    let a = &spec.account;
    let groups: Vec<String> = a.groups.iter().map(|g| g.as_raw().to_string()).collect();
    let mut args: Vec<OsString> = vec![
        "be-child".into(),
        "ssh".into(),
        format!("--uid={}", a.uid.as_raw()).into(),
        format!("--gid={}", a.gid.as_raw()).into(),
        format!("--groups={}", groups.join(",")).into(),
    ];
    let mut home = OsString::from("--home=");
    home.push(&a.home);
    args.push(home);
    if let Some(t) = tty {
        let mut s = OsString::from("--tty=");
        s.push(t);
        args.push(s);
    }
    let shell = a.shell.as_os_str().to_owned();
    match &spec.program {
        Program::LoginShell => {
            let base = a.shell.file_name().unwrap_or(std::ffi::OsStr::new("sh"));
            let mut argv0 = OsString::from("--argv0=-");
            argv0.push(base);
            args.push(argv0);
            args.push("--".into());
            args.push(shell);
        }
        Program::Command(c) => {
            args.extend(["--".into(), shell, "-c".into(), c.into()]);
        }
        Program::Binary(b) => {
            args.extend(["--".into(), b.as_os_str().to_owned()]);
        }
        Program::BuiltinSftp => args.push("--sftp".into()),
    }
    args
}

/// Start `spec` through the helper `exe` (flowmeshd).
pub fn spawn(exe: &Path, spec: Spec) -> std::io::Result<Started> {
    let mut pty = None;
    let mut tty = None;
    if let Some(p) = &spec.pty {
        let pair = nix::pty::openpty(None, None).map_err(std::io::Error::from)?;
        let _ = rustix::termios::tcsetwinsize(&pair.master, winsize(p.cols, p.rows));
        tty = Some(std::fs::read_link(format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&pair.slave)
        ))?);
        pty = Some((pair.master, pair.slave));
    }
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(helper_args(&spec, tty.as_deref()));
    cmd.env_clear();
    cmd.envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    if let (Some(p), Some(t)) = (&spec.pty, &tty) {
        if !p.term.is_empty() {
            cmd.env("TERM", &p.term);
        }
        cmd.env("SSH_TTY", t);
    }
    cmd.kill_on_drop(true);
    if pty.is_some() {
        // The helper connects itself to the terminal.
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
    } else {
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
    }
    let child = cmd.spawn()?;
    Ok(Started { child, pty })
}

/// The environment of a login, as observed of the official server (OBS-20261012-ssh-official/
/// ssh-alice-env.txt): HOME, PATH, SHELL, USER and the SSH_* connection variables (`spawn` adds
/// TERM and SSH_TTY with a pty).
pub fn login_env(
    a: &Account,
    client: std::net::SocketAddr,
    server: std::net::SocketAddr,
) -> Vec<(String, String)> {
    vec![
        ("HOME".to_string(), a.home.display().to_string()),
        ("PATH".into(), default_path(a.uid.is_root())),
        ("SHELL".into(), a.shell.display().to_string()),
        ("USER".into(), a.name.clone()),
        (
            "SSH_CLIENT".into(),
            format!("{} {} {}", client.ip(), client.port(), server.port()),
        ),
        (
            "SSH_CONNECTION".into(),
            format!(
                "{} {} {} {}",
                client.ip(),
                client.port(),
                server.ip(),
                server.port()
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Account {
        Account {
            name: "alice".into(),
            uid: Uid::from_raw(1000),
            gid: Gid::from_raw(1000),
            home: "/home/alice".into(),
            shell: "/bin/bash".into(),
            groups: vec![Gid::from_raw(1000), Gid::from_raw(27)],
        }
    }

    fn args(program: Program, tty: Option<&Path>) -> Vec<String> {
        let spec = Spec {
            account: account(),
            program,
            env: Vec::new(),
            pty: None,
        };
        helper_args(&spec, tty)
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn default_paths() {
        if std::path::Path::new("/etc/login.defs").exists() {
            return; // the host's own settings win
        }
        assert_eq!(default_path(false), "/usr/local/bin:/usr/bin:/bin");
        assert_eq!(
            default_path(true),
            [
                "/usr/local/sbin",
                "/usr/local/bin",
                "/usr/sbin",
                "/usr/bin",
                "/sbin",
                "/bin"
            ]
            .join(":")
        );
    }

    #[test]
    fn helper_command_lines() {
        let head = [
            "be-child",
            "ssh",
            "--uid=1000",
            "--gid=1000",
            "--groups=1000,27",
            "--home=/home/alice",
        ];
        let mut want: Vec<&str> = head.to_vec();
        want.extend(["--tty=/dev/pts/3", "--argv0=-bash", "--", "/bin/bash"]);
        assert_eq!(
            args(Program::LoginShell, Some(Path::new("/dev/pts/3"))),
            want
        );
        let mut want: Vec<&str> = head.to_vec();
        want.extend(["--", "/bin/bash", "-c", "id; echo 'a b'"]);
        assert_eq!(args(Program::Command("id; echo 'a b'".into()), None), want);
        let mut want: Vec<&str> = head.to_vec();
        want.push("--sftp");
        assert_eq!(args(Program::BuiltinSftp, None), want);
    }
}
