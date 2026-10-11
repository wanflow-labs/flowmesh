// SPDX-License-Identifier: Apache-2.0
//! `flowmeshd be-child ssh …`: the helper that becomes the login's user and runs its program.
//! It starts as root in a fresh process and, in this order: starts a new session, takes the
//! terminal as its controlling terminal (pty sessions), drops to the user's groups, group and
//! user (checking that root cannot be regained), enters the home directory, and execs.
//!
//! `be-child ssh --uid=U --gid=G --groups=G1,G2 --home=DIR [--tty=PATH] [--argv0=NAME]
//!  (--sftp | -- PROGRAM ARGS…)`

use nix::unistd::{Gid, Uid};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Args {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub home: PathBuf,
    pub tty: Option<PathBuf>,
    pub argv0: Option<OsString>,
    pub sftp: bool,
    pub program: Vec<OsString>,
}

fn num(v: &[u8], what: &str) -> Result<u32, String> {
    std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad {what}"))
}

/// Parse the arguments after `be-child ssh`.
pub fn parse(args: &[OsString]) -> Result<Args, String> {
    let mut a = Args::default();
    let (mut uid, mut gid) = (None, None);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let b = arg.as_bytes();
        if b == b"--" {
            a.program = it.cloned().collect();
            break;
        } else if b == b"--sftp" {
            a.sftp = true;
        } else if let Some(v) = b.strip_prefix(b"--uid=") {
            uid = Some(num(v, "uid")?);
        } else if let Some(v) = b.strip_prefix(b"--gid=") {
            gid = Some(num(v, "gid")?);
        } else if let Some(v) = b.strip_prefix(b"--groups=") {
            a.groups = v
                .split(|c| *c == b',')
                .filter(|g| !g.is_empty())
                .map(|g| num(g, "group"))
                .collect::<Result<_, _>>()?;
        } else if let Some(v) = b.strip_prefix(b"--home=") {
            a.home = PathBuf::from(std::ffi::OsStr::from_bytes(v));
        } else if let Some(v) = b.strip_prefix(b"--tty=") {
            a.tty = Some(PathBuf::from(std::ffi::OsStr::from_bytes(v)));
        } else if let Some(v) = b.strip_prefix(b"--argv0=") {
            a.argv0 = Some(std::ffi::OsStr::from_bytes(v).to_owned());
        } else {
            return Err(format!("unknown argument {arg:?}"));
        }
    }
    a.uid = uid.ok_or("missing --uid")?;
    a.gid = gid.ok_or("missing --gid")?;
    if a.program.is_empty() != a.sftp {
        return Err("need exactly one of --sftp or -- PROGRAM".into());
    }
    Ok(a)
}

/// Become the user (and take the terminal); everything that can fail before running anything.
fn become_user(a: &Args) -> Result<(), String> {
    nix::unistd::setsid().map_err(|e| format!("setsid: {e}"))?;
    if let Some(tty) = &a.tty {
        // Opened by a session leader without a controlling terminal: it becomes the controlling
        // terminal; the ioctl makes that explicit where opening alone does not.
        let t = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tty)
            .map_err(|e| format!("open {}: {e}", tty.display()))?;
        let _ = rustix::process::ioctl_tiocsctty(&t);
        nix::unistd::dup2_stdin(&t).map_err(|e| format!("dup2: {e}"))?;
        nix::unistd::dup2_stdout(&t).map_err(|e| format!("dup2: {e}"))?;
        nix::unistd::dup2_stderr(&t).map_err(|e| format!("dup2: {e}"))?;
    }
    let groups: Vec<Gid> = a.groups.iter().map(|g| Gid::from_raw(*g)).collect();
    nix::unistd::setgroups(&groups).map_err(|e| format!("setgroups: {e}"))?;
    nix::unistd::setgid(Gid::from_raw(a.gid)).map_err(|e| format!("setgid: {e}"))?;
    nix::unistd::setuid(Uid::from_raw(a.uid)).map_err(|e| format!("setuid: {e}"))?;
    // The switch must be complete and permanent.
    if nix::unistd::getuid().as_raw() != a.uid || nix::unistd::geteuid().as_raw() != a.uid {
        return Err("uid did not change".into());
    }
    if nix::unistd::getgid().as_raw() != a.gid || nix::unistd::getegid().as_raw() != a.gid {
        return Err("gid did not change".into());
    }
    if a.uid != 0 && nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
        return Err("root could be regained".into());
    }
    // As the user, so a home it cannot enter is noticed; fall back to / like sshd.
    if std::env::set_current_dir(&a.home).is_err() {
        std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;
    }
    Ok(())
}

pub fn main(args: &[OsString]) -> ExitCode {
    let a = match parse(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("flowmesh: be-child: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = become_user(&a) {
        eprintln!("flowmesh: cannot start the session: {e}");
        return ExitCode::from(1);
    }
    if a.sftp {
        return crate::sftp::serve_stdio();
    }
    let mut cmd = std::process::Command::new(&a.program[0]);
    cmd.args(&a.program[1..]);
    if let Some(argv0) = &a.argv0 {
        cmd.arg0(argv0);
    }
    let e = cmd.exec();
    eprintln!("flowmesh: run {:?}: {e}", a.program[0]);
    ExitCode::from(127)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn arguments() {
        let a = parse(&os(&[
            "--uid=1000",
            "--gid=100",
            "--groups=100,27",
            "--home=/home/a b",
            "--tty=/dev/pts/3",
            "--argv0=-bash",
            "--",
            "/bin/bash",
            "--norc",
        ]))
        .unwrap();
        assert_eq!(
            a,
            Args {
                uid: 1000,
                gid: 100,
                groups: vec![100, 27],
                home: "/home/a b".into(),
                tty: Some("/dev/pts/3".into()),
                argv0: Some("-bash".into()),
                sftp: false,
                program: os(&["/bin/bash", "--norc"]),
            }
        );
        assert!(parse(&os(&["--uid=0", "--gid=0", "--sftp"])).unwrap().sftp);
        assert!(parse(&os(&["--gid=0", "--", "x"])).is_err(), "no uid");
        assert!(parse(&os(&["--uid=x", "--gid=0", "--", "x"])).is_err());
        assert!(
            parse(&os(&["--uid=0", "--gid=0"])).is_err(),
            "nothing to run"
        );
        assert!(parse(&os(&["--uid=0", "--gid=0", "--sftp", "--", "x"])).is_err());
        assert!(parse(&os(&["--uid=0", "--gid=0", "--bogus", "--", "x"])).is_err());
    }
}
