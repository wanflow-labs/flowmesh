// SPDX-License-Identifier: Apache-2.0
//! A minimal SFTP server for hosts without one (OpenWrt has no sftp-server), like the official
//! client's built-in one. It runs in the helper after the switch to the user, on stdin/stdout, so
//! every file operation is the user's own.

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use russh_sftp::server::StatusReply;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

enum Entry {
    File(std::fs::File),
    /// Directory listing, sent in one reply, then EOF.
    Dir(Option<Vec<File>>),
}

#[derive(Default)]
struct Sftp {
    handles: HashMap<String, Entry>,
    next: u64,
}

fn status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

fn io_err(e: std::io::Error) -> StatusReply {
    let code = match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    };
    StatusReply::new(code).with_message(e.to_string())
}

/// `ls -l`-style line for directory listings (`sftp ls -l` prints it).
fn longname(name: &str, m: &std::fs::Metadata) -> String {
    let mode = m.mode();
    let kind = match mode & 0o170_000 {
        0o040_000 => 'd',
        0o120_000 => 'l',
        0o020_000 => 'c',
        0o060_000 => 'b',
        0o010_000 => 'p',
        0o140_000 => 's',
        _ => '-',
    };
    let mut perms = String::with_capacity(10);
    perms.push(kind);
    for shift in [6, 3, 0] {
        let b = (mode >> shift) & 7;
        perms.push(if b & 4 != 0 { 'r' } else { '-' });
        perms.push(if b & 2 != 0 { 'w' } else { '-' });
        perms.push(if b & 1 != 0 { 'x' } else { '-' });
    }
    let days = m.mtime().div_euclid(86_400);
    // Civil date from days since the epoch (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mon = MONTHS[usize::try_from(month - 1).unwrap_or(0).min(11)];
    format!(
        "{perms} {:>3} {:<8} {:<8} {:>8} {mon} {day:>2} {year:>5} {name}",
        m.nlink(),
        m.uid(),
        m.gid(),
        m.size()
    )
}

impl Sftp {
    fn add(&mut self, e: Entry) -> String {
        self.next += 1;
        let h = self.next.to_string();
        self.handles.insert(h.clone(), e);
        h
    }

    fn file(&mut self, handle: &str) -> Result<&mut std::fs::File, StatusReply> {
        match self.handles.get_mut(handle) {
            Some(Entry::File(f)) => Ok(f),
            _ => Err(StatusReply::new(StatusCode::Failure).with_message("bad handle")),
        }
    }
}

fn set_attrs(path: &Path, attrs: &FileAttributes) -> std::io::Result<()> {
    if let Some(p) = attrs.permissions {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(p & 0o7777))?;
    }
    if let Some(size) = attrs.size {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)?
            .set_len(size)?;
    }
    if let (Some(a), Some(m)) = (attrs.atime, attrs.mtime) {
        let t = |s: u32| std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(s));
        let f = std::fs::File::options()
            .write(true)
            .open(path)
            .or_else(|_| std::fs::File::open(path))?;
        f.set_times(
            std::fs::FileTimes::new()
                .set_accessed(t(a))
                .set_modified(t(m)),
        )?;
    }
    if attrs.uid.is_some() || attrs.gid.is_some() {
        std::os::unix::fs::chown(path, attrs.uid, attrs.gid)?;
    }
    Ok(())
}

impl russh_sftp::server::Handler for Sftp {
    type Error = StatusReply;

    fn unimplemented(&self) -> Self::Error {
        StatusReply::new(StatusCode::OpUnsupported)
    }

    async fn init(
        &mut self,
        _version: u32,
        _ext: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let mut o = std::fs::OpenOptions::new();
        o.read(pflags.contains(OpenFlags::READ))
            .write(pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::APPEND))
            .append(pflags.contains(OpenFlags::APPEND))
            .truncate(pflags.contains(OpenFlags::TRUNCATE));
        if pflags.contains(OpenFlags::EXCLUDE) {
            o.create_new(true);
        } else if pflags.contains(OpenFlags::CREATE) {
            o.create(true);
        }
        if let Some(p) = attrs.permissions {
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, p & 0o7777);
        }
        let f = o.open(&filename).map_err(io_err)?;
        Ok(Handle {
            id,
            handle: self.add(Entry::File(f)),
        })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(status(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let f = self.file(&handle)?;
        f.seek(SeekFrom::Start(offset)).map_err(io_err)?;
        let mut buf = vec![0u8; len.min(256 * 1024) as usize];
        let n = f.read(&mut buf).map_err(io_err)?;
        if n == 0 && len > 0 {
            return Err(StatusReply::new(StatusCode::Eof));
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let f = self.file(&handle)?;
        f.seek(SeekFrom::Start(offset)).map_err(io_err)?;
        f.write_all(&data).map_err(io_err)?;
        Ok(status(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let m = std::fs::symlink_metadata(&path).map_err(io_err)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let m = self.file(&handle)?.metadata().map_err(io_err)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        set_attrs(Path::new(&path), &attrs).map_err(io_err)?;
        Ok(status(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let f = self.file(&handle)?;
        if let Some(size) = attrs.size {
            f.set_len(size).map_err(io_err)?;
        }
        if let Some(p) = attrs.permissions {
            f.set_permissions(std::fs::Permissions::from_mode(p & 0o7777))
                .map_err(io_err)?;
        }
        Ok(status(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let mut files = Vec::new();
        for name in [".", ".."] {
            if let Ok(m) = std::fs::metadata(Path::new(&path).join(name)) {
                let mut f = File::new(name, FileAttributes::from(&m));
                f.longname = longname(name, &m);
                files.push(f);
            }
        }
        for e in std::fs::read_dir(&path).map_err(io_err)?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Ok(m) = e.path().symlink_metadata() {
                let mut f = File::new(name.clone(), FileAttributes::from(&m));
                f.longname = longname(&name, &m);
                files.push(f);
            }
        }
        Ok(Handle {
            id,
            handle: self.add(Entry::Dir(Some(files))),
        })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        match self.handles.get_mut(&handle) {
            Some(Entry::Dir(files)) => match files.take() {
                Some(files) if !files.is_empty() => Ok(Name { id, files }),
                _ => Err(StatusReply::new(StatusCode::Eof)),
            },
            _ => Err(StatusReply::new(StatusCode::Failure).with_message("bad handle")),
        }
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        std::fs::remove_file(&filename).map_err(io_err)?;
        Ok(status(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let mut b = std::fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut b, attrs.permissions.unwrap_or(0o777) & 0o7777);
        b.create(&path).map_err(io_err)?;
        Ok(status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_dir(&path).map_err(io_err)?;
        Ok(status(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let p = if path.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(&path)
        };
        let real = std::fs::canonicalize(&p).map_err(io_err)?;
        Ok(Name {
            id,
            files: vec![File::dummy(real.to_string_lossy())],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let m = std::fs::metadata(&path).map_err(io_err)?;
        Ok(Attrs {
            id,
            attrs: FileAttributes::from(&m),
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        std::fs::rename(&oldpath, &newpath).map_err(io_err)?;
        Ok(status(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let target = std::fs::read_link(&path).map_err(io_err)?;
        Ok(Name {
            id,
            files: vec![File::dummy(target.to_string_lossy())],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        // OpenSSH's sftp-server takes the arguments in this (reversed) order; clients follow it.
        std::os::unix::fs::symlink(&linkpath, &targetpath).map_err(io_err)?;
        Ok(status(id))
    }
}

/// stdin + stdout as one stream that reports when the client's side ends.
struct Stdio {
    r: tokio::io::Stdin,
    w: tokio::io::Stdout,
    ended: Arc<tokio::sync::Notify>,
}

impl AsyncRead for Stdio {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.r).poll_read(cx, buf);
        if matches!(&r, Poll::Ready(Err(_)))
            || (matches!(&r, Poll::Ready(Ok(()))) && buf.filled().len() == before)
        {
            self.ended.notify_one();
        }
        r
    }
}

impl AsyncWrite for Stdio {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.w).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.w).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.w).poll_shutdown(cx)
    }
}

/// Serve SFTP on stdin/stdout until the client goes away.
pub fn serve_stdio() -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("flowmesh: sftp: {e}");
            return ExitCode::from(1);
        }
    };
    rt.block_on(async {
        let ended = Arc::new(tokio::sync::Notify::new());
        let io = Stdio {
            r: tokio::io::stdin(),
            w: tokio::io::stdout(),
            ended: ended.clone(),
        };
        russh_sftp::server::run(io, Sftp::default()).await;
        ended.notified().await;
    });
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_names() {
        let dir = std::env::temp_dir().join(format!("fm-sftp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.txt");
        std::fs::write(&f, b"hello").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let line = longname("a.txt", &std::fs::metadata(&f).unwrap());
        assert!(line.starts_with("-rw-r----- "), "{line}");
        assert!(line.ends_with(" a.txt"), "{line}");
        assert!(line.contains("        5 "), "{line}");
        let d = longname("x", &std::fs::metadata(&dir).unwrap());
        assert!(d.starts_with('d'), "{d}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
