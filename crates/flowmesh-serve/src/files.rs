// SPDX-License-Identifier: Apache-2.0
//! Serving a file or a directory, as the official server does (OBS-20261012-serve-official/
//! get-dir-*.txt): `index.html` for a directory that has one, else a plain listing; files with a
//! type from their extension, `Last-Modified` and single byte ranges. A request never leaves the
//! served directory: `..` cannot climb above it.

use crate::server::{Body, not_found};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const CHUNK: usize = 64 * 1024;

/// Percent-decoded path segments, with `.` and `..` resolved inside the root.
pub fn clean(rel: &str) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for seg in rel.split('/') {
        let seg = percent_decode(seg)?;
        if seg.contains('\0') || seg.contains('/') {
            return None;
        }
        match seg.as_str() {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s.to_string()),
        }
    }
    Some(out)
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn escape_href(name: &str) -> String {
    name.bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// An HTTP date (`Sun, 11 Oct 2026 19:32:41 GMT`).
pub fn http_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs()) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1).clamp(0, 11) as usize],
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// Content type by extension, else by whether the start of the file looks like text.
pub fn content_type(path: &Path, head: &[u8]) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "txt" | "text" | "log" | "md" => "text/plain; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "xml" => "text/xml; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/vnd.microsoft.icon",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "mp4" => "video/mp4",
        _ if std::str::from_utf8(head).is_ok() && !head.contains(&0) => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn response(
    status: StatusCode,
    headers: Vec<(header::HeaderName, String)>,
    body: Body,
) -> Response<Body> {
    let mut r = Response::new(body);
    *r.status_mut() = status;
    for (k, v) in headers {
        if let Ok(v) = HeaderValue::try_from(v) {
            r.headers_mut().insert(k, v);
        }
    }
    r
}

fn bytes_body(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|e| match e {}).boxed()
}

/// The directory listing the official server writes.
pub fn listing(dir: &Path) -> std::io::Result<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| {
            let mut n = e.file_name().to_string_lossy().into_owned();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                n.push('/');
            }
            n
        })
        .collect();
    names.sort();
    let mut o = String::from(
        "<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n",
    );
    for n in names {
        o.push_str(&format!(
            "<a href=\"{}\">{}</a>\n",
            escape_href(&n),
            escape_html(&n)
        ));
    }
    o.push_str("</pre>\n");
    Ok(o)
}

/// A single `bytes=a-b` range within `len`.
fn range(h: Option<&HeaderValue>, len: u64) -> Option<(u64, u64)> {
    let spec = h?.to_str().ok()?.strip_prefix("bytes=")?;
    if spec.contains(',') || len == 0 {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (start, end) = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        (len.saturating_sub(n), len - 1)
    } else {
        let s: u64 = a.parse().ok()?;
        let e: u64 = if b.is_empty() {
            len - 1
        } else {
            b.parse::<u64>().ok()?.min(len - 1)
        };
        (s, e)
    };
    (start <= end && start < len).then_some((start, end))
}

pub async fn serve<B>(req: &Request<B>, root: &Path, rel: &str) -> Response<Body> {
    let Some(segs) = clean(rel) else {
        return not_found();
    };
    let root_meta = match tokio::fs::metadata(root).await {
        Ok(m) => m,
        Err(_) => return not_found(),
    };
    let target: PathBuf = if root_meta.is_dir() {
        segs.iter().fold(root.to_path_buf(), |p, s| p.join(s))
    } else if segs.is_empty() {
        root.to_path_buf()
    } else {
        return not_found();
    };
    let Ok(meta) = tokio::fs::metadata(&target).await else {
        return not_found();
    };
    let modified = meta.modified().map(http_date).unwrap_or_default();
    if meta.is_dir() {
        let path = req.uri().path();
        if !path.ends_with('/') {
            // A directory is addressed with a trailing slash, so relative links in it work.
            let last = path.rsplit('/').next().unwrap_or_default();
            return response(
                StatusCode::MOVED_PERMANENTLY,
                vec![(header::LOCATION, format!("{last}/"))],
                bytes_body(Bytes::new()),
            );
        }
        let index = target.join("index.html");
        if tokio::fs::metadata(&index).await.is_ok_and(|m| m.is_file()) {
            return file(req, &index).await;
        }
        return match listing(&target) {
            Ok(html) => response(
                StatusCode::OK,
                vec![
                    (header::CONTENT_TYPE, "text/html; charset=utf-8".into()),
                    (header::LAST_MODIFIED, modified),
                    (header::CONTENT_LENGTH, html.len().to_string()),
                ],
                if req.method() == Method::HEAD {
                    bytes_body(Bytes::new())
                } else {
                    bytes_body(html)
                },
            ),
            Err(_) => not_found(),
        };
    }
    file(req, &target).await
}

async fn file<B>(req: &Request<B>, path: &Path) -> Response<Body> {
    let Ok(mut f) = tokio::fs::File::open(path).await else {
        return not_found();
    };
    let Ok(meta) = f.metadata().await else {
        return not_found();
    };
    let len = meta.len();
    let mut head = vec![0u8; 512.min(len as usize)];
    let n = f.read(&mut head).await.unwrap_or(0);
    head.truncate(n);
    let mut headers = vec![
        (header::ACCEPT_RANGES, "bytes".to_string()),
        (header::CONTENT_TYPE, content_type(path, &head).to_string()),
        (
            header::LAST_MODIFIED,
            meta.modified().map(http_date).unwrap_or_default(),
        ),
    ];
    let (status, start, count) = match range(req.headers().get(header::RANGE), len) {
        Some((s, e)) => {
            headers.push((header::CONTENT_RANGE, format!("bytes {s}-{e}/{len}")));
            (StatusCode::PARTIAL_CONTENT, s, e - s + 1)
        }
        None => (StatusCode::OK, 0, len),
    };
    headers.push((header::CONTENT_LENGTH, count.to_string()));
    if req.method() == Method::HEAD || f.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return response(status, headers, bytes_body(Bytes::new()));
    }
    let stream = futures_util::stream::unfold((f, count), |(mut f, left)| async move {
        if left == 0 {
            return None;
        }
        let mut buf = vec![0u8; CHUNK.min(left as usize)];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(Frame::data(Bytes::from(buf))), (f, left - n as u64)))
            }
            Err(e) => Some((
                Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
                (f, 0),
            )),
        }
    });
    response(status, headers, StreamBody::new(stream).boxed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_stay_inside() {
        assert_eq!(clean("/sub/a.txt").unwrap(), ["sub", "a.txt"]);
        assert_eq!(clean("/../../etc/passwd").unwrap(), ["etc", "passwd"]);
        assert_eq!(clean("/a/%2e%2e/%2e%2e/b").unwrap(), ["b"]);
        assert!(
            clean("/a%2Fb").is_none(),
            "an encoded slash is not a separator"
        );
        assert!(clean("/a%00b").is_none());
        assert_eq!(clean("/a%20b").unwrap(), ["a b"]);
    }

    /// The listing the official server wrote for a directory holding a.txt (get-dir-listing.txt).
    #[test]
    fn listing_like_the_official_one() {
        let dir = std::env::temp_dir().join(format!("fm-serve-list-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("d")).unwrap();
        std::fs::write(dir.join("a.txt"), "x").unwrap();
        std::fs::write(dir.join("<b>.txt"), "x").unwrap();
        assert_eq!(
            listing(&dir).unwrap(),
            "<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n<a href=\"%3Cb%3E.txt\">&lt;b&gt;.txt</a>\n<a href=\"a.txt\">a.txt</a>\n<a href=\"d/\">d/</a>\n</pre>\n"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dates_types_ranges() {
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_791_754_361);
        assert_eq!(http_date(t), "Sun, 11 Oct 2026 21:32:41 GMT");
        assert_eq!(
            content_type(Path::new("a.txt"), b""),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("x"), b"hello"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("x"), b"\0\x01"),
            "application/octet-stream"
        );
        let r = |s: &'static str| range(Some(&HeaderValue::from_static(s)), 10);
        assert_eq!(r("bytes=2-4"), Some((2, 4)));
        assert_eq!(r("bytes=-3"), Some((7, 9)));
        assert_eq!(r("bytes=8-"), Some((8, 9)));
        assert_eq!(r("bytes=20-"), None);
        assert_eq!(r("bytes=1-2,4-5"), None);
    }
}
