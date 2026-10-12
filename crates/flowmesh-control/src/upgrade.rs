// SPDX-License-Identifier: Apache-2.0
//! HTTP/1.1 protocol upgrade request and response (control.md §2, observed).

use crate::Error;

pub const UPGRADE_PROTOCOL: &str = "tailscale-control-protocol";
pub const HANDSHAKE_HEADER: &str = "X-Tailscale-Handshake";

/// Builds the upgrade request. `host` goes into the Host header; `handshake_b64` is the base64-encoded initiation message.
pub fn build_request(host: &str, handshake_b64: &str) -> String {
    format!(
        "POST /ts2021 HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Length: 0\r\n\
         Connection: upgrade\r\n\
         Upgrade: {UPGRADE_PROTOCOL}\r\n\
         {HANDSHAKE_HEADER}: {handshake_b64}\r\n\
         \r\n"
    )
}

/// Finds the end of the response headers in the buffer; when found and the status is 101, returns the
/// header length (including the blank line). Any other status returns an error carrying the status line.
pub fn parse_response(buf: &[u8]) -> Result<Option<usize>, Error> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let head = String::from_utf8_lossy(&buf[..end]);
    let status_line = head.lines().next().unwrap_or_default();
    let code = status_line.split_whitespace().nth(1);
    if code != Some("101") {
        return Err(Error::Protocol(format!("upgrade rejected: {status_line}")));
    }
    Ok(Some(end + 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compares against the header set of the client request in OBS-20261010-control-handshake/framing-summary.json
    /// (User-Agent and the port form of Host are not compared).
    #[test]
    fn request_headers_match_observation() {
        let summary: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/observed/20261010-control-handshake/framing-summary.json"
        ))
        .unwrap();
        let client = &summary["directions"]["client"];
        assert_eq!(client["http_start_line"], "POST /ts2021 HTTP/1.1");
        let observed: Vec<String> = client["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap().split(':').next().unwrap().to_string())
            .filter(|n| n != "User-Agent")
            .collect();

        let req = build_request("headscale.lab", "QUJD");
        let mut lines = req.split("\r\n");
        assert_eq!(lines.next(), Some("POST /ts2021 HTTP/1.1"));
        let ours: Vec<String> = lines
            .take_while(|l| !l.is_empty())
            .map(|l| l.split(':').next().unwrap().to_string())
            .collect();
        let mut a = observed.clone();
        let mut b = ours.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b);
        assert!(req.ends_with("\r\n\r\n"));
        assert!(req.contains("Upgrade: tailscale-control-protocol\r\n"));
        assert!(req.contains("X-Tailscale-Handshake: QUJD\r\n"));
    }

    #[test]
    fn response_101_returns_header_length() {
        let raw = b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n\x02\x00\x30";
        assert_eq!(parse_response(raw).unwrap(), Some(raw.len() - 3));
    }

    #[test]
    fn incomplete_response_needs_more() {
        assert_eq!(parse_response(b"HTTP/1.1 101 Switch").unwrap(), None);
    }

    #[test]
    fn non_101_is_an_error_with_status_line() {
        let err = parse_response(b"HTTP/1.1 500 Internal\r\n\r\nboom").unwrap_err();
        assert!(err.to_string().contains("HTTP/1.1 500 Internal"), "{err}");
    }
}
