// SPDX-License-Identifier: Apache-2.0
//! `flowmesh bugreport`: a local diagnostic bundle. It is written to a file the user hands over (or
//! not); nothing is ever uploaded (design doc §7.4). Keys are shortened so the bundle identifies
//! nodes for debugging without carrying full key material.

use serde_json::{Map, Value, json};

/// Key prefixes whose hex payload is shortened.
const KEY_PREFIXES: [&str; 4] = ["nodekey:", "discokey:", "mkey:", "privkey:"];
/// How many hex digits of a key survive redaction.
const KEPT: usize = 8;

/// Shorten every `<prefix><64 hex>` to `<prefix><first 8>…`.
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    'scan: while !rest.is_empty() {
        for p in KEY_PREFIXES {
            if let Some(after) = rest.strip_prefix(p) {
                let hex = after.bytes().take_while(u8::is_ascii_hexdigit).count();
                if hex == 64 {
                    out.push_str(p);
                    out.push_str(&after[..KEPT]);
                    out.push('…');
                    rest = &after[64..];
                    continue 'scan;
                }
            }
        }
        let mut chars = rest.chars();
        if let Some(c) = chars.next() {
            out.push(c);
        }
        rest = chars.as_str();
    }
    out
}

/// One collected item: its output, or why it could not be collected.
pub struct Section {
    pub name: &'static str,
    pub content: Result<String, String>,
}

/// Assemble the bundle. `status`/`prefs` come from the daemon (or the error reaching it).
pub fn assemble(
    version: &str,
    created_unix: u64,
    status: Result<Value, String>,
    prefs: Result<Value, String>,
    sections: Vec<Section>,
) -> Value {
    let as_redacted_json = |r: Result<Value, String>| match r {
        Ok(v) => serde_json::from_str::<Value>(&redact(&v.to_string()))
            .unwrap_or_else(|e| json!({ "error": e.to_string() })),
        Err(e) => json!({ "error": e }),
    };
    let mut system = Map::new();
    for s in sections {
        let v = match s.content {
            Ok(text) => Value::from(redact(&text)),
            Err(e) => json!({ "error": e }),
        };
        system.insert(s.name.to_string(), v);
    }
    json!({
        "flowmesh_bugreport": 1,
        "cli_version": version,
        "created_unix": created_unix,
        "note": "Generated locally; nothing was sent anywhere. Keys are shortened.",
        "status": as_redacted_json(status),
        "prefs": as_redacted_json(prefs),
        "system": Value::Object(system),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "c7a7ea9b742c5d2960f1e11d6361da70f733b01db9bf854e4107571ff215e350";

    #[test]
    fn keys_are_shortened() {
        let text = format!("peer nodekey:{HEX} disco discokey:{HEX}, m mkey:{HEX}.");
        assert_eq!(
            redact(&text),
            "peer nodekey:c7a7ea9b… disco discokey:c7a7ea9b…, m mkey:c7a7ea9b…."
        );
        assert_eq!(redact(&format!("privkey:{HEX}")), "privkey:c7a7ea9b…");
    }

    #[test]
    fn non_keys_are_left_alone() {
        for t in [
            "nodekey:abc",          // too short
            "nodekey:",             // nothing after
            "100.64.0.1 ts1 linux", // plain text
            "nodekey:zz",           // not hex
            "héllo nodekey wörld",  // multibyte text around a bare word
        ] {
            assert_eq!(redact(t), t, "{t}");
        }
        // 65 hex digits is not a key.
        let long = format!("nodekey:{HEX}0");
        assert_eq!(redact(&long), long);
    }

    #[test]
    fn bundle_shape_and_redaction() {
        let status = Ok(json!({ "Self": { "PublicKey": format!("nodekey:{HEX}") } }));
        let v = assemble(
            "0.1.0",
            42,
            status,
            Err("cannot reach flowmeshd".into()),
            vec![
                Section {
                    name: "ip_addr",
                    content: Ok(format!("x nodekey:{HEX}")),
                },
                Section {
                    name: "journal",
                    content: Err("permission denied".into()),
                },
            ],
        );
        assert_eq!(v["flowmesh_bugreport"], 1);
        assert_eq!(v["created_unix"], 42);
        assert_eq!(v["status"]["Self"]["PublicKey"], "nodekey:c7a7ea9b…");
        assert_eq!(v["prefs"]["error"], "cannot reach flowmeshd");
        assert_eq!(v["system"]["ip_addr"], "x nodekey:c7a7ea9b…");
        assert_eq!(v["system"]["journal"]["error"], "permission denied");
        assert!(!v.to_string().contains(HEX));
    }
}
