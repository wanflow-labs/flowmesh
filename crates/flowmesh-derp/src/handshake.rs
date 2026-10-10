// SPDX-License-Identifier: Apache-2.0
//! DERP handshake (derp.md §3): server key frame → client info (NaCl box) → server info.

use crate::Error;
use crypto_box::aead::Aead;
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use flowmesh_proto::key::{NodePrivate, NodePublic};

/// Magic at the start of the server key frame: ASCII "DERP" followed by the UTF-8 encoding of 🔑.
pub const SERVER_KEY_MAGIC: [u8; 8] = [b'D', b'E', b'R', b'P', 0xf0, 0x9f, 0x94, 0x91];
pub const NONCE_LEN: usize = 24;
/// DERP protocol version declared by the client.
pub const PROTOCOL_VERSION: u32 = 2;

pub fn parse_server_key(payload: &[u8]) -> Result<NodePublic, Error> {
    let rest = payload
        .strip_prefix(&SERVER_KEY_MAGIC[..])
        .ok_or_else(|| Error::Protocol("server key frame has wrong magic".into()))?;
    let key: [u8; 32] = rest
        .get(..32)
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| Error::Protocol("server key frame too short".into()))?;
    Ok(NodePublic(key))
}

/// JSON carried in the client info.
pub fn default_client_info() -> serde_json::Value {
    serde_json::json!({ "version": PROTOCOL_VERSION, "canAckPings": true })
}

fn salsa(me: &NodePrivate, peer: &NodePublic) -> SalsaBox {
    SalsaBox::new(&PublicKey::from(peer.0), &SecretKey::from(*me.as_bytes()))
}

/// Client info frame payload: 32-byte client public key + 24-byte nonce + sealed JSON.
pub fn client_info(
    me: &NodePrivate,
    server: &NodePublic,
    info: &serde_json::Value,
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, Error> {
    let plain = serde_json::to_vec(info).map_err(|e| Error::Protocol(e.to_string()))?;
    let sealed = salsa(me, server)
        .encrypt((&nonce).into(), plain.as_slice())
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(32 + NONCE_LEN + sealed.len());
    out.extend_from_slice(&me.public().0);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Server info frame payload: 24-byte nonce + sealed JSON.
pub fn open_server_info(
    me: &NodePrivate,
    server: &NodePublic,
    payload: &[u8],
) -> Result<serde_json::Value, Error> {
    if payload.len() < NONCE_LEN {
        return Err(Error::Protocol("server info frame too short".into()));
    }
    let (nonce, sealed) = payload.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Crypto)?;
    let plain = salsa(me, server)
        .decrypt((&nonce).into(), sealed)
        .map_err(|_| Error::Crypto)?;
    serde_json::from_slice(&plain).map_err(|e| Error::Protocol(format!("server info json: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_key_frame(key: [u8; 32]) -> Vec<u8> {
        let mut v = SERVER_KEY_MAGIC.to_vec();
        v.extend_from_slice(&key);
        v
    }

    #[test]
    fn server_key_parses_and_rejects_bad_magic_or_length() {
        assert_eq!(
            parse_server_key(&server_key_frame([7; 32])).unwrap(),
            NodePublic([7; 32])
        );
        let mut bad = server_key_frame([7; 32]);
        bad[0] = b'X';
        assert!(parse_server_key(&bad).is_err());
        assert!(parse_server_key(&server_key_frame([7; 32])[..39]).is_err());
    }

    /// Open the client info with an independently constructed box (from the server's point of view), so the test does not pass merely because both ends share the same implementation.
    #[test]
    fn client_info_opens_with_independent_box() {
        let me = NodePrivate::generate().unwrap();
        let server = NodePrivate::generate().unwrap();
        let nonce = [3u8; NONCE_LEN];
        let payload = client_info(&me, &server.public(), &default_client_info(), nonce).unwrap();
        assert_eq!(&payload[..32], &me.public().0);
        assert_eq!(&payload[32..56], &nonce);
        let server_box = SalsaBox::new(
            &PublicKey::from(me.public().0),
            &SecretKey::from(*server.as_bytes()),
        );
        let plain = server_box.decrypt((&nonce).into(), &payload[56..]).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(v["version"], 2);
    }

    #[test]
    fn server_info_roundtrip_and_tamper_detection() {
        let me = NodePrivate::generate().unwrap();
        let server = NodePrivate::generate().unwrap();
        let server_box = SalsaBox::new(
            &PublicKey::from(me.public().0),
            &SecretKey::from(*server.as_bytes()),
        );
        let nonce = [5u8; NONCE_LEN];
        let mut payload = nonce.to_vec();
        payload.extend(
            server_box
                .encrypt((&nonce).into(), &b"{\"tokenBucketBytesPerSecond\":0}"[..])
                .unwrap(),
        );
        let v = open_server_info(&me, &server.public(), &payload).unwrap();
        assert_eq!(v["tokenBucketBytesPerSecond"], 0);
        let mut tampered = payload.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open_server_info(&me, &server.public(), &tampered).is_err());
        assert!(open_server_info(&me, &server.public(), &payload[..10]).is_err());
    }
}
