// SPDX-License-Identifier: Apache-2.0
//! disco envelope: 6-byte magic + 32-byte sender disco public key + 24-byte nonce + NaCl box (disco.md §1).

use crate::Error;
use crypto_box::aead::Aead;
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use flowmesh_proto::key::{DiscoPrivate, DiscoPublic};

/// Observed at the start of every disco message: ASCII "TS" followed by the UTF-8 encoding of 💬 (OBS-…-disco).
pub const MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac];
pub const NONCE_LEN: usize = 24;
pub const HEADER_LEN: usize = MAGIC.len() + 32 + NONCE_LEN;

pub fn is_disco(b: &[u8]) -> bool {
    b.starts_with(&MAGIC)
}

/// Read the sender's disco public key (without decrypting).
pub fn sender(b: &[u8]) -> Result<DiscoPublic, Error> {
    if !is_disco(b) {
        return Err(Error::NotDisco);
    }
    let key: [u8; 32] = b
        .get(MAGIC.len()..MAGIC.len() + 32)
        .and_then(|k| k.try_into().ok())
        .ok_or(Error::Truncated)?;
    Ok(DiscoPublic(key))
}

/// Decrypt with our disco private key and the sender public key from the envelope; return (sender, plaintext payload).
pub fn open(me: &DiscoPrivate, b: &[u8]) -> Result<(DiscoPublic, Vec<u8>), Error> {
    let from = sender(b)?;
    if b.len() < HEADER_LEN {
        return Err(Error::Truncated);
    }
    let nonce: [u8; NONCE_LEN] = b[MAGIC.len() + 32..HEADER_LEN]
        .try_into()
        .map_err(|_| Error::Truncated)?;
    let plain = salsa(me, &from)
        .decrypt((&nonce).into(), &b[HEADER_LEN..])
        .map_err(|_| Error::Crypto)?;
    Ok((from, plain))
}

/// Seal a payload with our disco private key for the recipient `to`.
pub fn seal(
    me: &DiscoPrivate,
    to: &DiscoPublic,
    payload: &[u8],
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, Error> {
    let sealed = salsa(me, to)
        .encrypt((&nonce).into(), payload)
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&me.public().0);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn salsa(me: &DiscoPrivate, peer: &DiscoPublic) -> SalsaBox {
    SalsaBox::new(&PublicKey::from(peer.0), &SecretKey::from(*me.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_layout_and_independent_open() {
        let (a, b) = (
            DiscoPrivate::generate().unwrap(),
            DiscoPrivate::generate().unwrap(),
        );
        let msg = seal(&a, &b.public(), b"\x01\x00hello", [9; NONCE_LEN]).unwrap();
        assert!(is_disco(&msg));
        assert_eq!(&msg[6..38], &a.public().0);
        assert_eq!(&msg[38..62], &[9; NONCE_LEN]);
        // Open with an independently built box, from the recipient's point of view.
        let bx = SalsaBox::new(
            &PublicKey::from(a.public().0),
            &SecretKey::from(*b.as_bytes()),
        );
        let plain = bx
            .decrypt((&[9u8; NONCE_LEN]).into(), &msg[HEADER_LEN..])
            .unwrap();
        assert_eq!(plain, b"\x01\x00hello");
    }

    #[test]
    fn open_roundtrip_sender_and_rejections() {
        let (a, b) = (
            DiscoPrivate::generate().unwrap(),
            DiscoPrivate::generate().unwrap(),
        );
        let msg = seal(&a, &b.public(), b"payload", [1; NONCE_LEN]).unwrap();
        assert_eq!(sender(&msg).unwrap(), a.public());
        assert_eq!(open(&b, &msg).unwrap(), (a.public(), b"payload".to_vec()));
        let mut bad = msg.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(open(&b, &bad), Err(Error::Crypto));
        assert_eq!(open(&b, &msg[..HEADER_LEN - 1]), Err(Error::Truncated));
        assert_eq!(open(&b, b"\x04\x00\x00\x00wireguard"), Err(Error::NotDisco));
        let stranger = DiscoPrivate::generate().unwrap();
        assert_eq!(open(&stranger, &msg), Err(Error::Crypto));
    }
}
