// SPDX-License-Identifier: Apache-2.0
//! Encrypted record layer after the handshake completes (control.md §4).
//!
//! Keys come from the Noise handshake split; the cipher is ChaCha20-Poly1305. The nonce is 4 zero bytes
//! followed by an **8-byte big-endian** counter, not the little-endian encoding of the Noise spec. Evidence:
//! with little-endian encoding the real server's second record fails to decrypt (both encodings agree for
//! nonce 0 and differ from 1 on); see the observation in control.md §4.

use crate::Error;
use crate::frame::{self, Frame, FrameType};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// Length of the ChaChaPoly authentication tag.
pub const TAG_LEN: usize = 16;
/// Maximum plaintext that fits in one frame.
pub const MAX_PLAINTEXT_PER_FRAME: usize = frame::MAX_FRAME_PAYLOAD - TAG_LEN;

/// Builds the 12-byte nonce: 4 zero bytes + 8-byte big-endian counter.
pub fn nonce_bytes(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

struct CipherState {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl CipherState {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            counter: 0,
        }
    }

    fn next_nonce(&mut self) -> Result<[u8; 12], Error> {
        let n = nonce_bytes(self.counter);
        // Refuse to continue once the counter is exhausted; never reuse a nonce.
        self.counter = self.counter.checked_add(1).ok_or(Error::NonceExhausted)?;
        Ok(n)
    }
}

pub struct Transport {
    send: CipherState,
    recv: CipherState,
}

impl Transport {
    /// Built from the two keys of the split: `send` encrypts what this side sends, `recv` decrypts the peer.
    pub fn from_raw_split(send: [u8; 32], recv: [u8; 32]) -> Self {
        Self {
            send: CipherState::new(send),
            recv: CipherState::new(recv),
        }
    }

    /// Encrypts plaintext of any length, slicing it at the frame limit into consecutive record frames.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(plaintext.len() + plaintext.len() / 64 + 32);
        for chunk in plaintext.chunks(MAX_PLAINTEXT_PER_FRAME) {
            let nonce = self.send.next_nonce()?;
            let ct = self
                .send
                .cipher
                .encrypt(Nonce::from_slice(&nonce), chunk)
                .map_err(|_| Error::Decrypt)?;
            out.extend(frame::encode(FrameType::Record, &ct)?);
        }
        Ok(out)
    }

    /// Decrypts one record frame.
    pub fn open(&mut self, frame: Frame) -> Result<Vec<u8>, Error> {
        if frame.ty != FrameType::Record {
            return Err(Error::UnexpectedFrame(frame.ty));
        }
        let nonce = self.recv.next_nonce()?;
        self.recv
            .cipher
            .decrypt(Nonce::from_slice(&nonce), frame.payload.as_slice())
            .map_err(|_| Error::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_layout_is_big_endian_counter() {
        assert_eq!(nonce_bytes(0), [0; 12]);
        assert_eq!(nonce_bytes(1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            nonce_bytes(0x0102),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02]
        );
    }

    /// The second record only opens with the big-endian nonce for counter 1: encrypt with an independently
    /// built nonce and let Transport decrypt it, so that "both ends share one implementation and the same
    /// mistake" cannot pass.
    #[test]
    fn second_record_uses_big_endian_nonce_one() {
        let key = [7u8; 32];
        let peer = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut t = Transport::from_raw_split([9u8; 32], key);
        for (counter, msg) in [(0u64, b"first"), (1, b"other")] {
            let mut nonce = [0u8; 12];
            nonce[11] = counter as u8;
            let ct = peer.encrypt(Nonce::from_slice(&nonce), &msg[..]).unwrap();
            let f = Frame {
                ty: FrameType::Record,
                payload: ct,
            };
            assert_eq!(t.open(f).unwrap(), msg);
        }
    }
}
