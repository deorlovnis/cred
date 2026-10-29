//! Sealing: authenticated encryption of small secrets that cred keeps inside a box's store (the
//! CA's key, sealed sessions), so they stay ciphertext even while the store is open.
//!
//! XChaCha20-Poly1305 with a random 192-bit nonce. The key is derived from the box key for one
//! purpose (see `derive`), and the purpose is also bound into every ciphertext, so a sealed
//! blob can't be opened as, or swapped for, another kind of blob.

use std::fs::File;
use std::io::Read;

use anyhow::{Result, anyhow};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

const NONCE: usize = 24;
const LABEL: &[u8] = b"cred box key v1";

/// A key for one purpose (`"ca"`, `"log"`, ...), derived from the box key. Different purposes
/// give unrelated keys.
pub fn derive(box_key: &[u8], purpose: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(LABEL);
    hash.update((purpose.len() as u64).to_be_bytes());
    hash.update(purpose);
    hash.update(box_key);
    hash.finalize().into()
}

/// Encrypt and authenticate `plaintext`. The result is the nonce followed by the ciphertext.
pub fn seal(key: &[u8; 32], purpose: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE];
    File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut nonce)).expect("reading /dev/urandom");
    let cipher = XChaCha20Poly1305::new(key.into());
    let sealed = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: purpose.as_bytes() })
        .expect("encrypting in memory");
    [nonce.as_slice(), &sealed].concat()
}

/// Decrypt what `seal` made. Fails for another key, another purpose, or any change to the bytes.
pub fn open(key: &[u8; 32], purpose: &str, sealed: &[u8]) -> Result<Vec<u8>> {
    let (nonce, ciphertext) = sealed.split_at_checked(NONCE).ok_or_else(|| anyhow!("sealed data is too short"))?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(&XNonce::try_from(nonce).expect("a nonce-sized slice"), Payload { msg: ciphertext, aad: purpose.as_bytes() })
        .map_err(|_| anyhow!("can't open the sealed {purpose}: wrong key, or it was changed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_blob_opens_with_the_same_key_and_purpose() {
        let key = derive(b"box key", "ca");
        let sealed = seal(&key, "ca", b"secret bytes");
        assert!(!sealed.windows(12).any(|w| w == b"secret bytes"));
        assert_eq!(open(&key, "ca", &sealed).unwrap(), b"secret bytes");
        assert_eq!(open(&key, "ca", &seal(&key, "ca", b"")).unwrap(), b"");
    }

    #[test]
    fn nothing_is_repeated_between_seals() {
        let key = derive(b"box key", "ca");
        assert_ne!(seal(&key, "ca", b"same"), seal(&key, "ca", b"same"));
    }

    #[test]
    fn another_key_or_purpose_cannot_open_it() {
        let key = derive(b"box key", "ca");
        let sealed = seal(&key, "ca", b"secret");
        assert!(open(&derive(b"other key", "ca"), "ca", &sealed).is_err());
        assert!(open(&derive(b"box key", "log"), "log", &sealed).is_err());
        // The right key with the wrong purpose label: the purpose is bound into the ciphertext.
        let e = open(&key, "session", &sealed).unwrap_err().to_string();
        assert!(e.contains("session"), "{e}");
    }

    #[test]
    fn any_change_or_truncation_is_caught() {
        let key = derive(b"box key", "ca");
        let sealed = seal(&key, "ca", b"secret");
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(open(&key, "ca", &bad).is_err(), "byte {i} changed");
        }
        for len in [0, 5, NONCE, sealed.len() - 1] {
            assert!(open(&key, "ca", &sealed[..len]).is_err(), "cut to {len}");
        }
        let mut longer = sealed.clone();
        longer.push(0);
        assert!(open(&key, "ca", &longer).is_err());
    }

    #[test]
    fn keys_differ_by_purpose_and_box_key() {
        let a = derive(b"k", "ca");
        assert_eq!(a, derive(b"k", "ca"));
        assert_ne!(a, derive(b"k", "log"));
        assert_ne!(a, derive(b"j", "ca"));
        // The purpose and the key can't trade bytes.
        assert_ne!(derive(b"bk", "a"), derive(b"k", "ab"));
    }
}
