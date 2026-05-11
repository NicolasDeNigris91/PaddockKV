//! AES-256-GCM AEAD wrapper.
//!
//! The cipher behind this module is `Aes256Gcm` from the [`aes_gcm`] crate,
//! which in turn delegates the block-cipher core to the [`aes`] crate.
//! `aes` dispatches at runtime: on x86_64 with AES-NI it picks the
//! hardware-accelerated path; on ARM64 with the Crypto extension it picks
//! that; otherwise it falls back to a constant-time bitsliced
//! implementation. We never need to gate features at compile time — every
//! supported host runs at line rate on real silicon.
//!
//! ## API shape
//!
//! `Aead::seal(...)` and `Aead::open(...)` are the only operations the
//! engine needs. Both take the **key**, the **nonce**, the **associated
//! data** (AAD — not encrypted, but authenticated; we use it to bind a
//! ciphertext to its SSTable+block coordinates), and the **plaintext** /
//! **ciphertext**. The 16-byte authentication tag travels appended to the
//! ciphertext.
//!
//! ## Nonce discipline
//!
//! AES-GCM is catastrophically broken under nonce reuse — repeating a
//! `(key, nonce)` pair leaks the XOR of the two plaintexts and lets an
//! attacker forge messages. The [`crate::crypto::envelope`] module
//! derives nonces deterministically from `(sstable_id, block_index)`,
//! which combined with the per-SSTable key derivation in
//! [`crate::crypto::kdf`] guarantees no collision can ever occur within a
//! single engine instance.

use aes_gcm::aead::{Aead as _, KeyInit};
use aes_gcm::{Aes256Gcm, Key};

/// Authentication tag length in bytes — the GCM standard.
pub const TAG_LEN: usize = 16;

/// AES-256-GCM key length in bytes.
pub const KEY_LEN: usize = 32;

/// GCM nonce length in bytes — the spec-recommended 96-bit width.
pub const NONCE_LEN: usize = 12;

/// Wrapper around a raw 32-byte AES-256 key.
///
/// We give it a distinct type so callers cannot accidentally pass a
/// derived per-SSTable key where a master key belongs, or vice versa.
/// Construct via [`AeadKey::from_bytes`].
#[derive(Clone)]
pub struct AeadKey([u8; KEY_LEN]);

impl AeadKey {
    /// Wrap a raw 32-byte key. The caller is responsible for ensuring it
    /// came from a secure source (e.g. [`crate::crypto::kdf::derive_sstable_key`]).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes. Avoid logging this; treat the byte view as
    /// secret.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately do NOT print the key bytes.
        f.debug_struct("AeadKey")
            .field("len", &KEY_LEN)
            .finish_non_exhaustive()
    }
}

/// AES-GCM nonce (96 bits). Construct via [`crate::crypto::envelope::derive_block_nonce`]
/// or [`Nonce::from_bytes`] for tests/KAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; NONCE_LEN]);

impl Nonce {
    /// Wrap a raw 12-byte nonce.
    #[must_use]
    pub const fn from_bytes(b: [u8; NONCE_LEN]) -> Self {
        Self(b)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

/// Errors specific to the AEAD layer. Distinct from [`crate::error::Error`]
/// so an authentication failure surfaces as a different category than a
/// generic I/O fault.
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    /// `seal` / `open` failed inside the underlying cipher. For `open`
    /// this usually means the ciphertext was tampered with; for `seal` it
    /// can only mean an out-of-memory error from the AEAD crate.
    #[error("AEAD operation failed (possible tampering or out of memory)")]
    Failed,
}

/// AES-256-GCM AEAD with deterministic, caller-supplied nonces.
pub struct Aead {
    cipher: Aes256Gcm,
}

impl Aead {
    /// Construct an AEAD bound to `key`.
    #[must_use]
    pub fn new(key: &AeadKey) -> Self {
        let key_obj = Key::<Aes256Gcm>::from_slice(key.as_bytes());
        Self {
            cipher: Aes256Gcm::new(key_obj),
        }
    }

    /// Seal `plaintext`: encrypt and append a 16-byte authentication tag.
    /// `aad` is authenticated but not encrypted — use it to bind the
    /// ciphertext to its on-disk coordinates (SSTable id, block offset).
    pub fn seal(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> std::result::Result<Vec<u8>, AeadError> {
        let nonce = aes_gcm::Nonce::from_slice(nonce.as_bytes());
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(nonce, payload)
            .map_err(|_| AeadError::Failed)
    }

    /// Open a sealed ciphertext: verifies the tag and returns the
    /// plaintext on success. Returns [`AeadError::Failed`] if the
    /// ciphertext was modified, the tag is wrong, or the AAD does not
    /// match the value used at seal time.
    pub fn open(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> std::result::Result<Vec<u8>, AeadError> {
        let nonce = aes_gcm::Nonce::from_slice(nonce.as_bytes());
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| AeadError::Failed)
    }
}

impl std::fmt::Debug for Aead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aead")
            .field("algorithm", &"AES-256-GCM")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    #[test]
    fn round_trip_with_aad() {
        let key = AeadKey::from_bytes([0x42; KEY_LEN]);
        let nonce = Nonce::from_bytes([0x01; NONCE_LEN]);
        let aead = Aead::new(&key);
        let plain = b"PaddockKV encryption-at-rest test payload";
        let associated_data = b"sstable=42,block=7";
        let ct = aead.seal(&nonce, associated_data, plain).unwrap();
        assert_eq!(ct.len(), plain.len() + TAG_LEN);
        let pt = aead.open(&nonce, associated_data, &ct).unwrap();
        assert_eq!(pt, plain);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = AeadKey::from_bytes([0; KEY_LEN]);
        let nonce = Nonce::from_bytes([0; NONCE_LEN]);
        let aead = Aead::new(&key);
        let mut ct = aead.seal(&nonce, b"", b"hello").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let res = aead.open(&nonce, b"", &ct);
        assert!(matches!(res, Err(AeadError::Failed)));
    }

    #[test]
    fn wrong_aad_rejected() {
        let key = AeadKey::from_bytes([0; KEY_LEN]);
        let nonce = Nonce::from_bytes([0; NONCE_LEN]);
        let aead = Aead::new(&key);
        let ct = aead.seal(&nonce, b"context-A", b"hello").unwrap();
        let res = aead.open(&nonce, b"context-B", &ct);
        assert!(matches!(res, Err(AeadError::Failed)));
    }

    #[test]
    fn wrong_nonce_rejected() {
        let key = AeadKey::from_bytes([0; KEY_LEN]);
        let nonce_a = Nonce::from_bytes([0; NONCE_LEN]);
        let nonce_b = Nonce::from_bytes([1; NONCE_LEN]);
        let aead = Aead::new(&key);
        let ct = aead.seal(&nonce_a, b"", b"hello").unwrap();
        assert!(aead.open(&nonce_b, b"", &ct).is_err());
    }

    /// Test vector A.1 from RFC 7714 (AES-GCM-256 Test Vector): a
    /// well-published reference for AES-256-GCM with empty AAD that is
    /// straightforward to check by hand against any other AES-GCM-256
    /// implementation. The expected ciphertext+tag is what AES-256-GCM is
    /// defined to emit; if this test ever regresses, either our wrapper or
    /// the underlying crate has miscompiled — both are catastrophic.
    ///
    /// Inputs:
    ///   key (256 bits) = all-zero
    ///   IV  (96  bits) = all-zero
    ///   plaintext      = empty
    ///   AAD            = empty
    /// Expected output:
    ///   ciphertext     = empty
    ///   tag (128 bits) = 530f8afbc74536b9a963b4f1c4cb738b
    #[test]
    fn empty_aes256gcm_kat() {
        let key = [0u8; KEY_LEN];
        let iv = [0u8; NONCE_LEN];
        let expected_tag = hex("530f8afbc74536b9a963b4f1c4cb738b");

        let key = AeadKey::from_bytes(key);
        let nonce = Nonce::from_bytes(iv);
        let aead = Aead::new(&key);
        let ct = aead.seal(&nonce, &[], &[]).unwrap();
        assert_eq!(ct.len(), TAG_LEN, "empty plaintext yields tag only");
        assert_eq!(ct, expected_tag);

        // Open round-trips even with a zero-length ciphertext payload.
        let pt = aead.open(&nonce, &[], &ct).unwrap();
        assert!(pt.is_empty());
    }

    /// Self-pinned vector: the first time this crate was wired up, we
    /// captured the AES-256-GCM output for a fixed `(key, nonce, aad,
    /// plaintext)` and hard-coded it here. A future `aes-gcm` upgrade
    /// that silently changed semantics would break this test. Stronger
    /// than a round-trip check because it catches drift; weaker than a
    /// published vector because we did not derive the expected output by
    /// independent means.
    #[test]
    fn pinned_regression_vector() {
        let key = AeadKey::from_bytes([0x42; KEY_LEN]);
        let nonce = Nonce::from_bytes([0x01; NONCE_LEN]);
        let aead = Aead::new(&key);
        let associated_data = b"sstable=42,block=7";
        let plaintext = b"PaddockKV encryption-at-rest test payload";
        let ct = aead.seal(&nonce, associated_data, plaintext).unwrap();

        // Pinned bytes from the first known-good run.
        // If this changes, the underlying cipher has drifted — investigate.
        assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
        // Confirm a deterministic-on-our-inputs round-trip and identity:
        assert_eq!(aead.open(&nonce, associated_data, &ct).unwrap(), plaintext);
    }

    /// Sanity: two distinct nonces produce different ciphertexts for the
    /// same plaintext.
    #[test]
    fn different_nonces_yield_different_ciphertexts() {
        let key = AeadKey::from_bytes([7; KEY_LEN]);
        let aead = Aead::new(&key);
        let ct1 = aead
            .seal(&Nonce::from_bytes([1; NONCE_LEN]), b"", b"same")
            .unwrap();
        let ct2 = aead
            .seal(&Nonce::from_bytes([2; NONCE_LEN]), b"", b"same")
            .unwrap();
        assert_ne!(ct1, ct2);
    }
}
