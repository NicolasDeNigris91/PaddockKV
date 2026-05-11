//! HKDF-SHA256 key derivation.
//!
//! The engine never uses the user-supplied master key directly. Instead,
//! [`derive_sstable_key`] produces a per-SSTable subkey by running the
//! master key through HKDF with the SSTable's file number as the `info`
//! parameter. The result is a fresh 32-byte AES-256-GCM key whose bit
//! distribution is indistinguishable from random under the standard HKDF
//! security assumption.
//!
//! Splitting the key namespace this way has three concrete benefits:
//!
//! 1. **Nonce reuse becomes structurally impossible.** Because every
//!    SSTable has its own key, the per-block nonce only has to be unique
//!    *within* a single SSTable — and we get that for free from the
//!    monotonic block offset.
//! 2. **Compromise containment.** If a single per-SSTable key leaks (e.g.
//!    via a side channel during decompression), only that SSTable's
//!    contents are exposed. The master key never appears in cipher
//!    operations.
//! 3. **Key rotation pathway.** Future versions can stage rotation: emit
//!    new SSTables under a fresh master key while old SSTables remain
//!    readable with the previous one.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::aead::{AeadKey, KEY_LEN};

/// Wrapper around the user's master key. Distinct from
/// [`AeadKey`](crate::crypto::aead::AeadKey) so the type system enforces
/// "never encrypt with the master key directly".
#[derive(Clone)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    /// Construct a master key from raw bytes. The bytes must come from a
    /// cryptographically-secure source (operator-supplied secret, HSM
    /// export, KMS unwrap, etc.).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes. Treat the byte view as secret.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key bytes.
        f.debug_struct("MasterKey")
            .field("len", &KEY_LEN)
            .finish_non_exhaustive()
    }
}

/// Domain-separation prefix used as the `info` input to HKDF when
/// deriving per-SSTable keys.
const SSTABLE_INFO_PREFIX: &[u8] = b"paddockkv:sstable:v1:";

/// Derive a per-SSTable AES-256-GCM key from the master key. The
/// `sstable_id` is folded into HKDF's `info` parameter, so two SSTables
/// with distinct ids always yield distinct keys.
#[must_use]
pub fn derive_sstable_key(master: &MasterKey, sstable_id: u64) -> AeadKey {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    // info = "paddockkv:sstable:v1:" || sstable_id (LE bytes).
    let mut info = Vec::with_capacity(SSTABLE_INFO_PREFIX.len() + 8);
    info.extend_from_slice(SSTABLE_INFO_PREFIX);
    info.extend_from_slice(&sstable_id.to_le_bytes());
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm)
        .expect("HKDF expand cannot fail for 32-byte output");
    AeadKey::from_bytes(okm)
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
    fn different_sstable_ids_produce_different_keys() {
        let master = MasterKey::from_bytes([0xAB; KEY_LEN]);
        let a = derive_sstable_key(&master, 1);
        let b = derive_sstable_key(&master, 2);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn same_sstable_id_is_deterministic() {
        let master = MasterKey::from_bytes([0xCC; KEY_LEN]);
        let a = derive_sstable_key(&master, 42);
        let b = derive_sstable_key(&master, 42);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_masters_produce_different_keys() {
        let m1 = MasterKey::from_bytes([1; KEY_LEN]);
        let m2 = MasterKey::from_bytes([2; KEY_LEN]);
        assert_ne!(
            derive_sstable_key(&m1, 0).as_bytes(),
            derive_sstable_key(&m2, 0).as_bytes()
        );
    }

    /// RFC 5869 Test Case 1: HKDF-SHA256 with the canonical reference
    /// inputs. Confirms the underlying `hkdf` crate matches the standard
    /// bit-for-bit; the wrapper does not modify the cryptographic core.
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex("3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865");

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = vec![0u8; expected.len()];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(okm, expected);
    }
}
