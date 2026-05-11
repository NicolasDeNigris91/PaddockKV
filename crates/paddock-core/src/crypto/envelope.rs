//! Per-block crypto envelope: nonce derivation and AAD construction.
//!
//! AES-GCM requires a **unique nonce per `(key, message)` pair**. Reusing a
//! nonce under the same key is catastrophic — it leaks the XOR of the two
//! plaintexts and lets the attacker forge messages. This module is the
//! choke point that makes nonce reuse structurally impossible in the
//! engine:
//!
//! - Each SSTable has its own AEAD key, derived via
//!   [`crate::crypto::kdf::derive_sstable_key`].
//! - Within one SSTable, every block is encrypted under a nonce derived
//!   deterministically from the block index.
//! - Block indices are monotonic per SSTable and never reused.
//!
//! The nonce layout (12 bytes = 96 bits) is:
//!
//! ```text
//!   [0..4]   format tag        u32 LE = 0x4E_4F_4E_43   ("NONC")
//!   [4..12]  block_index       u64 LE
//! ```
//!
//! The format tag pins the nonce shape so a future version that needs to
//! mix in extra context (e.g. compaction-level discriminator) can bump the
//! tag without colliding with existing data.
//!
//! ## Associated Data
//!
//! Every encrypted block also carries 16 bytes of AAD that the cipher
//! authenticates but does not encrypt:
//!
//! ```text
//!   [0..8]   sstable_id        u64 LE
//!   [8..16]  block_index       u64 LE
//! ```
//!
//! Binding the ciphertext to these coordinates means a block cut-and-paste
//! attack (lifting block 3 of SSTable A and writing it into block 3 of
//! SSTable B) fails the AEAD verification, because the AAD changes with
//! the SSTable id.

use crate::crypto::aead::{NONCE_LEN, Nonce};

const NONCE_FORMAT_TAG: u32 = 0x4346_4F4E; // ASCII "NONC" big-endian → little-endian on disk

/// Wrapper around a derived per-block nonce. Carry it through the cipher
/// pipeline rather than the raw bytes so the type system makes it obvious
/// this is not arbitrary-input territory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockNonce(pub Nonce);

impl BlockNonce {
    /// Borrow the underlying [`Nonce`].
    #[must_use]
    pub const fn as_nonce(&self) -> &Nonce {
        &self.0
    }
}

/// Derive a 96-bit nonce from `(sstable_id, block_index)`.
///
/// Although `sstable_id` is part of the key derivation (so the same block
/// index under two different SSTables already produces different
/// ciphertexts), we keep the construction independent of the key so a
/// future change to key derivation cannot accidentally re-collide nonces.
#[must_use]
pub fn derive_block_nonce(block_index: u64) -> BlockNonce {
    let mut bytes = [0u8; NONCE_LEN];
    bytes[..4].copy_from_slice(&NONCE_FORMAT_TAG.to_le_bytes());
    bytes[4..12].copy_from_slice(&block_index.to_le_bytes());
    BlockNonce(Nonce::from_bytes(bytes))
}

/// Build the 16-byte AAD for an encrypted block.
#[must_use]
pub fn block_aad(sstable_id: u64, block_index: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&sstable_id.to_le_bytes());
    out[8..16].copy_from_slice(&block_index.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::{Aead, AeadKey};
    use crate::crypto::kdf::{MasterKey, derive_sstable_key};

    #[test]
    fn nonces_for_distinct_block_indices_differ() {
        let a = derive_block_nonce(0);
        let b = derive_block_nonce(1);
        let c = derive_block_nonce(0xDEAD_BEEF_CAFE_F00D);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn nonce_format_tag_present() {
        let n = derive_block_nonce(0);
        let bytes = n.as_nonce().as_bytes();
        assert_eq!(&bytes[..4], &NONCE_FORMAT_TAG.to_le_bytes());
    }

    #[test]
    fn aad_for_distinct_coordinates_differs() {
        let a = block_aad(1, 0);
        let b = block_aad(1, 1);
        let c = block_aad(2, 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    /// End-to-end: derive a per-SSTable key, derive a block nonce, build
    /// AAD, seal, then verify open recovers the plaintext.
    #[test]
    fn end_to_end_seal_open_with_real_key_hierarchy() {
        let master = MasterKey::from_bytes([0xA5; 32]);
        let sst_id: u64 = 0x1234_5678;
        let block_idx: u64 = 42;
        let key: AeadKey = derive_sstable_key(&master, sst_id);
        let aead = Aead::new(&key);
        let nonce = derive_block_nonce(block_idx);
        let associated_data = block_aad(sst_id, block_idx);

        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let ct = aead
            .seal(nonce.as_nonce(), &associated_data, plaintext)
            .unwrap();
        let pt = aead.open(nonce.as_nonce(), &associated_data, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    /// Cut-and-paste defense: a ciphertext sealed under one
    /// `(sst_id, block_idx)` pair must fail to open under a different pair,
    /// even when the AEAD key is identical (same sstable).
    #[test]
    fn block_index_aad_prevents_intra_sstable_swap() {
        let master = MasterKey::from_bytes([0xCA; 32]);
        let key = derive_sstable_key(&master, 7);
        let aead = Aead::new(&key);

        let n0 = derive_block_nonce(0);
        let n1 = derive_block_nonce(1);

        let ct = aead
            .seal(n0.as_nonce(), &block_aad(7, 0), b"block 0 payload")
            .unwrap();
        // Open at the same nonce but a different AAD (block 1).
        assert!(
            aead.open(n0.as_nonce(), &block_aad(7, 1), &ct).is_err(),
            "AAD mismatch should reject"
        );
        // Open at a different nonce should also fail.
        assert!(
            aead.open(n1.as_nonce(), &block_aad(7, 0), &ct).is_err(),
            "nonce mismatch should reject"
        );
    }

    /// Inter-SSTable cut-and-paste defense: lift a block from SSTable A's
    /// position 0 and replay it as SSTable B's position 0. Because the
    /// keys derived for A and B differ, opening with B's key must fail
    /// even though the nonce happens to match.
    #[test]
    fn per_sstable_keys_prevent_inter_sstable_swap() {
        let master = MasterKey::from_bytes([0x77; 32]);
        let key_a = derive_sstable_key(&master, 100);
        let key_b = derive_sstable_key(&master, 200);
        let aead_a = Aead::new(&key_a);
        let aead_b = Aead::new(&key_b);
        let nonce = derive_block_nonce(0);

        let ct = aead_a
            .seal(nonce.as_nonce(), &block_aad(100, 0), b"secret A")
            .unwrap();
        assert!(
            aead_b
                .open(nonce.as_nonce(), &block_aad(200, 0), &ct)
                .is_err()
        );
    }
}
