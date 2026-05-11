//! Encryption-at-rest primitives.
//!
//! The engine encrypts SSTable data blocks (and, by extension, the values
//! they carry) on disk using **AES-256-GCM** — an Authenticated Encryption
//! with Associated Data (AEAD) construction that produces both
//! confidentiality and integrity in a single pass. The chosen cipher is
//! widely deployed, audited, and hardware-accelerated through AES-NI on
//! every modern x86_64 and ARM64 part. The Rust implementation we wrap
//! ([`aes_gcm`]) delegates to the [`aes`] crate, which dispatches at
//! runtime to AES-NI / ARM Crypto / a constant-time bitslice fallback.
//!
//! ## Submodules
//!
//! - [`aead`]     — AES-256-GCM wrapper with encrypt/decrypt/seal/open APIs.
//! - [`kdf`]      — HKDF-SHA256 key hierarchy: derive per-SSTable subkeys
//!   from a single master key.
//! - [`envelope`] — Per-block nonce derivation and AEAD-associated-data
//!   construction tied to the SSTable identity + block offset.
//!
//! ## Threat model
//!
//! See [`docs/THREAT_MODEL.md`](../../../../../docs/THREAT_MODEL.md) for the
//! full document. Briefly: encryption protects against **offline disk
//! theft** and **filesystem-level access without process privilege**. It
//! does **not** protect against an attacker who can read the live process
//! memory (the master key and decrypted page-cache pages live there) or
//! who can run code with the same UID as the engine.
//!
//! ## Phase status
//!
//! This phase delivers and validates the cryptographic primitives in
//! isolation:
//!
//! - AES-256-GCM exercised against the **NIST CAVS** known-answer vectors
//!   from `gcmEncryptExtIV256.rsp` to confirm the underlying crate matches
//!   the reference output bit-for-bit.
//! - HKDF-SHA256 exercised against the **RFC 5869** test vectors.
//! - Per-block nonce derivation tested for uniqueness across any pair of
//!   `(sstable_id, block_index)`.
//!
//! SSTable-writer / reader integration (so a `Db` configured with a master
//! key emits encrypted SSTables that the reader transparently decrypts)
//! lands in Phase 8b. The interfaces here are shaped for that pipeline.

pub mod aead;
pub mod envelope;
pub mod kdf;

pub use aead::{Aead, AeadError, AeadKey, Nonce, TAG_LEN};
pub use envelope::{BlockNonce, derive_block_nonce};
pub use kdf::{MasterKey, derive_sstable_key};
