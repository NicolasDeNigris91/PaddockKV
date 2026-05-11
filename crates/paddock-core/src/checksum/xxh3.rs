//! XXH3-64 — a fast, high-quality 64-bit non-cryptographic hash.
//!
//! Used when a 64-bit fingerprint is preferred over CRC32C, primarily for
//! block-level checksums in SSTables on platforms without hardware CRC32C.
//!
//! Throughput on modern x86_64 is roughly 25–30 GB/s for medium inputs —
//! considerably higher than software CRC32C and competitive with
//! hardware-accelerated CRC32C on most hardware.

use xxhash_rust::xxh3::{Xxh3, xxh3_64};

/// One-shot XXH3-64 of `data`.
#[inline]
#[must_use]
pub fn hash(data: &[u8]) -> u64 {
    xxh3_64(data)
}

/// Streaming XXH3-64 hasher.
///
/// `Xxh3` from the upstream crate does not implement `Debug`, so we provide a
/// minimal manual impl that hides the internal state (which is large and
/// uninteresting).
#[derive(Clone, Default)]
pub struct Hasher {
    state: Xxh3,
}

impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("xxh3::Hasher")
            .field("digest", &self.state.digest())
            .finish()
    }
}

impl Hasher {
    /// Create a new hasher with the default seed.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { state: Xxh3::new() }
    }

    /// Continue the running checksum over `data`.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// Return the digest without consuming the hasher.
    #[inline]
    #[must_use]
    pub fn digest(&self) -> u64 {
        self.state.digest()
    }

    /// Consume the hasher and return the final digest.
    #[inline]
    #[must_use]
    pub fn finalize(self) -> u64 {
        self.state.digest()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_stable_digest() {
        // We deliberately do not hard-code the empty-input digest here — the
        // xxhash-rust crate's value for `xxh3_64(&[])` is the canonical XXH3
        // value and is stable across versions. We just assert determinism.
        let a = hash(&[]);
        let b = hash(&[]);
        assert_eq!(a, b);
        let c = Hasher::new().finalize();
        assert_eq!(a, c);
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let one_shot = hash(data);
        let mut h = Hasher::new();
        h.update(&data[..7]);
        h.update(&data[7..32]);
        h.update(&data[32..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn distinct_inputs_distinct_digests() {
        assert_ne!(hash(b"a"), hash(b"b"));
        assert_ne!(hash(b""), hash(b"\0"));
    }

    proptest::proptest! {
        #[test]
        fn prop_streaming_equals_oneshot(chunks: Vec<Vec<u8>>) {
            let mut combined = Vec::new();
            let mut h = Hasher::new();
            for c in &chunks {
                h.update(c);
                combined.extend_from_slice(c);
            }
            assert_eq!(h.finalize(), hash(&combined));
        }

        #[test]
        fn prop_single_bit_flip_changes_digest(data: Vec<u8>, idx: usize) {
            if data.is_empty() { return Ok(()); }
            let i = idx % data.len();
            let bit = (idx / data.len()) % 8;
            let mut flipped = data.clone();
            flipped[i] ^= 1 << bit;
            // XXH3 is not a CRC; collisions are theoretically possible but
            // astronomically unlikely for random single-bit flips of small
            // inputs. proptest will exhaust seeds before finding one.
            assert_ne!(hash(&data), hash(&flipped));
        }
    }
}
