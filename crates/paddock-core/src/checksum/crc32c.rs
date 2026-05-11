//! CRC32C (Castagnoli) — hardware-accelerated when available.
//!
//! The underlying [`crc32c`] crate dispatches at runtime to the CRC32
//! extension on x86_64 (via `_mm_crc32_u64`) and ARM64. The scalar fallback is
//! a portable software implementation.
//!
//! ## Convention
//!
//! - All CRC32C results stored on disk are unsigned 32-bit little-endian.
//! - The initial value is `0` (NOT the IEEE convention of `0xFFFFFFFF` — that
//!   would be CRC32-IEEE, which is a different polynomial).

/// One-shot CRC32C of `data`.
#[inline]
#[must_use]
pub fn hash(data: &[u8]) -> u32 {
    ::crc32c::crc32c(data)
}

/// Streaming CRC32C hasher.
///
/// Use when the data to be checksummed is built up incrementally (e.g. a WAL
/// record header followed by a payload).
#[derive(Debug, Clone, Default)]
pub struct Hasher {
    state: u32,
}

impl Hasher {
    /// Create a new hasher initialised to zero.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { state: 0 }
    }

    /// Continue the running checksum over `data`.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.state = ::crc32c::crc32c_append(self.state, data);
    }

    /// Consume the hasher and return the final digest.
    #[inline]
    #[must_use]
    pub const fn finalize(self) -> u32 {
        self.state
    }

    /// Borrow-only finalize for callers that want to keep the hasher alive.
    #[inline]
    #[must_use]
    pub const fn state(&self) -> u32 {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Castagnoli test vectors from RFC 3720 appendix B.4.
    /// (CRC32C of all-zeros and all-ones inputs of 32 bytes.)
    #[test]
    fn rfc3720_test_vectors() {
        assert_eq!(hash(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(hash(&[0xFFu8; 32]), 0x62A8_AB43);

        // "123456789" — the canonical CRC check string for many polynomials.
        // CRC32C of "123456789" is 0xE3069283.
        assert_eq!(hash(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let one_shot = hash(data);

        let mut h = Hasher::new();
        h.update(&data[..10]);
        h.update(&data[10..25]);
        h.update(&data[25..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn empty_input_yields_zero() {
        // CRC32C of the empty string (with init=0, no final XOR) is 0.
        assert_eq!(hash(&[]), 0);
        assert_eq!(Hasher::new().finalize(), 0);
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
            assert_ne!(hash(&data), hash(&flipped));
        }
    }
}
