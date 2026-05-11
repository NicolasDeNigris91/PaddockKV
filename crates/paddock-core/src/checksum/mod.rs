//! Block- and record-level checksums.
//!
//! PaddockKV stores a checksum at the end of every persistent block (WAL
//! record, SSTable data block, footer). Two algorithms are supported and the
//! choice is recorded per-file in the SSTable / WAL header:
//!
//! - **CRC32C** (Castagnoli, polynomial `0x82F63B78`) — hardware-accelerated
//!   via `_mm_crc32_u64` on x86_64 and via the CRC32 extension on ARM64. Used
//!   everywhere by default. See [`crc32c`].
//! - **XXH3-64** — used when a 64-bit fingerprint is preferred (large blocks
//!   or future cross-file de-dup). See [`xxh3`].
//!
//! Both submodules expose a [`Hasher`] trait that abstracts over streaming and
//! one-shot use, so callers can pick the algorithm dynamically from a file
//! header byte without monomorphising the entire read path.

pub mod crc32c;
pub mod xxh3;

/// Algorithm tag persisted in file headers.
///
/// The numeric value is stable across versions and must match the
/// `checksum_alg` byte in the SSTable file header described in
/// `docs/format/sstable.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Algorithm {
    /// CRC32C / Castagnoli.
    Crc32c = 0,
    /// XXH3-64.
    Xxh3 = 1,
}

impl Algorithm {
    /// Compute the checksum of `data` using this algorithm.
    ///
    /// CRC32C results are zero-extended into the upper bits so the function
    /// signature can be uniform across both algorithms.
    #[inline]
    #[must_use]
    pub fn hash(self, data: &[u8]) -> u64 {
        match self {
            Self::Crc32c => u64::from(crc32c::hash(data)),
            Self::Xxh3 => xxh3::hash(data),
        }
    }

    /// Parse from the persisted byte tag.
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Crc32c),
            1 => Some(Self::Xxh3),
            _ => None,
        }
    }

    /// Byte tag for persistence.
    #[inline]
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_tag_round_trip() {
        for alg in [Algorithm::Crc32c, Algorithm::Xxh3] {
            assert_eq!(Algorithm::from_tag(alg.tag()), Some(alg));
        }
        assert_eq!(Algorithm::from_tag(255), None);
    }

    #[test]
    fn hash_dispatches_to_correct_algorithm() {
        let data = b"PaddockKV";
        assert_eq!(Algorithm::Crc32c.hash(data), u64::from(crc32c::hash(data)));
        assert_eq!(Algorithm::Xxh3.hash(data), xxh3::hash(data));
    }

    #[test]
    fn different_algorithms_produce_different_digests() {
        // This is not a guarantee for all inputs (different domains can
        // accidentally collide for short inputs), but for a 9-byte ASCII string
        // the two should not coincidentally line up — and the bit widths differ
        // anyway, since CRC32C only fills the lower 32 bits.
        let data = b"PaddockKV";
        let a = Algorithm::Crc32c.hash(data);
        let b = Algorithm::Xxh3.hash(data);
        assert_ne!(a, b);
        assert_eq!(a >> 32, 0, "crc32c should occupy only the lower 32 bits");
    }
}
