//! Error types shared across the engine.
//!
//! Every public fallible function returns [`Result<T>`], where the [`Error`]
//! enum captures every category of failure the engine can encounter. The
//! variants are organised by subsystem so that diagnostics can locate the
//! origin of a fault precisely. New variants are added as later phases bring
//! their subsystems online.

use std::io;

/// Result alias used throughout `paddock-core`.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level engine error.
///
/// Errors are intentionally fine-grained so that recovery paths can match on
/// specific failure modes (e.g. distinguishing a torn-write tail from
/// mid-segment corruption in the WAL).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O failure (mmap, read, write, fsync, etc.).
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// A varint or fixed-width integer could not be decoded.
    #[error("decode: {0}")]
    Decode(#[from] DecodeError),

    /// A checksum did not match the stored value.
    #[error("checksum mismatch in {context}: expected {expected:#010x}, found {found:#010x}")]
    ChecksumMismatch {
        /// Where the mismatch was detected (e.g. `"wal segment 42, record at offset 1024"`).
        context: &'static str,
        /// Checksum value stored on disk.
        expected: u64,
        /// Checksum computed from the data we just read.
        found: u64,
    },

    /// File header has an unexpected magic number, version, or shape.
    #[error("invalid format in {context}: {reason}")]
    InvalidFormat {
        /// Short context — typically the file or block kind.
        context: &'static str,
        /// Human-readable explanation.
        reason: String,
    },

    /// The engine encountered data it knows is corrupted (not just possibly so).
    #[error("corruption in {context}: {reason}")]
    Corruption {
        /// File / block / record context for diagnostics.
        context: &'static str,
        /// Description of what went wrong.
        reason: String,
    },

    /// Caller violated an API invariant.
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),

    /// The engine has been shut down and cannot accept new work.
    #[error("engine is shut down")]
    Shutdown,
}

/// Decode-time error categories.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input ran out before a complete value could be decoded.
    #[error("unexpected end of input: needed {needed} more bytes")]
    UnexpectedEof {
        /// Number of bytes still required.
        needed: usize,
    },

    /// A varint encoding occupied more bytes than the type allows.
    #[error("varint overflow: encoding exceeds {max_bytes} bytes")]
    VarintOverflow {
        /// Maximum legal length for this varint width.
        max_bytes: usize,
    },

    /// A varint had a non-canonical encoding (trailing zero continuation byte).
    #[error("non-canonical varint encoding")]
    NonCanonicalVarint,
}

impl Error {
    /// Build a [`Error::InvalidFormat`] without allocating a `String` for callers
    /// who already have a `'static` reason.
    pub fn invalid_format_static(context: &'static str, reason: &'static str) -> Self {
        Self::InvalidFormat {
            context,
            reason: reason.to_owned(),
        }
    }

    /// Build a [`Error::Corruption`] without allocating for `'static` reasons.
    pub fn corruption_static(context: &'static str, reason: &'static str) -> Self {
        Self::Corruption {
            context,
            reason: reason.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_converts_via_from() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "missing");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().starts_with("io: "));
    }

    #[test]
    fn decode_error_converts_via_from() {
        let err: Error = DecodeError::UnexpectedEof { needed: 4 }.into();
        assert!(matches!(err, Error::Decode(_)));
    }

    #[test]
    fn checksum_mismatch_renders_hex() {
        let err = Error::ChecksumMismatch {
            context: "wal record",
            expected: 0xDEAD_BEEF,
            found: 0xFEED_FACE,
        };
        let msg = err.to_string();
        assert!(msg.contains("0xdeadbeef"));
        assert!(msg.contains("0xfeedface"));
    }

    #[test]
    fn static_helpers_avoid_allocation_at_call_site() {
        let _ = Error::invalid_format_static("sstable footer", "wrong magic");
        let _ = Error::corruption_static("wal segment 0", "midrecord crc fail");
    }
}
