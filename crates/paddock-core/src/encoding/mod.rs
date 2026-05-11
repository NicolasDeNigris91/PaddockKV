//! Binary encoding primitives used by the WAL and SSTable formats.
//!
//! Two flavours of integers appear on disk in PaddockKV:
//!
//! - **Fixed-width little-endian integers** for stable header/footer layouts
//!   that are read via [`zerocopy`].
//! - **Variable-length unsigned integers** (LEB128) for record-internal fields
//!   like key/value lengths, where the average value is small.
//!
//! The varint codec lives in [`varint`].

pub mod varint;
