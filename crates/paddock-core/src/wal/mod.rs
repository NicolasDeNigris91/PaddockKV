//! Write-ahead log.
//!
//! The WAL provides durability: every `put` and `delete` is appended to the
//! current segment file and `fdatasync`'d before the engine reports success
//! to the caller. On startup, segments are scanned in order and their records
//! replayed back into a fresh memtable, restoring the engine to its
//! pre-crash state.
//!
//! ## Format
//!
//! Each segment file begins with a fixed 32-byte [`format::SegmentHeader`]
//! followed by a sequence of 32 KiB **physical blocks**. Inside each block
//! sits one or more **records**. A record carries a [`format::RecordHeader`]
//! (16 bytes — CRC32C, length, type tag, sequence number) followed by an
//! opaque payload (encoded [`batch::WriteBatch`] bytes).
//!
//! A record's payload may exceed the space remaining in its block, in which
//! case the writer splits it into `FIRST` / `MIDDLE…` / `LAST` fragments,
//! one per block — the same scheme LevelDB and RocksDB use. The
//! [`reader::SegmentReader`] reassembles fragments transparently.
//!
//! ## Durability and crash safety
//!
//! Every record header carries a CRC32C over the type tag + sequence + payload.
//! On replay, a CRC mismatch is interpreted as:
//!
//! - **Torn write at the tail** — at the end of the last segment, the kernel
//!   may have committed a partial record. The reader stops cleanly and the
//!   caller may truncate the segment.
//! - **Corruption mid-segment** — any record-level CRC failure followed by
//!   more valid-looking bytes is a hard error. Recovery aborts with a
//!   diagnostic that pinpoints the segment id and byte offset.
//!
//! ## Submodule layout
//!
//! - [`format`] — `#[repr(C)]` zerocopy types and on-disk constants.
//! - [`batch`]  — `WriteBatch` encoding and decoding (varints + ops).
//! - [`writer`] — generic segment writer over [`crate::io::vfs::VfsFile`].
//! - [`reader`] — segment replay with torn-write semantics.

pub mod batch;
pub mod format;
pub mod reader;
pub mod writer;
