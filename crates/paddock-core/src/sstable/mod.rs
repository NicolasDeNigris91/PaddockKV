//! Sorted String Table (SSTable) on-disk format and access layer.
//!
//! An SSTable is an immutable, sorted, prefix-compressed file produced when a
//! memtable is flushed (or two SSTables are compacted together). The engine
//! reads SSTables via `mmap` so point lookups return a `&[u8]` that points
//! directly into the page cache — the zero-copy property that makes
//! PaddockKV's read path fast.
//!
//! ## On-disk layout
//!
//! ```text
//!   ┌───────────────────────────────────────────────────────────────┐
//!   │ File header (4 KiB, page-aligned)                              │
//!   │   magic / version / flags / algorithm tags / counts / seqno    │
//!   │   range / smallest-key offset / largest-key offset / header CRC │
//!   ├───────────────────────────────────────────────────────────────┤
//!   │ Data blocks (16 KiB each, 4 KiB-aligned starts)                │
//!   │   records (prefix-compressed) + restart array + block CRC      │
//!   ├───────────────────────────────────────────────────────────────┤
//!   │ Filter block          (Phase 5 — bloom filter, optional)       │
//!   ├───────────────────────────────────────────────────────────────┤
//!   │ Meta block            (smallest_key, largest_key, …)           │
//!   ├───────────────────────────────────────────────────────────────┤
//!   │ Index block (one record per data block: last_key → block ptr)  │
//!   ├───────────────────────────────────────────────────────────────┤
//!   │ Footer (fixed 64 bytes at end of file)                         │
//!   │   index_block_off/len, filter/meta off/len, magic, format ver  │
//!   └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Modules
//!
//! - [`format`] — `#[repr(C, packed)]` zerocopy types and constants.
//! - [`block`]  — data-block builder and reader: prefix compression, restart
//!   binary search, intra-block iteration.
//! - [`writer`] — drive a sorted KV stream into a complete SSTable file.
//! - [`reader`] — open an SSTable, parse the footer, navigate the sparse
//!   index, and serve point lookups.

pub mod block;
pub mod format;
pub mod reader;
pub mod writer;

pub use reader::SstReader;
pub use writer::SstWriter;
