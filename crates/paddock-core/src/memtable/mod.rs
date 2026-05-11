//! In-memory write buffer (memtable).
//!
//! The memtable holds the engine's recent writes before they are flushed to
//! an SSTable. Writes land in the active memtable; reads consult the active
//! memtable first, then immutable memtables waiting to flush, then the
//! SSTables.
//!
//! ## Single-writer / multi-reader
//!
//! This Phase-3 implementation assumes a single writer thread (the same
//! thread that drives WAL group commit). Readers run concurrently and never
//! block writers. Insertions update forward pointers with `Release`
//! atomic stores; reads follow forward pointers with `Acquire` loads. This
//! is the same model RocksDB's `InlineSkipList` uses by default.
//!
//! A future multi-writer mode that swaps `Release` stores for CAS sits on
//! the roadmap (Phase 6 / 7). The data structures here are deliberately
//! shaped so that upgrade is a localised change.
//!
//! ## Layout
//!
//! - [`arena`]    — bump-allocator backing all skip-list nodes.
//! - [`skiplist`] — Pugh skip list with `AtomicPtr` forward pointers, lookup
//!   wait-free, insert single-writer.

pub mod arena;
pub mod skiplist;

pub use skiplist::{OpType, SkipList};
