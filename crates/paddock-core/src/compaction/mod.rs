//! Compaction: merge multiple SSTables into one.
//!
//! Without compaction the engine accumulates one SSTable per memtable
//! flush. Reads then walk all of them newest-first; the work per point
//! lookup grows linearly with the engine's lifetime. Compaction folds N
//! input SSTables into a single output SSTable, restoring **O(log N)**
//! read amplification.
//!
//! ## Algorithm
//!
//! [`merger::KWayMerge`] holds one stream per input SSTable. Each stream
//! is already sorted by `(key ascending, seqno descending)`. A binary
//! min-heap pops the globally smallest entry, the source stream advances,
//! and the merger emits records in the same global order — exactly what
//! [`crate::sstable::writer::SstWriter::add`] expects.
//!
//! ## Versioning
//!
//! Phase 7 keeps **every** version of every key it sees. This is
//! intentional: without snapshot tracking we cannot prove an old version
//! is unreferenced. The benefit of compaction is therefore the read-
//! amplification reduction (fewer SSTables to consult), not space
//! reduction. Phase 7b adds snapshot-aware version pruning and
//! bottom-level tombstone elision.
//!
//! ## Atomicity
//!
//! [`Db::compact_all`](crate::engine::Db::compact_all) builds the merged
//! output to a fresh file, then atomically swaps the engine state to
//! reference the new file and forget the old ones, then unlinks the
//! inputs from the VFS. A crash between the swap and the unlinks leaves
//! orphan files on disk that the next `Db::open` simply ignores (because
//! they are not in the manifest — once Phase 7b lands; for now they are
//! ignored because they have higher file numbers than the merged output
//! and `open` does not re-derive the live set).

pub mod compact;
pub mod merger;

pub use compact::compact_sstables;
pub use merger::KWayMerge;
