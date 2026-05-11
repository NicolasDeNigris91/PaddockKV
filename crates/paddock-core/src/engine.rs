//! Top-level engine: the public-facing key-value store.
//!
//! [`Db`] is what callers actually use. It coordinates the four subsystems
//! built up by Phases 0–5 into a single durable, recoverable, ordered
//! key-value store:
//!
//! - [`crate::wal`]      — durability. Every write hits the WAL before
//!   anything else.
//! - [`crate::memtable`] — read-and-write buffer. Lock-free skip list per
//!   active memtable.
//! - [`crate::sstable`]  — frozen on-disk levels. Built when a memtable
//!   flushes; consulted by reads after the memtable.
//! - [`crate::filter`]   — Bloom filters embedded in every SSTable that
//!   prune negative point reads.
//!
//! ## Concurrency model
//!
//! Writes serialise through a single `write_lock`: the WAL is append-only,
//! and the memtable's single-writer guarantee is preserved by that lock.
//! Readers never block writers. Every read does one `ArcSwap::load` to
//! snapshot the **engine state** ([`EngineState`]) — the active memtable,
//! the queue of immutable memtables waiting to flush, and the live SSTables
//! — then walks each in turn. Because the snapshot is an `Arc`, in-flight
//! reads continue to see a consistent view even after writers swap in a new
//! state.
//!
//! ## Files on disk
//!
//! For a database opened at path `data/`:
//!
//! - `data/wal-NNNNNN.log` — WAL segments, monotonically numbered.
//! - `data/NNNNNN.sst`     — SSTables, monotonically numbered. (NNNNNN is
//!   reused across WAL and SSTable numbering for simplicity.)
//!
//! ## Recovery
//!
//! On [`Db::open`], every existing WAL segment is replayed in order into a
//! fresh memtable; the engine is then ready for serving without re-opening
//! any SSTables (they live on the engine state, registered after the next
//! flush). A clean shutdown via [`Db::close`] flushes pending memtables,
//! which simplifies recovery to "just replay the WAL".

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;

use crate::checksum::Algorithm;
use crate::compaction::compact::{CompactionConfig, compact_sstables};
use crate::crypto::kdf::{MasterKey, derive_sstable_key};
use crate::error::Result;
use crate::filter::BloomParams;
use crate::io::vfs::Vfs;
use crate::memtable::{OpType, SkipList};
use crate::sstable::format::RecordOp;
use crate::sstable::reader::SstReader;
use crate::sstable::writer::SstWriter;
use crate::wal::batch::{Op, WriteBatch};
use crate::wal::reader::SegmentReader;
use crate::wal::writer::SegmentWriter;
use std::sync::Arc;

/// User-tunable knobs. Pass to [`Db::open_with`].
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Memtable size in bytes that triggers rotation (active → immutable
    /// queue) and a fresh WAL segment.
    pub memtable_threshold_bytes: usize,
    /// Bloom filter bit budget per key in newly-written SSTables.
    pub bloom_bits_per_key: u8,
    /// Number of hashes set per key in the Bloom filter.
    pub bloom_num_hashes: u8,
    /// Hint for the expected SSTable record count, used to size the Bloom
    /// filter eagerly. Overshooting is fine — only the FPR drifts.
    pub sstable_capacity_hint: usize,
    /// Optional master key for encryption-at-rest. When `Some`, every
    /// SSTable written by the engine is AES-256-GCM-encrypted under a
    /// per-table key derived via
    /// [`crate::crypto::kdf::derive_sstable_key`]. When `None`, SSTables
    /// are plaintext.
    ///
    /// Compaction inherits the key transparently: the merged output is
    /// encrypted iff the master key is set (the inputs' encryption flags
    /// must match what the reader expects, which the engine enforces at
    /// open time).
    pub master_key: Option<MasterKey>,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            memtable_threshold_bytes: 4 * 1024 * 1024, // 4 MiB
            bloom_bits_per_key: 10,
            bloom_num_hashes: 8,
            sstable_capacity_hint: 10_000,
            master_key: None,
        }
    }
}

impl DbConfig {
    const fn bloom_params(&self) -> BloomParams {
        BloomParams {
            num_hashes: self.bloom_num_hashes,
            bits_per_key: self.bloom_bits_per_key,
        }
    }
}

/// Captured engine sequence number. Reads taken with the same snapshot see
/// a consistent view across calls, even if intervening writes land.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    seqno: u64,
}

impl Snapshot {
    /// The sequence number this snapshot is pinned at. Used by tests and
    /// telemetry; engine code rarely needs the raw value.
    #[must_use]
    pub const fn seqno(self) -> u64 {
        self.seqno
    }
}

/// One live SSTable: its file id (so the engine can unlink the file after
/// compaction) plus the open reader.
pub struct LiveSst<F: crate::io::vfs::VfsFile> {
    /// File id (the `NNNNNNNN` in `NNNNNNNN.sst`).
    pub id: u64,
    /// Open reader.
    pub reader: Arc<SstReader<F>>,
}

impl<F: crate::io::vfs::VfsFile> Clone for LiveSst<F> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            reader: Arc::clone(&self.reader),
        }
    }
}

impl<F: crate::io::vfs::VfsFile> std::fmt::Debug for LiveSst<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveSst")
            .field("id", &self.id)
            .field("has_bloom", &self.reader.has_bloom_filter())
            .finish_non_exhaustive()
    }
}

/// An immutable memtable plus the id of the WAL segment that fed it.
///
/// The engine deletes that WAL segment once the memtable lands as an
/// SSTable — the on-disk state would otherwise double-replay every
/// flushed record on the next `Db::open`.
#[derive(Clone)]
pub struct ImmutableMemtable {
    /// The frozen memtable.
    pub memtable: Arc<SkipList>,
    /// WAL segment id whose records hydrated this memtable. `0` means
    /// "unknown / no segment to drop" — used for in-memory test setups
    /// that bypass the WAL.
    pub wal_segment_id: u64,
}

impl std::fmt::Debug for ImmutableMemtable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImmutableMemtable")
            .field("len", &self.memtable.len())
            .field("wal_segment_id", &self.wal_segment_id)
            .finish_non_exhaustive()
    }
}

/// Engine state pointed-to by [`Db::state`]. Every read captures one of
/// these via `Arc<EngineState<V>>` and walks the four collections inside.
pub struct EngineState<V: Vfs> {
    /// Active memtable — the writer thread mutates this; readers see it
    /// through `Arc`.
    pub active_memtable: Arc<SkipList>,
    /// Frozen memtables waiting to be flushed. Newest first.
    pub immutable_memtables: Vec<ImmutableMemtable>,
    /// Currently-live SSTables. Newest first (the first match wins on
    /// duplicate keys, so the freshest version always shadows older
    /// flushes).
    pub sstables: Vec<LiveSst<<V as Vfs>::File>>,
}

impl<V: Vfs> std::fmt::Debug for EngineState<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineState")
            .field("active_memtable_len", &self.active_memtable.len())
            .field("immutable_memtables", &self.immutable_memtables.len())
            .field("sstables", &self.sstables.len())
            .finish_non_exhaustive()
    }
}

/// Internal write-side state. Lives behind `Db::write_lock` so writers
/// serialise on the WAL.
struct WriterCtx<V: Vfs> {
    wal: SegmentWriter<<V as Vfs>::File>,
    wal_segment_id: u64,
    /// Bytes appended to the active memtable's arena since the last
    /// rotation. Tracked here so the writer can decide rotation purely
    /// from local state, without consulting the live memtable.
    active_memtable_bytes: usize,
    next_file_number: u64,
}

/// The engine.
pub struct Db<V: Vfs> {
    vfs: V,
    data_dir: String,
    config: DbConfig,
    seqno: AtomicU64,
    state: ArcSwap<EngineState<V>>,
    write_lock: Mutex<WriterCtx<V>>,
}

impl<V: Vfs> Db<V> {
    /// Open a database under `data_dir`, replaying any existing WAL
    /// segments. Creates the directory entries on demand.
    pub fn open(vfs: V, data_dir: &str) -> Result<Self> {
        Self::open_with(vfs, data_dir, DbConfig::default())
    }

    /// Open with an explicit configuration.
    pub fn open_with(vfs: V, data_dir: &str, config: DbConfig) -> Result<Self> {
        let dir = data_dir.to_owned();

        // Discover existing WAL segments. Recovery replays them in order.
        let mut wal_segments: Vec<u64> = vfs
            .list(&dir)
            .unwrap_or_default()
            .iter()
            .filter_map(|n| parse_wal_segment_name(n))
            .collect();
        wal_segments.sort_unstable();

        // Track the highest file number seen across both WAL and SST files
        // so newly-flushed SSTables can pick a fresh, monotonic id.
        let mut next_file_number = wal_segments.iter().copied().max().unwrap_or(0) + 1;
        let sst_files: Vec<u64> = vfs
            .list(&dir)
            .unwrap_or_default()
            .iter()
            .filter_map(|n| parse_sst_name(n))
            .collect();
        if let Some(&max_sst) = sst_files.iter().max() {
            next_file_number = next_file_number.max(max_sst + 1);
        }

        // Build the initial state. SSTables present on disk are opened and
        // registered newest-first. Memtable is empty until WAL replay
        // populates it.
        let mut sstables: Vec<LiveSst<V::File>> = Vec::new();
        let mut sst_sorted = sst_files;
        sst_sorted.sort_unstable_by(|a, b| b.cmp(a)); // newest first
        // Track the maximum sequence number seen across both SSTables and
        // WAL so the engine resumes from the right place. Deleting WAL
        // segments after flush (a Phase 8b optimisation) means the SSTable
        // file headers are the authoritative source for what seqnos
        // already exist on disk.
        let mut max_seen_seqno = 0u64;
        for n in sst_sorted {
            let path = sst_path(&dir, n);
            let file = vfs.open_readonly(&path)?;
            let reader = open_sst_reader(file, n, config.master_key.as_ref())?;
            max_seen_seqno = max_seen_seqno.max(reader.file_header().max_seqno.get());
            sstables.push(LiveSst {
                id: n,
                reader: Arc::new(reader),
            });
        }

        let memtable = Arc::new(SkipList::new());

        // Replay WAL into the active memtable. Any seqno greater than what
        // the SSTables already carry advances `max_seen_seqno` further.
        for &seg in &wal_segments {
            let path = wal_segment_path(&dir, seg);
            let file = vfs.open_readonly(&path)?;
            let mut reader = SegmentReader::open(file)?;
            let outcome = reader.replay(|view| {
                max_seen_seqno = max_seen_seqno.max(view.seqno);
                let batch = WriteBatch::decode(&view.payload)?;
                apply_batch_to_memtable(&memtable, view.seqno, &batch);
                Ok(())
            })?;
            // Phase 6 simply logs the outcome; Phase 9 (recovery hardening)
            // will pivot on TornTail and truncate.
            let _ = outcome;
        }

        let state = ArcSwap::new(Arc::new(EngineState {
            active_memtable: memtable,
            immutable_memtables: Vec::new(),
            sstables,
        }));

        // Open a fresh WAL segment for new writes; we never resume an
        // existing segment (avoids ambiguity around torn writes).
        let wal_segment_id = next_file_number;
        next_file_number += 1;
        let wal_path = wal_segment_path(&dir, wal_segment_id);
        let wal_file = vfs.open_writable(&wal_path)?;
        let wal = SegmentWriter::create(wal_file, wal_segment_id, max_seen_seqno + 1)?;

        Ok(Self {
            vfs,
            data_dir: dir,
            config,
            seqno: AtomicU64::new(max_seen_seqno),
            state,
            write_lock: Mutex::new(WriterCtx {
                wal,
                wal_segment_id,
                active_memtable_bytes: 0,
                next_file_number,
            }),
        })
    }

    /// Insert or update `key` to `value`.
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut batch = WriteBatch::new();
        batch.put(key.to_vec(), value.to_vec());
        self.commit_batch(&batch)
    }

    /// Remove `key`. Writes a tombstone — the actual record stays around
    /// until compaction drops it.
    pub fn delete(&self, key: &[u8]) -> Result<()> {
        let mut batch = WriteBatch::new();
        batch.delete(key.to_vec());
        self.commit_batch(&batch)
    }

    /// Apply an arbitrary [`WriteBatch`] atomically: every op in the batch
    /// is durable, or none of them are.
    pub fn write_batch(&self, batch: &WriteBatch) -> Result<()> {
        self.commit_batch(batch)
    }

    /// Capture a sequence-number snapshot for repeatable reads.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            seqno: self.seqno.load(Ordering::Acquire),
        }
    }

    /// Look up `key` against the latest committed state.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let snap = self.snapshot();
        self.get_at(key, snap)
    }

    /// Look up `key` against the state visible at `snapshot`. Records with
    /// `seqno > snapshot.seqno` are ignored — so a snapshot taken before a
    /// later overwrite still sees the older value.
    pub fn get_at(&self, key: &[u8], snapshot: Snapshot) -> Result<Option<Vec<u8>>> {
        let state = self.state.load();

        // 1. Active memtable. Returns the freshest record at or below
        //    `snapshot.seqno`. If found and not a tombstone, we're done.
        if let Some(node) = state.active_memtable.get(key, snapshot.seqno) {
            return Ok(match node.op_type() {
                OpType::Put => Some(node.value().to_vec()),
                OpType::Tombstone => None,
            });
        }

        // 2. Immutable memtables (newest first).
        for im in &state.immutable_memtables {
            if let Some(node) = im.memtable.get(key, snapshot.seqno) {
                return Ok(match node.op_type() {
                    OpType::Put => Some(node.value().to_vec()),
                    OpType::Tombstone => None,
                });
            }
        }

        // 3. SSTables (newest first).
        for sst in &state.sstables {
            if let Some(hit) = sst.reader.get(key, snapshot.seqno)? {
                return Ok(match hit.op {
                    RecordOp::Put => Some(hit.value),
                    RecordOp::Tombstone => None,
                });
            }
        }

        Ok(None)
    }

    /// Force the engine to drain every pending memtable to disk. After this
    /// call returns successfully, the only memtable is a fresh empty one
    /// and every previously-committed write lives in an SSTable.
    ///
    /// This is the API tests use to observe the SSTable read path; the
    /// real engine will eventually call this from a background thread when
    /// memtable size crosses the threshold.
    pub fn flush(&self) -> Result<()> {
        // Rotate the active memtable (if non-empty) into the immutable
        // queue and write a fresh WAL segment. We then drain every queued
        // memtable to an SSTable.
        {
            let mut ctx = self.write_lock.lock().expect("write_lock poisoned");
            if !self.state.load().active_memtable.is_empty() {
                self.rotate_memtable_locked(&mut ctx)?;
            }
        }
        loop {
            // Peek at the oldest immutable; flush if any.
            let to_flush = {
                let state = self.state.load();
                state.immutable_memtables.last().cloned()
            };
            let Some(im) = to_flush else {
                break;
            };
            self.flush_one(&im)?;
        }
        Ok(())
    }

    /// Clean shutdown. Flushes any pending memtables to SSTables.
    pub fn close(self) -> Result<()> {
        self.flush()
    }

    /// Merge **every currently-live SSTable** into a single new SSTable,
    /// atomically swap the engine state to reference the new file, and
    /// unlink the inputs from the VFS.
    ///
    /// Reads remain serviceable for the entire operation: an in-flight
    /// `get` running against the pre-compaction state continues to walk
    /// the old SSTables until it drops its `Arc<EngineState>`; the next
    /// `get` after the swap walks the post-compaction state with one
    /// fewer level of indirection.
    ///
    /// Phase 7 keeps every `(key, seqno)` pair the inputs carry — read
    /// amplification drops, space amplification does not. See
    /// [`crate::compaction`] for the rationale.
    pub fn compact_all(&self) -> Result<()> {
        let state = self.state.load_full();
        if state.sstables.len() < 2 {
            // Nothing to merge.
            return Ok(());
        }
        // Snapshot the inputs (id + Arc). Cloning a `LiveSst` is cheap —
        // the underlying reader is shared via `Arc`.
        let inputs: Vec<LiveSst<V::File>> = state.sstables.clone();
        drop(state);

        // Reserve a fresh file number under the write lock.
        let output_id = {
            let mut ctx = self.write_lock.lock().expect("write_lock poisoned");
            let n = ctx.next_file_number;
            ctx.next_file_number += 1;
            n
        };
        let output_path = sst_path(&self.data_dir, output_id);

        let input_readers: Vec<Arc<SstReader<V::File>>> =
            inputs.iter().map(|l| Arc::clone(&l.reader)).collect();

        // If encryption is enabled, the merged output needs its own
        // per-SSTable key derived from `output_id`. The input keys are
        // already wired up at open time (the readers above were opened via
        // `open_sst_reader`), so the merger transparently sees plaintext.
        let derived_output_key = self
            .config
            .master_key
            .as_ref()
            .map(|m| derive_sstable_key(m, output_id));
        let encryption_param = derived_output_key.as_ref().map(|k| (k, output_id));

        let output = compact_sstables(
            &self.vfs,
            &input_readers,
            &output_path,
            &CompactionConfig {
                bloom: self.config.bloom_params(),
                bloom_capacity_floor: self.config.sstable_capacity_hint,
                checksum: Algorithm::Crc32c,
                encryption: encryption_param,
            },
        )?;

        // Swap: remove every input SSTable from EngineState by id, insert
        // the merged output at the head.
        let new_state = {
            let prev = self.state.load_full();
            let input_ids: std::collections::HashSet<u64> = inputs.iter().map(|l| l.id).collect();
            let mut sstables: Vec<LiveSst<V::File>> =
                Vec::with_capacity(prev.sstables.len() - inputs.len() + 1);
            sstables.push(LiveSst {
                id: output_id,
                reader: output.reader,
            });
            for sst in &prev.sstables {
                if !input_ids.contains(&sst.id) {
                    sstables.push(sst.clone());
                }
            }
            Arc::new(EngineState::<V> {
                active_memtable: Arc::clone(&prev.active_memtable),
                immutable_memtables: prev.immutable_memtables.clone(),
                sstables,
            })
        };
        self.state.store(new_state);

        // Inputs are unreachable from the new state. Best-effort cleanup
        // of the on-disk files. We swallow `remove` errors because a
        // missing file is fine (idempotent) and the engine state is
        // already correct regardless.
        for input in inputs {
            let path = sst_path(&self.data_dir, input.id);
            let _ = self.vfs.remove(&path);
        }

        Ok(())
    }

    /// Engine-internal accessors used by tests / telemetry.
    #[must_use]
    pub fn current_seqno(&self) -> u64 {
        self.seqno.load(Ordering::Acquire)
    }

    /// Number of SSTables currently registered.
    #[must_use]
    pub fn sstable_count(&self) -> usize {
        self.state.load().sstables.len()
    }

    /// Borrow a snapshot of the engine state for diagnostics. The returned
    /// Arc lets callers inspect counts without taking the write lock.
    #[must_use]
    pub fn engine_state(&self) -> Arc<EngineState<V>> {
        self.state.load_full()
    }

    // ----- internals -----

    fn commit_batch(&self, batch: &WriteBatch) -> Result<()> {
        let mut ctx = self.write_lock.lock().expect("write_lock poisoned");

        // Allocate one seqno for the whole batch; the WAL record carries
        // this seqno verbatim, and every op inside the batch is applied
        // with the same seqno to the memtable.
        let seqno = self.seqno.fetch_add(1, Ordering::AcqRel) + 1;
        let encoded = batch.encode();
        ctx.wal.append_record(seqno, &encoded)?;
        ctx.wal.sync()?;

        // Apply to the active memtable.
        {
            let state = self.state.load();
            apply_batch_to_memtable(&state.active_memtable, seqno, batch);
        }
        ctx.active_memtable_bytes += encoded.len();

        // Rotate when over threshold.
        if ctx.active_memtable_bytes >= self.config.memtable_threshold_bytes {
            self.rotate_memtable_locked(&mut ctx)?;
        }
        drop(ctx);

        Ok(())
    }

    fn rotate_memtable_locked(&self, ctx: &mut WriterCtx<V>) -> Result<()> {
        // Build new EngineState moving the active memtable into the
        // immutable queue (paired with the WAL segment that fed it) and
        // seating a fresh active.
        let new_active = Arc::new(SkipList::new());
        let outgoing_wal_id = ctx.wal_segment_id;
        let new_state = {
            let prev = self.state.load_full();
            let mut immutables = Vec::with_capacity(prev.immutable_memtables.len() + 1);
            // Newest immutable goes to the *front* so iteration order
            // (newest-first) is preserved.
            immutables.push(ImmutableMemtable {
                memtable: Arc::clone(&prev.active_memtable),
                wal_segment_id: outgoing_wal_id,
            });
            immutables.extend(prev.immutable_memtables.iter().cloned());
            Arc::new(EngineState::<V> {
                active_memtable: new_active,
                immutable_memtables: immutables,
                sstables: prev.sstables.clone(),
            })
        };
        self.state.store(new_state);

        // Roll the WAL: close the current segment, open a fresh one.
        let new_segment_id = ctx.next_file_number;
        ctx.next_file_number += 1;
        let wal_path = wal_segment_path(&self.data_dir, new_segment_id);
        let new_file = self.vfs.open_writable(&wal_path)?;
        let first_seqno = self.seqno.load(Ordering::Acquire) + 1;
        let new_wal = SegmentWriter::create(new_file, new_segment_id, first_seqno)?;

        // Drop the old WAL by replacement.
        ctx.wal = new_wal;
        ctx.wal_segment_id = new_segment_id;
        ctx.active_memtable_bytes = 0;

        Ok(())
    }

    /// Flush exactly one immutable memtable to a new SSTable. Pops it off
    /// the engine state (oldest, by convention), registers the SSTable
    /// at the front of the `sstables` list, and unlinks the WAL segment
    /// that fed the memtable — the SSTable is now durable so the WAL is
    /// redundant.
    fn flush_one(&self, im: &ImmutableMemtable) -> Result<()> {
        let mem = &im.memtable;
        // Pick a file number under the write lock. We don't need to hold
        // the lock during the SSTable write — the file is private until we
        // publish it into EngineState.
        let file_number = {
            let mut ctx = self.write_lock.lock().expect("write_lock poisoned");
            let n = ctx.next_file_number;
            ctx.next_file_number += 1;
            n
        };
        let path = sst_path(&self.data_dir, file_number);
        let file = self.vfs.open_writable(&path)?;
        let key_count = mem.len();
        let mut w = match self.config.master_key.as_ref() {
            Some(master) => {
                let key = derive_sstable_key(master, file_number);
                SstWriter::create_encrypted(
                    file,
                    Algorithm::Crc32c,
                    key_count.max(1),
                    self.config.bloom_params(),
                    &key,
                    file_number,
                )?
            }
            None => SstWriter::create_with_filter_capacity(
                file,
                Algorithm::Crc32c,
                key_count.max(1),
                self.config.bloom_params(),
            )?,
        };

        // The memtable iterator is already in ascending `(key, !seqno)`
        // order — exactly what `SstWriter::add` requires.
        for node in mem.iter() {
            let op = match node.op_type() {
                OpType::Put => RecordOp::Put,
                OpType::Tombstone => RecordOp::Tombstone,
            };
            w.add(node.key(), node.value(), node.seqno(), op)?;
        }
        let _file = w.finish()?;

        // Open the SSTable read-side and publish it.
        let reader = open_sst_reader(
            self.vfs.open_readonly(&path)?,
            file_number,
            self.config.master_key.as_ref(),
        )?;
        let new_state = {
            let prev = self.state.load_full();
            let mut sstables = Vec::with_capacity(prev.sstables.len() + 1);
            sstables.push(LiveSst {
                id: file_number,
                reader: Arc::new(reader),
            });
            sstables.extend(prev.sstables.iter().cloned());
            // Drop the just-flushed memtable from the immutable queue by
            // matching the wal_segment_id (each immutable has its own
            // distinct id, so this is a unique key).
            let immutables: Vec<_> = prev
                .immutable_memtables
                .iter()
                .filter(|m| m.wal_segment_id != im.wal_segment_id)
                .cloned()
                .collect();
            Arc::new(EngineState::<V> {
                active_memtable: Arc::clone(&prev.active_memtable),
                immutable_memtables: immutables,
                sstables,
            })
        };
        self.state.store(new_state);

        // The WAL segment that fed this memtable is now redundant — the
        // SSTable carries every record durably. Best-effort unlink; a
        // missing file is fine (idempotent).
        if im.wal_segment_id != 0 {
            let wal_path = wal_segment_path(&self.data_dir, im.wal_segment_id);
            let _ = self.vfs.remove(&wal_path);
        }

        Ok(())
    }
}

impl<V: Vfs> std::fmt::Debug for Db<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.load();
        f.debug_struct("Db")
            .field("data_dir", &self.data_dir)
            .field("current_seqno", &self.seqno.load(Ordering::Relaxed))
            .field("memtable_len", &state.active_memtable.len())
            .field("immutable_count", &state.immutable_memtables.len())
            .field("sstable_count", &state.sstables.len())
            .finish_non_exhaustive()
    }
}

// ----- helpers -----

/// Open an SSTable file, picking the encrypted or plaintext path based on
/// whether a master key is present. The `sstable_id` is used in the key
/// derivation; it must match the file id under which the SSTable was
/// originally written.
fn open_sst_reader<F: crate::io::vfs::VfsFile>(
    file: F,
    sstable_id: u64,
    master_key: Option<&MasterKey>,
) -> Result<SstReader<F>> {
    match master_key {
        Some(master) => {
            let key = derive_sstable_key(master, sstable_id);
            SstReader::open_encrypted(file, &key, sstable_id)
        }
        None => SstReader::open(file),
    }
}

fn apply_batch_to_memtable(memtable: &SkipList, seqno: u64, batch: &WriteBatch) {
    for op in batch.ops() {
        match op {
            Op::Put { key, value } => {
                memtable.insert(key, value, seqno, OpType::Put);
            }
            Op::Delete { key } => {
                memtable.insert(key, &[], seqno, OpType::Tombstone);
            }
        }
    }
}

fn wal_segment_path(dir: &str, id: u64) -> String {
    format!("{dir}/wal-{id:08}.log")
}

fn sst_path(dir: &str, id: u64) -> String {
    format!("{dir}/{id:08}.sst")
}

fn parse_wal_segment_name(name: &str) -> Option<u64> {
    name.strip_prefix("wal-")?
        .strip_suffix(".log")?
        .parse::<u64>()
        .ok()
}

fn parse_sst_name(name: &str) -> Option<u64> {
    name.strip_suffix(".sst")?.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::vfs::MemVfs;

    fn open_fresh() -> Db<MemVfs> {
        let vfs = MemVfs::new();
        Db::open(vfs, "/db").expect("open")
    }

    #[test]
    fn put_then_get_round_trips() {
        let db = open_fresh();
        db.put(b"alpha", b"one").unwrap();
        db.put(b"bravo", b"two").unwrap();
        assert_eq!(db.get(b"alpha").unwrap(), Some(b"one".to_vec()));
        assert_eq!(db.get(b"bravo").unwrap(), Some(b"two".to_vec()));
        assert_eq!(db.get(b"missing").unwrap(), None);
    }

    #[test]
    fn delete_hides_a_previous_put() {
        let db = open_fresh();
        db.put(b"k", b"v").unwrap();
        assert_eq!(db.get(b"k").unwrap(), Some(b"v".to_vec()));
        db.delete(b"k").unwrap();
        assert_eq!(db.get(b"k").unwrap(), None);
    }

    #[test]
    fn snapshot_sees_old_value_after_overwrite() {
        let db = open_fresh();
        db.put(b"k", b"v1").unwrap();
        let snap = db.snapshot();
        db.put(b"k", b"v2").unwrap();
        assert_eq!(db.get_at(b"k", snap).unwrap(), Some(b"v1".to_vec()));
        assert_eq!(db.get(b"k").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn flush_drains_memtable_to_sstable_and_reads_still_work() {
        let db = open_fresh();
        for i in 0..50u32 {
            db.put(
                format!("k-{i:03}").as_bytes(),
                format!("v-{i:03}").as_bytes(),
            )
            .unwrap();
        }
        assert_eq!(db.sstable_count(), 0);
        db.flush().unwrap();
        assert_eq!(db.sstable_count(), 1);
        for i in 0..50u32 {
            let k = format!("k-{i:03}");
            let expected = format!("v-{i:03}");
            assert_eq!(
                db.get(k.as_bytes()).unwrap(),
                Some(expected.into_bytes()),
                "miss after flush for {k}"
            );
        }
    }

    #[test]
    fn after_flush_overwrites_still_shadow_sstable_value() {
        let db = open_fresh();
        db.put(b"k", b"first").unwrap();
        db.flush().unwrap();
        db.put(b"k", b"second").unwrap();
        // Read should see the memtable's newer record, not the SSTable's.
        assert_eq!(db.get(b"k").unwrap(), Some(b"second".to_vec()));
        // After a second flush both versions live on disk; reader still
        // walks newest SSTable first, so the freshest wins.
        db.flush().unwrap();
        assert_eq!(db.sstable_count(), 2);
        assert_eq!(db.get(b"k").unwrap(), Some(b"second".to_vec()));
    }

    #[test]
    fn recovery_replays_wal_into_a_fresh_memtable() {
        let vfs = MemVfs::new();
        {
            let db = Db::open(vfs.clone(), "/db").unwrap();
            db.put(b"persist", b"yes").unwrap();
            db.put(b"x", b"y").unwrap();
            // Note: no flush — values live only in the WAL.
            drop(db);
        }
        // Reopen against the same VFS. WAL replay should hydrate the
        // memtable.
        let db2 = Db::open(vfs, "/db").unwrap();
        assert_eq!(db2.get(b"persist").unwrap(), Some(b"yes".to_vec()));
        assert_eq!(db2.get(b"x").unwrap(), Some(b"y".to_vec()));
    }

    #[test]
    fn recovery_then_flush_emits_an_sstable() {
        let vfs = MemVfs::new();
        {
            let db = Db::open(vfs.clone(), "/db").unwrap();
            for i in 0..20u32 {
                db.put(format!("k{i}").as_bytes(), format!("v{i}").as_bytes())
                    .unwrap();
            }
        }
        let db2 = Db::open(vfs, "/db").unwrap();
        db2.flush().unwrap();
        assert!(db2.sstable_count() >= 1);
        for i in 0..20u32 {
            let k = format!("k{i}");
            assert_eq!(
                db2.get(k.as_bytes()).unwrap(),
                Some(format!("v{i}").into_bytes())
            );
        }
    }

    #[test]
    fn many_writes_and_flushes_stay_consistent() {
        let db = open_fresh();
        // Drive several memtable rotations + flushes.
        for round in 0..5u32 {
            for i in 0..100u32 {
                let k = format!("k-{round}-{i:04}");
                let v = format!("v-{round}-{i:04}");
                db.put(k.as_bytes(), v.as_bytes()).unwrap();
            }
            db.flush().unwrap();
        }
        // Spot-check a key from every round survived.
        for round in 0..5u32 {
            let k = format!("k-{round}-0042");
            let v = format!("v-{round}-0042");
            assert_eq!(db.get(k.as_bytes()).unwrap(), Some(v.into_bytes()));
        }
    }

    #[test]
    fn delete_then_flush_persists_tombstone() {
        let db = open_fresh();
        db.put(b"k", b"v").unwrap();
        db.flush().unwrap();
        db.delete(b"k").unwrap();
        db.flush().unwrap();
        // Newer SSTable has the tombstone; older has the put. Newest wins.
        assert_eq!(db.get(b"k").unwrap(), None);
    }

    #[test]
    fn seqno_advances_monotonically() {
        let db = open_fresh();
        let s0 = db.current_seqno();
        db.put(b"a", b"1").unwrap();
        assert!(db.current_seqno() > s0);
        let s1 = db.current_seqno();
        db.put(b"b", b"2").unwrap();
        assert!(db.current_seqno() > s1);
    }
}
