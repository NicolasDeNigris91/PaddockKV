# PaddockKV

A from-scratch, Linux-native LSM-tree key-value store in Rust, designed to
beat RocksDB on single-threaded p999 cold-cache point-read latency.

## Status

Pre-alpha. Phase 0 (foundations) in progress.

## Design

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

Headline decisions:

- **Rust 2024**, MSRV pinned to 1.95.
- **Linux 6.x** only (io_uring, O_DIRECT, mmap, madvise).
- **No high-level engine dependencies** — checksums, hashing, epoch GC, and
  zerocopy only.
- **Lock-free skip-list memtable** with epoch-based reclamation
  (`crossbeam-epoch`).
- **16 KB SSTable data blocks**, 4 KB-aligned, partitioned blocked-bloom
  filters with AVX2/AVX-512 dispatch.
- **io_uring SQPOLL** for WAL group commit, **O_DIRECT** for compaction I/O,
  **mmap + MADV_RANDOM** for hot point-read SSTables.
- **AES-256-GCM** encryption at rest with hand-rolled AES-NI intrinsics.

## Quick start (Linux)

```bash
git clone https://github.com/ndenigris/PaddockKV
cd PaddockKV
cargo build --release
cargo test --workspace
```

## API preview

```rust
use paddock_core::{Db, io::vfs::MemVfs};

let vfs = MemVfs::new();              // production path uses a Linux VFS
let db = Db::open(vfs, "/data")?;

db.put(b"hello", b"world")?;
assert_eq!(db.get(b"hello")?, Some(b"world".to_vec()));

let snap = db.snapshot();
db.put(b"hello", b"there")?;
assert_eq!(db.get_at(b"hello", snap)?, Some(b"world".to_vec()));  // MVCC

db.flush()?;                           // drain memtable → SSTable
let reopened = Db::open(vfs, "/data")?; // WAL replay restores in-memory state
```

## Benchmarks

See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) once Phase 10 lands.

## License

Dual-licensed under MIT or Apache-2.0.
