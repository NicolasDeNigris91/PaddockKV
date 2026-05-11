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

// In tests / scripts:  MemVfs.
// On Linux production:  paddock_core::io::LinuxVfs::create_at("/var/lib/paddock")?
let vfs = MemVfs::new();
let db = Db::open(vfs, "/data")?;

db.put(b"hello", b"world")?;
assert_eq!(db.get(b"hello")?, Some(b"world".to_vec()));

let snap = db.snapshot();
db.put(b"hello", b"there")?;
assert_eq!(db.get_at(b"hello", snap)?, Some(b"world".to_vec()));  // MVCC

// Ordered range scan over an arbitrary slice of the keyspace.
for rec in db.range(b"a", b"z")? {
    let rec = rec?;
    println!("{:?} -> {:?}", rec.key, rec.value);
}

db.flush()?;                            // drain memtable → encrypted SSTable
db.compact_all()?;                      // k-way-merge several SSTables → one
```

## Encryption at rest

```rust
use paddock_core::{Db, crypto::MasterKey, engine::DbConfig, io::vfs::MemVfs};

let cfg = DbConfig {
    master_key: Some(MasterKey::from_bytes([0u8; 32])), // load from KMS
    ..DbConfig::default()
};
let db = Db::open_with(MemVfs::new(), "/data", cfg)?;
// Every SSTable the engine emits is AES-256-GCM-encrypted under a
// per-table key derived via HKDF-SHA256 from the master key.
```

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for what the
encryption layer protects and (importantly) what it does **not**.

## Benchmarks

See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) once Phase 10 lands.

## License

Dual-licensed under MIT or Apache-2.0.
