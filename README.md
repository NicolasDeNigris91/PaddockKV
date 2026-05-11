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

## Benchmarks

See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) once Phase 10 lands.

## License

Dual-licensed under MIT or Apache-2.0.
