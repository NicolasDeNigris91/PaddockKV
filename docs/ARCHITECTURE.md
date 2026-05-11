# PaddockKV Architecture

> Public-facing summary of the engine design. The exhaustive internal plan
> with phase-by-phase implementation roadmap is kept private; this document is
> what an outside reader (recruiter, contributor) should read first.

## What it is

PaddockKV is a Linux-native, single-node Log-Structured Merge-tree key-value
store written in Rust. It is built to demonstrate three things at once:

1. **Performance** — single-threaded p999 cold-cache point-read latency that
   beats RocksDB on small values in the working-set-exceeds-RAM regime.
2. **Security** — encryption at rest with a documented threat model, plus the
   memory-safety guarantees Rust ownership provides over the C++ comparison.
3. **Hardware mastery** — io_uring, O_DIRECT, mmap, AVX2/AVX-512, AES-NI, and
   cache-line-aware data structures are used deliberately, not decoratively.

## Pillars

| Pillar | Mechanism |
|---|---|
| Durability | Write-ahead log with CRC32C-framed records, group commit via io_uring linked `IORING_OP_WRITE` + `IORING_OP_FDATASYNC`. |
| Write throughput | Lock-free skip-list memtable with epoch-based reclamation; multiple writers, single WAL writer thread. |
| Read latency | Direct mmap of SSTable files with `MADV_RANDOM`; zero-copy `&[u8]` returns from `get()`. |
| Index efficiency | Partitioned blocked-bloom filters with AVX2/AVX-512 dispatch; sparse two-level index. |
| Compaction throughput | O_DIRECT writes via io_uring registered buffers; k-way merge iterator with prefetch. |
| Versioning | Immutable file set captured in an `ArcSwap<Version>`; readers grab a snapshot without locking. |
| Integrity | CRC32C or XXH3-64 over every persistent block; AES-256-GCM authentication tags when encryption is enabled. |
| Encryption (opt-in) | Per-block AES-256-GCM with AES-NI intrinsics; per-SSTable / per-WAL keys derived via HKDF-SHA256. |

## SSTable file format

See [`docs/format/sstable.md`](format/sstable.md) for the byte-exact layout.
Headlines:

- 16 KB data blocks, 4 KB-aligned file offsets, little-endian.
- Restart points every 16 records for intra-block binary search.
- Footer is exactly 64 bytes at end of file, contains offsets to index,
  filter, and meta blocks.
- File header is 4 KB, page-aligned, parsed via [`zerocopy`].

## WAL format

See [`docs/format/wal.md`](format/wal.md). 32 KB block-framed log,
LevelDB-style FULL/FIRST/MIDDLE/LAST record types for records spanning block
boundaries, per-record CRC32C.

## Threat model (encryption)

See [`docs/THREAT_MODEL.md`](THREAT_MODEL.md). Protects offline disks. Does
**not** protect against memory disclosure or a compromised process.

## Status

| Phase | Component | State |
|---|---|---|
| 0 | Foundations (errors, varint, checksums, CI) | ✅ done |
| 1 | I/O foundation (mmap, O_DIRECT, io_uring) | ✅ done |
| 2 | WAL (format, batch, writer, reader, replay) | ✅ done |
| 3 | Memtable (arena + Pugh skip list) | ✅ done |
| 4 | SSTable read path (format, block, writer, reader) | ✅ done |
| 5 | Bloom filters (blocked, AVX2 SIMD, SSTable-integrated) | ✅ done |
| 6 | Engine integration (`Db::open/put/get/flush/close`, recovery) | ✅ done |
| 7 | Compaction (k-way merge, `Db::compact_all`) | ✅ done |
| 7b | Snapshot-aware version pruning + manifest | ⏳ |
| 8a | Crypto primitives (AES-256-GCM, HKDF-SHA256, envelope) | ✅ done |
| 8b | SSTable encryption pipeline (per-block AEAD, file-header back-fill, WAL post-flush cleanup) | ✅ done |
| 9 | Fuzz harness (4 targets) + Miri CI on unsafe-heavy modules | ✅ done |
| 10 | End-to-end engine criterion benchmarks + published numbers | ✅ done |
| 11 | Production Linux VFS (`O_DIRECT` + io_uring + mmap), vs-RocksDB benches | ⏳ |
| 9 | Fuzzing + sanitizers | ⏳ |
| 10 | Benchmarks + docs | ⏳ |

[`zerocopy`]: https://docs.rs/zerocopy
