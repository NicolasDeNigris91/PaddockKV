# PaddockKV

[![CI](https://github.com/NicolasDeNigris91/PaddockKV/actions/workflows/ci.yml/badge.svg)](https://github.com/NicolasDeNigris91/PaddockKV/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95+-orange.svg)](rust-toolchain.toml)

A from-scratch, Linux-native LSM-tree key-value store in Rust, built to
beat RocksDB on single-threaded p999 cold-cache point-read latency
without leaning on any high-level engine dependency.

## Highlights

- **Lock-free skip-list memtable** with epoch-based reclamation
  (`crossbeam-epoch`) — readers never block, writers never lock.
- **Three I/O strategies, one per workload**: `io_uring` SQPOLL for WAL
  group commit, `O_DIRECT` with 4 KiB-aligned page buffers for
  compaction, `mmap` + `MADV_RANDOM` for hot point-read SSTables.
- **Partitioned blocked-bloom filters** with runtime AVX2/AVX-512
  dispatch — flat ~25 M probes/s independent of filter size, sub-1 %
  FPR, one cache-line touch per probe.
- **AES-256-GCM encryption at rest** with HKDF-SHA256 per-table key
  derivation. Hand-rolled AES-NI dispatch; master key supplied via env
  or a KMS shim.
- **MVCC reads via `ArcSwap<Version>`**: every reader grabs an immutable
  snapshot of the file set without taking a lock; compaction publishes
  a new version atomically.
- **Verified `unsafe`**: every unsafe-heavy module (`io::aligned_buf`,
  `memtable::arena`, `memtable::skiplist`, `filter::blocked_bloom`) is
  exercised under Miri in CI; end-to-end recovery + parse + decode
  paths are smoke-fuzzed under `cargo-fuzz` on every push.
- **Rust 2024, MSRV 1.95**, `#![deny(unsafe_op_in_unsafe_fn)]` with
  dense SAFETY-comment discipline. CI gates clippy with `-W pedantic
  -W nursery` and `-D warnings`.

## Architecture

```
                        write path                            read path
                       ┌──────────┐                          ┌──────────┐
   put(k,v) ─────────► │   WAL    │  ◄── fsync via           │ memtable │ ◄── skiplist probe
                       │ (group   │      io_uring SQPOLL     │  check   │
                       │  commit) │                          └────┬─────┘
                       └────┬─────┘                               │ miss
                            ▼                                     ▼
                       ┌──────────┐                  for each SSTable (newest first):
                       │ memtable │                  ┌─────────────────────────────────┐
                       │ skiplist │                  │ blocked-bloom probe (~40 ns)    │
                       │ (lock-   │                  │   ↓ probable hit                │
                       │  free)   │                  │ binary search in sparse index   │
                       └────┬─────┘                  │   ↓                             │
                            │ rotates                │ data block read via mmap        │
                            │ at ~8 MiB              │   ↓                             │
                            ▼                        │ prefix-decompress + checksum    │
                       ┌──────────┐                  │   ↓                             │
                       │ SSTable  │ ◄─ compaction    │ return value (zero-copy borrow) │
                       │ 16 KiB   │   k-way merge    └─────────────────────────────────┘
                       │ blocks,  │
                       │ bloom +  │
                       │ index    │
                       └────┬─────┘
                            │ optional
                            ▼
                       ┌──────────┐
                       │ AES-256- │   per-table key via HKDF-SHA256
                       │  GCM     │   AAD-bound to (file_id, block_offset)
                       └──────────┘
```

Full design rationale in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md);
threat model for the encryption layer in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md); byte-exact file
formats in [`docs/format/`](docs/format/).

## Benchmarks

Dev-machine baselines (Windows x86_64, Rust 1.95 release + LTO,
in-memory `MemVfs` — measures engine logic without the disk-bandwidth
ceiling). Full methodology and per-phase numbers in
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

**Reads — `Db::get` over a hot 100 K-record dataset:**

| Layout                 | Throughput     | Per-op   |
|------------------------|----------------|----------|
| 1 SSTable, 100 K keys  | 192 K gets/s   | ~5.2 µs  |
| 8 SSTables, 100 K keys | 221 K gets/s   | ~4.5 µs  |

The 8-SSTable variant is **faster than the single-SSTable variant** at
small N (data blocks fit in L1) and only ~13 % slower at large N — the
Bloom filter prunes ~99 % of negative probes, so 7 of 8 SSTables exit
without a disk read. This is the read-amplification target the
compaction layer is built around.

**Bloom probe** — ~25 M probes/s flat across 10 K, 100 K, 1 M-key filters
via AVX2; each probe touches a single 64-byte cache line.

**Checksum throughput on 16 KiB blocks** — XXH3-64 at **33 GiB/s**;
CRC32C at 6.7 GiB/s (software fallback; the gap closes on Linux with
hardware `_mm_crc32_u64`).

Linux + `O_DIRECT` + `io_uring` end-to-end vs RocksDB on YCSB A–F lands
alongside Phase 11c.

## Quick start

### Cargo

```bash
git clone https://github.com/NicolasDeNigris91/PaddockKV
cd PaddockKV
cargo build --release
cargo test --workspace --all-features
```

Linux gets the full engine (io_uring + O_DIRECT + mmap via
`LinuxVfs`). Windows and macOS get the platform-neutral engine code +
an in-memory VFS — useful for tests and the HTTP server demo, but
no persistence across restarts.

### Docker

```bash
docker build -t paddockkv .
docker run --rm -p 8080:8080 -v paddock-data:/data paddockkv

# Round-trip a value over HTTP
curl -X PUT --data 'world' http://127.0.0.1:8080/kv/hello
curl http://127.0.0.1:8080/kv/hello
# → world
```

The multi-stage Dockerfile uses [`cargo-chef`] to cache the dependency
graph, runs the server as an unprivileged user (UID 10001), and chowns
the mounted volume at startup via
[`docker/entrypoint.sh`](docker/entrypoint.sh) — the same pattern
Railway, Fly.io, and Render need.

[`cargo-chef`]: https://github.com/LukeMathWalker/cargo-chef

## API preview

```rust
use paddock_core::{Db, io::vfs::MemVfs};

// In tests / scripts: MemVfs.
// On Linux production: paddock_core::io::LinuxVfs::create_at("/var/lib/paddock")?
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
// per-table key derived via HKDF-SHA256 from the master key. Block
// AADs bind the ciphertext to (file_id, block_offset) so a swap of
// encrypted blocks between files fails authentication.
```

The threat model — what this protects (offline disk seizure) and what
it does **not** (memory disclosure, compromised process) — is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## HTTP server

A thin axum-based wrapper lives in
[`crates/paddock-server`](crates/paddock-server/). It reads its
configuration from environment variables so the same binary deploys to
any PaaS without flag wiring.

| Variable              | Default        | Meaning                                              |
|-----------------------|----------------|------------------------------------------------------|
| `PORT`                | `8080`         | TCP port to bind on `0.0.0.0`                        |
| `DATA_DIR`            | `./data`       | Engine data directory                                |
| `PADDOCK_MASTER_KEY`  | _(unset)_      | 64-char hex (32 bytes) → enables encryption-at-rest |
| `RUST_LOG`            | `info,paddock_server=debug,tower_http=info` | Tracing filter         |

Routes:

| Method | Path           | Effect                                                            |
|--------|----------------|-------------------------------------------------------------------|
| GET    | `/health`      | Liveness probe (always 200 OK)                                    |
| GET    | `/stats`       | JSON `{sstable_count, current_seqno, encrypted}`                  |
| PUT    | `/kv/:key`     | Body is the raw value bytes; stores `key → value`                 |
| GET    | `/kv/:key`     | Returns value bytes on hit, 404 on miss                           |
| DELETE | `/kv/:key`     | Writes a tombstone                                                |
| GET    | `/scan`        | `?start=<b64>&end=<b64>&limit=<n>`; JSON array of `{key, value, seqno}` |
| POST   | `/flush`       | Drain pending memtables to SSTables                               |
| POST   | `/compact`     | Merge every SSTable into one                                      |

> **Security caveat**: the server has no authentication. Anyone who can
> reach the URL can read and write every key. Before exposing it to the
> open internet, put it behind an API gateway, a sidecar that adds
> Bearer-token auth, or wire authentication into `paddock-server`
> directly.

### Self-hosting

The repo ships a [`Dockerfile`](Dockerfile) (multi-stage cargo-chef
cache) and a [`railway.toml`](railway.toml) (Railway service config)
so the server deploys to any container platform without extra glue.
For Railway specifically: **New Project → Deploy from GitHub repo →
PaddockKV**, add a Volume mounted at `/data`, optionally set
`PADDOCK_MASTER_KEY`.

## Project layout

```
crates/
├── paddock-core    — engine: WAL, memtable, SSTable, compaction, crypto, io
├── paddock-server  — axum HTTP frontend (the binary you deploy)
├── paddock-bench   — criterion benchmark binaries
└── paddock-fuzz    — cargo-fuzz targets (WAL recovery, SSTable parse,
                      Bloom decode, WriteBatch decode)
docker/             — container entrypoint that chowns the mounted volume
docs/               — ARCHITECTURE.md, BENCHMARKS.md, THREAT_MODEL.md,
                      format/ (byte-exact SSTable + WAL specifications)
```

## Development

```bash
# Unit + integration + property tests
cargo test --workspace --all-features
cargo test --workspace --all-features --release  # catches release-only bugs

# Criterion benchmarks (full run ~few minutes per group)
cargo bench --workspace
cargo bench --workspace -- --quick              # ~10 s sanity run

# Lint discipline (matches CI)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Miri on unsafe-heavy modules (requires nightly)
rustup toolchain install nightly --component miri
cargo +nightly miri test -p paddock-core --lib io::aligned_buf -- --skip prop_

# Smoke fuzzing (requires nightly + cargo-fuzz)
cargo install cargo-fuzz
cd crates/paddock-fuzz
cargo +nightly fuzz run --fuzz-dir . fuzz_wal_recovery -- -max_total_time=30
```

All of the above runs on every push to `main` and every PR via
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## License

Dual-licensed under MIT or Apache-2.0, at your option.

- [LICENSE-MIT](LICENSE-MIT)
- Apache-2.0: <https://www.apache.org/licenses/LICENSE-2.0>
