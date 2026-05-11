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

## HTTP server

A thin axum-based HTTP wrapper lives in [`crates/paddock-server`](crates/paddock-server/).
It exposes the engine over a small JSON API and reads its configuration
from environment variables so the same binary deploys to Railway,
Fly.io, Render, or a bare VM with no flags:

| Variable              | Default        | Meaning                                                |
|-----------------------|----------------|--------------------------------------------------------|
| `PORT`                | `8080`         | TCP port to bind on `0.0.0.0`                          |
| `DATA_DIR`            | `./data`       | Engine data directory                                   |
| `PADDOCK_MASTER_KEY`  | _(unset)_      | 64-char hex (32 bytes) → enables encryption-at-rest    |
| `RUST_LOG`            | `info,paddock_server=debug,tower_http=info` | Tracing filter |

Routes:

- `GET /health` — liveness probe (always 200 OK)
- `GET /stats` — JSON `{sstable_count, current_seqno, encrypted}`
- `PUT /kv/:key` — body is the raw value bytes; stores `key → value`
- `GET /kv/:key` — returns value bytes on hit, `404` on miss
- `DELETE /kv/:key` — writes a tombstone
- `GET /scan?start=<b64>&end=<b64>&limit=<n>` — JSON array of records, keys & values base64-encoded
- `POST /flush` — drain pending memtables to SSTables
- `POST /compact` — merge every SSTable into one

### Run locally

```bash
cargo run --release -p paddock-server
# server listens on 0.0.0.0:8080
curl -X PUT --data 'world' http://127.0.0.1:8080/kv/hello
curl http://127.0.0.1:8080/kv/hello
# → world
```

### Deploy to Railway

1. Push this repository to GitHub (already done if you are reading this on github.com).
2. From Railway: **New Project → Deploy from GitHub repo → PaddockKV**.
3. Railway picks up [`railway.toml`](railway.toml) and the
   [`Dockerfile`](Dockerfile) automatically and runs a multi-stage
   cargo-chef build.
4. **Add a Volume**: Settings → Volumes → Add Volume, mount path `/data`.
   Without a volume, SSTables and the WAL live only inside the container
   and are wiped on every redeploy.
5. *(Optional)* Enable encryption-at-rest:
   ```bash
   railway variables --set "PADDOCK_MASTER_KEY=$(openssl rand -hex 32)"
   ```
   Keep that value safe — losing it makes every previously-written
   SSTable unreadable.
6. Hit your `*.up.railway.app` URL:
   ```bash
   curl -X PUT --data 'world' https://<your-app>.up.railway.app/kv/hello
   curl https://<your-app>.up.railway.app/kv/hello
   ```

> **Security caveat**: the demo server has no authentication. Anyone who
> can reach the URL can read and write every key. Before exposing it to
> the open internet, put it behind an API gateway, a sidecar that adds
> Bearer-token auth, or wire authentication into `paddock-server`
> directly.

## Benchmarks

See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) once Phase 10 lands.

## License

Dual-licensed under MIT or Apache-2.0.
