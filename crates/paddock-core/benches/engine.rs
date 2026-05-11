// `criterion_group!`/`criterion_main!` generate undocumented items at the
// crate root of the bench harness.
#![allow(missing_docs)]
// Bench fixtures use deterministic LCG; small bounded values where
// truncation is impossible by construction.
#![allow(clippy::cast_possible_truncation)]
// Module-level doc references workload names verbatim ("write_then_read_hot")
// without backticks — these are bench-group identifiers, not Rust items.
#![allow(clippy::doc_markdown)]

//! End-to-end engine benchmarks.
//!
//! Three workloads at three sizes (1K / 10K / 100K records, 64-byte values).
//! Every benchmark runs against a fresh in-memory `MemVfs` so results
//! reflect engine logic — not the host disk. Linux benchmarks against an
//! `O_DIRECT` + io_uring backend land alongside Phase 11 once the
//! production VFS ships.
//!
//! ## Workloads
//!
//! - **write_then_read_hot**: ingest N records, flush to one SSTable, then
//!   point-lookup every key. Measures the steady-state read path with
//!   data resident in memory (Bloom filter + index in RAM, data block
//!   bytes in the `MemFile`'s `Vec<u8>`).
//!
//! - **write_throughput**: ingest N records into a fresh DB and call
//!   `flush()` once at the end. Measures the WAL+memtable write path; the
//!   single final flush keeps the per-record bookkeeping in scope without
//!   over-counting flush amortization.
//!
//! - **read_amplification_after_flushes**: ingest N records across 8
//!   flushes (so the read path walks 8 SSTables), then point-lookup every
//!   key. Shows the cost the compaction layer exists to eliminate.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use paddock_core::Db;
use paddock_core::engine::DbConfig;
use paddock_core::io::vfs::MemVfs;

const SIZES: &[usize] = &[1_000, 10_000, 100_000];
const VALUE_LEN: usize = 64;

fn deterministic_keys(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("key-{i:010}").into_bytes())
        .collect()
}

fn value() -> [u8; VALUE_LEN] {
    let mut v = [0u8; VALUE_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }
    v
}

fn populate(db: &Db<MemVfs>, keys: &[Vec<u8>], value: &[u8]) {
    for k in keys {
        db.put(k, value).expect("put");
    }
}

fn bench_write_then_read_hot(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_write_then_read_hot");
    for &n in SIZES {
        let keys = deterministic_keys(n);
        let val = value();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("get", n), &(keys, val), |b, (ks, v)| {
            // Pre-build the DB once outside the timed region; reuse across
            // iterations.
            let vfs = MemVfs::new();
            let db = Db::open(vfs, "/db").expect("open");
            populate(&db, ks, v);
            db.flush().expect("flush");
            b.iter(|| {
                for k in ks {
                    let got = db.get(std::hint::black_box(k)).expect("get");
                    std::hint::black_box(got);
                }
            });
        });
    }
    group.finish();
}

fn bench_write_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_write_throughput");
    for &n in SIZES {
        let keys = deterministic_keys(n);
        let val = value();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("put", n), &(keys, val), |b, (ks, v)| {
            b.iter_with_setup(
                || {
                    let vfs = MemVfs::new();
                    Db::open(vfs, "/db").expect("open")
                },
                |db| {
                    for k in ks {
                        db.put(std::hint::black_box(k), v).expect("put");
                    }
                    db.flush().expect("flush");
                    std::hint::black_box(db);
                },
            );
        });
    }
    group.finish();
}

/// Always 8 SSTables, so the reader walks all 8 newest-first on every
/// miss (the Bloom filter prunes most). The per-table size scales with
/// N so the bench measures the cost of N rather than the SSTable count.
const NUM_FLUSHES: usize = 8;

fn bench_read_amp_after_flushes(c: &mut Criterion) {
    let mut group = c.benchmark_group("engine_read_amplification");
    for &n in SIZES {
        let keys = deterministic_keys(n);
        let val = value();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::new("get_after_8_flushes", n),
            &(keys, val),
            |b, (ks, v)| {
                let vfs = MemVfs::new();
                let cfg = DbConfig {
                    // Small enough that no rotation is triggered during a
                    // chunk; we call flush() explicitly between chunks.
                    memtable_threshold_bytes: 256 * 1024 * 1024,
                    ..DbConfig::default()
                };
                let db = Db::open_with(vfs, "/db", cfg).expect("open");
                let chunk_size = ks.len() / NUM_FLUSHES;
                for chunk in 0..NUM_FLUSHES {
                    for k in &ks[chunk * chunk_size..(chunk + 1) * chunk_size] {
                        db.put(k, v).expect("put");
                    }
                    db.flush().expect("flush");
                }
                assert!(db.sstable_count() >= NUM_FLUSHES);
                b.iter(|| {
                    for k in ks {
                        let got = db.get(std::hint::black_box(k)).expect("get");
                        std::hint::black_box(got);
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_write_throughput,
    bench_write_then_read_hot,
    bench_read_amp_after_flushes
);
criterion_main!(benches);
