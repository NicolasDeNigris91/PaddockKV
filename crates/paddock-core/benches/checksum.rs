// `criterion_group!`/`criterion_main!` generate undocumented items at the
// crate root of the bench harness. Suppress the workspace-wide `missing_docs`
// for the bench file only.
#![allow(missing_docs)]

//! Throughput benchmarks for the checksum primitives.
//!
//! Run with:
//!
//! ```bash
//! cargo bench -p paddock-core --bench checksum
//! ```
//!
//! Each algorithm is exercised at three sizes that mirror real workloads:
//!
//! - **64 B**   — a small WAL record.
//! - **4 KiB**  — a single NVMe page (lower end of SSTable block range).
//! - **16 KiB** — the SSTable data-block size we target.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use paddock_core::checksum::{crc32c, xxh3};

const SIZES: &[usize] = &[64, 4 * 1024, 16 * 1024];

fn make_data(size: usize) -> Vec<u8> {
    // Deterministic pseudo-random payload — no entropy from the OS, just a
    // mulberry-like LCG so the benchmark is reproducible.
    let mut buf = vec![0u8; size];
    let mut state: u32 = 0x9E37_79B9;
    for byte in &mut buf {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        // SAFETY-ish: we explicitly want the low 8 bits of the LCG output.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "low byte of LCG output is the desired random byte"
        )]
        let b = (state >> 16) as u8;
        *byte = b;
    }
    buf
}

fn bench_checksums(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");
    for &size in SIZES {
        let data = make_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("crc32c", size), &data, |b, d| {
            b.iter(|| crc32c::hash(std::hint::black_box(d)));
        });

        group.bench_with_input(BenchmarkId::new("xxh3_64", size), &data, |b, d| {
            b.iter(|| xxh3::hash(std::hint::black_box(d)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_checksums);
criterion_main!(benches);
