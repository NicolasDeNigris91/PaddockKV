// `criterion_group!`/`criterion_main!` generate undocumented items at the
// crate root of the bench harness. Suppress the workspace-wide `missing_docs`
// for the bench file only.
#![allow(missing_docs)]
// Bench inputs are bounded by `SIZES` (≤ 1M entries), so usize→u64 widening
// is loss-free in practice and the cast sites stay explicit.
#![allow(clippy::cast_possible_truncation)]

//! Blocked Bloom filter throughput benchmarks.
//!
//! Five sizes spanning the realistic SSTable range: 10K through 10M keys.
//! For each size we measure (a) build throughput (inserts per second) and
//! (b) probe throughput, with separate "hit" and "miss" inputs to capture
//! both fast-path and short-circuit behaviour.
//!
//! On x86_64 with AVX2 the runtime dispatch in [`BlockedBloom::contains`]
//! picks the SIMD probe automatically; the scalar fallback is exercised
//! explicitly through the private API in the integration test suite.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use paddock_core::filter::{BlockedBloom, BloomParams};

const SIZES: &[usize] = &[10_000, 100_000, 1_000_000];

fn build_filter(n: usize) -> BlockedBloom {
    let mut f = BlockedBloom::new(n, BloomParams::default());
    for i in 0..n {
        f.insert(format!("k-{i:010}").as_bytes());
    }
    f
}

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_insert");
    for &n in SIZES {
        // We pre-generate the keys so the benchmark measures the filter,
        // not `format!`.
        let keys: Vec<Vec<u8>> = (0..n).map(|i| format!("k-{i:010}").into_bytes()).collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("insert", n), &keys, |b, ks| {
            b.iter(|| {
                let mut f = BlockedBloom::new(ks.len(), BloomParams::default());
                for k in ks {
                    f.insert(std::hint::black_box(k));
                }
                std::hint::black_box(f);
            });
        });
    }
    group.finish();
}

fn bench_probe_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_probe_hit");
    for &n in SIZES {
        let f = build_filter(n);
        let keys: Vec<Vec<u8>> = (0..n).map(|i| format!("k-{i:010}").into_bytes()).collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("contains_hit", n), &keys, |b, ks| {
            b.iter(|| {
                let mut count = 0usize;
                for k in ks {
                    if f.contains(std::hint::black_box(k)) {
                        count += 1;
                    }
                }
                std::hint::black_box(count)
            });
        });
    }
    group.finish();
}

fn bench_probe_miss(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_probe_miss");
    for &n in SIZES {
        let f = build_filter(n);
        // Disjoint key set so hits are nominal (~1% FPR).
        let keys: Vec<Vec<u8>> = (0..n)
            .map(|i| format!("absent-{i:010}").into_bytes())
            .collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("contains_miss", n), &keys, |b, ks| {
            b.iter(|| {
                let mut count = 0usize;
                for k in ks {
                    if f.contains(std::hint::black_box(k)) {
                        count += 1;
                    }
                }
                std::hint::black_box(count)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_insert, bench_probe_hit, bench_probe_miss);
criterion_main!(benches);
