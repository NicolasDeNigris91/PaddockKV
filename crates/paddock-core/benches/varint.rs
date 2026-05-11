// `criterion_group!`/`criterion_main!` generate undocumented items at the
// crate root of the bench harness. Suppress the workspace-wide `missing_docs`
// for the bench file only.
#![allow(missing_docs)]

//! Throughput benchmarks for varint encode and decode.
//!
//! Three value distributions are tested:
//!
//! - **Small** (always fits in 1 byte): every value is `< 128`. Dominant in
//!   record headers where lengths are typically small.
//! - **Medium** (3 bytes): values in `[1<<14, 1<<21)`.
//! - **Large** (10 bytes): values in `[1<<57, u64::MAX)`.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use paddock_core::encoding::varint::{MAX_VARINT_U64_BYTES, decode_u64, encode_u64};

fn make_values(seed: u64, count: usize, mask: u64) -> Vec<u64> {
    let mut s = seed;
    (0..count)
        .map(|_| {
            s = s.wrapping_mul(0x5851_F42D_4C95_7F2D).wrapping_add(1);
            s & mask
        })
        .collect()
}

fn bench_encode(c: &mut Criterion) {
    let cases = [
        ("small", make_values(1, 1024, 0x7F)),
        ("medium", make_values(2, 1024, (1 << 21) - 1)),
        ("large", make_values(3, 1024, u64::MAX)),
    ];

    let mut group = c.benchmark_group("varint_encode");
    for (label, values) in &cases {
        group.throughput(Throughput::Elements(values.len() as u64));
        group.bench_with_input(BenchmarkId::new("encode_u64", label), values, |b, vs| {
            let mut buf = [0u8; MAX_VARINT_U64_BYTES];
            b.iter(|| {
                let mut total = 0usize;
                for &v in vs {
                    let n = encode_u64(std::hint::black_box(v), &mut buf).unwrap();
                    total = total.wrapping_add(n);
                }
                std::hint::black_box(total)
            });
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let cases = [
        ("small", make_values(1, 1024, 0x7F)),
        ("medium", make_values(2, 1024, (1 << 21) - 1)),
        ("large", make_values(3, 1024, u64::MAX)),
    ];

    let mut group = c.benchmark_group("varint_decode");
    for (label, values) in &cases {
        // Encode into a contiguous buffer once, then bench decoding.
        let mut buf = Vec::with_capacity(values.len() * MAX_VARINT_U64_BYTES);
        let mut tmp = [0u8; MAX_VARINT_U64_BYTES];
        for &v in values {
            let n = encode_u64(v, &mut tmp).unwrap();
            buf.extend_from_slice(&tmp[..n]);
        }

        group.throughput(Throughput::Elements(values.len() as u64));
        group.bench_with_input(BenchmarkId::new("decode_u64", label), &buf, |b, encoded| {
            b.iter(|| {
                let mut input: &[u8] = std::hint::black_box(encoded);
                let mut sum: u64 = 0;
                while !input.is_empty() {
                    let (v, n) = decode_u64(input).unwrap();
                    sum = sum.wrapping_add(v);
                    input = &input[n..];
                }
                std::hint::black_box(sum)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
