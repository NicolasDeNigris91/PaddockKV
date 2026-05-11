//! Approximate set-membership filters.
//!
//! The SSTable filter block holds a [`BlockedBloom`] over every key in the
//! table. On a point lookup, the engine consults the filter before reading
//! the data block from disk — a `false` answer is a definitive miss and
//! lets the read path skip the block load entirely. With the default
//! parameters (`10` bits/key, `8` hashes), the empirical false-positive
//! rate is around 0.5–1%, so the filter prunes ~99% of negative lookups in
//! exchange for ~10 bits of RAM per key.
//!
//! ## Why "blocked"
//!
//! A classical Bloom filter probes `k` bits scattered across the entire bit
//! array; on a 100M-key table that means `k` independent cache-line misses
//! per probe. A **blocked** Bloom filter restricts every key's bits to a
//! single 64-byte block (one CPU cache line on every contemporary x86_64
//! and ARM64 part). One hash picks the block, the rest of the hash picks
//! the in-block bits — exactly one cache miss per probe, regardless of
//! `k`. The minor FPR penalty (a few extra basis points vs. classical
//! Bloom for the same memory budget) is a great trade.
//!
//! ## SIMD acceleration
//!
//! Each block is exactly 512 bits, which fits in two AVX2 `__m256i`
//! registers (or a single AVX-512 `__m512i`). The probe builds a 512-bit
//! mask carrying the `k` candidate bits, `_mm256_and_si256`s it against
//! the block, and tests subset inclusion with `_mm256_testc_si256` —
//! roughly 3× the throughput of the scalar loop on a Zen3+ / Sapphire
//! Rapids host. Runtime CPU feature detection picks the fastest path on
//! first use; the scalar implementation stays as the always-available
//! fallback.

pub mod blocked_bloom;

pub use blocked_bloom::{BlockedBloom, BloomParams};
