// SIMD intrinsics in the AVX2 probe path involve several `unsafe` ops that
// share a single invariant (the function is `#[target_feature(enable =
// "avx2")]` and the data pointer comes from an `AlignedBuf` allocated at
// `BLOCK_BYTES` alignment). Splitting each intrinsic into its own block
// would obscure that invariant; SAFETY comments stay at the call sites.
#![allow(clippy::multiple_unsafe_ops_per_block)]
// `*const u8` and `*const u64` cast to `*const __m256i` after `AlignedBuf`
// guarantees the 64-byte alignment SIMD requires.
#![allow(clippy::cast_ptr_alignment)]

//! Cache-line-blocked Bloom filter with AVX2 SIMD probing.
//!
//! Each block is **64 bytes = 512 bits** (one x86_64 cache line). A key's
//! bits all live in a single block, so one probe = one cache miss. See the
//! module-level docs in [`crate::filter`] for the design rationale.
//!
//! ## Hashing
//!
//! A single XXH3-64 over the key gives all the randomness we need. The
//! 64-bit hash is split as `(h_low, h_high)`. `h_low` (as `u32`) picks the
//! block via Lemire's multiply-shift fast mod. `h_high` (as `u32`) is then
//! folded into `K` bit positions inside the block by a Kirsch–Mitzenmacher
//! double-hashing scheme (`bit_i = (h_a + i * h_b) % 512`). Both `h_a` and
//! `h_b` are derived from the same 64-bit hash, so we do exactly one hash
//! per probe.
//!
//! ## On-disk layout
//!
//! When persisted in the SSTable filter block, the bytes are:
//!
//! ```text
//!   Header (16 bytes, little-endian):
//!     u32 magic           = 0xB100_0F11
//!     u8  version         = 1
//!     u8  num_hashes      (K, default 8)
//!     u8  bits_per_key    (default 10)
//!     u8  _reserved
//!     u32 num_blocks
//!     u32 num_keys
//!   Bytes (num_blocks * 64): the block array, 64-byte aligned in memory.
//! ```

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::checksum::xxh3;
use crate::error::{Error, Result};

/// Magic at the start of a serialised filter. ASCII-ish `"BLOOM"` tagged.
const FILTER_MAGIC: u32 = 0xB100_0F11;

/// Persisted format version. Readers refuse other values.
const FILTER_VERSION: u8 = 1;

/// Fixed 16-byte header in front of the block bytes.
const HEADER_SIZE: usize = 16;

/// Block size in bytes. One cache line on x86_64 and ARM64.
pub const BLOCK_BYTES: usize = 64;

/// Block size in bits (`BLOCK_BYTES * 8`). Fits trivially in `u32`.
pub const BLOCK_BITS: u32 = 512;

/// Default number of hash bits set per key. Optimal-ish for 10 bits/key.
pub const DEFAULT_NUM_HASHES: u8 = 8;

/// Default bits-per-key budget. 10 bits/key ≈ 1% false-positive rate.
pub const DEFAULT_BITS_PER_KEY: u8 = 10;

/// Tunable parameters for filter construction.
#[derive(Debug, Clone, Copy)]
pub struct BloomParams {
    /// Number of bit positions to set per key (`k`). Must be in `1..=16`.
    pub num_hashes: u8,
    /// Bit budget per key. Picked together with `num_hashes` to hit the
    /// target false-positive rate; 10 bits/key with `k = 8` is the typical
    /// "1% FPR" setting.
    pub bits_per_key: u8,
}

impl Default for BloomParams {
    fn default() -> Self {
        Self {
            num_hashes: DEFAULT_NUM_HASHES,
            bits_per_key: DEFAULT_BITS_PER_KEY,
        }
    }
}

/// Cache-line-blocked Bloom filter.
///
/// Construct via [`BlockedBloom::new`], populate with [`insert`](Self::insert),
/// then either query in-memory with [`contains`](Self::contains) or
/// serialise to bytes with [`encode`](Self::encode) for the SSTable filter
/// block.
pub struct BlockedBloom {
    /// Concatenated 64-byte blocks. The first byte is 64-byte aligned in
    /// memory (we route the allocation through
    /// [`crate::io::aligned_buf::AlignedBuf`] so SIMD probes never straddle
    /// a cache line).
    blocks: crate::io::aligned_buf::AlignedBuf,
    num_blocks: u32,
    num_keys: u32,
    params: BloomParams,
}

impl BlockedBloom {
    /// Build an empty filter sized for `expected_keys` insertions.
    ///
    /// `num_blocks` is chosen so the average block load matches the
    /// `bits_per_key` budget; the result is rounded up to give a touch of
    /// headroom and to avoid the degenerate 1-block case.
    #[must_use]
    pub fn new(expected_keys: usize, params: BloomParams) -> Self {
        assert!(
            params.num_hashes >= 1 && params.num_hashes <= 16,
            "BloomParams::num_hashes must lie in 1..=16"
        );
        let total_bits = (expected_keys.max(1) as u64) * u64::from(params.bits_per_key);
        let num_blocks = u32::try_from(total_bits.div_ceil(u64::from(BLOCK_BITS)))
            .unwrap_or(u32::MAX)
            .max(1);
        let bytes = (num_blocks as usize) * BLOCK_BYTES;
        let blocks = crate::io::aligned_buf::AlignedBuf::with_alignment(bytes, BLOCK_BYTES)
            .expect("blocked Bloom allocation");
        Self {
            blocks,
            num_blocks,
            num_keys: 0,
            params,
        }
    }

    /// Number of populated entries. Read for stats; the value the engine
    /// uses for FPR computation comes from the per-SSTable record count.
    #[must_use]
    pub const fn num_keys(&self) -> u32 {
        self.num_keys
    }

    /// Number of 64-byte blocks in the filter.
    #[must_use]
    pub const fn num_blocks(&self) -> u32 {
        self.num_blocks
    }

    /// Tunable parameters this filter was built with.
    #[must_use]
    pub const fn params(&self) -> BloomParams {
        self.params
    }

    /// Total bytes the in-memory filter occupies (excluding the persisted
    /// header).
    #[must_use]
    pub const fn byte_size(&self) -> usize {
        (self.num_blocks as usize) * BLOCK_BYTES
    }

    /// Insert `key` into the filter. Must be called only at build time —
    /// after [`encode`](Self::encode), the filter is logically frozen.
    pub fn insert(&mut self, key: &[u8]) {
        let hash = xxh3::hash(key);
        let block_idx = pick_block(hash, self.num_blocks);
        let k = self.params.num_hashes;
        let positions = bit_positions(hash, k);
        // SAFETY: `block_idx < num_blocks` by construction of `pick_block`.
        let block = unsafe { self.block_mut(block_idx) };
        for &pos in positions.iter().take(k as usize) {
            let byte = (pos / 8) as usize;
            let bit = (pos % 8) as u8;
            block[byte] |= 1 << bit;
        }
        self.num_keys = self.num_keys.saturating_add(1);
    }

    /// `true` if `key` was ever inserted (or, with the filter's nominal
    /// false-positive rate, occasionally even if it wasn't). `false` is a
    /// definitive miss.
    #[must_use]
    pub fn contains(&self, key: &[u8]) -> bool {
        let hash = xxh3::hash(key);
        let block_idx = pick_block(hash, self.num_blocks);
        // SAFETY: `block_idx < num_blocks`.
        let block = unsafe { self.block(block_idx) };
        dispatch_probe(block, hash, self.params.num_hashes)
    }

    /// Serialise the filter to a 16-byte header followed by the raw block
    /// bytes. The output is what gets persisted in the SSTable filter
    /// block.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + self.byte_size());
        out.extend_from_slice(&FILTER_MAGIC.to_le_bytes());
        out.push(FILTER_VERSION);
        out.push(self.params.num_hashes);
        out.push(self.params.bits_per_key);
        out.push(0); // _reserved
        out.extend_from_slice(&self.num_blocks.to_le_bytes());
        out.extend_from_slice(&self.num_keys.to_le_bytes());
        debug_assert_eq!(out.len(), HEADER_SIZE);
        out.extend_from_slice(&self.blocks[..self.byte_size()]);
        out
    }

    /// Reconstruct a filter from the bytes produced by [`encode`](Self::encode).
    ///
    /// The returned filter is `Send + Sync` and may be queried from many
    /// threads concurrently — it never mutates internal state after this
    /// point.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::invalid_format_static(
                "bloom filter",
                "shorter than header",
            ));
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("4-byte slice"));
        if magic != FILTER_MAGIC {
            return Err(Error::invalid_format_static("bloom filter", "wrong magic"));
        }
        let version = bytes[4];
        if version != FILTER_VERSION {
            return Err(Error::InvalidFormat {
                context: "bloom filter",
                reason: format!("unsupported version {version}"),
            });
        }
        let num_hashes = bytes[5];
        let bits_per_key = bytes[6];
        // bytes[7] is reserved.
        let num_blocks = u32::from_le_bytes(bytes[8..12].try_into().expect("4-byte slice"));
        let num_keys = u32::from_le_bytes(bytes[12..16].try_into().expect("4-byte slice"));
        if num_hashes == 0 || num_hashes > 16 {
            return Err(Error::InvalidFormat {
                context: "bloom filter",
                reason: format!("num_hashes out of range: {num_hashes}"),
            });
        }
        if num_blocks == 0 {
            return Err(Error::invalid_format_static(
                "bloom filter",
                "num_blocks must be >= 1",
            ));
        }
        let expected_payload = (num_blocks as usize) * BLOCK_BYTES;
        if bytes.len() != HEADER_SIZE + expected_payload {
            return Err(Error::InvalidFormat {
                context: "bloom filter",
                reason: format!(
                    "payload length {} does not match num_blocks={num_blocks} (expected {})",
                    bytes.len() - HEADER_SIZE,
                    expected_payload
                ),
            });
        }
        let mut blocks =
            crate::io::aligned_buf::AlignedBuf::with_alignment(expected_payload, BLOCK_BYTES)
                .expect("bloom filter allocation");
        blocks[..expected_payload].copy_from_slice(&bytes[HEADER_SIZE..]);
        Ok(Self {
            blocks,
            num_blocks,
            num_keys,
            params: BloomParams {
                num_hashes,
                bits_per_key,
            },
        })
    }

    /// # Safety
    ///
    /// `idx` must be `< self.num_blocks`.
    unsafe fn block(&self, idx: u32) -> &[u8; BLOCK_BYTES] {
        let start = (idx as usize) * BLOCK_BYTES;
        // SAFETY: caller asserts the index is in range; the slice is
        // exactly BLOCK_BYTES long and laid out contiguously.
        let slice = unsafe { self.blocks.get_unchecked(start..start + BLOCK_BYTES) };
        slice.try_into().expect("BLOCK_BYTES-sized slice")
    }

    /// # Safety
    ///
    /// `idx` must be `< self.num_blocks`.
    unsafe fn block_mut(&mut self, idx: u32) -> &mut [u8; BLOCK_BYTES] {
        let start = (idx as usize) * BLOCK_BYTES;
        // SAFETY: caller asserts the index is in range.
        let slice = unsafe { self.blocks.get_unchecked_mut(start..start + BLOCK_BYTES) };
        slice.try_into().expect("BLOCK_BYTES-sized slice")
    }
}

impl std::fmt::Debug for BlockedBloom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockedBloom")
            .field("num_blocks", &self.num_blocks)
            .field("num_keys", &self.num_keys)
            .field("num_hashes", &self.params.num_hashes)
            .field("bits_per_key", &self.params.bits_per_key)
            .field("byte_size", &self.byte_size())
            .finish_non_exhaustive()
    }
}

/// Pick a block index in `0..num_blocks` from a 64-bit hash using Lemire's
/// fast mod (no integer division). The distribution is uniform across
/// `num_blocks` regardless of whether `num_blocks` is a power of two.
#[inline]
fn pick_block(hash: u64, num_blocks: u32) -> u32 {
    let low = (hash & 0xFFFF_FFFF) as u32;
    let product = (u64::from(low)) * u64::from(num_blocks);
    (product >> 32) as u32
}

/// Compute the `k` in-block bit positions for `hash`. Uses
/// Kirsch–Mitzenmacher double hashing on the upper 32 bits of `hash`, with
/// the bit positions modulo [`BLOCK_BITS`].
#[inline]
fn bit_positions(hash: u64, k: u8) -> [u16; 16] {
    let h_high = (hash >> 32) as u32;
    let mut h_a = h_high;
    // Make `h_b` independent-ish from `h_a` via a Wyhash-style xorshift.
    let mut h_b = h_high.wrapping_mul(0x9E37_79B9);
    h_b ^= h_b >> 16;
    h_b = h_b.wrapping_mul(0x85EB_CA6B);

    let mut out = [0u16; 16];
    let k = k as usize;
    for slot in out.iter_mut().take(k) {
        *slot = (h_a & (BLOCK_BITS - 1)) as u16;
        h_a = h_a.wrapping_add(h_b);
    }
    out
}

// ---------- probe dispatch ----------

/// Cached CPU feature byte: 0 = scalar, 1 = AVX2.
static PROBE_BACKEND_INIT: AtomicBool = AtomicBool::new(false);
static PROBE_BACKEND: AtomicU8 = AtomicU8::new(0);

fn select_probe_backend() -> u8 {
    if PROBE_BACKEND_INIT.load(Ordering::Acquire) {
        return PROBE_BACKEND.load(Ordering::Relaxed);
    }
    #[allow(unused_assignments, reason = "needed when no SIMD feature is enabled")]
    let mut chosen: u8 = 0;
    chosen = 0;
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            chosen = 1;
        }
    }
    PROBE_BACKEND.store(chosen, Ordering::Relaxed);
    PROBE_BACKEND_INIT.store(true, Ordering::Release);
    chosen
}

/// Dispatch table: scalar (always available) vs AVX2 (x86_64 with the
/// CPU feature). The scalar path is small enough to inline; we still take
/// the function-pointer branch because the AVX2 path lives behind a
/// `#[target_feature]` boundary.
fn dispatch_probe(block: &[u8; BLOCK_BYTES], hash: u64, k: u8) -> bool {
    match select_probe_backend() {
        #[cfg(target_arch = "x86_64")]
        1 => {
            // SAFETY: backend tag is set only after a successful
            // `is_x86_feature_detected!("avx2")` on this thread.
            unsafe { probe_avx2(block, hash, k) }
        }
        _ => probe_scalar(block, hash, k),
    }
}

#[inline]
fn probe_scalar(block: &[u8; BLOCK_BYTES], hash: u64, k: u8) -> bool {
    let positions = bit_positions(hash, k);
    for &pos in positions.iter().take(k as usize) {
        let byte = (pos / 8) as usize;
        let bit = (pos % 8) as u8;
        if block[byte] & (1 << bit) == 0 {
            return false;
        }
    }
    true
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn probe_avx2(block: &[u8; BLOCK_BYTES], hash: u64, k: u8) -> bool {
    use std::arch::x86_64::{__m256i, _mm256_load_si256, _mm256_loadu_si256, _mm256_testc_si256};

    // Build a 512-bit mask carrying exactly `k` set bits at the positions
    // dictated by `hash`. Walk the candidate positions, ORing each into
    // the right half/word.
    let positions = bit_positions(hash, k);
    let mut mask_low: U64x4 = [0u64; 4];
    let mut mask_high: U64x4 = [0u64; 4];
    for &pos in positions.iter().take(k as usize) {
        let word = (pos / 64) as usize; // 0..8
        let bit = pos % 64;
        if word < 4 {
            mask_low[word] |= 1u64 << bit;
        } else {
            mask_high[word - 4] |= 1u64 << bit;
        }
    }

    // SAFETY: this function is gated behind `avx2` detection by
    // `dispatch_probe`; the intrinsics below all require AVX2, which the
    // CPU has confirmed. `block.as_ptr()` is 64-byte aligned because
    // `BlockedBloom` allocates via `AlignedBuf` with `BLOCK_BYTES`
    // alignment; the `mask_low`/`mask_high` arrays are stack-allocated u64
    // arrays of 32 bytes whose `as_ptr()` is at least `align_of::<u64>` =
    // 8-byte aligned — `_mm256_loadu_si256` accepts any alignment.
    unsafe {
        let blk_ptr = block.as_ptr().cast::<__m256i>();
        let blk_lo = _mm256_load_si256(blk_ptr);
        let blk_hi = _mm256_load_si256(blk_ptr.add(1));
        let mask_lo = _mm256_loadu_si256(mask_low.as_ptr().cast::<__m256i>());
        let mask_hi = _mm256_loadu_si256(mask_high.as_ptr().cast::<__m256i>());
        // `_mm256_testc_si256(a, b)` returns 1 if every bit set in `b` is
        // also set in `a` (i.e. `(NOT a) AND b == 0`). That is exactly
        // the Bloom membership predicate.
        let lo_ok = _mm256_testc_si256(blk_lo, mask_lo);
        let hi_ok = _mm256_testc_si256(blk_hi, mask_hi);
        lo_ok == 1 && hi_ok == 1
    }
}

#[cfg(target_arch = "x86_64")]
type U64x4 = [u64; 4];

#[cfg(test)]
#[allow(
    clippy::cast_precision_loss,
    reason = "test fixtures use small values where precision loss is impossible"
)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_rejects_everything() {
        let f = BlockedBloom::new(100, BloomParams::default());
        assert!(!f.contains(b"missing"));
        assert!(!f.contains(b""));
    }

    #[test]
    fn inserted_keys_are_definitely_present() {
        let mut f = BlockedBloom::new(1000, BloomParams::default());
        for i in 0..1000u32 {
            let k = format!("key-{i:05}").into_bytes();
            f.insert(&k);
        }
        for i in 0..1000u32 {
            let k = format!("key-{i:05}").into_bytes();
            assert!(f.contains(&k), "missing key-{i:05}");
        }
    }

    #[test]
    fn false_positive_rate_is_close_to_target() {
        let n = 10_000usize;
        let mut f = BlockedBloom::new(n, BloomParams::default());
        for i in 0..n {
            f.insert(format!("k-{i:08}").as_bytes());
        }
        // Probe 100k keys we did NOT insert.
        let probes = 100_000u32;
        let mut hits = 0u32;
        for i in 0..probes {
            let k = format!("miss-{i:010}");
            if f.contains(k.as_bytes()) {
                hits += 1;
            }
        }
        let fpr = f64::from(hits) / f64::from(probes);
        // With 10 bits/key and k=8 we expect ~0.6% empirical FPR. Give a
        // generous bound to avoid flaky tests across allocator quirks.
        assert!(
            fpr <= 0.03,
            "blocked-bloom FPR drifted: hits={hits}, fpr={fpr}"
        );
    }

    #[test]
    fn encode_decode_round_trip_preserves_membership() {
        let mut f = BlockedBloom::new(500, BloomParams::default());
        for i in 0..500u32 {
            f.insert(format!("k-{i:05}").as_bytes());
        }
        let bytes = f.encode();
        let f2 = BlockedBloom::decode(&bytes).unwrap();
        for i in 0..500u32 {
            let k = format!("k-{i:05}");
            assert!(f.contains(k.as_bytes()));
            assert!(f2.contains(k.as_bytes()), "decoded miss for {k}");
        }
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let bytes = vec![0u8; 16 + BLOCK_BYTES];
        let err = BlockedBloom::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat { .. }));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let mut f = BlockedBloom::new(10, BloomParams::default());
        f.insert(b"x");
        let mut bytes = f.encode();
        bytes.truncate(bytes.len() - 1);
        let err = BlockedBloom::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat { .. }));
    }

    #[test]
    fn scalar_and_avx2_agree() {
        // Construct a filter, probe a mix of present and absent keys, and
        // verify the two backends agree on every result. This is the
        // SIMD-equivalence guarantee.
        let mut f = BlockedBloom::new(2_000, BloomParams::default());
        for i in 0..2_000u32 {
            f.insert(format!("present-{i:06}").as_bytes());
        }
        let mut diffs = 0u32;
        for i in 0..4_000u32 {
            let key = if i % 2 == 0 {
                format!("present-{:06}", i / 2).into_bytes()
            } else {
                format!("absent-{i:06}").into_bytes()
            };
            let hash = xxh3::hash(&key);
            let blk_idx = pick_block(hash, f.num_blocks);
            // SAFETY: blk_idx < num_blocks
            let blk = unsafe { f.block(blk_idx) };
            let s = probe_scalar(blk, hash, f.params.num_hashes);
            #[cfg(target_arch = "x86_64")]
            let a = if std::is_x86_feature_detected!("avx2") {
                // SAFETY: feature detected.
                unsafe { probe_avx2(blk, hash, f.params.num_hashes) }
            } else {
                s
            };
            #[cfg(not(target_arch = "x86_64"))]
            let a = s;
            if s != a {
                diffs += 1;
            }
        }
        assert_eq!(diffs, 0, "scalar/AVX2 disagreed on {diffs} probes");
    }

    #[test]
    fn pick_block_is_uniform_enough() {
        // Sanity: the multiply-shift fast mod doesn't degenerate.
        let mut counts = vec![0u32; 16];
        for i in 0..1_000_000u64 {
            let h = xxh3::hash(&i.to_le_bytes());
            let b = pick_block(h, 16);
            counts[b as usize] += 1;
        }
        let mean = 1_000_000u32 / 16;
        for &c in &counts {
            // Allow ±5% drift.
            assert!(
                c > mean - mean / 20 && c < mean + mean / 20,
                "pick_block uneven: bucket count {c}, mean {mean}"
            );
        }
    }
}
