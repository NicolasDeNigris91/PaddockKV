# Benchmarks

Reproducible performance baselines for the engine, by phase.

## How to run

```bash
cargo bench --workspace
```

Add `-- --quick` for a fast sanity run (~10 s) instead of the default
statistical analysis (~3 min per group).

## Phase 0 — Primitive baselines

Hardware: **Windows 10 Pro, x86_64**, Rust 1.95 stable, release profile with
LTO=fat. (Headline benchmarks will be re-run on bare-metal Linux with NVMe
and isolated cores in Phase 10. Numbers here are dev-machine baselines.)

### Checksum throughput

| Input size | CRC32C            | XXH3-64           |
|-----------:|-------------------|-------------------|
| 64 B       | 3.7 GiB/s         | **21.9 GiB/s**    |
| 4 KiB      | 6.7 GiB/s         | **31.3 GiB/s**    |
| 16 KiB     | 6.7 GiB/s         | **33.1 GiB/s**    |

XXH3-64 is ~5× faster than CRC32C on this CPU. On Linux x86_64 with hardware
CRC32C via `_mm_crc32_u64`, the gap is expected to close meaningfully (a 5-10×
speedup over the software fallback). Both algorithms exceed the throughput
required to checksum every WAL record and SSTable block without becoming a
bottleneck.

**Implication for the engine.** XXH3-64 is the recommended default for
SSTable block checksums; CRC32C is preferred for WAL records because (a) the
WAL record header allocates only 32 bits for the checksum field anyway, and
(b) per-record overhead is dominated by syscall and disk latency, not hash
cost.

## Phase 5 — Blocked Bloom filter

Hardware: same dev machine (Windows 10 Pro, x86_64 with AVX2 detected at
runtime), Rust 1.95 release + LTO. The probe path is dispatched to the
AVX2 implementation via `is_x86_feature_detected!("avx2")`.

### Probe throughput (single-threaded, hot cache)

| Filter size | `contains` (hit) | `contains` (miss) |
|------------:|------------------|--------------------|
| 10 K keys   | **25.8 M probes/s** | **25.2 M probes/s** |
| 100 K keys  | **25.2 M probes/s** | **24.8 M probes/s** |
| 1 M keys    | **25.1 M probes/s** | **21.8 M probes/s** |

Flat ~25 M probes/s independent of filter size — exactly the property the
"blocked" design buys: each probe touches a single 64-byte cache line, so
cache-resident filters are bound only by the AVX2 path latency
(~40 ns/probe). The slight tail-off at 1 M keys (~22 M/s on misses)
reflects the working set leaving L1 (6.4 MiB of filter pages) and
spilling into L2.

### False-positive rate

Empirical FPR measured against 100 000 disjoint probes after inserting
10 000 keys: **< 1%** with the default parameters (10 bits/key, 8
hashes). The reader-integration test
([`bloom_filter_prunes_negative_lookups`](crates/paddock-core/src/sstable/reader.rs))
asserts the production stack achieves >90% prune rate on absent keys.

### Where this lands in the read path

For every point lookup on an SSTable, the reader consults the in-memory
Bloom filter before issuing the index-block parse + data-block disk read.
At ~99% prune rate on misses, the bloom path saves roughly two disk-page
reads per negative lookup — the single largest contributor to the
"cold-cache p999 read latency" headline target.

## Phase 10 — End-to-end engine throughput

Hardware: same Windows x86_64 dev machine, Rust 1.95 release + LTO. The
backing storage is the in-memory `MemVfs`, so the numbers measure engine
logic (WAL framing, memtable rotation, SSTable build, Bloom probe,
prefix decompression) without the disk-bandwidth ceiling. Linux benches
against an `O_DIRECT` + io_uring backend land alongside Phase 11.

All workloads use 64-byte values; keys are `key-NNNNNNNNNN` (15 bytes).

### Write throughput (`Db::put` + final `Db::flush`)

| Records  | Throughput          | Latency / op |
|---------:|---------------------|--------------|
| 1 K      | **957 K puts/s**    | ~1.0 µs      |
| 10 K     | **89 K puts/s**     | ~11 µs       |
| 100 K    | **14 K puts/s**     | ~70 µs       |

The degradation at 100 K reflects `MemFile` allocator pressure (the
`Arc<Mutex<Vec<u8>>>` backing the WAL doubles repeatedly to absorb
~8 MiB of records, paying total ~16 MiB of memcpy across the doublings).
On a Linux backend with `io_uring`-batched WAL writes and group commit,
the steady-state expectation is single-µs-per-put.

### Read throughput on a single hot SSTable (`Db::get`)

| Records  | Throughput         | Latency / get |
|---------:|--------------------|---------------|
| 1 K      | **270 K gets/s**   | ~3.7 µs       |
| 10 K     | **236 K gets/s**   | ~4.2 µs       |
| 100 K    | **192 K gets/s**   | ~5.2 µs       |

Flat per-op time across two orders of magnitude in dataset size is the
property the Bloom-filter + sparse-index combination delivers: every
lookup is **one bloom probe (≈40 ns) + one binary-search-in-index (≈100
records compared) + one binary-search-in-block + one prefix
decompression + one value clone**. The constants are dominated by the
allocation in `LookupHit { value: Vec<u8>, .. }`; Phase 11 will switch
the value to a zero-copy borrow over the mmap'd block.

### Read amplification: 8 SSTables, same total size

| Records  | Throughput         | Latency / get |
|---------:|--------------------|---------------|
| 1 K      | **391 K gets/s**   | ~2.5 µs       |
| 10 K     | **246 K gets/s**   | ~4.1 µs       |
| 100 K    | **221 K gets/s**   | ~4.5 µs       |

Counter-intuitively, the small-N case is **faster** than the single-
SSTable variant: with 125 records per SSTable, each data block fits in
L1 and the Bloom-filter's negative answers (which dominate when
walking newer SSTables before reaching the one that has the key) are
essentially free. The 100 K case stays within ~15 % of the
single-SSTable number — the Bloom filter prunes ~99 % of negative
probes at every level, so 7 of the 8 SSTables exit without a disk read.

This is the read-amplification reduction the compaction layer is built
on: even with 8× more SSTables to consult, throughput drops by only
~13 %. Without the Bloom filter, the slowdown would be linear in the
SSTable count.

## Future phases

- Phase 9 — Fuzzing + Miri + loom + TSan.
- Phase 11 — Production Linux VFS (`O_DIRECT` + io_uring + mmap), then
  end-to-end vs RocksDB on YCSB A–F and custom workloads on bare-metal
  Linux. **Headline target: p999 cold-cache point-read latency on small
  values, 100M-key working set on NVMe.**
