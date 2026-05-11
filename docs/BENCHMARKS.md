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

## Future phases

- Phase 6 — Memtable + immutable + SSTable read-path integration; striped block cache.
- Phase 7 — Compaction (k-way merge, leveled scheduler).
- Phase 8 — Encryption-at-rest (AES-NI per-block, HKDF key hierarchy).
- Phase 9 — Fuzzing + Miri + loom + TSan.
- Phase 10 — End-to-end vs RocksDB on YCSB A–F and custom workloads, on
  bare-metal Linux. **Headline target: p999 cold-cache point-read latency
  on small values, 100M-key working set on NVMe.**
