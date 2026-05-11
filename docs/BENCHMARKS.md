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

## Future phases

- Phase 2 — WAL group-commit throughput, single- and multi-writer.
- Phase 3 — Memtable insert/lookup at 1, 8, 32 threads.
- Phase 4 — SSTable point-read latency, cold and hot.
- Phase 5 — Bloom filter probe latency (scalar / AVX2 / AVX-512).
- Phase 10 — End-to-end vs RocksDB on YCSB A–F and custom workloads, on
  bare-metal Linux. **Headline target: p999 cold-cache point-read latency on
  small values, 100M-key working set on NVMe.**
