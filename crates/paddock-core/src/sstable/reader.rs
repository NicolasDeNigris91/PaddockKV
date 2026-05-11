// `usize` ↔ `u64` casts in this file are bounded by realistic SSTable
// sizes on a 64-bit host where `usize == u64`. See module-level reasoning
// in `writer.rs`.
#![allow(clippy::cast_possible_truncation)]

//! SSTable reader.
//!
//! Opens a complete SSTable file produced by [`super::writer::SstWriter`],
//! parses its footer, loads the index, and serves point lookups.
//!
//! The current implementation reads through any [`VfsFile`]. A future
//! revision will specialise the path for `Mmap` so the value bytes returned
//! by [`SstReader::get`] point directly into the page cache; for now reads
//! are buffered (`read_at` into a heap buffer).

use std::sync::atomic::{AtomicU64, Ordering};

use zerocopy::FromBytes;

use crate::checksum::Algorithm;
use crate::error::{Error, Result};
use crate::filter::BlockedBloom;
use crate::io::vfs::VfsFile;
use crate::sstable::block::{BlockReader, RecordView};
use crate::sstable::format::{BLOCK_HANDLE_SIZE, BlockHandle, FOOTER_SIZE, Footer, RecordOp};

/// SSTable reader.
pub struct SstReader<F: VfsFile> {
    file: F,
    footer: Footer,
    index_bytes: Vec<u8>,
    bloom: Option<BlockedBloom>,
    /// Per-table counter for filter pruning hits. Used for diagnostics and
    /// can drive automatic dynamic tuning later. `Relaxed` because this is
    /// purely observability — losing an increment under contention is fine.
    bloom_misses_pruned: AtomicU64,
}

impl<F: VfsFile> std::fmt::Debug for SstReader<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let idx_off = self.footer.index_handle.offset.get();
        let idx_len = self.footer.index_handle.length.get();
        f.debug_struct("SstReader")
            .field("index_offset", &idx_off)
            .field("index_len", &idx_len)
            .field("index_bytes_loaded", &self.index_bytes.len())
            .field("has_bloom", &self.bloom.is_some())
            .field(
                "bloom_pruned",
                &self.bloom_misses_pruned.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

/// Result of a successful point lookup.
#[derive(Debug, Clone)]
pub struct LookupHit {
    /// Sequence number stored on the record.
    pub seqno: u64,
    /// Operation tag.
    pub op: RecordOp,
    /// Value bytes (empty when `op` is a tombstone).
    pub value: Vec<u8>,
}

impl<F: VfsFile> SstReader<F> {
    /// Open `file`, validate the footer, and load the index block into
    /// memory. The data blocks themselves stay on disk and are loaded on
    /// demand during point lookups.
    pub fn open(file: F) -> Result<Self> {
        let size = file.size()?;
        if size < FOOTER_SIZE as u64 {
            return Err(Error::invalid_format_static(
                "sstable",
                "file smaller than footer",
            ));
        }
        let mut footer_bytes = [0u8; FOOTER_SIZE];
        file.read_at(&mut footer_bytes, size - FOOTER_SIZE as u64)?;
        let footer = *Footer::ref_from_bytes(&footer_bytes)
            .map_err(|_| Error::invalid_format_static("sstable footer", "size mismatch"))?;
        if !footer.is_valid() {
            return Err(Error::Corruption {
                context: "sstable footer",
                reason: "checksum / magic mismatch".to_owned(),
            });
        }
        // Load the index block.
        let idx_off = footer.index_handle.offset.get();
        let idx_len = footer.index_handle.length.get() as usize;
        let mut index_bytes = vec![0u8; idx_len];
        file.read_at(&mut index_bytes, idx_off)?;

        // Load the filter block if one is present. A zero-length handle
        // indicates the SSTable was written without a Bloom filter.
        let bloom = {
            let filter_off = footer.filter_handle.offset.get();
            let filter_len = footer.filter_handle.length.get() as usize;
            if filter_len == 0 {
                None
            } else {
                let mut filter_bytes = vec![0u8; filter_len];
                file.read_at(&mut filter_bytes, filter_off)?;
                Some(BlockedBloom::decode(&filter_bytes)?)
            }
        };

        Ok(Self {
            file,
            footer,
            index_bytes,
            bloom,
            bloom_misses_pruned: AtomicU64::new(0),
        })
    }

    /// Borrow the footer for diagnostics.
    #[must_use]
    pub const fn footer(&self) -> &Footer {
        &self.footer
    }

    /// Look up `key`. Returns `Some(LookupHit)` if the SSTable contains a
    /// record at this exact key whose seqno is `<= snapshot`; otherwise
    /// `None`. (Tombstones surface as hits with `op = Tombstone`; the engine
    /// layer above interprets them.)
    pub fn get(&self, key: &[u8], snapshot: u64) -> Result<Option<LookupHit>> {
        // Step 0 — consult the Bloom filter. A `false` answer is a
        // definitive miss; we skip the data-block read entirely.
        if let Some(bloom) = &self.bloom
            && !bloom.contains(key)
        {
            self.bloom_misses_pruned.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        // Step 1 — find the data block whose last_key is >= target by
        // seeking inside the index block.
        let Some(handle) = self.locate_block(key)? else {
            return Ok(None);
        };

        // Step 2 — read the data block from disk.
        let block_off = handle.offset.get();
        let block_len = handle.length.get() as usize;
        let mut block_bytes = vec![0u8; block_len];
        self.file.read_at(&mut block_bytes, block_off)?;

        // Step 3 — seek inside the block.
        let reader = BlockReader::open(&block_bytes)?;
        let mut rec_opt = reader.seek(key);
        // Skip over records that match the user key but exceed the snapshot.
        while let Some(rec) = rec_opt.as_ref() {
            if rec.key.as_slice() != key {
                return Ok(None);
            }
            if rec.seqno <= snapshot {
                return Ok(Some(into_hit(rec)));
            }
            rec_opt = Self::next_after(&reader, &rec.key, rec.seqno);
        }
        Ok(None)
    }

    /// Iterate every record in the SSTable in ascending order. Materialises
    /// each block on demand. The iterator is meant for tests and scans; the
    /// hot point-read path uses [`get`](Self::get).
    pub fn scan(&self) -> Result<Vec<(Vec<u8>, LookupHit)>> {
        let mut out = Vec::new();
        let index_reader = BlockReader::open(&self.index_bytes)?;
        for index_rec in &index_reader {
            let handle = decode_block_handle(index_rec.value)?;
            let block_off = handle.offset.get();
            let block_len = handle.length.get() as usize;
            let mut block_bytes = vec![0u8; block_len];
            self.file.read_at(&mut block_bytes, block_off)?;
            let data_reader = BlockReader::open(&block_bytes)?;
            for rec in &data_reader {
                out.push((rec.key.clone(), into_hit(&rec)));
            }
        }
        Ok(out)
    }

    /// Algorithm tag stored on disk for block checksums (informational).
    #[must_use]
    pub const fn checksum_algorithm(&self) -> Algorithm {
        // We persist this in the file header (Phase 6 back-fill). Until then
        // the writer hard-codes CRC32C, so we report that.
        Algorithm::Crc32c
    }

    /// `true` if this SSTable carries a Bloom filter the reader can consult
    /// for pruning negative lookups.
    #[must_use]
    pub const fn has_bloom_filter(&self) -> bool {
        self.bloom.is_some()
    }

    /// Number of point lookups that the Bloom filter rejected without
    /// touching the data blocks. Exposed for engine-level telemetry; the
    /// counter monotonically increases over the reader's lifetime.
    #[must_use]
    pub fn bloom_pruned_count(&self) -> u64 {
        self.bloom_misses_pruned.load(Ordering::Relaxed)
    }

    fn locate_block(&self, key: &[u8]) -> Result<Option<BlockHandle>> {
        let reader = BlockReader::open(&self.index_bytes)?;
        let Some(rec) = reader.seek(key) else {
            return Ok(None);
        };
        let handle = decode_block_handle(rec.value)?;
        Ok(Some(handle))
    }

    fn next_after<'a>(
        reader: &BlockReader<'a>,
        same_key: &[u8],
        seqno: u64,
    ) -> Option<RecordView<'a>> {
        // Continue iterating from where the seek landed by re-scanning until
        // we move past (key, seqno).
        reader
            .iter()
            .find(|rec| rec.key.as_slice() == same_key && rec.seqno < seqno)
    }
}

fn into_hit(rec: &RecordView<'_>) -> LookupHit {
    LookupHit {
        seqno: rec.seqno,
        op: rec.op,
        value: rec.value.to_vec(),
    }
}

fn decode_block_handle(bytes: &[u8]) -> Result<BlockHandle> {
    if bytes.len() < BLOCK_HANDLE_SIZE {
        return Err(Error::invalid_format_static(
            "sstable index value",
            "shorter than BlockHandle",
        ));
    }
    let handle = BlockHandle::ref_from_bytes(&bytes[..BLOCK_HANDLE_SIZE])
        .map_err(|_| Error::invalid_format_static("sstable index value", "size mismatch"))?;
    Ok(*handle)
}

#[cfg(test)]
#[allow(clippy::cast_precision_loss, reason = "test fixtures use small values")]
mod tests {
    use super::*;
    use crate::io::vfs::{MemVfs, Vfs};
    use crate::sstable::writer::SstWriter;

    fn build_table(records: &[(&[u8], &[u8], u64, RecordOp)]) -> MemVfs {
        let vfs = MemVfs::new();
        let file = vfs.open_writable("sst").unwrap();
        let mut w = SstWriter::create(file, Algorithm::Crc32c).unwrap();
        for (k, v, s, op) in records {
            w.add(k, v, *s, *op).unwrap();
        }
        let _ = w.finish().unwrap();
        vfs
    }

    #[test]
    fn open_then_get_single_record() {
        let vfs = build_table(&[(b"k", b"v", 1, RecordOp::Put)]);
        let r = SstReader::open(vfs.open_readonly("sst").unwrap()).unwrap();
        let hit = r.get(b"k", u64::MAX).unwrap().expect("hit");
        assert_eq!(hit.value, b"v".to_vec());
        assert_eq!(hit.seqno, 1);
        assert_eq!(hit.op, RecordOp::Put);
    }

    #[test]
    fn get_missing_key_returns_none() {
        let vfs = build_table(&[(b"a", b"1", 1, RecordOp::Put)]);
        let r = SstReader::open(vfs.open_readonly("sst").unwrap()).unwrap();
        assert!(r.get(b"z", u64::MAX).unwrap().is_none());
    }

    #[test]
    fn get_across_many_blocks() {
        let vfs = MemVfs::new();
        let file = vfs.open_writable("sst").unwrap();
        let mut w = SstWriter::create(file, Algorithm::Crc32c).unwrap();
        w.set_block_size(512);
        let n = 256u32;
        for i in 0..n {
            let k = format!("key-{i:05}");
            let v = format!("value-{i:05}");
            w.add(k.as_bytes(), v.as_bytes(), u64::from(i + 1), RecordOp::Put)
                .unwrap();
        }
        let _ = w.finish().unwrap();

        let r = SstReader::open(vfs.open_readonly("sst").unwrap()).unwrap();
        for i in 0..n {
            let k = format!("key-{i:05}");
            let hit = r.get(k.as_bytes(), u64::MAX).unwrap().expect("hit");
            let expected = format!("value-{i:05}");
            assert_eq!(hit.value, expected.into_bytes());
        }
    }

    #[test]
    fn tombstones_round_trip() {
        let vfs = build_table(&[
            (b"alive", b"v", 1, RecordOp::Put),
            (b"dead", b"", 2, RecordOp::Tombstone),
        ]);
        let r = SstReader::open(vfs.open_readonly("sst").unwrap()).unwrap();

        let alive = r.get(b"alive", u64::MAX).unwrap().unwrap();
        assert_eq!(alive.op, RecordOp::Put);

        let dead = r.get(b"dead", u64::MAX).unwrap().unwrap();
        assert_eq!(dead.op, RecordOp::Tombstone);
        assert!(dead.value.is_empty());
    }

    #[test]
    fn scan_returns_records_in_order() {
        let vfs = MemVfs::new();
        let file = vfs.open_writable("sst").unwrap();
        let mut w = SstWriter::create(file, Algorithm::Crc32c).unwrap();
        w.set_block_size(256);
        for i in 0..50u32 {
            let k = format!("key-{i:05}");
            w.add(k.as_bytes(), b"v", u64::from(i + 1), RecordOp::Put)
                .unwrap();
        }
        let _ = w.finish().unwrap();

        let r = SstReader::open(vfs.open_readonly("sst").unwrap()).unwrap();
        let all = r.scan().unwrap();
        assert_eq!(all.len(), 50);
        let keys: Vec<_> = all.iter().map(|(k, _)| k.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn bloom_filter_prunes_negative_lookups() {
        // Build a small table; query 1000 keys that are NOT in it.
        // The Bloom filter should prune the vast majority (target ~99%)
        // before any data block read happens.
        let vfs = MemVfs::new();
        let file = vfs.open_writable("sst").unwrap();
        let mut w = SstWriter::create(file, Algorithm::Crc32c).unwrap();
        for i in 0..200u32 {
            let k = format!("present-{i:05}");
            w.add(k.as_bytes(), b"v", u64::from(i + 1), RecordOp::Put)
                .unwrap();
        }
        let _ = w.finish().unwrap();

        let r = SstReader::open(vfs.open_readonly("sst").unwrap()).unwrap();
        assert!(r.has_bloom_filter());

        let probes = 1_000u64;
        for i in 0..probes {
            let k = format!("absent-{i:06}");
            let res = r.get(k.as_bytes(), u64::MAX).unwrap();
            assert!(res.is_none());
        }
        let pruned = r.bloom_pruned_count();
        let prune_rate = pruned as f64 / probes as f64;
        assert!(
            prune_rate > 0.90,
            "filter prune rate too low: {pruned}/{probes} = {prune_rate}"
        );
    }

    #[test]
    fn corrupted_footer_is_rejected() {
        let vfs = build_table(&[(b"k", b"v", 1, RecordOp::Put)]);

        // Read original bytes, corrupt the last 4 bytes (footer CRC), write
        // to a different path, then try to open it.
        let r = vfs.open_readonly("sst").unwrap();
        let size = r.size().unwrap();
        let mut all = vec![0u8; size as usize];
        r.read_at(&mut all, 0).unwrap();
        let last = all.len() - 1;
        all[last] ^= 0xFF;
        let mut wf = vfs.open_writable("sst_corrupt").unwrap();
        wf.append(&all).unwrap();

        let err = SstReader::open(vfs.open_readonly("sst_corrupt").unwrap()).unwrap_err();
        assert!(matches!(
            err,
            Error::Corruption { .. } | Error::InvalidFormat { .. }
        ));
    }
}
