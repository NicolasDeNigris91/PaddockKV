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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use zerocopy::FromBytes;

use crate::checksum::Algorithm;
use crate::crypto::aead::{Aead, AeadKey, TAG_LEN};
use crate::crypto::envelope::{block_aad, derive_block_nonce};
use crate::error::{Error, Result};
use crate::filter::BlockedBloom;
use crate::io::vfs::VfsFile;
use crate::sstable::block::{BlockReader, RecordView};
use crate::sstable::format::{
    BLOCK_HANDLE_SIZE, BlockHandle, FILE_HEADER_SIZE, FOOTER_SIZE, FileHeader, Footer, RecordOp,
    flag,
};

/// Per-SSTable decryption state. Stored when the file header carries the
/// `ENCRYPTED` flag.
pub(crate) struct DecryptionCtx {
    pub(crate) aead: Aead,
    pub(crate) sstable_id: u64,
}

impl std::fmt::Debug for DecryptionCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptionCtx")
            .field("sstable_id", &self.sstable_id)
            .finish_non_exhaustive()
    }
}

/// SSTable reader.
pub struct SstReader<F: VfsFile> {
    file: F,
    header: FileHeader,
    footer: Footer,
    index_bytes: Vec<u8>,
    bloom: Option<BlockedBloom>,
    /// Per-table counter for filter pruning hits. Used for diagnostics and
    /// can drive automatic dynamic tuning later. `Relaxed` because this is
    /// purely observability — losing an increment under contention is fine.
    bloom_misses_pruned: AtomicU64,
    crypto: Option<DecryptionCtx>,
}

impl<F: VfsFile> std::fmt::Debug for SstReader<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let idx_off = self.footer.index_handle.offset.get();
        let idx_len = self.footer.index_handle.length.get();
        let num_entries = self.header.num_entries.get();
        f.debug_struct("SstReader")
            .field("num_entries", &num_entries)
            .field("index_offset", &idx_off)
            .field("index_len", &idx_len)
            .field("index_bytes_loaded", &self.index_bytes.len())
            .field("has_bloom", &self.bloom.is_some())
            .field("encrypted", &self.crypto.is_some())
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
    /// Open a plaintext `file`, validate the footer + canonical file
    /// header, and load the index block into memory. The data blocks
    /// themselves stay on disk and are loaded on demand during point
    /// lookups.
    ///
    /// Fails with [`Error::InvalidFormat`] if the file's header advertises
    /// encryption — callers must use [`open_encrypted`](Self::open_encrypted)
    /// for those tables.
    pub fn open(file: F) -> Result<Self> {
        Self::open_inner(file, None)
    }

    /// Open an **encrypted** `file`. The caller-supplied `aead_key` is the
    /// per-SSTable subkey derived from the engine's master key (see
    /// [`crate::crypto::kdf::derive_sstable_key`]). `sstable_id` must
    /// match the value the writer passed at construction, so the AAD that
    /// authenticates each block matches.
    ///
    /// Fails if the file's header does NOT advertise encryption — refusing
    /// to silently treat a plaintext file as encrypted (or vice versa) is
    /// part of the threat-model contract.
    pub fn open_encrypted(file: F, aead_key: &AeadKey, sstable_id: u64) -> Result<Self> {
        let ctx = DecryptionCtx {
            aead: Aead::new(aead_key),
            sstable_id,
        };
        Self::open_inner(file, Some(ctx))
    }

    fn open_inner(file: F, crypto: Option<DecryptionCtx>) -> Result<Self> {
        let size = file.size()?;
        if size < (FILE_HEADER_SIZE as u64) + (FOOTER_SIZE as u64) {
            return Err(Error::invalid_format_static(
                "sstable",
                "file smaller than header + footer",
            ));
        }

        // Footer first — it carries the offsets we need to find the
        // index / filter / meta blocks.
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

        // Now the canonical file header (back-filled at offset 0).
        let mut header_bytes = [0u8; FILE_HEADER_SIZE];
        file.read_at(&mut header_bytes, 0)?;
        let header = *FileHeader::ref_from_bytes(&header_bytes)
            .map_err(|_| Error::invalid_format_static("sstable file header", "size mismatch"))?;
        if !header.is_valid() {
            return Err(Error::Corruption {
                context: "sstable file header",
                reason: "magic / version / reserved / checksum mismatch".to_owned(),
            });
        }

        // Cross-check the encryption flag with the caller's intent. We
        // refuse to silently bridge the gap in either direction.
        let file_is_encrypted = header.flags.get() & flag::ENCRYPTED != 0;
        match (file_is_encrypted, crypto.is_some()) {
            (true, false) => {
                return Err(Error::InvalidFormat {
                    context: "sstable",
                    reason: "file is encrypted; open via SstReader::open_encrypted".to_owned(),
                });
            }
            (false, true) => {
                return Err(Error::InvalidFormat {
                    context: "sstable",
                    reason: "file is not encrypted; open via SstReader::open".to_owned(),
                });
            }
            _ => {}
        }

        // Load the index block (always plaintext — only data blocks are
        // encrypted in this format).
        let idx_off = footer.index_handle.offset.get();
        let idx_len = footer.index_handle.length.get() as usize;
        let mut index_bytes = vec![0u8; idx_len];
        file.read_at(&mut index_bytes, idx_off)?;

        // Load the filter block if present. The filter is plaintext too —
        // it leaks only the set of key hashes, which is metadata we
        // explicitly do not promise to hide (see `docs/THREAT_MODEL.md`).
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
            header,
            footer,
            index_bytes,
            bloom,
            bloom_misses_pruned: AtomicU64::new(0),
            crypto,
        })
    }

    /// Read a data block at the given handle, transparently decrypting if
    /// the SSTable is encrypted. Returns the plaintext block bytes that
    /// [`BlockReader::open`] expects.
    fn read_data_block(&self, handle: BlockHandle) -> Result<Vec<u8>> {
        let block_off = handle.offset.get();
        let block_len = handle.length.get() as usize;
        let mut on_disk = vec![0u8; block_len];
        self.file.read_at(&mut on_disk, block_off)?;
        if let Some(ctx) = &self.crypto {
            // AEAD seal/open is symmetric: the writer derived
            // `derive_block_nonce(block_off)` and AAD = (sstable_id, block_off);
            // we reproduce both here.
            let nonce = derive_block_nonce(block_off);
            let aad = block_aad(ctx.sstable_id, block_off);
            let plaintext = ctx
                .aead
                .open(nonce.as_nonce(), &aad, &on_disk)
                .map_err(|_| Error::Corruption {
                    context: "sstable data block",
                    reason: "AEAD authentication failed (corruption or wrong key)".to_owned(),
                })?;
            debug_assert_eq!(plaintext.len() + TAG_LEN, on_disk.len());
            Ok(plaintext)
        } else {
            Ok(on_disk)
        }
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

        // Step 2 — read the data block from disk (decrypting if needed).
        let block_bytes = self.read_data_block(handle)?;

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
            let block_bytes = self.read_data_block(handle)?;
            let data_reader = BlockReader::open(&block_bytes)?;
            for rec in &data_reader {
                out.push((rec.key.clone(), into_hit(&rec)));
            }
        }
        Ok(out)
    }

    /// Streaming, block-by-block scan of every record in ascending order.
    ///
    /// Unlike [`scan`](Self::scan), the streaming form never materialises
    /// the whole table in RAM — each record is yielded as soon as it is
    /// decoded, and only the current data block is held in memory. This is
    /// the iterator the compaction layer pulls from when merging multiple
    /// SSTables.
    pub fn scan_stream(self: &Arc<Self>) -> Result<SstStream<F>> {
        let handles = decode_index_handles(&self.index_bytes)?;
        Ok(SstStream {
            reader: Arc::clone(self),
            handles,
            next_block: 0,
            current: Vec::new().into_iter(),
        })
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

    /// `true` if data blocks in this SSTable are AES-256-GCM encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.crypto.is_some()
    }

    /// Borrow the canonical file header (back-filled at offset 0 by the
    /// writer's `finish()`). Useful for diagnostics — engine code does not
    /// usually need this.
    #[must_use]
    pub const fn file_header(&self) -> &FileHeader {
        &self.header
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

fn decode_index_handles(index_bytes: &[u8]) -> Result<Vec<BlockHandle>> {
    let reader = BlockReader::open(index_bytes)?;
    let mut out = Vec::new();
    for rec in &reader {
        out.push(decode_block_handle(rec.value)?);
    }
    Ok(out)
}

/// Streaming iterator over every record in an SSTable.
///
/// Yielded by [`SstReader::scan_stream`]; lives at most one data block at
/// a time in memory. Records come back in `(key ascending, seqno
/// descending)` order — the same convention the memtable and the
/// compaction merger use.
pub struct SstStream<F: VfsFile> {
    reader: Arc<SstReader<F>>,
    handles: Vec<BlockHandle>,
    next_block: usize,
    current: std::vec::IntoIter<(Vec<u8>, LookupHit)>,
}

impl<F: VfsFile> SstStream<F> {
    fn refill(&mut self) -> Result<bool> {
        while self.next_block < self.handles.len() {
            let h = self.handles[self.next_block];
            self.next_block += 1;
            let block_bytes = self.reader.read_data_block(h)?;
            let data_reader = BlockReader::open(&block_bytes)?;
            let mut records = Vec::with_capacity(64);
            for rec in &data_reader {
                records.push((rec.key.clone(), into_hit(&rec)));
            }
            if records.is_empty() {
                continue;
            }
            self.current = records.into_iter();
            return Ok(true);
        }
        Ok(false)
    }

    /// Pull the next record, or `Ok(None)` at the end of the stream.
    pub fn next_record(&mut self) -> Result<Option<(Vec<u8>, LookupHit)>> {
        loop {
            if let Some(rec) = self.current.next() {
                return Ok(Some(rec));
            }
            if !self.refill()? {
                return Ok(None);
            }
        }
    }
}

impl<F: VfsFile> Iterator for SstStream<F> {
    type Item = Result<(Vec<u8>, LookupHit)>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_record() {
            Ok(Some(rec)) => Some(Ok(rec)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl<F: VfsFile> std::fmt::Debug for SstStream<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SstStream")
            .field("blocks_total", &self.handles.len())
            .field("blocks_remaining", &(self.handles.len() - self.next_block))
            .finish_non_exhaustive()
    }
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
