// Block-offset and file-position arithmetic is bounded by typical SSTable
// sizes (gigabytes) on 64-bit hosts where `usize == u64`. Each cast site is
// kept explicit; this module-level allow keeps the source uncluttered.
#![allow(clippy::cast_possible_truncation)]

//! SSTable writer.
//!
//! Drives a sorted stream of `(key, value, seqno, op)` records into a
//! complete SSTable file. Records are routed into [`BlockBuilder`]s sized
//! to [`DEFAULT_BLOCK_SIZE`]; when a block fills, its bytes are flushed and
//! padded out to the next [`BLOCK_ALIGNMENT`] boundary so the next block
//! starts page-aligned (a prerequisite for the future O_DIRECT compaction
//! reader).
//!
//! The writer is generic over [`VfsFile`] so unit tests using `MemVfs` and
//! production using a real `O_DIRECT` file both go through the same code
//! path.
//!
//! ## Output structure
//!
//! 1. Reserved file-header region: [`FILE_HEADER_REGION_SIZE`] bytes. The
//!    actual [`FileHeader`] is written here last (after totals are known)
//!    via a back-fill.
//! 2. One or more data blocks (padded to [`BLOCK_ALIGNMENT`]).
//! 3. Filter block: empty in Phase 4 (bloom filter lands in Phase 5).
//! 4. Meta block: empty placeholder.
//! 5. Index block (built from the last key of every data block).
//! 6. Footer ([`FOOTER_SIZE`] bytes).

use zerocopy::IntoBytes;

use crate::checksum::Algorithm;
use crate::crypto::aead::{Aead, AeadKey, TAG_LEN};
use crate::crypto::envelope::{block_aad, derive_block_nonce};
use crate::error::Result;
use crate::filter::{BlockedBloom, BloomParams};
use crate::io::vfs::VfsFile;
use crate::sstable::block::BlockBuilder;
use crate::sstable::format::{
    BLOCK_ALIGNMENT, BLOCK_HANDLE_SIZE, BlockHandle, CompressionAlg, DEFAULT_BLOCK_SIZE,
    FILE_HEADER_REGION_SIZE, FOOTER_SIZE, FileHeader, Footer, RecordOp, flag,
};

/// Per-SSTable encryption state. When [`SstWriter`] holds `Some`, every
/// data block is encrypted in place before it is written; the on-disk
/// block bytes are the AEAD ciphertext (plaintext bytes + 16-byte tag).
pub(crate) struct EncryptionCtx {
    pub(crate) aead: Aead,
    pub(crate) sstable_id: u64,
}

impl std::fmt::Debug for EncryptionCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionCtx")
            .field("sstable_id", &self.sstable_id)
            .finish_non_exhaustive()
    }
}

/// Build a complete SSTable by streaming sorted records through [`add`](Self::add).
pub struct SstWriter<F: VfsFile> {
    file: F,
    data_builder: BlockBuilder,
    /// (Last key, handle) for every block already flushed to disk.
    pending_index: Vec<(Vec<u8>, BlockHandle)>,
    /// Key + value + metadata of the most recent record we added (used to
    /// emit the index entry for a block when we seal it).
    last_key: Vec<u8>,
    /// Bytes written so far. Tracks the position where the next block
    /// (post-alignment) will land.
    bytes_written: u64,
    /// Engine-wide accumulators that land in the file header.
    num_entries: u64,
    num_blocks: u64,
    min_seqno: u64,
    max_seqno: u64,
    checksum_alg: Algorithm,
    block_size: usize,
    /// Bloom filter being populated as keys arrive. Sized eagerly on
    /// construction (`new_with_filter_capacity`); the default `create`
    /// sizes it for 10K keys and re-sizes lazily if it overshoots.
    bloom: Option<BlockedBloom>,
    /// Per-block AES-256-GCM context. `None` for plaintext SSTables.
    crypto: Option<EncryptionCtx>,
}

impl<F: VfsFile> SstWriter<F> {
    /// Construct a new writer over `file`. Pads out the reserved header
    /// region immediately so subsequent appends produce the data-blocks
    /// region at offset [`FILE_HEADER_REGION_SIZE`].
    pub fn create(file: F, checksum_alg: Algorithm) -> Result<Self> {
        Self::create_with_filter_capacity(file, checksum_alg, 10_000, BloomParams::default())
    }

    /// Construct a writer with an explicit Bloom-filter capacity hint.
    ///
    /// The filter is sized for `expected_keys` entries; insertions beyond
    /// that bound still work (the FPR creeps up gracefully) so a sloppy
    /// hint never causes a hard failure. Pass `0` to omit the filter
    /// entirely — useful when the engine knows it will never lookup into
    /// this table (e.g. a write-only sink).
    pub fn create_with_filter_capacity(
        file: F,
        checksum_alg: Algorithm,
        expected_keys: usize,
        params: BloomParams,
    ) -> Result<Self> {
        Self::create_inner(file, checksum_alg, expected_keys, params, None)
    }

    /// Construct an **encrypted** writer.
    ///
    /// Every data block this writer emits is wrapped in AES-256-GCM with a
    /// nonce derived from the block's file offset and AAD that binds the
    /// ciphertext to `(sstable_id, block_offset)`. Filter, meta, and index
    /// blocks are left in the clear — they leak metadata only and never
    /// carry plaintext values; see `docs/THREAT_MODEL.md`.
    ///
    /// The `aead_key` is typically the output of
    /// [`crate::crypto::kdf::derive_sstable_key`] applied to the engine's
    /// master key and this SSTable's file id.
    pub fn create_encrypted(
        file: F,
        checksum_alg: Algorithm,
        expected_keys: usize,
        params: BloomParams,
        aead_key: &AeadKey,
        sstable_id: u64,
    ) -> Result<Self> {
        let ctx = EncryptionCtx {
            aead: Aead::new(aead_key),
            sstable_id,
        };
        Self::create_inner(file, checksum_alg, expected_keys, params, Some(ctx))
    }

    fn create_inner(
        mut file: F,
        checksum_alg: Algorithm,
        expected_keys: usize,
        params: BloomParams,
        crypto: Option<EncryptionCtx>,
    ) -> Result<Self> {
        // Reserve the file-header region with zeros. We back-fill the real
        // header inside `finish()` via `VfsFile::write_at`.
        let pad = vec![0u8; FILE_HEADER_REGION_SIZE];
        file.append(&pad)?;
        let bloom = if expected_keys == 0 {
            None
        } else {
            Some(BlockedBloom::new(expected_keys, params))
        };
        Ok(Self {
            file,
            data_builder: BlockBuilder::new(),
            pending_index: Vec::new(),
            last_key: Vec::new(),
            bytes_written: FILE_HEADER_REGION_SIZE as u64,
            num_entries: 0,
            num_blocks: 0,
            min_seqno: u64::MAX,
            max_seqno: 0,
            checksum_alg,
            block_size: DEFAULT_BLOCK_SIZE,
            bloom,
            crypto,
        })
    }

    /// Override the block-size target (default [`DEFAULT_BLOCK_SIZE`]).
    /// Useful in tests that want to force many small blocks without writing
    /// gigabytes.
    pub const fn set_block_size(&mut self, size: usize) {
        self.block_size = size;
    }

    /// Number of bytes written into the file so far.
    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Append a record. Caller must ensure ascending `(key, seqno desc)`
    /// order — the writer does not sort.
    pub fn add(&mut self, key: &[u8], value: &[u8], seqno: u64, op: RecordOp) -> Result<()> {
        debug_assert!(
            self.last_key.is_empty() || key >= self.last_key.as_slice(),
            "SstWriter::add called out of order: previous key {:?}, new key {:?}",
            self.last_key,
            key
        );
        self.data_builder.add(key, value, seqno, op);
        // Feed the filter on every record so the reader can short-circuit
        // negative point lookups.
        if let Some(bloom) = self.bloom.as_mut() {
            bloom.insert(key);
        }
        self.last_key.clear();
        self.last_key.extend_from_slice(key);
        self.num_entries += 1;
        self.min_seqno = self.min_seqno.min(seqno);
        self.max_seqno = self.max_seqno.max(seqno);

        if self.data_builder.estimated_size() >= self.block_size {
            self.flush_block()?;
        }
        Ok(())
    }

    /// Seal the current data block (if non-empty) and write it out.
    fn flush_block(&mut self) -> Result<()> {
        if self.data_builder.is_empty() {
            return Ok(());
        }
        let bytes = self.data_builder.finish();
        let handle = self.write_block(&bytes)?;
        self.pending_index
            .push((std::mem::take(&mut self.last_key), handle));
        self.num_blocks += 1;
        Ok(())
    }

    /// Append `bytes` as a single block and pad up to the next [`BLOCK_ALIGNMENT`].
    /// Returns the [`BlockHandle`] for the block.
    ///
    /// When encryption is active the on-disk bytes are the AEAD ciphertext
    /// (plaintext + 16-byte tag); the `checksum` field of the handle is
    /// zero because the AEAD tag is the integrity check. When encryption
    /// is off the bytes are written verbatim and the handle records the
    /// block's intrinsic CRC32C.
    fn write_block(&mut self, plaintext: &[u8]) -> Result<BlockHandle> {
        let offset = self.bytes_written;
        let (on_disk, checksum) = if let Some(ctx) = &self.crypto {
            let nonce = derive_block_nonce(offset);
            let aad = block_aad(ctx.sstable_id, offset);
            let ct = ctx
                .aead
                .seal(nonce.as_nonce(), &aad, plaintext)
                .map_err(|_| {
                    crate::error::Error::corruption_static("sstable writer", "AEAD seal failed")
                })?;
            debug_assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
            (ct, 0u32)
        } else {
            // Block checksum is the last 4 bytes (CRC32C) — surface it on
            // the handle so the reader can sanity-check before parsing.
            let crc = u32::from_le_bytes(
                plaintext[plaintext.len() - 4..]
                    .try_into()
                    .expect("4-byte slice"),
            );
            (plaintext.to_vec(), crc)
        };
        self.file.append(&on_disk)?;
        self.bytes_written += on_disk.len() as u64;
        let length = u32::try_from(on_disk.len()).expect("block length always fits in u32");
        let handle = BlockHandle {
            offset: zerocopy::little_endian::U64::new(offset),
            length: zerocopy::little_endian::U32::new(length),
            checksum: zerocopy::little_endian::U32::new(checksum),
        };
        self.align_to_block_boundary()?;
        Ok(handle)
    }

    fn align_to_block_boundary(&mut self) -> Result<()> {
        let rem = self.bytes_written as usize % BLOCK_ALIGNMENT;
        if rem != 0 {
            let pad = vec![0u8; BLOCK_ALIGNMENT - rem];
            self.file.append(&pad)?;
            self.bytes_written += pad.len() as u64;
        }
        Ok(())
    }

    /// Build the index block from the per-block (last_key, handle) tuples
    /// gathered so far. The value of each index record is the serialised
    /// [`BlockHandle`] bytes.
    fn build_index_block(&mut self) -> Vec<u8> {
        let mut b = BlockBuilder::new();
        let entries = std::mem::take(&mut self.pending_index);
        for (last_key, handle) in &entries {
            // The value of an index record is the BlockHandle's raw bytes.
            let value: [u8; BLOCK_HANDLE_SIZE] =
                handle.as_bytes().try_into().expect("16-byte BlockHandle");
            // We do not use seqno/op for index records; they encode 0/Put.
            b.add(last_key, &value, 0, RecordOp::Put);
        }
        b.finish()
    }

    /// Seal the SSTable: flush any open data block, write filter/meta/index
    /// blocks, back-fill the file header at offset 0, then append the footer.
    pub fn finish(mut self) -> Result<F> {
        self.flush_block()?;
        let data_blocks_end_offset = self.bytes_written;
        let encrypted = self.crypto.is_some();

        // Filter block: persist the Bloom filter we accumulated as keys
        // arrived. Zero-length handle when filter is disabled.
        let filter_handle = if let Some(bloom) = self.bloom.take() {
            let bytes = bloom.encode();
            let offset = self.bytes_written;
            self.file.append(&bytes)?;
            self.bytes_written += bytes.len() as u64;
            BlockHandle {
                offset: zerocopy::little_endian::U64::new(offset),
                length: zerocopy::little_endian::U32::new(
                    u32::try_from(bytes.len()).expect("filter block fits in u32"),
                ),
                checksum: zerocopy::little_endian::U32::new(0),
            }
        } else {
            BlockHandle {
                offset: zerocopy::little_endian::U64::new(self.bytes_written),
                length: zerocopy::little_endian::U32::new(0),
                checksum: zerocopy::little_endian::U32::new(0),
            }
        };

        // Meta block — empty placeholder.
        let meta_handle = BlockHandle {
            offset: zerocopy::little_endian::U64::new(self.bytes_written),
            length: zerocopy::little_endian::U32::new(0),
            checksum: zerocopy::little_endian::U32::new(0),
        };

        // Index block.
        let index_bytes = self.build_index_block();
        let index_offset = self.bytes_written;
        self.file.append(&index_bytes)?;
        self.bytes_written += index_bytes.len() as u64;
        let index_checksum = u32::from_le_bytes(
            index_bytes[index_bytes.len() - 4..]
                .try_into()
                .expect("4-byte slice"),
        );
        let index_handle = BlockHandle {
            offset: zerocopy::little_endian::U64::new(index_offset),
            length: zerocopy::little_endian::U32::new(
                u32::try_from(index_bytes.len()).expect("u32 fits"),
            ),
            checksum: zerocopy::little_endian::U32::new(index_checksum),
        };

        // Footer.
        let footer = Footer::new_signed(index_handle, filter_handle, meta_handle);
        self.file.append(footer.as_bytes())?;
        self.bytes_written += FOOTER_SIZE as u64;

        // Back-fill the canonical file header at offset 0. The 4 KiB
        // header region was reserved (zeros) at construction; we now
        // overwrite the leading bytes with the real FileHeader. The
        // remaining zeros pad to the page boundary so the first data
        // block stays page-aligned for future O_DIRECT reads.
        let mut flags = flag::CHECKSUMMED;
        if encrypted {
            flags |= flag::ENCRYPTED;
        }
        let header = FileHeader::new_signed(
            flags,
            CompressionAlg::None,
            self.checksum_alg,
            self.num_entries,
            self.num_blocks,
            if self.min_seqno == u64::MAX {
                0
            } else {
                self.min_seqno
            },
            self.max_seqno,
            data_blocks_end_offset,
        );
        self.file.write_at(header.as_bytes(), 0)?;
        Ok(self.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::vfs::{MemVfs, Vfs};
    use zerocopy::FromBytes;

    #[test]
    fn empty_writer_with_filter_disabled_has_only_layout_overhead() {
        let vfs = MemVfs::new();
        let file = vfs.open_writable("sst").unwrap();
        let w = SstWriter::create_with_filter_capacity(
            file,
            Algorithm::Crc32c,
            0, // no Bloom filter
            BloomParams::default(),
        )
        .unwrap();
        let _ = w.finish().unwrap();

        let f = vfs.open_readonly("sst").unwrap();
        let size = f.size().unwrap();
        // header region + (empty) index block (num_restarts + crc = 8 bytes)
        // + footer.
        let expected = FILE_HEADER_REGION_SIZE as u64 + 8 + FOOTER_SIZE as u64;
        assert_eq!(size, expected);
    }

    #[test]
    fn single_record_writer_seals_one_block() {
        let vfs = MemVfs::new();
        let file = vfs.open_writable("sst").unwrap();
        let mut w = SstWriter::create(file, Algorithm::Crc32c).unwrap();
        w.add(b"hello", b"world", 1, RecordOp::Put).unwrap();
        let _ = w.finish().unwrap();
        let f = vfs.open_readonly("sst").unwrap();
        let size = f.size().unwrap();
        // At minimum: 4 KiB header + one block (small) padded to 4 KiB + index + footer
        assert!(size >= (FILE_HEADER_REGION_SIZE * 2) as u64);
    }

    #[test]
    fn many_records_flow_into_multiple_blocks() {
        let vfs = MemVfs::new();
        let file = vfs.open_writable("sst").unwrap();
        let mut w = SstWriter::create(file, Algorithm::Crc32c).unwrap();
        w.set_block_size(512); // tiny blocks to force several flushes
        for i in 0..1024u32 {
            let k = format!("key-{i:05}");
            let v = format!("value-{i:05}");
            w.add(k.as_bytes(), v.as_bytes(), u64::from(i + 1), RecordOp::Put)
                .unwrap();
        }
        let f = w.finish().unwrap();
        let _ = f; // confirm finish accepts; reader tests live next door.
    }

    #[test]
    fn footer_lands_in_last_64_bytes() {
        let vfs = MemVfs::new();
        let file = vfs.open_writable("sst").unwrap();
        let mut w = SstWriter::create(file, Algorithm::Crc32c).unwrap();
        w.add(b"k", b"v", 1, RecordOp::Put).unwrap();
        let _ = w.finish().unwrap();

        let r = vfs.open_readonly("sst").unwrap();
        let size = r.size().unwrap();
        let mut buf = [0u8; FOOTER_SIZE];
        r.read_at(&mut buf, size - FOOTER_SIZE as u64).unwrap();
        let footer = Footer::ref_from_bytes(&buf).unwrap();
        assert!(footer.is_valid());
    }
}
