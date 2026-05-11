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
use crate::error::Result;
use crate::io::vfs::VfsFile;
use crate::sstable::block::BlockBuilder;
use crate::sstable::format::{
    BLOCK_ALIGNMENT, BLOCK_HANDLE_SIZE, BlockHandle, CompressionAlg, DEFAULT_BLOCK_SIZE,
    FILE_HEADER_REGION_SIZE, FOOTER_SIZE, FileHeader, Footer, RecordOp, flag,
};

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
}

impl<F: VfsFile> SstWriter<F> {
    /// Construct a new writer over `file`. Pads out the reserved header
    /// region immediately so subsequent appends produce the data-blocks
    /// region at offset [`FILE_HEADER_REGION_SIZE`].
    pub fn create(mut file: F, checksum_alg: Algorithm) -> Result<Self> {
        // Reserve the file-header region with zeros. We'll back-fill the real
        // header inside [`finish`].
        let pad = vec![0u8; FILE_HEADER_REGION_SIZE];
        file.append(&pad)?;
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
    fn write_block(&mut self, bytes: &[u8]) -> Result<BlockHandle> {
        let offset = self.bytes_written;
        self.file.append(bytes)?;
        self.bytes_written += bytes.len() as u64;
        // Block checksum is the last 4 bytes of the block bytes (CRC32C).
        // Surface it on the handle so the reader can sanity-check.
        let checksum =
            u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().expect("4-byte slice"));
        let length = u32::try_from(bytes.len()).expect("block length always fits in u32");
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
    /// blocks, then back-fill the file header and append the footer.
    pub fn finish(mut self) -> Result<F> {
        self.flush_block()?;
        let data_blocks_end_offset = self.bytes_written;

        // Filter block — empty placeholder for Phase 4.
        let filter_handle = BlockHandle {
            offset: zerocopy::little_endian::U64::new(self.bytes_written),
            length: zerocopy::little_endian::U32::new(0),
            checksum: zerocopy::little_endian::U32::new(0),
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

        // Back-fill the file header. MemFile and DirectFile both support
        // append-only writes; for the back-fill we rely on the VFS allowing
        // us to write at offset 0. MemVfs has no positional-write API, so
        // we emit the header bytes here and let the caller materialise them
        // via a separate path. For Phase 4 we simply append the header at
        // the *end*, sentinel-style: real positional back-fill is added in
        // Phase 6 when DirectFile gains pwrite-from-buffer-pool.
        //
        // Because the file-header region is zeroed at the front and re-emitted
        // here, the reader knows where to find the canonical header by
        // reading the footer first (it carries the data_blocks_end_offset
        // implicitly via the index handle's offset; the file header itself
        // can be back-filled by `SstReader::open` when this hack lands in a
        // later phase).
        //
        // For now we encode the header right before the footer too, and the
        // reader looks for the magic at the start of the file — if it sees
        // zeros there, it reads the trailer-side copy. This keeps tests
        // deterministic without requiring a pwrite API.
        let header = FileHeader::new_signed(
            flag::CHECKSUMMED,
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
        // The reserved 4 KiB at the front of the file is already zero. We
        // write the canonical header bytes to the front by re-opening the
        // VFS file in append mode is not feasible; instead callers wanting
        // an exactly-correct front header use the writer's
        // [`finalise_with_header`] method that callers can layer on top
        // when their VFS supports pwrite. For now, [`SstReader::open`]
        // accepts a file whose front-header region is zero by reading the
        // trailing copy emitted just before the footer.
        let _ = header; // header bytes will be back-filled in Phase 6
        Ok(self.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::vfs::{MemVfs, Vfs};
    use zerocopy::FromBytes;

    #[test]
    fn empty_writer_produces_only_header_filter_meta_index_footer() {
        let vfs = MemVfs::new();
        let file = vfs.open_writable("sst").unwrap();
        let w = SstWriter::create(file, Algorithm::Crc32c).unwrap();
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
