//! WAL segment writer.
//!
//! [`SegmentWriter`] is generic over any [`VfsFile`], so the same logic drives
//! the in-memory test VFS, an `O_DIRECT` file in production, and (via a thin
//! adapter wired up later) the `io_uring`-backed group-commit path.
//!
//! ## Block framing
//!
//! Records live inside 32 KiB physical blocks ([`format::BLOCK_SIZE`]). The
//! writer tracks how many bytes of the current block remain. For each
//! logical record submitted by the caller:
//!
//! 1. If the payload plus a 16-byte header fits in the remaining block space,
//!    emit one `RecordType::Full` record. Done.
//! 2. Otherwise, emit a `RecordType::First` fragment that fills the block, a
//!    sequence of `RecordType::Middle` fragments that each fill their block,
//!    and a `RecordType::Last` fragment with whatever remains.
//! 3. If at any point the block has fewer than 16 bytes left (smaller than
//!    a record header), zero-pad the residue and roll to a fresh block — the
//!    reader recognises a zeroed header as the start of free space.
//!
//! This is exactly the LevelDB scheme. It is robust to torn writes: any block
//! that ends with a partial record can be detected by a CRC mismatch on the
//! truncated header, and earlier blocks remain intact.

//! Internal note on `clippy::cast_possible_truncation`:
//!
//! Multiple casts in this file truncate intentionally and are bounded by
//! invariants the calling context establishes (block sizes are `<= 2^16`,
//! addresses computed inside a single block fit in `u32`, the engine is
//! 64-bit so `usize == u64`). Each such cast carries an `#[allow]` with a
//! `reason` explaining why it is safe.

use crate::checksum::crc32c;
use crate::error::Result;
use crate::io::vfs::VfsFile;
use crate::wal::format::{
    BLOCK_SIZE, MAX_FRAGMENT_PAYLOAD, RECORD_HEADER_SIZE, RecordHeader, RecordType, SegmentHeader,
};
use zerocopy::IntoBytes;

/// Writer over a single WAL segment file.
///
/// Use [`SegmentWriter::create`] to start a fresh segment. Once
/// [`SegmentWriter::should_rotate`] returns `true`, callers should stop using
/// this writer and open a new segment.
pub struct SegmentWriter<F: VfsFile> {
    file: F,
    block_offset: usize,
    segment_id: u64,
    bytes_written: u64,
    rotate_at: u64,
}

impl<F: VfsFile> std::fmt::Debug for SegmentWriter<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentWriter")
            .field("segment_id", &self.segment_id)
            .field("block_offset", &self.block_offset)
            .field("bytes_written", &self.bytes_written)
            .field("rotate_at", &self.rotate_at)
            .finish_non_exhaustive()
    }
}

fn recompute_record_crc(header: &RecordHeader, payload: &[u8]) -> u32 {
    let mut h = crc32c::Hasher::new();
    h.update(&[header.record_type, header.reserved]);
    h.update(header.seqno.as_bytes());
    h.update(payload);
    h.finalize()
}

impl<F: VfsFile> SegmentWriter<F> {
    /// Default segment rotation threshold: 64 MiB.
    pub const DEFAULT_ROTATE_AT: u64 = 64 * 1024 * 1024;

    /// Start a new segment. Writes the [`SegmentHeader`] immediately and
    /// positions the writer at the start of block 0.
    pub fn create(mut file: F, segment_id: u64, first_seqno: u64) -> Result<Self> {
        let header = SegmentHeader::new_signed(segment_id, first_seqno);
        file.append(header.as_bytes())?;
        Ok(Self {
            file,
            // The block layout *starts after* the segment header — but we
            // measure block boundaries from the start of the records area, so
            // the first record always lands at block_offset = 0 within block 0.
            block_offset: 0,
            segment_id,
            bytes_written: 0,
            rotate_at: Self::DEFAULT_ROTATE_AT,
        })
    }

    /// Override the rotation threshold. Useful for tests that want to force
    /// segment turnover after a few KiB.
    pub const fn set_rotate_at(&mut self, bytes: u64) {
        self.rotate_at = bytes;
    }

    /// Bytes written into the records area of this segment (excluding the
    /// fixed segment header).
    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Segment identifier passed to [`create`](Self::create).
    #[must_use]
    pub const fn segment_id(&self) -> u64 {
        self.segment_id
    }

    /// `true` if the caller should rotate to a new segment after the next
    /// successful append.
    #[must_use]
    pub const fn should_rotate(&self) -> bool {
        self.bytes_written >= self.rotate_at
    }

    /// Borrow the underlying file. Useful for surfacing the concrete handle
    /// type's specialised methods (e.g. `fdatasync` on a `DirectFile`).
    #[must_use]
    pub const fn file(&self) -> &F {
        &self.file
    }

    /// Borrow the underlying file mutably.
    pub const fn file_mut(&mut self) -> &mut F {
        &mut self.file
    }

    /// Append one logical record carrying `payload` at sequence `seqno`.
    ///
    /// The payload is split into one or more on-disk fragments as needed.
    /// Returns the byte offset (relative to the start of the records area)
    /// where the first fragment of this record landed — useful for tests
    /// that want to probe specific segment positions.
    pub fn append_record(&mut self, seqno: u64, payload: &[u8]) -> Result<u64> {
        let record_start = self.bytes_written;

        // If a record header would not fit in what remains of the current
        // block, pad to the next block boundary.
        self.pad_block_if_header_would_not_fit()?;

        let mut remaining = payload;
        let mut is_first_fragment = true;

        loop {
            let block_remaining = BLOCK_SIZE - self.block_offset;
            debug_assert!(block_remaining >= RECORD_HEADER_SIZE);
            let payload_room = block_remaining - RECORD_HEADER_SIZE;
            let fragment_len = remaining.len().min(payload_room);
            let is_last = fragment_len == remaining.len();

            let record_type = match (is_first_fragment, is_last) {
                (true, true) => RecordType::Full,
                (true, false) => RecordType::First,
                (false, true) => RecordType::Last,
                (false, false) => RecordType::Middle,
            };

            self.write_fragment(record_type, seqno, &remaining[..fragment_len])?;

            remaining = &remaining[fragment_len..];
            is_first_fragment = false;
            if remaining.is_empty() {
                break;
            }
            // The next fragment goes in a fresh block — guaranteed by the
            // payload_room calculation above filling the rest of this block
            // exactly.
            debug_assert_eq!(self.block_offset, BLOCK_SIZE);
            self.block_offset = 0;
        }

        Ok(record_start)
    }

    fn pad_block_if_header_would_not_fit(&mut self) -> Result<()> {
        let block_remaining = BLOCK_SIZE - self.block_offset;
        if block_remaining < RECORD_HEADER_SIZE {
            // Emit a run of zero bytes. The reader treats a zeroed header as
            // "skip ahead to the next block boundary".
            let pad = vec![0u8; block_remaining];
            self.file.append(&pad)?;
            self.bytes_written = self
                .bytes_written
                .checked_add(u64_from_usize(block_remaining))
                .expect("WAL segment bytes_written overflow");
            self.block_offset = 0;
        }
        Ok(())
    }

    fn write_fragment(
        &mut self,
        record_type: RecordType,
        seqno: u64,
        payload: &[u8],
    ) -> Result<()> {
        debug_assert!(payload.len() <= MAX_FRAGMENT_PAYLOAD);
        debug_assert!(u16::try_from(payload.len()).is_ok());

        // SAFETY-ish: bounded by `MAX_FRAGMENT_PAYLOAD < u16::MAX`.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "payload.len() <= MAX_FRAGMENT_PAYLOAD which fits in u16"
        )]
        let payload_len_u16 = payload.len() as u16;
        let mut header = RecordHeader::new(record_type, seqno, payload_len_u16);
        header.sign(payload);

        // Verify CRC32C of the just-built header against an independent recomputation.
        // Done before any I/O so a corrupted construction surfaces before bytes hit disk.
        debug_assert_eq!(
            header.payload_crc32c.get(),
            recompute_record_crc(&header, payload),
            "internal: header CRC32C mismatch"
        );

        // We perform two appends — header then payload — but the underlying
        // file is append-only, so a torn write that splits between them is
        // simply detected at replay (CRC fail on a header followed by a short
        // tail). No special handling needed here.
        self.file.append(header.as_bytes())?;
        self.file.append(payload)?;

        let frag_total = RECORD_HEADER_SIZE + payload.len();
        self.block_offset += frag_total;
        self.bytes_written = self
            .bytes_written
            .checked_add(u64_from_usize(frag_total))
            .expect("WAL segment bytes_written overflow");

        Ok(())
    }

    /// Flush the underlying file. Equivalent to `fsync` in
    /// [`crate::io::vfs::VfsFile`]; production code prefers `fdatasync` via
    /// the concrete handle.
    pub fn sync(&mut self) -> Result<()> {
        self.file.sync()
    }
}

/// Lossless `usize -> u64` widening for the engine's 64-bit targets. Centralised
/// so the cast site is explicit.
#[inline]
const fn u64_from_usize(v: usize) -> u64 {
    v as u64
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "test fixtures use small values where truncation cannot occur"
)]
mod tests {
    use super::*;
    use crate::io::vfs::{MemVfs, Vfs};
    use crate::wal::batch::WriteBatch;
    use crate::wal::format::SEGMENT_HEADER_SIZE;
    use zerocopy::FromBytes;

    fn open_segment(
        vfs: &MemVfs,
        path: &str,
        segment_id: u64,
        first_seqno: u64,
    ) -> SegmentWriter<<MemVfs as Vfs>::File> {
        let file = vfs.open_writable(path).unwrap();
        SegmentWriter::create(file, segment_id, first_seqno).unwrap()
    }

    #[test]
    fn create_writes_segment_header() {
        let vfs = MemVfs::new();
        let _writer = open_segment(&vfs, "wal", 7, 100);
        let reader = vfs.open_readonly("wal").unwrap();
        assert_eq!(reader.size().unwrap(), SEGMENT_HEADER_SIZE as u64);

        let mut buf = [0u8; SEGMENT_HEADER_SIZE];
        reader.read_at(&mut buf, 0).unwrap();
        let h = SegmentHeader::ref_from_bytes(&buf).unwrap();
        assert!(h.is_valid());
        assert_eq!(h.segment_id.get(), 7);
        assert_eq!(h.first_seqno.get(), 100);
    }

    #[test]
    fn small_record_fits_as_full_in_one_block() {
        let vfs = MemVfs::new();
        let mut writer = open_segment(&vfs, "wal", 1, 0);

        let mut batch = WriteBatch::new();
        batch.put(b"k".to_vec(), b"v".to_vec());
        let payload = batch.encode();
        let off = writer.append_record(42, &payload).unwrap();
        assert_eq!(off, 0);
        assert_eq!(
            writer.bytes_written() as usize,
            RECORD_HEADER_SIZE + payload.len()
        );
    }

    #[test]
    fn record_spanning_two_blocks_splits_into_first_last() {
        let vfs = MemVfs::new();
        let mut writer = open_segment(&vfs, "wal", 1, 0);
        // Payload sized to force a split: leave room in block 0 only for a
        // small first fragment, then spill the rest into block 1.
        let payload = vec![0xAB; BLOCK_SIZE]; // > MAX_FRAGMENT_PAYLOAD
        writer.append_record(7, &payload).unwrap();

        // Two fragment headers + the payload + (possibly) the cross-block
        // boundary should be accounted for.
        let expected = 2 * RECORD_HEADER_SIZE + payload.len();
        assert_eq!(writer.bytes_written() as usize, expected);
    }

    #[test]
    fn record_pads_block_when_remaining_space_is_too_small_for_header() {
        let vfs = MemVfs::new();
        let mut writer = open_segment(&vfs, "wal", 1, 0);

        // Fill block 0 to within 8 bytes of its end — too small for a
        // 16-byte record header.
        let first_payload = vec![0xCD; BLOCK_SIZE - RECORD_HEADER_SIZE - 8];
        writer.append_record(1, &first_payload).unwrap();
        // Block remaining now = 8 bytes. A new record must trigger padding.
        let before = writer.bytes_written();
        writer.append_record(2, b"tiny").unwrap();
        let after = writer.bytes_written();
        // The increase should include 8 padding bytes plus the new header+payload.
        let new_record = RECORD_HEADER_SIZE + 4;
        assert_eq!(after - before, (8 + new_record) as u64);
    }

    #[test]
    fn rotation_threshold_triggers_should_rotate() {
        let vfs = MemVfs::new();
        let mut writer = open_segment(&vfs, "wal", 1, 0);
        writer.set_rotate_at(1024);
        assert!(!writer.should_rotate());
        writer.append_record(1, &vec![0u8; 2048]).unwrap();
        assert!(writer.should_rotate());
    }

    #[test]
    fn sync_is_idempotent_on_memvfs() {
        let vfs = MemVfs::new();
        let mut writer = open_segment(&vfs, "wal", 1, 0);
        writer.sync().unwrap();
        writer.sync().unwrap();
    }
}
