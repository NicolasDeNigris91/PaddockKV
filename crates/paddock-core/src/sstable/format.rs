//! SSTable on-disk format types and constants.
//!
//! Every field is little-endian. Headers and footers are
//! `FromBytes + IntoBytes + Unaligned + Immutable + KnownLayout`, so they
//! cast from an `&[u8]` returned by `read_at` or by mmap in place.
//!
//! The exact byte layout is the authoritative spec; any documentation that
//! disagrees with this module is stale and must be updated to match the code.

use zerocopy::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// File header magic — ASCII `"PKVS"` in little-endian.
pub const SSTABLE_MAGIC: u32 = 0x5356_4B50;

/// Footer magic — `"PKVSSRTF"` packed into a `u64`. Used to confirm we are
/// reading the back of a real PaddockKV SSTable and not a truncated blob.
pub const FOOTER_MAGIC: u64 = 0x4654_5253_5356_4B50;

/// Current on-disk format version. Readers refuse files with a different
/// value; writers always emit this constant.
pub const FORMAT_VERSION: u32 = 1;

/// Wire size of [`FileHeader`].
pub const FILE_HEADER_SIZE: usize = 64;

/// Padded file-header region size — the data blocks start at this offset.
/// Holds the 64-byte [`FileHeader`] plus zero padding so the first data
/// block is on a 4 KiB boundary (required for `O_DIRECT`).
pub const FILE_HEADER_REGION_SIZE: usize = 4096;

/// Wire size of [`Footer`].
pub const FOOTER_SIZE: usize = 64;

/// Default data-block size: 16 KiB. Sized so a point read pulls one cache
/// line of bloom plus 4 NVMe pages of data; smaller blocks bloat the index,
/// larger blocks inflate read amplification.
pub const DEFAULT_BLOCK_SIZE: usize = 16 * 1024;

/// Alignment used for the start of every data block. Permits the future
/// O_DIRECT compaction reader to issue page-aligned reads.
pub const BLOCK_ALIGNMENT: usize = 4096;

/// Restart interval: every Nth record stores its full key (no prefix
/// compression) and records its offset in the restart array. Used as
/// binary-search pivots inside a block. 16 matches LevelDB / RocksDB.
pub const RESTART_INTERVAL: usize = 16;

/// Bit flag for the `flags` field.
pub mod flag {
    /// Block payloads carry an end-of-block CRC32C / XXH3 checksum.
    pub const CHECKSUMMED: u32 = 1 << 0;
    /// Data block payloads are encrypted with AES-256-GCM.
    ///
    /// Filter, index, and meta blocks remain plaintext — see
    /// `docs/THREAT_MODEL.md` for the metadata-leakage discussion. When
    /// this flag is set, readers must derive the per-SSTable key via
    /// [`crate::crypto::kdf::derive_sstable_key`] from the operator's
    /// master key and the SSTable's file id.
    pub const ENCRYPTED: u32 = 1 << 1;
}

/// Tag for the compression algorithm applied to data blocks. Phase 4 emits
/// `None` exclusively; LZ4 and Zstd land in a later phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionAlg {
    /// Blocks are stored verbatim.
    None = 0,
    /// LZ4 frame format.
    Lz4 = 1,
    /// Zstandard.
    Zstd = 2,
}

impl CompressionAlg {
    /// Parse from the persisted byte tag.
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Lz4),
            2 => Some(Self::Zstd),
            _ => None,
        }
    }
}

/// Op type stored on every record. Mirrors [`crate::memtable::OpType`] and
/// [`crate::wal::batch::Op`] tags so the in-memory and on-disk
/// representations align.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordOp {
    /// Insert or overwrite.
    Put = 0,
    /// Tombstone for `key`.
    Tombstone = 1,
}

impl RecordOp {
    /// Parse from the persisted byte tag.
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Put),
            1 => Some(Self::Tombstone),
            _ => None,
        }
    }
}

/// File header. Sits at offset 0 of every SSTable, padded with zeros to a
/// page boundary so data blocks start aligned.
///
/// Layout (64 bytes, little-endian):
///
/// | Offset | Size | Field            |
/// |-------:|-----:|:-----------------|
/// | 0      | 4    | `magic`          |
/// | 4      | 4    | `version`        |
/// | 8      | 4    | `flags`          |
/// | 12     | 1    | `compression_alg`|
/// | 13     | 1    | `checksum_alg`   |
/// | 14     | 2    | `_reserved`      |
/// | 16     | 8    | `num_entries`    |
/// | 24     | 8    | `num_blocks`     |
/// | 32     | 8    | `min_seqno`      |
/// | 40     | 8    | `max_seqno`      |
/// | 48     | 8    | `data_blocks_end_offset` |
/// | 56     | 4    | `header_crc32c`  |
/// | 60     | 4    | `_reserved2`     |
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct FileHeader {
    /// Magic number — see [`SSTABLE_MAGIC`].
    pub magic: U32,
    /// Format version — see [`FORMAT_VERSION`].
    pub version: U32,
    /// Bit flags — see [`flag`].
    pub flags: U32,
    /// Compression algorithm tag — see [`CompressionAlg`].
    pub compression_alg: u8,
    /// Checksum algorithm tag — see [`crate::checksum::Algorithm`].
    pub checksum_alg: u8,
    /// Reserved 2 bytes; must be zero.
    pub reserved: [u8; 2],
    /// Total number of records across all data blocks.
    pub num_entries: U64,
    /// Number of data blocks.
    pub num_blocks: U64,
    /// Minimum sequence number written to this file (MVCC).
    pub min_seqno: U64,
    /// Maximum sequence number written to this file (MVCC).
    pub max_seqno: U64,
    /// File offset just past the last byte of the last data block (where
    /// the filter / meta / index blocks begin).
    pub data_blocks_end_offset: U64,
    /// CRC32C over bytes 0..56 of this header.
    pub header_crc32c: U32,
    /// Reserved 4 bytes; must be zero.
    pub reserved2: U32,
}

const _: () = assert!(std::mem::size_of::<FileHeader>() == FILE_HEADER_SIZE);

impl FileHeader {
    /// Construct a header with `header_crc32c` computed from the rest of
    /// the fields.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "FileHeader fields each carry distinct semantics; a builder struct would just rename the same arguments"
    )]
    pub fn new_signed(
        flags: u32,
        compression: CompressionAlg,
        checksum: crate::checksum::Algorithm,
        num_entries: u64,
        num_blocks: u64,
        min_seqno: u64,
        max_seqno: u64,
        data_blocks_end_offset: u64,
    ) -> Self {
        let mut h = Self {
            magic: U32::new(SSTABLE_MAGIC),
            version: U32::new(FORMAT_VERSION),
            flags: U32::new(flags),
            compression_alg: compression as u8,
            checksum_alg: checksum.tag(),
            reserved: [0; 2],
            num_entries: U64::new(num_entries),
            num_blocks: U64::new(num_blocks),
            min_seqno: U64::new(min_seqno),
            max_seqno: U64::new(max_seqno),
            data_blocks_end_offset: U64::new(data_blocks_end_offset),
            header_crc32c: U32::new(0),
            reserved2: U32::new(0),
        };
        let crc = crate::checksum::crc32c::hash(&h.as_bytes()[..56]);
        h.header_crc32c = U32::new(crc);
        h
    }

    /// `true` if magic, version, reserved zeros, and the header checksum all
    /// validate.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.magic.get() != SSTABLE_MAGIC || self.version.get() != FORMAT_VERSION {
            return false;
        }
        if self.reserved != [0; 2] || self.reserved2.get() != 0 {
            return false;
        }
        let stored = self.header_crc32c.get();
        let expected = crate::checksum::crc32c::hash(&self.as_bytes()[..56]);
        stored == expected
    }
}

/// Pointer to a single block on disk.
///
/// Stored inside index records (see [`crate::sstable::block`]). Three fields:
/// where the block starts in the file, how long it is, and a checksum so
/// readers can verify the block without parsing it.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct BlockHandle {
    /// File offset where the block begins. Always a multiple of
    /// [`BLOCK_ALIGNMENT`] for data blocks.
    pub offset: U64,
    /// Length of the block in bytes.
    pub length: U32,
    /// CRC32C / XXH3 of the block contents (algorithm chosen by the header
    /// `checksum_alg` field). Zero when the block is unchecksummed.
    pub checksum: U32,
}

/// Wire size of a [`BlockHandle`].
pub const BLOCK_HANDLE_SIZE: usize = std::mem::size_of::<BlockHandle>();

const _: () = assert!(BLOCK_HANDLE_SIZE == 16);

/// File footer. Sits at the last [`FOOTER_SIZE`] bytes of every SSTable.
///
/// Layout (64 bytes, little-endian):
///
/// | Offset | Size | Field             |
/// |-------:|-----:|:------------------|
/// | 0      | 16   | `index_handle`    |
/// | 16     | 16   | `filter_handle`   |
/// | 32     | 16   | `meta_handle`     |
/// | 48     | 8    | `footer_magic`    |
/// | 56     | 4    | `format_version`  |
/// | 60     | 4    | `footer_crc32c`   |
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct Footer {
    /// Pointer to the index block.
    pub index_handle: BlockHandle,
    /// Pointer to the filter block (zeroed if no bloom filter is present).
    pub filter_handle: BlockHandle,
    /// Pointer to the meta block.
    pub meta_handle: BlockHandle,
    /// Magic number — see [`FOOTER_MAGIC`].
    pub footer_magic: U64,
    /// Format version — see [`FORMAT_VERSION`].
    pub format_version: U32,
    /// CRC32C over the preceding 60 bytes.
    pub footer_crc32c: U32,
}

const _: () = assert!(std::mem::size_of::<Footer>() == FOOTER_SIZE);

impl Footer {
    /// Construct a footer with `footer_crc32c` computed from the rest of the
    /// fields.
    #[must_use]
    pub fn new_signed(
        index_handle: BlockHandle,
        filter_handle: BlockHandle,
        meta_handle: BlockHandle,
    ) -> Self {
        let mut f = Self {
            index_handle,
            filter_handle,
            meta_handle,
            footer_magic: U64::new(FOOTER_MAGIC),
            format_version: U32::new(FORMAT_VERSION),
            footer_crc32c: U32::new(0),
        };
        let crc = crate::checksum::crc32c::hash(&f.as_bytes()[..60]);
        f.footer_crc32c = U32::new(crc);
        f
    }

    /// `true` if footer magic, format version, and checksum all validate.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.footer_magic.get() != FOOTER_MAGIC || self.format_version.get() != FORMAT_VERSION {
            return false;
        }
        let stored = self.footer_crc32c.get();
        let expected = crate::checksum::crc32c::hash(&self.as_bytes()[..60]);
        stored == expected
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "test fixtures use small values where truncation cannot occur"
)]
mod tests {
    use super::*;

    #[test]
    fn file_header_size_matches_constant() {
        assert_eq!(std::mem::size_of::<FileHeader>(), FILE_HEADER_SIZE);
    }

    #[test]
    fn footer_size_matches_constant() {
        assert_eq!(std::mem::size_of::<Footer>(), FOOTER_SIZE);
    }

    #[test]
    fn block_handle_size_is_16_bytes() {
        assert_eq!(BLOCK_HANDLE_SIZE, 16);
    }

    #[test]
    fn signed_file_header_validates() {
        let h = FileHeader::new_signed(
            flag::CHECKSUMMED,
            CompressionAlg::None,
            crate::checksum::Algorithm::Crc32c,
            42,
            7,
            1,
            42,
            FILE_HEADER_REGION_SIZE as u64 + 7 * DEFAULT_BLOCK_SIZE as u64,
        );
        assert!(h.is_valid());
    }

    #[test]
    fn flipping_any_signed_byte_invalidates_file_header() {
        let h = FileHeader::new_signed(
            0,
            CompressionAlg::None,
            crate::checksum::Algorithm::Crc32c,
            0,
            0,
            0,
            0,
            FILE_HEADER_REGION_SIZE as u64,
        );
        let bytes = h.as_bytes().to_vec();
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut copy = bytes.clone();
                copy[i] ^= 1 << bit;
                let parsed = FileHeader::ref_from_bytes(&copy).unwrap();
                assert!(
                    !parsed.is_valid(),
                    "bit flip at {i}:{bit} should invalidate"
                );
            }
        }
    }

    #[test]
    fn signed_footer_validates() {
        let bh = BlockHandle {
            offset: U64::new(8192),
            length: U32::new(123),
            checksum: U32::new(0xDEAD_BEEF),
        };
        let f = Footer::new_signed(bh, bh, bh);
        assert!(f.is_valid());
    }

    #[test]
    fn footer_with_wrong_magic_is_invalid() {
        let bh = BlockHandle {
            offset: U64::new(0),
            length: U32::new(0),
            checksum: U32::new(0),
        };
        let mut f = Footer::new_signed(bh, bh, bh);
        f.footer_magic = U64::new(0xDEAD_BEEF);
        assert!(!f.is_valid());
    }

    #[test]
    fn compression_and_record_op_tags_round_trip() {
        for alg in [
            CompressionAlg::None,
            CompressionAlg::Lz4,
            CompressionAlg::Zstd,
        ] {
            assert_eq!(CompressionAlg::from_byte(alg as u8), Some(alg));
        }
        assert_eq!(CompressionAlg::from_byte(99), None);

        for op in [RecordOp::Put, RecordOp::Tombstone] {
            assert_eq!(RecordOp::from_byte(op as u8), Some(op));
        }
        assert_eq!(RecordOp::from_byte(99), None);
    }
}
