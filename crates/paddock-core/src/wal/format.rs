//! On-disk WAL format: `#[repr(C)]` zerocopy types and constants.
//!
//! Every field is little-endian. Headers are `Unaligned + FromBytes + IntoBytes`
//! so they can be safely cast in place from an `&[u8]` returned by `read_at`
//! or by mmap-ing a segment file.
//!
//! The exact byte layout is documented in `docs/format/wal.md`. This module is
//! the authoritative implementation: if the doc and the code disagree, the
//! code is right, and the doc must be updated to match.

use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Physical block size used by the segment layout.
///
/// Records that exceed the remaining space in their block are split into
/// `FIRST`/`MIDDLE…`/`LAST` fragments, one fragment per block. A 32 KiB block
/// keeps fragmentation rare for typical small-value workloads while leaving
/// enough room to spread very large batches across many blocks without
/// blowing up record-header overhead.
pub const BLOCK_SIZE: usize = 32 * 1024;

/// Wire size of [`SegmentHeader`].
pub const SEGMENT_HEADER_SIZE: usize = 32;

/// Wire size of [`RecordHeader`].
pub const RECORD_HEADER_SIZE: usize = 16;

/// Maximum payload bytes carried by a single record fragment.
///
/// A fragment must fit inside one block. We subtract the record header and
/// stay 16-byte-aligned for tidy arithmetic; the upper bound also fits the
/// `length: U16` field with comfortable headroom.
pub const MAX_FRAGMENT_PAYLOAD: usize = BLOCK_SIZE - RECORD_HEADER_SIZE;

/// Magic number at the start of every segment file. ASCII `"PKWL"` in LE.
pub const SEGMENT_MAGIC: u32 = 0x4C57_4B50;

/// Current WAL format version. Bump when changing any on-disk layout in this
/// module. Readers refuse versions other than this value.
pub const FORMAT_VERSION: u32 = 1;

/// Segment header, written once at the start of every segment file.
///
/// Layout (32 bytes, little-endian):
///
/// | Offset | Size | Field           | Description                                    |
/// |-------:|-----:|:----------------|:-----------------------------------------------|
/// | 0      | 4    | `magic`         | [`SEGMENT_MAGIC`]                              |
/// | 4      | 4    | `version`       | [`FORMAT_VERSION`]                             |
/// | 8      | 8    | `segment_id`    | Monotonic per-engine segment number            |
/// | 16     | 8    | `first_seqno`   | First sequence number written into this segment |
/// | 24     | 4    | `header_crc32c` | CRC32C over bytes `0..24`                      |
/// | 28     | 4    | `reserved`     | Padding, must be zero                          |
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct SegmentHeader {
    /// Magic number — see [`SEGMENT_MAGIC`].
    pub magic: U32,
    /// Format version — see [`FORMAT_VERSION`].
    pub version: U32,
    /// Monotonic segment identifier assigned by the writer.
    pub segment_id: U64,
    /// First sequence number recorded by the writer for this segment.
    pub first_seqno: U64,
    /// CRC32C over the 24 header bytes preceding this field.
    pub header_crc32c: U32,
    /// Padding to fill 32 bytes. Always written as zero.
    pub reserved: U32,
}

const _: () = assert!(std::mem::size_of::<SegmentHeader>() == SEGMENT_HEADER_SIZE);

impl SegmentHeader {
    /// Construct a header without computing its checksum. Use
    /// [`SegmentHeader::new_signed`] to also fill `header_crc32c`.
    #[must_use]
    pub const fn new(segment_id: u64, first_seqno: u64) -> Self {
        Self {
            magic: U32::new(SEGMENT_MAGIC),
            version: U32::new(FORMAT_VERSION),
            segment_id: U64::new(segment_id),
            first_seqno: U64::new(first_seqno),
            header_crc32c: U32::new(0),
            reserved: U32::new(0),
        }
    }

    /// Construct a fully-populated header with the correct `header_crc32c`.
    #[must_use]
    pub fn new_signed(segment_id: u64, first_seqno: u64) -> Self {
        let mut h = Self::new(segment_id, first_seqno);
        let crc = crate::checksum::crc32c::hash(&h.as_bytes()[..24]);
        h.header_crc32c = U32::new(crc);
        h
    }

    /// `true` if the magic, version, reserved padding, and CRC32C all check out.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.magic.get() != SEGMENT_MAGIC || self.version.get() != FORMAT_VERSION {
            return false;
        }
        if self.reserved.get() != 0 {
            return false;
        }
        let stored = self.header_crc32c.get();
        let expected = crate::checksum::crc32c::hash(&self.as_bytes()[..24]);
        stored == expected
    }
}

/// Record fragment type — borrowed from LevelDB's WAL design.
///
/// Stored on disk as a single byte in [`RecordHeader::record_type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RecordType {
    /// The whole payload fits in this record. No further fragments follow.
    Full = 1,
    /// First fragment of a logical record split across multiple blocks.
    First = 2,
    /// A middle fragment. Any number of these may precede the `Last`.
    Middle = 3,
    /// Final fragment that completes a multi-block logical record.
    Last = 4,
}

impl RecordType {
    /// Parse from the byte stored on disk.
    pub const fn from_byte(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Full),
            2 => Some(Self::First),
            3 => Some(Self::Middle),
            4 => Some(Self::Last),
            _ => None,
        }
    }

    /// Persisted byte value.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Per-record header. Sits immediately before the fragment payload.
///
/// Layout (16 bytes, little-endian):
///
/// | Offset | Size | Field            | Description                                              |
/// |-------:|-----:|:-----------------|:---------------------------------------------------------|
/// | 0      | 4    | `payload_crc32c` | CRC32C over `record_type` + `seqno` + `payload`          |
/// | 4      | 2    | `length`         | Payload length in bytes (`<= MAX_FRAGMENT_PAYLOAD`)      |
/// | 6      | 1    | `record_type`    | [`RecordType`] tag                                       |
/// | 7      | 1    | `reserved`      | Padding, must be zero                                    |
/// | 8      | 8    | `seqno`          | Logical-record sequence number                           |
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct RecordHeader {
    /// CRC32C over `[record_type, reserved, seqno_bytes, payload]`.
    pub payload_crc32c: U32,
    /// Fragment payload length.
    pub length: U16,
    /// [`RecordType`] tag (validated via [`RecordType::from_byte`]).
    pub record_type: u8,
    /// Reserved byte, must be written as zero.
    pub reserved: u8,
    /// Sequence number assigned by the engine.
    pub seqno: U64,
}

const _: () = assert!(std::mem::size_of::<RecordHeader>() == RECORD_HEADER_SIZE);

impl RecordHeader {
    /// Build a header **without** filling the checksum. Use
    /// [`RecordHeader::sign`] (taking a payload) to compute it.
    #[must_use]
    pub const fn new(record_type: RecordType, seqno: u64, payload_len: u16) -> Self {
        Self {
            payload_crc32c: U32::new(0),
            length: U16::new(payload_len),
            record_type: record_type.as_byte(),
            reserved: 0,
            seqno: U64::new(seqno),
        }
    }

    /// Compute and store the CRC32C over `(record_type, reserved, seqno, payload)`.
    pub fn sign(&mut self, payload: &[u8]) {
        let mut hasher = crate::checksum::crc32c::Hasher::new();
        hasher.update(&[self.record_type, self.reserved]);
        hasher.update(self.seqno.as_bytes());
        hasher.update(payload);
        self.payload_crc32c = U32::new(hasher.finalize());
    }

    /// Re-compute the CRC32C the on-disk header should carry, given a payload.
    #[must_use]
    pub fn expected_crc(&self, payload: &[u8]) -> u32 {
        let mut hasher = crate::checksum::crc32c::Hasher::new();
        hasher.update(&[self.record_type, self.reserved]);
        hasher.update(self.seqno.as_bytes());
        hasher.update(payload);
        hasher.finalize()
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "test payloads are tiny; truncation cannot occur"
)]
mod tests {
    use super::*;

    #[test]
    fn segment_header_size_matches_constant() {
        assert_eq!(std::mem::size_of::<SegmentHeader>(), SEGMENT_HEADER_SIZE);
    }

    #[test]
    fn record_header_size_matches_constant() {
        assert_eq!(std::mem::size_of::<RecordHeader>(), RECORD_HEADER_SIZE);
    }

    #[test]
    fn signed_segment_header_validates() {
        let h = SegmentHeader::new_signed(42, 1_000);
        assert!(h.is_valid());
        // sanity: storing the same fields without the signature does not.
        let unsigned = SegmentHeader::new(42, 1_000);
        assert!(!unsigned.is_valid());
    }

    #[test]
    fn flipping_any_header_bit_invalidates() {
        let h = SegmentHeader::new_signed(42, 1_000);
        let bytes = h.as_bytes().to_vec();
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut copy = bytes.clone();
                copy[i] ^= 1 << bit;
                let parsed = SegmentHeader::ref_from_bytes(&copy).expect("size matches");
                assert!(!parsed.is_valid(), "flip at byte {i} bit {bit} should fail");
            }
        }
        let original = SegmentHeader::ref_from_bytes(&bytes[..]).expect("size matches");
        assert!(original.is_valid());
    }

    #[test]
    fn record_type_round_trip() {
        for rt in [
            RecordType::Full,
            RecordType::First,
            RecordType::Middle,
            RecordType::Last,
        ] {
            assert_eq!(RecordType::from_byte(rt.as_byte()), Some(rt));
        }
        assert_eq!(RecordType::from_byte(0), None);
        assert_eq!(RecordType::from_byte(99), None);
    }

    #[test]
    fn signed_record_header_recomputes_same_crc() {
        let payload = b"hello batch";
        let mut h = RecordHeader::new(RecordType::Full, 7, payload.len() as u16);
        h.sign(payload);
        assert_eq!(h.payload_crc32c.get(), h.expected_crc(payload));
    }

    #[test]
    fn signed_record_header_detects_payload_mutation() {
        let payload = b"hello batch";
        let mut h = RecordHeader::new(RecordType::Full, 7, payload.len() as u16);
        h.sign(payload);
        let stored = h.payload_crc32c.get();
        let tampered = b"hello b!tch";
        assert_ne!(stored, h.expected_crc(tampered));
    }

    #[test]
    fn zerocopy_round_trip_segment_header() {
        let h = SegmentHeader::new_signed(0xAA_BB_CC_DD, 0x1234);
        let bytes = h.as_bytes();
        let parsed = SegmentHeader::ref_from_bytes(bytes).expect("exact size");
        assert_eq!(parsed.magic.get(), SEGMENT_MAGIC);
        assert_eq!(parsed.version.get(), FORMAT_VERSION);
        assert_eq!(parsed.segment_id.get(), 0xAA_BB_CC_DD);
        assert_eq!(parsed.first_seqno.get(), 0x1234);
        assert!(parsed.is_valid());
    }

    #[test]
    fn zerocopy_round_trip_record_header() {
        let payload = vec![0xABu8; 256];
        let mut h = RecordHeader::new(RecordType::Middle, 999, payload.len() as u16);
        h.sign(&payload);
        let parsed = RecordHeader::ref_from_bytes(h.as_bytes()).expect("exact size");
        assert_eq!(parsed.length.get(), 256);
        assert_eq!(parsed.record_type, RecordType::Middle.as_byte());
        assert_eq!(parsed.seqno.get(), 999);
        assert_eq!(parsed.payload_crc32c.get(), parsed.expected_crc(&payload));
    }
}
