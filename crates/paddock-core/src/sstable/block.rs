// Block payload-length values are bounded by `DEFAULT_BLOCK_SIZE` (16 KiB)
// so usize→u32 truncation cannot occur in practice. Each cast site is
// kept explicit; the module-level allow keeps the noise out of the source.
#![allow(clippy::cast_possible_truncation)]

//! SSTable data block: builder and reader.
//!
//! A data block holds a sorted run of records using prefix-compressed keys
//! with periodic *restart points*. The layout is the LevelDB / RocksDB
//! convention:
//!
//! ```text
//!   Records (variable size, grow forward from offset 0)
//!     varint shared_prefix_len
//!     varint unshared_key_len
//!     varint value_len
//!     u64    seqno
//!     u8     op_type            (0 = Put, 1 = Tombstone)
//!     bytes  key_suffix[unshared_key_len]
//!     bytes  value[value_len]
//!   ...
//!   u32[num_restarts]    restart offsets   (each points to a "shared=0" record)
//!   u32                  num_restarts
//!   u32                  block_checksum    (CRC32C of everything before this)
//! ```
//!
//! Every Nth record (`RESTART_INTERVAL`) is a *restart*: its `shared` is
//! always zero so its key is stored in full. Restart offsets give point-read
//! binary-search pivots; intra-restart-range scanning is linear.
//!
//! The same layout serves the **index block**: there the value bytes are the
//! 16-byte serialised [`BlockHandle`] of the data block whose largest key is
//! `key`, and `seqno` and `op_type` are left at zero. Treating the index as
//! "just another block" keeps the reader hot path symmetric.

use std::cmp::Ordering;

use crate::checksum::crc32c;
use crate::encoding::varint::{MAX_VARINT_U32_BYTES, decode_u32, encode_u32};
use crate::error::{Error, Result};
use crate::sstable::format::{RESTART_INTERVAL, RecordOp};

/// Bytes occupied by the per-block trailer (num_restarts + checksum).
pub const BLOCK_TRAILER_SIZE: usize = 8;

/// Builds one data block in memory.
///
/// Call [`add`](Self::add) for each `(key, value, seqno, op)` in ascending
/// order, then [`finish`](Self::finish) to emit the complete block bytes
/// (records + restart array + trailer).
#[derive(Debug)]
pub struct BlockBuilder {
    buffer: Vec<u8>,
    restarts: Vec<u32>,
    last_key: Vec<u8>,
    /// Records appended since the last restart point.
    counter: usize,
}

impl BlockBuilder {
    /// Construct an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(crate::sstable::format::DEFAULT_BLOCK_SIZE),
            restarts: Vec::new(),
            last_key: Vec::new(),
            // Force the very first `add` to register a restart at offset 0
            // (the `else` branch in `add` pushes when `counter >= RESTART_INTERVAL`).
            counter: RESTART_INTERVAL,
        }
    }

    /// `true` if no records have been appended yet.
    #[must_use]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::is_empty is not yet const fn on stable"
    )]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Approximate finished-block size in bytes (records + restart array +
    /// trailer). Used by [`crate::sstable::writer`] to decide when to seal
    /// the block.
    #[must_use]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::len is not yet const fn on stable"
    )]
    pub fn estimated_size(&self) -> usize {
        self.buffer.len() + self.restarts.len() * 4 + BLOCK_TRAILER_SIZE
    }

    /// Append a record. Caller must ensure `key >= last_key`. Equal keys
    /// across distinct seqnos are allowed; they sort by seqno descending.
    pub fn add(&mut self, key: &[u8], value: &[u8], seqno: u64, op: RecordOp) {
        // Decide whether this record opens a new restart range.
        let shared = if self.counter < RESTART_INTERVAL {
            shared_prefix_len(&self.last_key, key)
        } else {
            // Start a new restart range: emit a full key.
            self.restarts.push(self.buffer.len() as u32);
            self.counter = 0;
            0
        };
        let unshared = key.len() - shared;

        let mut scratch = [0u8; MAX_VARINT_U32_BYTES];
        let n = encode_u32(shared as u32, &mut scratch).expect("u32 fits");
        self.buffer.extend_from_slice(&scratch[..n]);
        let n = encode_u32(unshared as u32, &mut scratch).expect("u32 fits");
        self.buffer.extend_from_slice(&scratch[..n]);
        let n = encode_u32(value.len() as u32, &mut scratch).expect("u32 fits");
        self.buffer.extend_from_slice(&scratch[..n]);
        self.buffer.extend_from_slice(&seqno.to_le_bytes());
        self.buffer.push(op as u8);
        self.buffer.extend_from_slice(&key[shared..]);
        self.buffer.extend_from_slice(value);

        // Track the full key for the next prefix-compression decision.
        self.last_key.clear();
        self.last_key.extend_from_slice(key);
        self.counter += 1;
    }

    /// Emit the complete block bytes and reset the builder.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = std::mem::replace(
            &mut self.buffer,
            Vec::with_capacity(crate::sstable::format::DEFAULT_BLOCK_SIZE),
        );
        // Restart array, big-end first.
        for r in &self.restarts {
            out.extend_from_slice(&r.to_le_bytes());
        }
        let num_restarts =
            u32::try_from(self.restarts.len()).expect("restart array length always fits in u32");
        out.extend_from_slice(&num_restarts.to_le_bytes());
        // CRC over everything we have so far.
        let crc = crc32c::hash(&out);
        out.extend_from_slice(&crc.to_le_bytes());

        // Reset for the next block.
        self.restarts.clear();
        self.last_key.clear();
        self.counter = RESTART_INTERVAL;
        out
    }
}

impl Default for BlockBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Read-only view over a complete block in memory or mmap'd from disk.
#[derive(Debug, Clone, Copy)]
pub struct BlockReader<'a> {
    /// Records slice (excludes the trailing restart array and trailer).
    records: &'a [u8],
    /// Restart array as raw bytes (each entry is a `u32` LE).
    restart_bytes: &'a [u8],
}

/// One decoded record exposed by [`BlockIter`].
///
/// The `key` is owned (reassembled from the prefix-compressed encoding —
/// shared prefix bytes are not contiguous in the block bytes, so the key
/// has to be materialised). The `value` is a slice into the block's
/// underlying byte buffer (typically a page-cache page reached via mmap),
/// so values are zero-copy — the engine's hot read path.
#[derive(Debug, Clone)]
pub struct RecordView<'a> {
    /// Full user key, reassembled.
    pub key: Vec<u8>,
    /// Inline value bytes (empty for tombstones). Borrowed from the block.
    pub value: &'a [u8],
    /// Sequence number stored on the record.
    pub seqno: u64,
    /// Operation tag.
    pub op: RecordOp,
}

impl<'a> BlockReader<'a> {
    /// Open `bytes` as a complete block, validating the CRC32C.
    pub fn open(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < BLOCK_TRAILER_SIZE {
            return Err(Error::invalid_format_static(
                "sstable data block",
                "shorter than block trailer",
            ));
        }
        let stored_crc =
            u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().expect("4-byte slice"));
        let crc_input = &bytes[..bytes.len() - 4];
        let computed_crc = crc32c::hash(crc_input);
        if stored_crc != computed_crc {
            return Err(Error::ChecksumMismatch {
                context: "sstable data block",
                expected: u64::from(stored_crc),
                found: u64::from(computed_crc),
            });
        }

        let num_restarts = u32::from_le_bytes(
            bytes[bytes.len() - 8..bytes.len() - 4]
                .try_into()
                .expect("4-byte slice"),
        );
        let restart_bytes_len = (num_restarts as usize).checked_mul(4).ok_or_else(|| {
            Error::invalid_format_static("sstable data block", "restart overflow")
        })?;
        if restart_bytes_len + BLOCK_TRAILER_SIZE > bytes.len() {
            return Err(Error::invalid_format_static(
                "sstable data block",
                "restart array overflows block",
            ));
        }
        let records_end = bytes.len() - BLOCK_TRAILER_SIZE - restart_bytes_len;
        Ok(Self {
            records: &bytes[..records_end],
            restart_bytes: &bytes[records_end..bytes.len() - BLOCK_TRAILER_SIZE],
        })
    }

    /// Number of restart points in this block.
    #[must_use]
    pub const fn num_restarts(&self) -> usize {
        self.restart_bytes.len() / 4
    }

    /// Iterate every record in ascending order.
    #[must_use]
    pub fn iter(&self) -> BlockIter<'a> {
        IntoIterator::into_iter(*self)
    }

    /// Restart offset at index `i`.
    fn restart_offset(&self, i: usize) -> usize {
        let off = u32::from_le_bytes(
            self.restart_bytes[i * 4..i * 4 + 4]
                .try_into()
                .expect("4-byte slice"),
        );
        off as usize
    }

    /// Position the iterator on the first record whose key is `>= target`,
    /// or `None` if no such record exists in this block.
    pub fn seek(&self, target: &[u8]) -> Option<RecordView<'a>> {
        // Binary search over the restart array to find the largest restart
        // whose key is `<= target`.
        let n = self.num_restarts();
        if n == 0 {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = n;
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            let mid_off = self.restart_offset(mid);
            match key_at_restart(self.records, mid_off) {
                Some(k) => match k.cmp(target) {
                    Ordering::Less => lo = mid,
                    Ordering::Equal => {
                        lo = mid;
                        hi = mid + 1;
                    }
                    Ordering::Greater => hi = mid,
                },
                None => return None,
            }
        }
        // Linear-scan forward from the chosen restart.
        let start_off = self.restart_offset(lo);
        let iter = BlockIter {
            records: self.records,
            cursor: start_off,
            last_key: Vec::new(),
        };
        iter.into_iter().find(|rec| rec.key.as_slice() >= target)
    }
}

impl<'a> IntoIterator for BlockReader<'a> {
    type Item = RecordView<'a>;
    type IntoIter = BlockIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        BlockIter {
            records: self.records,
            cursor: 0,
            last_key: Vec::new(),
        }
    }
}

impl<'a> IntoIterator for &BlockReader<'a> {
    type Item = RecordView<'a>;
    type IntoIter = BlockIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        (*self).into_iter()
    }
}

/// Forward iterator over a [`BlockReader`].
#[derive(Debug)]
pub struct BlockIter<'a> {
    records: &'a [u8],
    cursor: usize,
    last_key: Vec<u8>,
}

impl<'a> Iterator for BlockIter<'a> {
    type Item = RecordView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.records.len() {
            return None;
        }
        let rest = &self.records[self.cursor..];
        let (shared, c1) = decode_u32(rest).ok()?;
        let (unshared, c2) = decode_u32(&rest[c1..]).ok()?;
        let (value_len, c3) = decode_u32(&rest[c1 + c2..]).ok()?;
        let pre = c1 + c2 + c3;
        let header_total = pre + 8 + 1; // seqno + op_type
        if rest.len() < header_total {
            return None;
        }
        let seqno = u64::from_le_bytes(rest[pre..pre + 8].try_into().ok()?);
        let op = RecordOp::from_byte(rest[pre + 8])?;
        let key_start = self.cursor + header_total;
        let key_end = key_start + unshared as usize;
        let val_end = key_end + value_len as usize;
        if val_end > self.records.len() {
            return None;
        }

        let key_suffix = &self.records[key_start..key_end];
        let value: &'a [u8] = &self.records[key_end..val_end];

        // Reassemble the full key by maintaining the running `last_key` and
        // returning an owned copy. This costs one allocation per record on
        // raw iteration. Point lookups go through `seek()` which exercises
        // this once, not per-record.
        self.last_key.truncate(shared as usize);
        self.last_key.extend_from_slice(key_suffix);
        let key = self.last_key.clone();

        self.cursor = val_end;
        Some(RecordView {
            key,
            value,
            seqno,
            op,
        })
    }
}

/// Extract the full key of the record stored at offset `off` (which must be
/// a restart, so `shared == 0`).
fn key_at_restart(records: &[u8], off: usize) -> Option<&[u8]> {
    if off >= records.len() {
        return None;
    }
    let rest = &records[off..];
    let (shared, c1) = decode_u32(rest).ok()?;
    if shared != 0 {
        // Not a restart record; bail to keep the binary search well-formed.
        return None;
    }
    let (unshared, c2) = decode_u32(&rest[c1..]).ok()?;
    let (_value_len, c3) = decode_u32(&rest[c1 + c2..]).ok()?;
    let pre = c1 + c2 + c3;
    let key_start = pre + 8 + 1; // seqno + op_type
    let key_end = key_start + unshared as usize;
    if key_end > rest.len() {
        return None;
    }
    Some(&rest[key_start..key_end])
}

fn shared_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let limit = a.len().min(b.len());
    let mut i = 0;
    while i < limit && a[i] == b[i] {
        i += 1;
    }
    i
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "test fixtures use small values where truncation cannot occur"
)]
mod tests {
    use super::*;

    fn build(records: &[(&[u8], &[u8], u64, RecordOp)]) -> Vec<u8> {
        let mut b = BlockBuilder::new();
        for (k, v, seqno, op) in records {
            b.add(k, v, *seqno, *op);
        }
        b.finish()
    }

    #[test]
    fn empty_block_has_only_trailer() {
        let mut b = BlockBuilder::new();
        let bytes = b.finish();
        // empty restart array + num_restarts(0) + crc
        assert_eq!(bytes.len(), 4 + 4);
    }

    #[test]
    fn single_record_round_trip() {
        let bytes = build(&[(b"key", b"value", 7, RecordOp::Put)]);
        let r = BlockReader::open(&bytes).unwrap();
        let mut it = r.iter();
        let rec = it.next().unwrap();
        assert_eq!(rec.key, b"key".to_vec());
        assert_eq!(rec.value, b"value");
        assert_eq!(rec.seqno, 7);
        assert_eq!(rec.op, RecordOp::Put);
        assert!(it.next().is_none());
    }

    #[test]
    fn many_records_iterate_in_order() {
        let n = 100u32;
        let records: Vec<_> = (0..n)
            .map(|i| {
                (
                    format!("key-{i:05}").into_bytes(),
                    format!("v-{i}").into_bytes(),
                    u64::from(i + 1),
                    RecordOp::Put,
                )
            })
            .collect();
        let mut b = BlockBuilder::new();
        for (k, v, s, op) in &records {
            b.add(k, v, *s, *op);
        }
        let bytes = b.finish();
        let r = BlockReader::open(&bytes).unwrap();
        let collected: Vec<_> = r.iter().map(|v| v.key).collect();
        let expected: Vec<_> = records.iter().map(|(k, _, _, _)| k.clone()).collect();
        assert_eq!(collected, expected);
    }

    #[test]
    fn prefix_compression_shrinks_block_for_shared_prefixes() {
        let common = b"long_shared_prefix_".to_vec();
        let mut shared_records: Vec<(Vec<u8>, Vec<u8>, u64, RecordOp)> = Vec::new();
        for i in 0..50u32 {
            let mut k = common.clone();
            k.extend_from_slice(format!("{i:05}").as_bytes());
            shared_records.push((k, b"v".to_vec(), u64::from(i + 1), RecordOp::Put));
        }
        let mut b = BlockBuilder::new();
        for (k, v, s, op) in &shared_records {
            b.add(k, v, *s, *op);
        }
        let shared_bytes = b.finish();

        // Compare against the same records with all unique prefixes.
        let mut b2 = BlockBuilder::new();
        for (i, (_, v, s, op)) in shared_records.iter().enumerate() {
            let k = format!("UNIQUE-{:05}-prefix-burn-{:0width$}", i, 0, width = 20);
            b2.add(k.as_bytes(), v, *s, *op);
        }
        let unique_bytes = b2.finish();

        assert!(
            shared_bytes.len() < unique_bytes.len(),
            "prefix-compressed block should be smaller: shared {} vs unique {}",
            shared_bytes.len(),
            unique_bytes.len(),
        );
    }

    #[test]
    fn corrupted_crc_is_detected() {
        let mut bytes = build(&[(b"k", b"v", 1, RecordOp::Put)]);
        let last_idx = bytes.len() - 1;
        bytes[last_idx] ^= 0x55;
        let err = BlockReader::open(&bytes).unwrap_err();
        assert!(matches!(err, Error::ChecksumMismatch { .. }));
    }

    #[test]
    fn seek_finds_exact_match() {
        let n = 64u32;
        let mut b = BlockBuilder::new();
        for i in 0..n {
            let k = format!("key-{i:05}");
            b.add(k.as_bytes(), b"v", u64::from(i + 1), RecordOp::Put);
        }
        let bytes = b.finish();
        let r = BlockReader::open(&bytes).unwrap();
        let rec = r.seek(b"key-00032").unwrap();
        assert_eq!(rec.key, b"key-00032".to_vec());
    }

    #[test]
    fn seek_returns_first_key_geq_target_when_no_exact_match() {
        let mut b = BlockBuilder::new();
        for k in [b"alpha".as_slice(), b"bravo", b"delta", b"echo"] {
            b.add(k, b"v", 1, RecordOp::Put);
        }
        let bytes = b.finish();
        let r = BlockReader::open(&bytes).unwrap();
        let rec = r.seek(b"charlie").unwrap();
        assert_eq!(rec.key, b"delta".to_vec());
    }

    #[test]
    fn seek_past_last_key_returns_none() {
        let mut b = BlockBuilder::new();
        for k in [b"alpha".as_slice(), b"bravo", b"delta"] {
            b.add(k, b"v", 1, RecordOp::Put);
        }
        let bytes = b.finish();
        let r = BlockReader::open(&bytes).unwrap();
        assert!(r.seek(b"zzz").is_none());
    }

    #[test]
    fn restart_array_grows_every_interval_records() {
        let mut b = BlockBuilder::new();
        for i in 0..(RESTART_INTERVAL * 3 + 2) {
            let k = format!("key-{i:05}");
            b.add(k.as_bytes(), b"v", 1, RecordOp::Put);
        }
        let bytes = b.finish();
        let r = BlockReader::open(&bytes).unwrap();
        // Records 0, RESTART_INTERVAL, 2*RESTART_INTERVAL, 3*RESTART_INTERVAL are restarts.
        assert_eq!(r.num_restarts(), 4);
    }

    #[test]
    fn tombstone_stores_empty_value() {
        let bytes = build(&[(b"k", b"", 9, RecordOp::Tombstone)]);
        let r = BlockReader::open(&bytes).unwrap();
        let rec = r.iter().next().unwrap();
        assert_eq!(rec.op, RecordOp::Tombstone);
        assert!(rec.value.is_empty());
        assert_eq!(rec.seqno, 9);
    }

    /// Round-trip the raw bytes through `IntoBytes` to make sure the
    /// block-trailer encoding matches the byte-level expectation.
    #[test]
    fn block_trailer_layout_is_stable() {
        let bytes = build(&[(b"k", b"v", 1, RecordOp::Put)]);
        let len = bytes.len();
        // num_restarts at len-8..len-4, checksum at len-4..len
        let num = u32::from_le_bytes(bytes[len - 8..len - 4].try_into().unwrap());
        assert_eq!(num, 1);
        let _crc = u32::from_le_bytes(bytes[len - 4..len].try_into().unwrap());
    }

    /// Sanity: zerocopy types are still IntoBytes-able. (Defensive ping in
    /// case a dependency upgrade silently drops the derive.)
    #[test]
    fn zerocopy_traits_compile() {
        use crate::sstable::format::BlockHandle;
        use zerocopy::IntoBytes;
        let bh = BlockHandle {
            offset: zerocopy::little_endian::U64::new(0),
            length: zerocopy::little_endian::U32::new(0),
            checksum: zerocopy::little_endian::U32::new(0),
        };
        let _bytes = bh.as_bytes();
    }
}
