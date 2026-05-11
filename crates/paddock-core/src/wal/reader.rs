//! WAL segment reader and replay.
//!
//! [`SegmentReader`] reads a segment file written by [`super::writer::SegmentWriter`]
//! and yields one decoded *logical* record at a time — fragments are joined
//! transparently and surfaced as a single payload plus the sequence number.
//!
//! ## Torn-write semantics
//!
//! At the end of an unclean shutdown, the last block of the last segment may
//! contain a partial fragment whose CRC does not check out. The reader
//! distinguishes two cases:
//!
//! - **Torn tail.** A CRC mismatch in the *final* fragment we see, with no
//!   well-formed data after it, is reported as [`ReplayOutcome::TornTail`].
//!   The caller is expected to truncate the segment at the reported offset
//!   and resume operation.
//! - **Mid-segment corruption.** A CRC mismatch followed by data that the
//!   reader cannot continue past is reported as an [`Error::Corruption`].
//!   This is unrecoverable from the WAL alone.
//!
//! The current implementation reports any CRC failure as `TornTail`: callers
//! today treat the entire last partial segment as truncatable. A future
//! refinement (Phase 2.1) will tighten this by scanning past the failure and
//! escalating to `Corruption` if more valid records follow.

use crate::error::{Error, Result};
use crate::io::vfs::VfsFile;
use crate::wal::format::{
    BLOCK_SIZE, FORMAT_VERSION, MAX_FRAGMENT_PAYLOAD, RECORD_HEADER_SIZE, RecordHeader, RecordType,
    SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SegmentHeader,
};
use zerocopy::FromBytes;

/// One logical record yielded by [`SegmentReader::next_record`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordView {
    /// Sequence number recorded in the (first) fragment header.
    pub seqno: u64,
    /// Reassembled record payload.
    pub payload: Vec<u8>,
}

/// Outcome of a single [`SegmentReader::next_record`] call.
#[derive(Debug)]
pub enum ReadOutcome {
    /// A complete logical record was read successfully.
    Record(RecordView),
    /// The reader reached the end of the segment cleanly.
    EndOfSegment,
    /// A torn write was detected at the segment tail. The caller should
    /// truncate the segment at `truncate_to` bytes from the start of the
    /// records area (i.e. after [`SEGMENT_HEADER_SIZE`]).
    TornTail {
        /// Byte offset (in the records area) where the corruption begins.
        truncate_to: u64,
        /// Diagnostic description.
        reason: &'static str,
    },
}

/// Whole-segment replay outcome.
#[derive(Debug)]
pub enum ReplayOutcome {
    /// Segment ended cleanly.
    Clean,
    /// Segment had a torn tail. The caller may truncate to `truncate_to`
    /// records-area bytes and continue.
    TornTail {
        /// Byte offset (in the records area) where the corruption begins.
        truncate_to: u64,
        /// Diagnostic description.
        reason: &'static str,
    },
}

/// Reader over a WAL segment file.
pub struct SegmentReader<F: VfsFile> {
    file: F,
    file_size: u64,
    cursor: u64,
    header: SegmentHeader,
}

impl<F: VfsFile> std::fmt::Debug for SegmentReader<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentReader")
            .field("segment_id", &self.header.segment_id.get())
            .field("first_seqno", &self.header.first_seqno.get())
            .field("cursor", &self.cursor)
            .field("file_size", &self.file_size)
            .finish_non_exhaustive()
    }
}

impl<F: VfsFile> SegmentReader<F> {
    /// Open `file` as a WAL segment, validating its header.
    pub fn open(file: F) -> Result<Self> {
        let file_size = file.size()?;
        if file_size < SEGMENT_HEADER_SIZE as u64 {
            return Err(Error::InvalidFormat {
                context: "wal segment",
                reason: format!(
                    "file too short: {file_size} bytes (need at least {SEGMENT_HEADER_SIZE})"
                ),
            });
        }
        let mut buf = [0u8; SEGMENT_HEADER_SIZE];
        file.read_at(&mut buf, 0)?;
        let header = SegmentHeader::ref_from_bytes(&buf)
            .map_err(|_| Error::invalid_format_static("wal segment header", "size mismatch"))?;
        if header.magic.get() != SEGMENT_MAGIC {
            return Err(Error::invalid_format_static(
                "wal segment header",
                "bad magic",
            ));
        }
        if header.version.get() != FORMAT_VERSION {
            return Err(Error::InvalidFormat {
                context: "wal segment header",
                reason: format!(
                    "unsupported version {} (this build understands {FORMAT_VERSION})",
                    header.version.get()
                ),
            });
        }
        if !header.is_valid() {
            return Err(Error::Corruption {
                context: "wal segment header",
                reason: "checksum mismatch".to_owned(),
            });
        }
        let header_owned = *header;

        Ok(Self {
            file,
            file_size,
            cursor: 0, // measured from the start of the records area
            header: header_owned,
        })
    }

    /// Segment identifier from the file header.
    #[must_use]
    pub const fn segment_id(&self) -> u64 {
        self.header.segment_id.get()
    }

    /// First sequence number recorded by the writer that produced this segment.
    #[must_use]
    pub const fn first_seqno(&self) -> u64 {
        self.header.first_seqno.get()
    }

    /// Read the next logical record. See [`ReadOutcome`] for the semantics.
    pub fn next_record(&mut self) -> Result<ReadOutcome> {
        let mut assembled: Option<RecordView> = None;
        let record_start_cursor = self.cursor;
        let records_area_end = self.file_size - SEGMENT_HEADER_SIZE as u64;

        loop {
            self.skip_block_padding_if_needed(records_area_end);

            if self.cursor + RECORD_HEADER_SIZE as u64 > records_area_end {
                return self.handle_tail(records_area_end, assembled.as_ref(), record_start_cursor);
            }

            let frag = match self.read_fragment(record_start_cursor)? {
                FragmentStep::Got(f) => f,
                FragmentStep::SkipBlock => continue,
                FragmentStep::TornTail { reason } => {
                    return Ok(ReadOutcome::TornTail {
                        truncate_to: record_start_cursor,
                        reason,
                    });
                }
            };

            self.cursor += RECORD_HEADER_SIZE as u64 + u64_from_usize(frag.payload.len());

            match assemble(&mut assembled, frag)? {
                AssemblyStep::Continue => {}
                AssemblyStep::Complete(view) => return Ok(ReadOutcome::Record(view)),
            }
        }
    }

    const fn skip_block_padding_if_needed(&mut self, records_area_end: u64) {
        let block_offset = usize_from_u64(self.cursor) % BLOCK_SIZE;
        let block_remaining = BLOCK_SIZE - block_offset;
        if block_remaining < RECORD_HEADER_SIZE {
            let next_block = self.cursor + u64_from_usize(block_remaining);
            if next_block <= records_area_end {
                self.cursor = next_block;
            }
        }
    }

    fn handle_tail(
        &self,
        records_area_end: u64,
        assembled: Option<&RecordView>,
        record_start_cursor: u64,
    ) -> Result<ReadOutcome> {
        if assembled.is_some() {
            return Ok(ReadOutcome::TornTail {
                truncate_to: record_start_cursor,
                reason: "segment ended mid-fragment",
            });
        }
        let bytes_remaining = records_area_end.saturating_sub(self.cursor);
        if bytes_remaining == 0 {
            return Ok(ReadOutcome::EndOfSegment);
        }
        let mut tail = vec![0u8; usize_from_u64(bytes_remaining)];
        self.file
            .read_at(&mut tail, SEGMENT_HEADER_SIZE as u64 + self.cursor)?;
        if tail.iter().all(|&b| b == 0) {
            Ok(ReadOutcome::EndOfSegment)
        } else {
            Ok(ReadOutcome::TornTail {
                truncate_to: record_start_cursor,
                reason: "stray bytes shorter than a record header at segment tail",
            })
        }
    }

    fn read_fragment(&mut self, _record_start_cursor: u64) -> Result<FragmentStep> {
        let mut header_bytes = [0u8; RECORD_HEADER_SIZE];
        let file_offset = SEGMENT_HEADER_SIZE as u64 + self.cursor;
        self.file.read_at(&mut header_bytes, file_offset)?;

        // A zeroed header marks block padding the writer left when rolling
        // onto a fresh block.
        if header_bytes.iter().all(|&b| b == 0) {
            let next_block = ((usize_from_u64(self.cursor) / BLOCK_SIZE) + 1) * BLOCK_SIZE;
            self.cursor = u64_from_usize(next_block);
            return Ok(FragmentStep::SkipBlock);
        }

        let header = RecordHeader::ref_from_bytes(&header_bytes)
            .map_err(|_| Error::invalid_format_static("wal record header", "size mismatch"))?;
        let payload_len = usize::from(header.length.get());
        if payload_len > MAX_FRAGMENT_PAYLOAD {
            return Ok(FragmentStep::TornTail {
                reason: "fragment length exceeds block size",
            });
        }
        let payload_offset = file_offset + RECORD_HEADER_SIZE as u64;
        if payload_offset + u64_from_usize(payload_len) > self.file_size {
            return Ok(FragmentStep::TornTail {
                reason: "fragment payload truncated by segment EOF",
            });
        }

        let mut payload = vec![0u8; payload_len];
        self.file.read_at(&mut payload, payload_offset)?;
        if header.expected_crc(&payload) != header.payload_crc32c.get() {
            return Ok(FragmentStep::TornTail {
                reason: "fragment crc32c mismatch",
            });
        }

        let record_type_byte = header.record_type;
        let seqno = header.seqno.get();
        let record_type =
            RecordType::from_byte(record_type_byte).ok_or_else(|| Error::InvalidFormat {
                context: "wal record header",
                reason: format!("invalid record_type byte {record_type_byte:#04x}"),
            })?;

        Ok(FragmentStep::Got(Fragment {
            record_type,
            seqno,
            payload,
        }))
    }

    /// Drive the reader to completion, invoking `on_record` for every
    /// successfully reassembled record. Returns the overall outcome.
    #[allow(
        clippy::missing_errors_doc,
        reason = "documented in the module-level overview"
    )]
    pub fn replay<H>(&mut self, mut on_record: H) -> Result<ReplayOutcome>
    where
        H: FnMut(RecordView) -> Result<()>,
    {
        loop {
            match self.next_record()? {
                ReadOutcome::Record(view) => on_record(view)?,
                ReadOutcome::EndOfSegment => return Ok(ReplayOutcome::Clean),
                ReadOutcome::TornTail {
                    truncate_to,
                    reason,
                } => {
                    return Ok(ReplayOutcome::TornTail {
                        truncate_to,
                        reason,
                    });
                }
            }
        }
    }
}

/// A successfully parsed fragment, returned from
/// [`SegmentReader::read_fragment`] when the bytes on disk passed every check.
struct Fragment {
    record_type: RecordType,
    seqno: u64,
    payload: Vec<u8>,
}

/// Output of a single [`SegmentReader::read_fragment`] call.
enum FragmentStep {
    Got(Fragment),
    SkipBlock,
    TornTail { reason: &'static str },
}

/// Output of folding a freshly parsed [`Fragment`] into the running record
/// assembly.
enum AssemblyStep {
    /// Fragment consumed; keep reading more fragments.
    Continue,
    /// The record is now complete.
    Complete(RecordView),
}

fn assemble(state: &mut Option<RecordView>, frag: Fragment) -> Result<AssemblyStep> {
    let Fragment {
        record_type,
        seqno,
        payload,
    } = frag;
    match (record_type, state) {
        (RecordType::Full, slot @ None) => {
            *slot = None; // explicit reset for clarity; was None already
            Ok(AssemblyStep::Complete(RecordView { seqno, payload }))
        }
        (RecordType::Full, Some(_)) => Err(Error::Corruption {
            context: "wal segment",
            reason: "FULL fragment encountered mid-record assembly".to_owned(),
        }),
        (RecordType::First, slot @ None) => {
            *slot = Some(RecordView { seqno, payload });
            Ok(AssemblyStep::Continue)
        }
        (RecordType::First, Some(_)) => Err(Error::Corruption {
            context: "wal segment",
            reason: "FIRST fragment encountered mid-record assembly".to_owned(),
        }),
        (RecordType::Middle | RecordType::Last, None) => Err(Error::Corruption {
            context: "wal segment",
            reason: format!("{record_type:?} fragment encountered without a preceding FIRST"),
        }),
        (RecordType::Middle, Some(view)) => {
            if view.seqno != seqno {
                return Err(Error::Corruption {
                    context: "wal segment",
                    reason: format!(
                        "MIDDLE fragment seqno {seqno} does not match in-progress {}",
                        view.seqno
                    ),
                });
            }
            view.payload.extend_from_slice(&payload);
            Ok(AssemblyStep::Continue)
        }
        (RecordType::Last, slot) => {
            let view = slot.as_mut().expect("matched Some above");
            if view.seqno != seqno {
                return Err(Error::Corruption {
                    context: "wal segment",
                    reason: format!(
                        "LAST fragment seqno {seqno} does not match in-progress {}",
                        view.seqno
                    ),
                });
            }
            view.payload.extend_from_slice(&payload);
            let finished = slot.take().expect("matched Some above");
            Ok(AssemblyStep::Complete(finished))
        }
    }
}

/// Lossless `u64 -> usize` narrowing for the engine's 64-bit targets.
/// Centralised so cast sites are explicit and clippy can be calmed in one
/// place.
#[inline]
#[allow(
    clippy::cast_possible_truncation,
    reason = "engine targets are 64-bit; usize == u64"
)]
const fn usize_from_u64(v: u64) -> usize {
    v as usize
}

/// Lossless `usize -> u64` widening for the engine's 64-bit targets.
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
    use crate::wal::writer::SegmentWriter;

    fn write_segment(vfs: &MemVfs, path: &str, ops: &[(u64, WriteBatch)]) {
        let file = vfs.open_writable(path).unwrap();
        let mut writer =
            SegmentWriter::create(file, 1, ops.first().map_or(0, |(s, _)| *s)).unwrap();
        for (seqno, batch) in ops {
            writer.append_record(*seqno, &batch.encode()).unwrap();
        }
    }

    fn replay_all(vfs: &MemVfs, path: &str) -> (Vec<RecordView>, ReplayOutcome) {
        let f = vfs.open_readonly(path).unwrap();
        let mut reader = SegmentReader::open(f).unwrap();
        let mut got = Vec::new();
        let outcome = reader
            .replay(|v| {
                got.push(v);
                Ok(())
            })
            .unwrap();
        (got, outcome)
    }

    #[test]
    fn empty_segment_replays_clean() {
        let vfs = MemVfs::new();
        write_segment(&vfs, "s", &[]);
        let (records, outcome) = replay_all(&vfs, "s");
        assert!(records.is_empty());
        assert!(matches!(outcome, ReplayOutcome::Clean));
    }

    #[test]
    fn single_record_round_trip() {
        let vfs = MemVfs::new();
        let mut b = WriteBatch::new();
        b.put(b"k".to_vec(), b"v".to_vec());
        write_segment(&vfs, "s", &[(42, b.clone())]);

        let (records, outcome) = replay_all(&vfs, "s");
        assert!(matches!(outcome, ReplayOutcome::Clean));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].seqno, 42);
        let decoded = WriteBatch::decode(&records[0].payload).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn many_small_records_round_trip() {
        let vfs = MemVfs::new();
        let mut ops = Vec::new();
        for i in 0..200u64 {
            let mut b = WriteBatch::new();
            b.put(format!("key-{i}").into_bytes(), vec![i as u8; 32]);
            ops.push((i, b));
        }
        write_segment(&vfs, "s", &ops);

        let (records, outcome) = replay_all(&vfs, "s");
        assert!(matches!(outcome, ReplayOutcome::Clean));
        assert_eq!(records.len(), ops.len());
        for ((seqno, batch), got) in ops.iter().zip(records.iter()) {
            assert_eq!(got.seqno, *seqno);
            assert_eq!(WriteBatch::decode(&got.payload).unwrap(), *batch);
        }
    }

    #[test]
    fn record_spanning_multiple_blocks_reassembles() {
        let vfs = MemVfs::new();
        let mut b = WriteBatch::new();
        // A single value larger than BLOCK_SIZE forces a FIRST/MIDDLE/LAST run.
        b.put(b"big".to_vec(), vec![0xCD; 3 * BLOCK_SIZE + 17]);
        write_segment(&vfs, "s", &[(7, b.clone())]);

        let (records, outcome) = replay_all(&vfs, "s");
        assert!(matches!(outcome, ReplayOutcome::Clean));
        assert_eq!(records.len(), 1);
        assert_eq!(WriteBatch::decode(&records[0].payload).unwrap(), b);
    }

    #[test]
    fn torn_tail_truncates_cleanly() {
        let vfs = MemVfs::new();
        let mut b = WriteBatch::new();
        b.put(b"k".to_vec(), b"v".to_vec());
        write_segment(&vfs, "s", &[(1, b.clone()), (2, b.clone())]);

        // Truncate the file so the second record's payload is missing.
        let mut writer = vfs.open_writable("s_torn").unwrap();
        let mut all = vec![0u8; vfs.open_readonly("s").unwrap().size().unwrap() as usize];
        vfs.open_readonly("s")
            .unwrap()
            .read_at(&mut all, 0)
            .unwrap();
        // Keep header + first record header + first payload + part of second header
        let keep = SEGMENT_HEADER_SIZE + RECORD_HEADER_SIZE + b.encode().len() + 4;
        writer.append(&all[..keep]).unwrap();

        let f = vfs.open_readonly("s_torn").unwrap();
        let mut reader = SegmentReader::open(f).unwrap();
        let mut got = Vec::new();
        let outcome = reader
            .replay(|v| {
                got.push(v);
                Ok(())
            })
            .unwrap();
        assert_eq!(got.len(), 1);
        assert!(matches!(outcome, ReplayOutcome::TornTail { .. }));
    }

    #[test]
    fn header_with_bad_magic_is_rejected() {
        let vfs = MemVfs::new();
        let mut f = vfs.open_writable("bad").unwrap();
        // 32 bytes of garbage that look nothing like a valid header.
        f.append(&[0xFFu8; 64]).unwrap();
        let r = vfs.open_readonly("bad").unwrap();
        let err = SegmentReader::open(r).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat { .. }));
    }

    #[test]
    fn header_with_bad_version_is_rejected() {
        let vfs = MemVfs::new();
        let mut h = SegmentHeader::new_signed(1, 0);
        // Bump version after signing; corrupts the magic-check before CRC.
        h.version = zerocopy::little_endian::U32::new(FORMAT_VERSION + 1);
        let mut f = vfs.open_writable("badv").unwrap();
        f.append(zerocopy::IntoBytes::as_bytes(&h)).unwrap();
        let r = vfs.open_readonly("badv").unwrap();
        let err = SegmentReader::open(r).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat { reason, .. } if reason.contains("version")));
    }

    #[test]
    fn header_with_bad_crc_is_corruption() {
        let vfs = MemVfs::new();
        let mut h = SegmentHeader::new_signed(1, 0);
        // Mutate segment_id after signing so CRC fails but magic/version are right.
        h.segment_id = zerocopy::little_endian::U64::new(99);
        let mut f = vfs.open_writable("badcrc").unwrap();
        f.append(zerocopy::IntoBytes::as_bytes(&h)).unwrap();
        let r = vfs.open_readonly("badcrc").unwrap();
        let err = SegmentReader::open(r).unwrap_err();
        assert!(matches!(err, Error::Corruption { .. }));
    }
}
