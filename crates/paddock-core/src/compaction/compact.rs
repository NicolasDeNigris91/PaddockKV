//! High-level compaction primitive: merge N SSTables into one.
//!
//! [`compact_sstables`] is the building block the engine wraps for both
//! manual and auto-triggered compaction. It is intentionally generic over
//! the [`crate::io::vfs::Vfs`]: the same code path drives MemVfs in tests
//! and a Linux VFS in production.

use std::sync::Arc;

use crate::checksum::Algorithm;
use crate::compaction::merger::KWayMerge;
use crate::crypto::aead::AeadKey;
use crate::error::Result;
use crate::filter::BloomParams;
use crate::io::vfs::Vfs;
use crate::sstable::reader::SstStream;
use crate::sstable::{SstReader, SstWriter};

/// Tunables for one invocation of [`compact_sstables`].
#[derive(Debug)]
pub struct CompactionConfig<'a> {
    /// Bloom parameters for the output SSTable.
    pub bloom: BloomParams,
    /// Output SSTable's Bloom filter capacity hint. The compactor picks
    /// `max(this, sum_of_inputs_num_entries)` automatically; this is the
    /// floor.
    pub bloom_capacity_floor: usize,
    /// Output SSTable's block-checksum algorithm.
    pub checksum: Algorithm,
    /// When `Some`, the merged output is encrypted with this per-SSTable
    /// AEAD key (typically derived from the engine's master key + the new
    /// SSTable's file id). The supplied `output_sstable_id` is bound into
    /// every block's AAD.
    pub encryption: Option<(&'a AeadKey, u64)>,
}

impl Default for CompactionConfig<'_> {
    fn default() -> Self {
        Self {
            bloom: BloomParams::default(),
            bloom_capacity_floor: 1024,
            checksum: Algorithm::Crc32c,
            encryption: None,
        }
    }
}

/// Merge `inputs` (already newest-first) into a single SSTable at
/// `output_path`. Returns the freshly-opened reader on the new file plus
/// the number of records emitted.
///
/// The merge preserves every `(key, seqno)` pair from the inputs. Version
/// pruning and bottom-level tombstone elision are explicit non-goals for
/// Phase 7 — they require snapshot tracking that lands in Phase 7b.
pub fn compact_sstables<V: Vfs>(
    vfs: &V,
    inputs: &[Arc<SstReader<V::File>>],
    output_path: &str,
    config: &CompactionConfig<'_>,
) -> Result<CompactionOutput<V>> {
    // Stream every input.
    let mut streams: Vec<SstStream<V::File>> = Vec::with_capacity(inputs.len());
    for sst in inputs {
        streams.push(sst.scan_stream()?);
    }

    // Bloom capacity: sum the input filters' key counts as a tight upper
    // bound on the merged-record count. (We may emit slightly fewer if
    // Phase 7b ever enables version pruning; over-sizing the Bloom is
    // cheap.)
    let bloom_capacity = config
        .bloom_capacity_floor
        .max(estimate_total_entries::<V>(inputs));

    let writer_file = vfs.open_writable(output_path)?;
    let mut writer = match config.encryption {
        Some((key, sst_id)) => SstWriter::create_encrypted(
            writer_file,
            config.checksum,
            bloom_capacity,
            config.bloom,
            key,
            sst_id,
        )?,
        None => SstWriter::create_with_filter_capacity(
            writer_file,
            config.checksum,
            bloom_capacity,
            config.bloom,
        )?,
    };

    let mut merger = KWayMerge::new(streams);
    let mut emitted: u64 = 0;
    while let Some((key, hit)) = merger.next_record()? {
        writer.add(&key, &hit.value, hit.seqno, hit.op)?;
        emitted += 1;
    }
    let _file = writer.finish()?;

    // Re-open the produced SSTable for the read side, matching whatever
    // encryption mode the writer used.
    let reader = match config.encryption {
        Some((key, sst_id)) => {
            SstReader::open_encrypted(vfs.open_readonly(output_path)?, key, sst_id)?
        }
        None => SstReader::open(vfs.open_readonly(output_path)?)?,
    };

    Ok(CompactionOutput {
        reader: Arc::new(reader),
        records_emitted: emitted,
    })
}

/// Result of one compaction run.
#[derive(Debug)]
pub struct CompactionOutput<V: Vfs> {
    /// Reader on the freshly-written merged SSTable.
    pub reader: Arc<SstReader<V::File>>,
    /// Number of records emitted into the output.
    pub records_emitted: u64,
}

fn estimate_total_entries<V: Vfs>(inputs: &[Arc<SstReader<V::File>>]) -> usize {
    // The file header carries num_entries (Phase 6 will back-fill it; for
    // now it is zero, so we fall back to a coarse linear estimate based on
    // index-block size). Either way the bloom is cheap enough that small
    // mis-sizing is fine.
    let mut sum: usize = 0;
    for sst in inputs {
        let entries = sst.footer().index_handle.length.get() as usize;
        sum = sum.saturating_add(entries);
    }
    sum.max(1024)
}

#[cfg(test)]
#[allow(clippy::uninlined_format_args, reason = "test fixtures")]
mod tests {
    use super::*;
    use crate::io::vfs::{MemVfs, Vfs};
    use crate::sstable::SstWriter;
    use crate::sstable::format::RecordOp;

    fn build_table(vfs: &MemVfs, path: &str, records: &[(&[u8], &[u8], u64, RecordOp)]) {
        let file = vfs.open_writable(path).unwrap();
        let mut w = SstWriter::create(file, Algorithm::Crc32c).unwrap();
        for (k, v, s, op) in records {
            w.add(k, v, *s, *op).unwrap();
        }
        let _ = w.finish().unwrap();
    }

    fn read_all<V: Vfs>(sst: &Arc<SstReader<V::File>>) -> Vec<(Vec<u8>, u64, RecordOp, Vec<u8>)> {
        sst.scan()
            .unwrap()
            .into_iter()
            .map(|(k, h)| (k, h.seqno, h.op, h.value))
            .collect()
    }

    #[test]
    fn compacts_two_disjoint_tables_into_one() {
        let vfs = MemVfs::new();
        build_table(
            &vfs,
            "a.sst",
            &[
                (b"alpha", b"1", 1, RecordOp::Put),
                (b"bravo", b"2", 2, RecordOp::Put),
            ],
        );
        build_table(
            &vfs,
            "b.sst",
            &[
                (b"charlie", b"3", 3, RecordOp::Put),
                (b"delta", b"4", 4, RecordOp::Put),
            ],
        );
        let r_a = Arc::new(SstReader::open(vfs.open_readonly("a.sst").unwrap()).unwrap());
        let r_b = Arc::new(SstReader::open(vfs.open_readonly("b.sst").unwrap()).unwrap());

        let out = compact_sstables(
            &vfs,
            // Newer first: b is "newer".
            &[r_b, r_a],
            "merged.sst",
            &CompactionConfig::default(),
        )
        .unwrap();
        assert_eq!(out.records_emitted, 4);

        let records = read_all::<MemVfs>(&out.reader);
        let keys: Vec<_> = records.iter().map(|r| r.0.clone()).collect();
        assert_eq!(
            keys,
            vec![
                b"alpha".to_vec(),
                b"bravo".to_vec(),
                b"charlie".to_vec(),
                b"delta".to_vec(),
            ]
        );
    }

    #[test]
    fn duplicate_keys_appear_in_newest_first_order() {
        let vfs = MemVfs::new();
        // Newer SSTable
        build_table(&vfs, "new.sst", &[(b"k", b"new", 100, RecordOp::Put)]);
        // Older SSTable
        build_table(&vfs, "old.sst", &[(b"k", b"old", 50, RecordOp::Put)]);
        let r_new = Arc::new(SstReader::open(vfs.open_readonly("new.sst").unwrap()).unwrap());
        let r_old = Arc::new(SstReader::open(vfs.open_readonly("old.sst").unwrap()).unwrap());

        let out = compact_sstables(
            &vfs,
            &[r_new, r_old],
            "merged.sst",
            &CompactionConfig::default(),
        )
        .unwrap();
        assert_eq!(out.records_emitted, 2);

        // Phase 7 keeps every version. Newest first means seqno 100 comes
        // before seqno 50.
        let records = read_all::<MemVfs>(&out.reader);
        assert_eq!(records[0].1, 100);
        assert_eq!(records[0].3, b"new".to_vec());
        assert_eq!(records[1].1, 50);
        assert_eq!(records[1].3, b"old".to_vec());
    }

    #[test]
    fn point_lookup_via_merged_reader_finds_newest_version() {
        let vfs = MemVfs::new();
        build_table(&vfs, "new.sst", &[(b"k", b"new", 100, RecordOp::Put)]);
        build_table(&vfs, "old.sst", &[(b"k", b"old", 50, RecordOp::Put)]);
        let r_new = Arc::new(SstReader::open(vfs.open_readonly("new.sst").unwrap()).unwrap());
        let r_old = Arc::new(SstReader::open(vfs.open_readonly("old.sst").unwrap()).unwrap());
        let out =
            compact_sstables(&vfs, &[r_new, r_old], "m.sst", &CompactionConfig::default()).unwrap();
        // `get` skips records whose seqno > snapshot; with u64::MAX it
        // takes the freshest one.
        let hit = out.reader.get(b"k", u64::MAX).unwrap().unwrap();
        assert_eq!(hit.value, b"new".to_vec());
        assert_eq!(hit.seqno, 100);
    }

    #[test]
    fn large_compaction_preserves_ordering_and_count() {
        let vfs = MemVfs::new();
        // Build 5 tables, each 200 records, with overlapping keys.
        let mut readers = Vec::new();
        for shard in 0..5u32 {
            let path = format!("shard-{shard}.sst");
            let file = vfs.open_writable(&path).unwrap();
            let mut w = SstWriter::create(file, Algorithm::Crc32c).unwrap();
            for i in 0..200u32 {
                let k = format!("k-{:04}", i);
                let v = format!("s{shard}-v{i}");
                let seqno = u64::from(shard) * 1000 + u64::from(i);
                w.add(k.as_bytes(), v.as_bytes(), seqno, RecordOp::Put)
                    .unwrap();
            }
            let _ = w.finish().unwrap();
            readers.push(Arc::new(
                SstReader::open(vfs.open_readonly(&path).unwrap()).unwrap(),
            ));
        }
        // Caller's convention: newest first. We declared shard 4 as
        // newest (highest seqno), shard 0 as oldest.
        readers.reverse();

        let out = compact_sstables(&vfs, &readers, "m.sst", &CompactionConfig::default()).unwrap();
        assert_eq!(out.records_emitted, 5 * 200);

        let records = read_all::<MemVfs>(&out.reader);
        // Verify global ordering.
        for w in records.windows(2) {
            let (k1, s1, _, _) = &w[0];
            let (k2, s2, _, _) = &w[1];
            match k1.cmp(k2) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => assert!(s1 >= s2),
                std::cmp::Ordering::Greater => panic!("key order broken"),
            }
        }
    }
}
