//! K-way merge over sorted SSTable streams.
//!
//! Generic over any iterator that yields `Result<(Vec<u8>, LookupHit)>` in
//! `(key ascending, seqno descending)` order — typically
//! [`crate::sstable::SstStream`].
//!
//! Internally the merger maintains a binary min-heap keyed on
//! `(key, !seqno, source_index)`. When two streams have a record at the
//! same `(key, seqno)`, the **lower source index** wins; callers should
//! pass inputs **newest-first** so a tie always resolves toward the more
//! recent record.

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

use crate::error::Result;
use crate::sstable::LookupHit;

/// One pending record sitting in the heap, tagged with the source stream
/// index it came from.
#[derive(Debug, Clone)]
struct HeapEntry {
    key: Vec<u8>,
    seqno: u64,
    hit: LookupHit,
    source: usize,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for HeapEntry {}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Primary: key ascending.
        match self.key.cmp(&other.key) {
            Ordering::Equal => {}
            o => return o,
        }
        // Secondary: seqno descending (higher seqno wins among same-key).
        match other.seqno.cmp(&self.seqno) {
            Ordering::Equal => {}
            o => return o,
        }
        // Tertiary: source ascending (newer SSTable preferred on a tie,
        // since the caller passed inputs newest-first).
        self.source.cmp(&other.source)
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// K-way merger over `I` independent sorted streams.
pub struct KWayMerge<I>
where
    I: Iterator<Item = Result<(Vec<u8>, LookupHit)>>,
{
    streams: Vec<I>,
    heap: BinaryHeap<Reverse<HeapEntry>>,
    primed: bool,
}

impl<I> KWayMerge<I>
where
    I: Iterator<Item = Result<(Vec<u8>, LookupHit)>>,
{
    /// Build a merger from the given input streams. Caller is expected to
    /// have ordered the streams newest-first so duplicate `(key, seqno)`
    /// pairs (rare but possible across flushes) resolve toward the
    /// freshest copy.
    #[must_use]
    pub fn new(streams: Vec<I>) -> Self {
        Self {
            heap: BinaryHeap::with_capacity(streams.len()),
            streams,
            primed: false,
        }
    }

    /// Number of input streams.
    #[must_use]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::len is not yet const fn on stable"
    )]
    pub fn input_count(&self) -> usize {
        self.streams.len()
    }

    /// Initial fill of the heap from each stream's first element. Called
    /// lazily on the first `next` so construction is cheap.
    fn prime(&mut self) -> Result<()> {
        if self.primed {
            return Ok(());
        }
        for source in 0..self.streams.len() {
            self.advance(source)?;
        }
        self.primed = true;
        Ok(())
    }

    /// Pull the next record from `source` and push it onto the heap.
    /// `Ok(false)` when the source is exhausted.
    fn advance(&mut self, source: usize) -> Result<bool> {
        if let Some(item) = self.streams[source].next() {
            let (key, hit) = item?;
            self.heap.push(Reverse(HeapEntry {
                key,
                seqno: hit.seqno,
                hit,
                source,
            }));
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Pull the next merged record, or `Ok(None)` when every input is
    /// drained.
    pub fn next_record(&mut self) -> Result<Option<(Vec<u8>, LookupHit)>> {
        self.prime()?;
        let Some(Reverse(top)) = self.heap.pop() else {
            return Ok(None);
        };
        let source = top.source;
        // Advance the source that just lost its lead element so the heap
        // is ready for the next round.
        self.advance(source)?;
        Ok(Some((top.key, top.hit)))
    }
}

impl<I> Iterator for KWayMerge<I>
where
    I: Iterator<Item = Result<(Vec<u8>, LookupHit)>>,
{
    type Item = Result<(Vec<u8>, LookupHit)>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_record() {
            Ok(Some(rec)) => Some(Ok(rec)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl<I> std::fmt::Debug for KWayMerge<I>
where
    I: Iterator<Item = Result<(Vec<u8>, LookupHit)>>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KWayMerge")
            .field("inputs", &self.streams.len())
            .field("heap_len", &self.heap.len())
            .field("primed", &self.primed)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(
    clippy::uninlined_format_args,
    clippy::needless_collect,
    clippy::type_complexity,
    reason = "test fixtures favour readability over conciseness"
)]
mod tests {
    use super::*;
    use crate::sstable::format::RecordOp;

    /// Helper to build a synthetic stream from owned records — keeps the
    /// merger test independent of the SSTable byte format.
    fn stream(
        records: Vec<(&[u8], u64, &[u8])>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, LookupHit)>> {
        records.into_iter().map(|(k, s, v)| {
            Ok((
                k.to_vec(),
                LookupHit {
                    seqno: s,
                    op: RecordOp::Put,
                    value: v.to_vec(),
                },
            ))
        })
    }

    fn collect_keys<I>(m: KWayMerge<I>) -> Vec<(Vec<u8>, u64)>
    where
        I: Iterator<Item = Result<(Vec<u8>, LookupHit)>>,
    {
        m.map(|r| {
            let (k, h) = r.unwrap();
            (k, h.seqno)
        })
        .collect()
    }

    #[test]
    fn empty_merger_yields_nothing() {
        let streams: Vec<std::vec::IntoIter<Result<(Vec<u8>, LookupHit)>>> = Vec::new();
        let mut m = KWayMerge::new(streams);
        assert!(m.next_record().unwrap().is_none());
    }

    #[test]
    fn single_input_passes_through() {
        let s = stream(vec![(b"a", 1, b"1"), (b"b", 2, b"2"), (b"c", 3, b"3")])
            .collect::<Vec<_>>()
            .into_iter();
        let m = KWayMerge::new(vec![s]);
        let keys = collect_keys(m);
        assert_eq!(
            keys,
            vec![(b"a".to_vec(), 1), (b"b".to_vec(), 2), (b"c".to_vec(), 3)]
        );
    }

    #[test]
    fn two_disjoint_inputs_interleave_by_key() {
        let s1 = stream(vec![(b"a", 1, b""), (b"c", 3, b"")])
            .collect::<Vec<_>>()
            .into_iter();
        let s2 = stream(vec![(b"b", 2, b""), (b"d", 4, b"")])
            .collect::<Vec<_>>()
            .into_iter();
        let m = KWayMerge::new(vec![s1, s2]);
        let keys: Vec<_> = collect_keys(m).into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]
        );
    }

    #[test]
    fn same_key_different_seqnos_emerge_newest_first() {
        // Source 0 (newest): key=X with seqno=100
        // Source 1 (older):  key=X with seqno=50
        let s_new = stream(vec![(b"X", 100, b"new")])
            .collect::<Vec<_>>()
            .into_iter();
        let s_old = stream(vec![(b"X", 50, b"old")])
            .collect::<Vec<_>>()
            .into_iter();
        let m = KWayMerge::new(vec![s_new, s_old]);
        let order: Vec<_> = collect_keys(m).into_iter().map(|(_, s)| s).collect();
        assert_eq!(order, vec![100, 50]);
    }

    #[test]
    fn same_key_same_seqno_resolves_toward_lower_source_index() {
        // Both inputs claim (X, 7). The merger emits the one from source 0
        // first because the caller's convention is "newest first".
        let s_new = stream(vec![(b"X", 7, b"new")])
            .collect::<Vec<_>>()
            .into_iter();
        let s_old = stream(vec![(b"X", 7, b"old")])
            .collect::<Vec<_>>()
            .into_iter();
        let mut m = KWayMerge::new(vec![s_new, s_old]);
        let first = m.next_record().unwrap().unwrap();
        assert_eq!(first.1.value, b"new");
        let second = m.next_record().unwrap().unwrap();
        assert_eq!(second.1.value, b"old");
        assert!(m.next_record().unwrap().is_none());
    }

    #[test]
    fn large_interleaved_workload_emerges_globally_sorted() {
        // 4 streams, each 250 records, with overlapping key ranges.
        let mut streams = Vec::new();
        for shard in 0..4u32 {
            let recs: Vec<_> = (0..250u32)
                .map(|i| {
                    // Same set of keys across shards but different seqnos.
                    let key = format!("k-{:04}", i);
                    let seqno = u64::from(shard) * 1000 + u64::from(i);
                    let value = format!("s{shard}-i{i}");
                    (key.into_bytes(), seqno, value.into_bytes())
                })
                .collect();
            let stream_iter = recs
                .into_iter()
                .map(|(k, s, v)| {
                    Ok((
                        k,
                        LookupHit {
                            seqno: s,
                            op: RecordOp::Put,
                            value: v,
                        },
                    ))
                })
                .collect::<Vec<_>>()
                .into_iter();
            streams.push(stream_iter);
        }
        let m = KWayMerge::new(streams);
        let merged: Vec<_> = m.map(|r| r.unwrap()).collect();
        // Total: 4 * 250 = 1000 records.
        assert_eq!(merged.len(), 1000);
        // Verify global (key asc, seqno desc) ordering on every consecutive
        // pair.
        for w in merged.windows(2) {
            let (k1, h1) = &w[0];
            let (k2, h2) = &w[1];
            match k1.cmp(k2) {
                Ordering::Less => {}
                Ordering::Equal => {
                    assert!(h1.seqno >= h2.seqno, "seqno order broken at {k1:?}");
                }
                Ordering::Greater => panic!("key order broken: {k1:?} > {k2:?}"),
            }
        }
    }
}
