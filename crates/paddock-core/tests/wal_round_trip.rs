//! End-to-end WAL property test: any sequence of [`WriteBatch`]es that we
//! write to a segment must replay back identically.
//!
//! This sits in the integration-test directory so it exercises only the
//! crate's public API. Property tests live here too because they are slow
//! enough to benefit from the integration-test compile cache and because
//! their failure mode is "the engine is broken end-to-end" rather than "this
//! one module has a unit bug."

#![allow(clippy::missing_docs_in_private_items)]

use paddock_core::io::vfs::{MemVfs, Vfs};
use paddock_core::wal::batch::{Op, WriteBatch};
use paddock_core::wal::reader::{ReadOutcome, ReplayOutcome, SegmentReader};
use paddock_core::wal::writer::SegmentWriter;
use proptest::collection::vec;
use proptest::prelude::*;

fn op_strategy() -> impl Strategy<Value = Op> {
    let key = vec(any::<u8>(), 0..48);
    let value = vec(any::<u8>(), 0..200);
    prop_oneof![
        (key.clone(), value).prop_map(|(k, v)| Op::Put { key: k, value: v }),
        key.prop_map(|k| Op::Delete { key: k }),
    ]
}

fn batch_strategy() -> impl Strategy<Value = WriteBatch> {
    vec(op_strategy(), 0..16).prop_map(|ops| {
        let mut b = WriteBatch::new();
        for op in ops {
            match op {
                Op::Put { key, value } => {
                    b.put(key, value);
                }
                Op::Delete { key } => {
                    b.delete(key);
                }
            }
        }
        b
    })
}

fn run_round_trip(batches: &[WriteBatch]) {
    let vfs = MemVfs::new();
    let file = vfs.open_writable("wal").unwrap();
    let mut writer = SegmentWriter::create(file, 1, 100).unwrap();
    for (i, batch) in batches.iter().enumerate() {
        writer
            .append_record(100 + i as u64, &batch.encode())
            .expect("append");
    }

    let reader_file = vfs.open_readonly("wal").unwrap();
    let mut reader = SegmentReader::open(reader_file).unwrap();
    for (i, batch) in batches.iter().enumerate() {
        match reader.next_record().unwrap() {
            ReadOutcome::Record(view) => {
                assert_eq!(view.seqno, 100 + i as u64, "seqno mismatch at index {i}");
                let decoded = WriteBatch::decode(&view.payload).expect("decode");
                assert_eq!(decoded, *batch, "batch mismatch at index {i}");
            }
            other => panic!("expected Record, got {other:?}"),
        }
    }
    match reader.next_record().unwrap() {
        ReadOutcome::EndOfSegment => {}
        other => panic!("expected EndOfSegment, got {other:?}"),
    }
}

#[test]
fn fixed_round_trip_small_set() {
    let mut a = WriteBatch::new();
    a.put(b"a".to_vec(), b"1".to_vec());
    let mut b = WriteBatch::new();
    b.delete(b"x".to_vec());
    let mut c = WriteBatch::new();
    c.put(b"big".to_vec(), vec![0xCD; 50_000]); // forces fragmentation
    run_round_trip(&[a, b, c]);
}

proptest! {
    #[test]
    fn prop_any_batch_sequence_round_trips(batches in vec(batch_strategy(), 0..32)) {
        run_round_trip(&batches);
    }

    #[test]
    fn prop_replay_returns_clean_outcome(batches in vec(batch_strategy(), 0..16)) {
        let vfs = MemVfs::new();
        let file = vfs.open_writable("wal").unwrap();
        let mut writer = SegmentWriter::create(file, 1, 0).unwrap();
        for (i, b) in batches.iter().enumerate() {
            writer.append_record(i as u64, &b.encode()).unwrap();
        }
        let reader_file = vfs.open_readonly("wal").unwrap();
        let mut reader = SegmentReader::open(reader_file).unwrap();
        let mut seen = 0;
        let outcome = reader
            .replay(|_| { seen += 1; Ok(()) })
            .unwrap();
        prop_assert_eq!(seen, batches.len());
        prop_assert!(matches!(outcome, ReplayOutcome::Clean));
    }
}
