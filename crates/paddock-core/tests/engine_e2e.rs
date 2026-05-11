//! End-to-end engine tests.
//!
//! Exercises the public [`Db`] surface as an outside caller would: open,
//! mix writes/reads, force flushes to drive records through the SSTable
//! path, take snapshots before mutations, simulate a clean shutdown plus
//! reopen, and assert the engine returns coherent answers throughout.

#![allow(clippy::missing_docs_in_private_items)]

use paddock_core::Db;
use paddock_core::io::vfs::MemVfs;
use paddock_core::wal::batch::WriteBatch;

fn open() -> (MemVfs, Db<MemVfs>) {
    let vfs = MemVfs::new();
    let db = Db::open(vfs.clone(), "/db").expect("open");
    (vfs, db)
}

#[test]
fn writes_survive_repeated_reopen_cycles() {
    let vfs = MemVfs::new();
    // Round 0: install an immutable record `first=hello` and the initial
    // value of the mutable key `second=world`.
    {
        let db = Db::open(vfs.clone(), "/db").unwrap();
        db.put(b"first", b"hello").unwrap();
        db.put(b"second", b"world").unwrap();
        db.flush().unwrap();
    }
    // Subsequent rounds: reopen, observe the immutable record and whatever
    // `second` was last set to, then advance `second` and flush.
    let mut expected_second = b"world".to_vec();
    for round in 0..4u32 {
        let db = Db::open(vfs.clone(), "/db").unwrap();
        assert_eq!(db.get(b"first").unwrap(), Some(b"hello".to_vec()));
        assert_eq!(db.get(b"second").unwrap(), Some(expected_second.clone()));
        let next = format!("v-{round}");
        db.put(b"second", next.as_bytes()).unwrap();
        db.flush().unwrap();
        expected_second = next.into_bytes();
    }
    let db = Db::open(vfs, "/db").unwrap();
    assert_eq!(db.get(b"first").unwrap(), Some(b"hello".to_vec()));
    assert_eq!(db.get(b"second").unwrap(), Some(b"v-3".to_vec()));
}

#[test]
fn batch_write_is_atomic_across_keys() {
    let (_vfs, db) = open();
    let mut batch = WriteBatch::new();
    batch.put(b"k1".to_vec(), b"v1".to_vec());
    batch.put(b"k2".to_vec(), b"v2".to_vec());
    batch.delete(b"k3".to_vec());
    db.write_batch(&batch).unwrap();
    assert_eq!(db.get(b"k1").unwrap(), Some(b"v1".to_vec()));
    assert_eq!(db.get(b"k2").unwrap(), Some(b"v2".to_vec()));
    assert_eq!(db.get(b"k3").unwrap(), None);
}

#[test]
fn snapshots_remain_stable_across_flush() {
    let (_vfs, db) = open();
    db.put(b"k", b"v0").unwrap();
    let snap = db.snapshot();

    // Drive the value through a flush boundary.
    db.put(b"k", b"v1").unwrap();
    db.flush().unwrap();
    db.put(b"k", b"v2").unwrap();
    db.flush().unwrap();

    // The snapshot's seqno still points at the original write, so even
    // though that value now lives in an SSTable beneath two newer ones,
    // `get_at(snap)` must still resolve it.
    assert_eq!(db.get_at(b"k", snap).unwrap(), Some(b"v0".to_vec()));
    assert_eq!(db.get(b"k").unwrap(), Some(b"v2".to_vec()));
}

#[test]
fn large_workload_traverses_many_sstables() {
    let (_vfs, db) = open();
    // Force frequent rotations.
    let n_writes = 5_000u32;
    let chunk = 250;
    for chunk_idx in 0..(n_writes / chunk) {
        for i in 0..chunk {
            let k = format!("k-{chunk_idx:03}-{i:04}");
            let v = format!("v-{chunk_idx:03}-{i:04}");
            db.put(k.as_bytes(), v.as_bytes()).unwrap();
        }
        db.flush().unwrap();
    }
    assert!(db.sstable_count() >= 1);

    // Sample 100 keys from across the workload.
    let mut sampled = 0;
    for chunk_idx in 0..(n_writes / chunk) {
        for &i in &[0u32, 7, 42, 99, 200] {
            let k = format!("k-{chunk_idx:03}-{i:04}");
            let v = format!("v-{chunk_idx:03}-{i:04}");
            assert_eq!(
                db.get(k.as_bytes()).unwrap(),
                Some(v.into_bytes()),
                "miss at {k}"
            );
            sampled += 1;
        }
    }
    assert_eq!(sampled, 100);
}

#[test]
fn missing_keys_report_none() {
    let (_vfs, db) = open();
    for i in 0..200u32 {
        db.put(format!("k-{i:05}").as_bytes(), b"v").unwrap();
    }
    db.flush().unwrap();
    for i in 0..50u32 {
        let absent = format!("nope-{i:05}");
        assert!(db.get(absent.as_bytes()).unwrap().is_none());
    }
}

#[test]
fn compact_all_reduces_sstable_count_to_one() {
    let (_vfs, db) = open();
    for chunk in 0..5u32 {
        for i in 0..40u32 {
            let k = format!("k-{chunk}-{i:03}");
            db.put(k.as_bytes(), b"v").unwrap();
        }
        db.flush().unwrap();
    }
    assert_eq!(db.sstable_count(), 5);
    db.compact_all().unwrap();
    assert_eq!(db.sstable_count(), 1);
    // Every record still resolves.
    for chunk in 0..5u32 {
        for i in 0..40u32 {
            let k = format!("k-{chunk}-{i:03}");
            assert_eq!(db.get(k.as_bytes()).unwrap(), Some(b"v".to_vec()));
        }
    }
}

#[test]
fn compact_all_preserves_newest_value_on_duplicate_keys() {
    let (_vfs, db) = open();
    db.put(b"k", b"v0").unwrap();
    db.flush().unwrap();
    db.put(b"k", b"v1").unwrap();
    db.flush().unwrap();
    db.put(b"k", b"v2").unwrap();
    db.flush().unwrap();
    assert_eq!(db.sstable_count(), 3);
    db.compact_all().unwrap();
    assert_eq!(db.sstable_count(), 1);
    assert_eq!(db.get(b"k").unwrap(), Some(b"v2".to_vec()));
}

#[test]
fn compact_all_preserves_tombstones() {
    let (_vfs, db) = open();
    db.put(b"alive", b"v").unwrap();
    db.put(b"dead", b"v").unwrap();
    db.flush().unwrap();
    db.delete(b"dead").unwrap();
    db.flush().unwrap();
    assert_eq!(db.sstable_count(), 2);
    db.compact_all().unwrap();
    assert_eq!(db.sstable_count(), 1);
    assert_eq!(db.get(b"alive").unwrap(), Some(b"v".to_vec()));
    assert_eq!(db.get(b"dead").unwrap(), None);
}

#[test]
fn compact_all_is_a_noop_when_only_one_sstable_exists() {
    let (_vfs, db) = open();
    db.put(b"k", b"v").unwrap();
    db.flush().unwrap();
    assert_eq!(db.sstable_count(), 1);
    db.compact_all().unwrap();
    assert_eq!(db.sstable_count(), 1);
    assert_eq!(db.get(b"k").unwrap(), Some(b"v".to_vec()));
}

#[test]
fn compact_all_survives_subsequent_reopen() {
    let vfs = MemVfs::new();
    {
        let db = Db::open(vfs.clone(), "/db").unwrap();
        for round in 0..4u32 {
            for i in 0..50u32 {
                db.put(format!("k-{round}-{i:03}").as_bytes(), b"v")
                    .unwrap();
            }
            db.flush().unwrap();
        }
        db.compact_all().unwrap();
        assert_eq!(db.sstable_count(), 1);
    }
    // Reopen.
    let db = Db::open(vfs, "/db").unwrap();
    assert_eq!(db.sstable_count(), 1);
    for round in 0..4u32 {
        for i in 0..50u32 {
            let k = format!("k-{round}-{i:03}");
            assert_eq!(db.get(k.as_bytes()).unwrap(), Some(b"v".to_vec()));
        }
    }
}

#[test]
fn tombstones_survive_through_multiple_flush_rounds() {
    let (_vfs, db) = open();
    for i in 0..30u32 {
        db.put(format!("k-{i:03}").as_bytes(), b"value").unwrap();
    }
    db.flush().unwrap();
    for i in (0..30u32).step_by(2) {
        db.delete(format!("k-{i:03}").as_bytes()).unwrap();
    }
    db.flush().unwrap();
    for i in 0..30u32 {
        let k = format!("k-{i:03}");
        let res = db.get(k.as_bytes()).unwrap();
        if i % 2 == 0 {
            assert!(res.is_none(), "expected tombstone for {k}");
        } else {
            assert_eq!(res, Some(b"value".to_vec()), "expected value for {k}");
        }
    }
}
