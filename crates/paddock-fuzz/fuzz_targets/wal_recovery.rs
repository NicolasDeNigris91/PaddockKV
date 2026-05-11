//! Fuzz target — WAL recovery.
//!
//! Feeds arbitrary bytes to [`paddock_core::wal::reader::SegmentReader`].
//! The contract: parsing must never panic. Bad magic, bad version, torn
//! tails, mid-block corruption — all must come back as either a
//! structured `Error` or a graceful clean / torn-tail outcome.

#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

#[cfg(fuzzing)]
use paddock_core::wal::reader::SegmentReader;
#[cfg(fuzzing)]
use paddock_fuzz::BorrowedFile;

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    let file = BorrowedFile::new(data);
    if let Ok(mut reader) = SegmentReader::open(file) {
        // Drain the segment. Loop bounded by file size so we cannot spin
        // forever on a corrupt cursor.
        let mut budget = 8 * 1024usize;
        while budget > 0 {
            budget -= 1;
            match reader.next_record() {
                Ok(paddock_core::wal::reader::ReadOutcome::Record(_)) => continue,
                Ok(_) | Err(_) => break,
            }
        }
    }
});

#[cfg(not(fuzzing))]
fn main() {
    // libFuzzer-less builds (e.g. on Windows) just verify the harness
    // links. The fuzzer body is only compiled under `cfg(fuzzing)` which
    // is set by `cargo-fuzz`.
}
