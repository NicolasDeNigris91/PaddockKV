//! Fuzz target — SSTable parser.
//!
//! Constructs a `BorrowedFile` from arbitrary bytes and asks
//! [`paddock_core::sstable::SstReader::open`] to make sense of them.
//! Random bytes will not be valid SSTables (footer magic / CRC will
//! almost always fail) but the parser must surface that as an `Error`,
//! never panic.
//!
//! The corpus is most useful when seeded with real SSTable bytes plus
//! random mutations.

#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

#[cfg(fuzzing)]
use paddock_core::sstable::SstReader;
#[cfg(fuzzing)]
use paddock_fuzz::BorrowedFile;

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    let file = BorrowedFile::new(data);
    if let Ok(reader) = SstReader::open(file) {
        // Lucky: a valid-looking SSTable. Exercise the read path on a
        // handful of arbitrary keys — none of which will be present, but
        // the lookup must still terminate cleanly.
        let probes: &[&[u8]] = &[b"", b"a", b"key", b"\xff\xff", b"random"];
        for k in probes {
            let _ = reader.get(k, u64::MAX);
        }
        let _ = reader.scan();
    }
});

#[cfg(not(fuzzing))]
fn main() {}
