//! Fuzz target — Bloom filter decode.
//!
//! `BlockedBloom::decode` is the only public way to reconstruct a filter
//! from on-disk bytes. Arbitrary inputs must surface as `Error`s, not
//! panics or out-of-bounds reads. Once a filter is decoded successfully
//! we also exercise `contains` to make sure no probe path triggers UB
//! on a small / malformed filter.

#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

#[cfg(fuzzing)]
use paddock_core::filter::BlockedBloom;

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    if let Ok(filter) = BlockedBloom::decode(data) {
        let probes: &[&[u8]] = &[b"", b"hello", b"\x00\x00\x00", b"\xff", b"some-key"];
        for k in probes {
            let _ = filter.contains(k);
        }
    }
});

#[cfg(not(fuzzing))]
fn main() {}
