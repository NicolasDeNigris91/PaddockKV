//! Fuzz target — WriteBatch decode.
//!
//! The WAL replay path runs `WriteBatch::decode` on every record payload.
//! A maliciously crafted record could try to make the decoder allocate
//! gigabytes (via a giant op_count or key_len) or panic via integer
//! overflow. Both are bounded by the explicit checks in
//! `paddock_core::wal::batch::WriteBatch::decode`; the fuzzer enforces
//! that those checks remain panic-free.

#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

#[cfg(fuzzing)]
use paddock_core::wal::batch::WriteBatch;

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    if let Ok(batch) = WriteBatch::decode(data) {
        // Sanity: a successfully-decoded batch must round-trip back to
        // bytes whose decode again yields the same logical batch.
        let bytes = batch.encode();
        let again = WriteBatch::decode(&bytes).expect("re-decode of self-encoded batch");
        assert_eq!(batch, again);
    }
});

#[cfg(not(fuzzing))]
fn main() {}
