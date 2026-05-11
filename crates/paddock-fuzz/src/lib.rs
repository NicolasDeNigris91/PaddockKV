//! Shared helpers for fuzz targets.
//!
//! `cargo-fuzz` discovers each binary in `fuzz_targets/` independently. They
//! all link this lib so they can share a `MemVfs` setup helper without
//! duplicating boilerplate.
//!
//! The fuzz targets exercise every external attack surface the engine has:
//!
//! - `wal_recovery`        — feed arbitrary bytes to [`paddock_core::wal::reader::SegmentReader`]
//!   and assert it never panics. CRC errors, length-overflow records, torn
//!   tails, mid-block corruption — all must surface as either an `Error`
//!   or a graceful end-of-segment.
//! - `sstable_parse`       — pad arbitrary bytes to look like an SSTable
//!   (file header + footer slots) and feed them to
//!   [`paddock_core::sstable::SstReader::open`]. Same panic-freedom
//!   contract.
//! - `bloom_decode`        — bytes ➜ [`paddock_core::filter::BlockedBloom::decode`].
//! - `writebatch_decode`   — bytes ➜ [`paddock_core::wal::batch::WriteBatch::decode`].
//!
//! Run any target locally on Linux with:
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_wal_recovery
//! ```
//!
//! On Windows the targets compile (`cargo build -p paddock-fuzz`) to verify
//! the harness still links; actual fuzzing requires libFuzzer, which is
//! Linux/macOS only.

use std::sync::Arc;
use std::sync::Mutex;

use paddock_core::error::Result as PaddockResult;
use paddock_core::io::vfs::{Vfs, VfsFile};

/// One-shot read-only file backed by a borrowed byte slice. Used by
/// fuzz targets that want to feed arbitrary bytes into an SSTable parser
/// without going through the `MemVfs` lock dance.
#[derive(Debug, Clone)]
pub struct BorrowedFile {
    bytes: Arc<Vec<u8>>,
}

impl BorrowedFile {
    /// Construct from a byte slice.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: Arc::new(bytes.to_vec()),
        }
    }
}

impl VfsFile for BorrowedFile {
    fn append(&mut self, _data: &[u8]) -> PaddockResult<u64> {
        Err(paddock_core::error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "BorrowedFile is read-only",
        )))
    }

    fn write_at(&mut self, _data: &[u8], _offset: u64) -> PaddockResult<()> {
        Err(paddock_core::error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "BorrowedFile is read-only",
        )))
    }

    fn sync(&mut self) -> PaddockResult<()> {
        Ok(())
    }

    fn read_at(&self, buf: &mut [u8], offset: u64) -> PaddockResult<()> {
        let off = usize::try_from(offset).map_err(|_| {
            paddock_core::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "offset overflow",
            ))
        })?;
        let end = off.checked_add(buf.len()).ok_or_else(|| {
            paddock_core::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "offset + length overflow",
            ))
        })?;
        if end > self.bytes.len() {
            return Err(paddock_core::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "BorrowedFile: short read",
            )));
        }
        buf.copy_from_slice(&self.bytes[off..end]);
        Ok(())
    }

    fn size(&self) -> PaddockResult<u64> {
        Ok(self.bytes.len() as u64)
    }
}

/// `Vfs` that hands out a single read-only file backed by some bytes.
#[derive(Debug, Clone)]
pub struct OneFileVfs {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl OneFileVfs {
    /// Wrap `bytes` so a Vfs caller asking for `"/file"` reads them.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            inner: Arc::new(Mutex::new(bytes.to_vec())),
        }
    }
}

impl Vfs for OneFileVfs {
    type File = BorrowedFile;

    fn open_writable(&self, _path: &str) -> PaddockResult<Self::File> {
        Err(paddock_core::error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "OneFileVfs is read-only",
        )))
    }

    fn open_readonly(&self, _path: &str) -> PaddockResult<Self::File> {
        let bytes = self.inner.lock().expect("OneFileVfs lock poisoned");
        let snap = bytes.clone();
        drop(bytes);
        Ok(BorrowedFile {
            bytes: Arc::new(snap),
        })
    }

    fn rename(&self, _from: &str, _to: &str) -> PaddockResult<()> {
        Ok(())
    }

    fn remove(&self, _path: &str) -> PaddockResult<()> {
        Ok(())
    }

    fn list(&self, _dir: &str) -> PaddockResult<Vec<String>> {
        Ok(Vec::new())
    }
}
