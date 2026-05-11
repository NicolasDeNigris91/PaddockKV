//! Virtual file-system trait — the testing seam for I/O.
//!
//! Higher-level engine modules (WAL writer, SSTable reader, compaction) are
//! written against [`Vfs`] rather than directly against `libc` / `io_uring`.
//! Two implementations exist:
//!
//! - [`MemVfs`] — in-memory, used by unit tests. Lives here so that every
//!   higher-level test gets it for free.
//! - `LinuxVfs` (in [`crate::io::direct`]) — production, hooked to `O_DIRECT`
//!   and `io_uring`. Available only on Linux.
//!
//! The trait is intentionally minimal: open, append, sync, read at an offset,
//! truncate, list, remove. Anything fancier (`io_uring` SQE batching, mmap
//! regions) is exposed by concrete types directly, not through the trait —
//! abstracting those would defeat the purpose of using them.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

use crate::error::Result;

/// Read/write seek mode is never needed; the engine always knows its offsets.
/// The trait therefore exposes positional I/O only.
pub trait Vfs: Send + Sync {
    /// File handle type returned by [`open_writable`](Vfs::open_writable) and
    /// [`open_readonly`](Vfs::open_readonly). It is intentionally opaque so
    /// production implementations can carry a libc fd, a mapped region, an
    /// `io_uring` registered fd index, etc.
    type File: VfsFile;

    /// Open a file for append-only writes. Created if it does not exist.
    fn open_writable(&self, path: &str) -> Result<Self::File>;

    /// Open a file for positional read-only access.
    fn open_readonly(&self, path: &str) -> Result<Self::File>;

    /// Atomically rename `from` to `to`. Required for atomic publish of newly
    /// written SSTables and manifest versions.
    fn rename(&self, from: &str, to: &str) -> Result<()>;

    /// Remove a file. Idempotent: removing a missing file is not an error.
    fn remove(&self, path: &str) -> Result<()>;

    /// List entries inside `dir`. Order is unspecified.
    fn list(&self, dir: &str) -> Result<Vec<String>>;
}

/// File handle behaviour expected by engine code. Implementations are free to
/// add inherent methods on top (e.g. `O_DIRECT`-specific aligned reads).
///
/// `Send + Sync + 'static` lets the engine ship file handles into
/// background threads (Phase 11 flush/compaction workers) and into
/// streaming iterators that need a thread-safe `Arc<File>` underneath.
pub trait VfsFile: Send + Sync + 'static {
    /// Append `data` to the file. Returns the offset at which the write
    /// landed.
    fn append(&mut self, data: &[u8]) -> Result<u64>;

    /// Overwrite the bytes at `[offset, offset + data.len())` in place.
    /// The range must already lie within the file: this method never
    /// extends the file. Use [`append`](Self::append) for that.
    ///
    /// Production implementations map this onto `pwrite(2)`; the test
    /// `MemFile` mutates its backing `Vec<u8>` directly.
    fn write_at(&mut self, data: &[u8], offset: u64) -> Result<()>;

    /// Fsync the underlying file data + metadata. Production implementations
    /// should prefer `fdatasync` and expose that as a separate inherent
    /// method; this trait method is the safe default for tests.
    fn sync(&mut self) -> Result<()>;

    /// Read `buf.len()` bytes starting at `offset`. Short reads are an error.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<()>;

    /// Logical size of the file in bytes.
    fn size(&self) -> Result<u64>;
}

// ----- In-memory implementation -----

/// In-memory `Vfs` for unit tests.
///
/// Files are stored as `Vec<u8>`. Cloning the `MemVfs` shares the same
/// underlying file table — useful when an engine module needs to hand the VFS
/// to multiple subsystems.
#[derive(Debug, Clone, Default)]
pub struct MemVfs {
    inner: Arc<Mutex<MemVfsInner>>,
}

#[derive(Debug, Default)]
struct MemVfsInner {
    files: BTreeMap<String, Arc<Mutex<Vec<u8>>>>,
}

impl MemVfs {
    /// Construct an empty in-memory file system.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Vfs for MemVfs {
    type File = MemFile;

    fn open_writable(&self, path: &str) -> Result<Self::File> {
        let bytes = {
            let mut inner = self.inner.lock().expect("MemVfs lock poisoned");
            inner
                .files
                .entry(path.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(Vec::new())))
                .clone()
        };
        Ok(MemFile { bytes })
    }

    fn open_readonly(&self, path: &str) -> Result<Self::File> {
        let bytes = {
            let inner = self.inner.lock().expect("MemVfs lock poisoned");
            inner.files.get(path).cloned()
        };
        let bytes = bytes.ok_or_else(|| {
            crate::error::Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("MemVfs: missing file '{path}'"),
            ))
        })?;
        Ok(MemFile { bytes })
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        let mut inner = self.inner.lock().expect("MemVfs lock poisoned");
        let bytes = inner.files.remove(from).ok_or_else(|| {
            crate::error::Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("MemVfs: rename source '{from}' missing"),
            ))
        })?;
        inner.files.insert(to.to_owned(), bytes);
        drop(inner);
        Ok(())
    }

    fn remove(&self, path: &str) -> Result<()> {
        self.inner
            .lock()
            .expect("MemVfs lock poisoned")
            .files
            .remove(path);
        Ok(())
    }

    fn list(&self, dir: &str) -> Result<Vec<String>> {
        let prefix = if dir.ends_with('/') {
            dir.to_owned()
        } else {
            format!("{dir}/")
        };
        let names = {
            let inner = self.inner.lock().expect("MemVfs lock poisoned");
            inner
                .files
                .keys()
                .filter_map(|k| k.strip_prefix(&prefix).map(str::to_owned))
                .filter(|k| !k.contains('/'))
                .collect()
        };
        Ok(names)
    }
}

/// File handle returned by [`MemVfs`].
#[derive(Debug, Clone)]
pub struct MemFile {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl VfsFile for MemFile {
    fn append(&mut self, data: &[u8]) -> Result<u64> {
        let mut bytes = self.bytes.lock().expect("MemFile lock poisoned");
        let offset = bytes.len() as u64;
        bytes.extend_from_slice(data);
        drop(bytes);
        Ok(offset)
    }

    fn write_at(&mut self, data: &[u8], offset: u64) -> Result<()> {
        let off = usize::try_from(offset).map_err(|_| {
            crate::error::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MemFile: offset overflow",
            ))
        })?;
        let end = off.checked_add(data.len()).ok_or_else(|| {
            crate::error::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MemFile: offset + length overflow",
            ))
        })?;
        let mut bytes = self.bytes.lock().expect("MemFile lock poisoned");
        if end > bytes.len() {
            return Err(crate::error::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MemFile::write_at: range extends past file end",
            )));
        }
        bytes[off..end].copy_from_slice(data);
        drop(bytes);
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        Ok(())
    }

    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        let off = usize::try_from(offset).map_err(|_| {
            crate::error::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MemFile: offset overflow",
            ))
        })?;
        let end = off.checked_add(buf.len()).ok_or_else(|| {
            crate::error::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MemFile: offset + length overflow",
            ))
        })?;
        let bytes = self.bytes.lock().expect("MemFile lock poisoned");
        if end > bytes.len() {
            return Err(crate::error::Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "MemFile: short read",
            )));
        }
        buf.copy_from_slice(&bytes[off..end]);
        drop(bytes);
        Ok(())
    }

    fn size(&self) -> Result<u64> {
        Ok(self.bytes.lock().expect("MemFile lock poisoned").len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_then_read_round_trips() {
        let vfs = MemVfs::new();
        let mut f = vfs.open_writable("/wal/000001.log").unwrap();
        let off_a = f.append(b"hello").unwrap();
        let off_b = f.append(b" world").unwrap();
        assert_eq!(off_a, 0);
        assert_eq!(off_b, 5);
        assert_eq!(f.size().unwrap(), 11);

        let reader = vfs.open_readonly("/wal/000001.log").unwrap();
        let mut buf = [0u8; 11];
        reader.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"hello world");
    }

    #[test]
    fn read_past_end_is_error() {
        let vfs = MemVfs::new();
        let mut w = vfs.open_writable("a").unwrap();
        w.append(b"abc").unwrap();
        let r = vfs.open_readonly("a").unwrap();
        let mut buf = [0u8; 10];
        let err = r.read_at(&mut buf, 0).unwrap_err();
        assert!(
            matches!(err, crate::error::Error::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn rename_moves_content_atomically() {
        let vfs = MemVfs::new();
        let mut f = vfs.open_writable("tmp").unwrap();
        f.append(b"draft").unwrap();
        vfs.rename("tmp", "final").unwrap();
        let r = vfs.open_readonly("final").unwrap();
        assert_eq!(r.size().unwrap(), 5);
        assert!(matches!(
            vfs.open_readonly("tmp").unwrap_err(),
            crate::error::Error::Io(_)
        ));
    }

    #[test]
    fn remove_is_idempotent() {
        let vfs = MemVfs::new();
        vfs.remove("nope").unwrap();
        let mut f = vfs.open_writable("doomed").unwrap();
        f.append(b"x").unwrap();
        vfs.remove("doomed").unwrap();
        vfs.remove("doomed").unwrap();
    }

    #[test]
    fn list_filters_to_immediate_children_of_dir() {
        let vfs = MemVfs::new();
        for path in ["wal/1.log", "wal/2.log", "sst/a.sst", "wal/sub/3.log"] {
            vfs.open_writable(path).unwrap().append(b"x").unwrap();
        }
        let mut wal = vfs.list("wal").unwrap();
        wal.sort();
        assert_eq!(wal, vec!["1.log".to_owned(), "2.log".to_owned()]);
        let mut sst = vfs.list("sst").unwrap();
        sst.sort();
        assert_eq!(sst, vec!["a.sst".to_owned()]);
    }

    #[test]
    fn shared_handle_sees_appends_from_other_writer() {
        let vfs = MemVfs::new();
        let mut a = vfs.open_writable("shared").unwrap();
        let mut b = vfs.open_writable("shared").unwrap();
        a.append(b"AAA").unwrap();
        b.append(b"BBB").unwrap();
        assert_eq!(a.size().unwrap(), 6);
        assert_eq!(b.size().unwrap(), 6);
    }
}
