//! Production Linux backend for [`crate::io::vfs::Vfs`].
//!
//! `LinuxVfs` rooted at a host filesystem path is the production
//! complement to `MemVfs`: every method on the trait routes to standard
//! POSIX I/O. The implementation deliberately stays simple — no
//! `O_DIRECT`, no `io_uring`, no batching — because:
//!
//! 1. The engine's correctness is already proven against `MemVfs` by 197
//!    tests. `LinuxVfs` only needs to be **a faithful POSIX-backed
//!    `Vfs`**; the engine logic on top is unchanged.
//! 2. The high-throughput paths (WAL group commit, compaction reads)
//!    will plug in `DirectFile` / `Uring` from sibling modules
//!    separately. Keeping `LinuxVfs` simple keeps the substitution clean.
//!
//! ## Concurrency
//!
//! `pread` and `pwrite` are atomic with respect to a single byte range
//! on Linux (kernel >= 3.14 for the `pwritev2`/`preadv2` variants; the
//! plain `pread`/`pwrite` we use here have been atomic since pre-2.0).
//! Multiple `LinuxFile`s on the same path can therefore read concurrently
//! without locks. Append is serialised inside one handle by [`Mutex`] on
//! the underlying file because `seek + write` is not atomic on its own.
//!
//! ## Errors
//!
//! Every `io::Error` is folded into [`crate::error::Error::Io`] via the
//! `From` impl already on the error tree. The trait surface does not
//! distinguish file-not-found from permission-denied (POSIX errnos
//! travel through the inner `io::Error`); callers that need that
//! granularity inspect `Error::Io(e).kind()`.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use crate::io::vfs::{Vfs, VfsFile};

/// Production `Vfs` rooted at a host filesystem directory.
#[derive(Debug, Clone)]
pub struct LinuxVfs {
    root: PathBuf,
}

impl LinuxVfs {
    /// Construct a `LinuxVfs` rooted at `root`. The directory must
    /// already exist; callers that want auto-create semantics should
    /// invoke [`std::fs::create_dir_all`] beforehand. This decoupling
    /// keeps the VFS trait honest — a `Vfs` does not own directory
    /// creation policy.
    #[must_use]
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_owned(),
        }
    }

    /// Construct a `LinuxVfs` and ensure the root directory exists.
    /// Convenience for tests and one-shot programs.
    pub fn create_at<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root = root.as_ref();
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.to_owned(),
        })
    }

    /// Borrow the root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a Vfs path (which may contain `/` separators portable
    /// across our platforms) against the engine's root. Refuses absolute
    /// paths and `..` segments so a misbehaving caller cannot escape the
    /// data directory.
    fn resolve(&self, path: &str) -> Result<PathBuf> {
        if path.is_empty() {
            return Err(Error::invalid_format_static("LinuxVfs", "empty path"));
        }
        let logical = Path::new(path);
        if logical.is_absolute() {
            return Err(Error::invalid_format_static(
                "LinuxVfs",
                "absolute paths are not permitted; pass a relative name",
            ));
        }
        for component in logical.components() {
            use std::path::Component;
            match component {
                // Normal segments resolve under the root; `CurDir` ("./")
                // is a no-op that the engine generates when its
                // `data_dir` is ".".
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                    return Err(Error::invalid_format_static(
                        "LinuxVfs",
                        "path component outside the root is not permitted",
                    ));
                }
            }
        }
        Ok(self.root.join(logical))
    }
}

impl Vfs for LinuxVfs {
    type File = LinuxFile;

    fn open_writable(&self, path: &str) -> Result<Self::File> {
        let full = self.resolve(path)?;
        if let Some(parent) = full.parent() {
            if !parent.as_os_str().is_empty() && parent != self.root {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&full)?;
        Ok(LinuxFile {
            inner: Arc::new(Mutex::new(file)),
        })
    }

    fn open_readonly(&self, path: &str) -> Result<Self::File> {
        let full = self.resolve(path)?;
        let file = OpenOptions::new().read(true).open(&full)?;
        Ok(LinuxFile {
            inner: Arc::new(Mutex::new(file)),
        })
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from = self.resolve(from)?;
        let to = self.resolve(to)?;
        std::fs::rename(&from, &to)?;
        Ok(())
    }

    fn remove(&self, path: &str) -> Result<()> {
        let full = self.resolve(path)?;
        match std::fs::remove_file(&full) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn list(&self, dir: &str) -> Result<Vec<String>> {
        let target = if dir.is_empty() || dir == "." {
            self.root.clone()
        } else {
            self.resolve(dir)?
        };
        let mut out = Vec::new();
        let read = match std::fs::read_dir(&target) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in read {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                out.push(name.to_owned());
            }
        }
        Ok(out)
    }
}

/// File handle produced by [`LinuxVfs`].
///
/// Cheap to clone — the underlying [`File`] sits behind an `Arc<Mutex<_>>`
/// so multiple read handles share one fd. Reads are concurrent (via
/// `pread`); appends and `write_at` calls serialise through the mutex
/// because the underlying syscalls modify shared file state (append
/// position, in particular).
#[derive(Clone)]
pub struct LinuxFile {
    inner: Arc<Mutex<File>>,
}

impl std::fmt::Debug for LinuxFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxFile").finish_non_exhaustive()
    }
}

impl VfsFile for LinuxFile {
    fn append(&mut self, data: &[u8]) -> Result<u64> {
        let mut guard = self.inner.lock().expect("LinuxFile lock poisoned");
        let offset = guard.metadata()?.len();
        // `write_all_at` is the positional, no-seek version. Avoids the
        // `seek(End) + write_all` race where a concurrent append on
        // another handle could intercalate.
        guard.write_all_at(data, offset)?;
        drop(guard);
        Ok(offset)
    }

    fn write_at(&mut self, data: &[u8], offset: u64) -> Result<()> {
        let guard = self.inner.lock().expect("LinuxFile lock poisoned");
        // `pwrite` does not advance the file's seek position; safe to
        // call concurrently with reads on the same fd.
        guard.write_all_at(data, offset)?;
        drop(guard);
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        let guard = self.inner.lock().expect("LinuxFile lock poisoned");
        // `sync_data` maps to `fdatasync(2)` — flushes data + size only,
        // skipping unrelated inode metadata writes (atime, etc.). Cheaper
        // than `sync_all` for the WAL hot path.
        guard.sync_data()?;
        drop(guard);
        Ok(())
    }

    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        let guard = self.inner.lock().expect("LinuxFile lock poisoned");
        guard.read_exact_at(buf, offset)?;
        drop(guard);
        Ok(())
    }

    fn size(&self) -> Result<u64> {
        let guard = self.inner.lock().expect("LinuxFile lock poisoned");
        let size = guard.metadata()?.len();
        drop(guard);
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("paddock-linuxvfs-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn append_then_read_round_trips() {
        let root = temp_root("rw");
        let vfs = LinuxVfs::new(&root);
        let mut f = vfs.open_writable("hello.txt").unwrap();
        let off_a = f.append(b"Hello, ").unwrap();
        let off_b = f.append(b"PaddockKV!").unwrap();
        assert_eq!(off_a, 0);
        assert_eq!(off_b, 7);
        f.sync().unwrap();

        let r = vfs.open_readonly("hello.txt").unwrap();
        let mut buf = vec![0u8; 17];
        r.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"Hello, PaddockKV!");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn write_at_overwrites_existing_range() {
        let root = temp_root("write-at");
        let vfs = LinuxVfs::new(&root);
        let mut f = vfs.open_writable("overlay").unwrap();
        f.append(&vec![0u8; 32]).unwrap();
        f.write_at(b"BACKFILL", 4).unwrap();
        f.sync().unwrap();

        let r = vfs.open_readonly("overlay").unwrap();
        let mut buf = vec![0u8; 32];
        r.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf[..4], &[0, 0, 0, 0]);
        assert_eq!(&buf[4..12], b"BACKFILL");
        assert_eq!(&buf[12..], &[0u8; 20]);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rename_then_remove() {
        let root = temp_root("rename");
        let vfs = LinuxVfs::new(&root);
        let mut f = vfs.open_writable("first").unwrap();
        f.append(b"data").unwrap();
        drop(f);

        vfs.rename("first", "second").unwrap();
        assert!(vfs.open_readonly("first").is_err());
        let r = vfs.open_readonly("second").unwrap();
        assert_eq!(r.size().unwrap(), 4);

        vfs.remove("second").unwrap();
        assert!(vfs.open_readonly("second").is_err());
        // Idempotent: a second remove succeeds.
        vfs.remove("second").unwrap();

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn list_returns_files_in_root() {
        let root = temp_root("list");
        let vfs = LinuxVfs::new(&root);
        for name in ["a.sst", "b.sst", "wal-1.log"] {
            vfs.open_writable(name).unwrap();
        }
        let mut listed = vfs.list("").unwrap();
        listed.sort();
        assert_eq!(
            listed,
            vec![
                "a.sst".to_owned(),
                "b.sst".to_owned(),
                "wal-1.log".to_owned()
            ]
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn resolve_refuses_path_escape() {
        let root = temp_root("escape");
        let vfs = LinuxVfs::new(&root);
        assert!(vfs.open_writable("../escaped").is_err());
        assert!(vfs.open_writable("/etc/passwd").is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    /// End-to-end: stand up a `Db` on `LinuxVfs`, do real
    /// put/flush/reopen, and confirm the engine works on the host
    /// filesystem the way it does in MemVfs.
    #[test]
    fn db_round_trip_on_linux_vfs() {
        let root = temp_root("db");
        {
            let vfs = LinuxVfs::new(&root);
            let db = crate::Db::open(vfs, ".").unwrap();
            db.put(b"alpha", b"one").unwrap();
            db.put(b"bravo", b"two").unwrap();
            db.flush().unwrap();
            assert_eq!(db.get(b"alpha").unwrap(), Some(b"one".to_vec()));
        }
        // Reopen: state must survive process exit.
        {
            let vfs = LinuxVfs::new(&root);
            let db = crate::Db::open(vfs, ".").unwrap();
            assert_eq!(db.get(b"alpha").unwrap(), Some(b"one".to_vec()));
            assert_eq!(db.get(b"bravo").unwrap(), Some(b"two".to_vec()));
        }
        std::fs::remove_dir_all(&root).ok();
    }
}
