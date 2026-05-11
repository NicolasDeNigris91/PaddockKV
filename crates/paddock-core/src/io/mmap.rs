//! Read-only Linux mmap regions.
//!
//! `Mmap` is the foundation of PaddockKV's zero-copy read path: an SSTable is
//! mapped once on open with `mmap(PROT_READ, MAP_PRIVATE)` and every later
//! point read returns a `&[u8]` that lives inside the page cache. There is no
//! intermediate block cache copy on this path.
//!
//! ## Madvise hints
//!
//! The OS does not know what we are about to do with each region. We tell it.
//! [`Advice`] wraps the hints the engine actually uses; everything else can be
//! reached via [`Mmap::advise_raw`] if needed.
//!
//! - [`Advice::Random`] — point-read SSTable bodies. Disables read-ahead.
//! - [`Advice::WillNeed`] — bloom filter and index regions at open time.
//! - [`Advice::Sequential`] — fallback path for compaction scans when we
//!   choose mmap over `O_DIRECT`.
//! - [`Advice::DontNeed`] — drop a region from the page cache when done.
//!
//! ## Lifetime model
//!
//! `Mmap` owns its mapping. The `&[u8]` returned by [`Mmap::as_slice`] borrows
//! from `&self`, so the borrow checker prevents the slice from outliving the
//! mapping. Higher-level code holds `Arc<Mmap>` per open SSTable, and every
//! `BorrowedValue<'_>` returned by `get()` carries that lifetime.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::ptr::NonNull;

use crate::error::Result;

/// Page-cache hint passed to [`madvise`](libc::madvise).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advice {
    /// `MADV_NORMAL` — the kernel's default.
    Normal,
    /// `MADV_RANDOM` — random access pattern; disable read-ahead.
    Random,
    /// `MADV_SEQUENTIAL` — sequential access; aggressive read-ahead.
    Sequential,
    /// `MADV_WILLNEED` — populate pages now.
    WillNeed,
    /// `MADV_DONTNEED` — discard pages, freeing memory.
    DontNeed,
}

impl Advice {
    #[inline]
    const fn as_c_int(self) -> libc::c_int {
        match self {
            Self::Normal => libc::MADV_NORMAL,
            Self::Random => libc::MADV_RANDOM,
            Self::Sequential => libc::MADV_SEQUENTIAL,
            Self::WillNeed => libc::MADV_WILLNEED,
            Self::DontNeed => libc::MADV_DONTNEED,
        }
    }
}

/// Read-only memory-mapped region.
///
/// Construct via [`Mmap::open`] from a path, or [`Mmap::from_file`] from an
/// existing `File`. The returned region is `PROT_READ | MAP_PRIVATE`.
pub struct Mmap {
    ptr: NonNull<libc::c_void>,
    len: usize,
}

// SAFETY: the mapped memory is read-only and the underlying file backs it
// independently of which thread accesses the bytes. Concurrent `&[u8]` reads
// from multiple threads are well-defined.
unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Mmap {
    /// Open the file at `path` and map it read-only.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        Self::from_file(&file)
    }

    /// Map an already-open file read-only.
    pub fn from_file(file: &File) -> Result<Self> {
        let len = usize::try_from(file.metadata()?.len()).map_err(|_| {
            crate::error::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file size does not fit in usize",
            ))
        })?;
        if len == 0 {
            return Err(crate::error::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot mmap a zero-length file",
            )));
        }
        // SAFETY: `mmap` is the documented syscall for creating a mapping of a
        // file descriptor. We pass:
        //   - `addr = NULL`     — let the kernel choose the address.
        //   - `length = len`    — non-zero, fits in size_t.
        //   - `prot = PROT_READ`— we never write through this mapping.
        //   - `flags = MAP_PRIVATE` — copy-on-write; we never modify pages.
        //   - `fd = file.fd`    — valid, owned by the `&File`.
        //   - `offset = 0`      — map the whole file.
        // The returned pointer is either `MAP_FAILED` (checked) or a valid
        // mapping of `len` bytes that we own for the lifetime of `self`.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        let ptr = NonNull::new(addr.cast::<libc::c_void>()).ok_or_else(|| {
            crate::error::Error::Io(io::Error::new(
                io::ErrorKind::Other,
                "mmap returned null without setting MAP_FAILED",
            ))
        })?;
        Ok(Self { ptr, len })
    }

    /// Borrow the mapping as a byte slice.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` came from a successful `mmap` of `len` bytes for
        // `PROT_READ`. The kernel keeps the mapping valid until we `munmap`
        // in `Drop`. The slice borrows `&self`, so it cannot outlive the
        // mapping. The bytes are initialised (they reflect the file contents).
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast::<u8>(), self.len) }
    }

    /// Length of the mapped region in bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` if the mapping is zero-length (cannot happen — mmap rejects it —
    /// but kept for slice-API symmetry).
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Apply a [`madvise`](libc::madvise) hint to the entire mapping.
    pub fn advise(&self, advice: Advice) -> Result<()> {
        self.advise_raw(advice.as_c_int())
    }

    /// Apply a [`madvise`](libc::madvise) hint over `[offset, offset + length)`.
    ///
    /// `offset` and `length` must lie within the mapping; they are checked
    /// against `self.len`. `offset` and `length` should be page-aligned —
    /// `madvise` itself permits unaligned offsets on Linux but the effect is
    /// rounded to whole pages.
    pub fn advise_range(&self, advice: Advice, offset: usize, length: usize) -> Result<()> {
        let end = offset.checked_add(length).ok_or_else(|| {
            crate::error::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "advise range overflow",
            ))
        })?;
        if end > self.len {
            return Err(crate::error::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "advise range exceeds mapping length",
            )));
        }
        // SAFETY: the pointer arithmetic stays within the bounds we just
        // checked. `madvise` is documented to accept any valid sub-range of an
        // existing mapping.
        let addr = unsafe { self.ptr.as_ptr().cast::<u8>().add(offset) };
        // SAFETY: `addr` is within our mapping; `length` was bound-checked.
        let rc = unsafe { libc::madvise(addr.cast::<libc::c_void>(), length, advice.as_c_int()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }

    /// Apply a raw `madvise` advice code over the entire mapping. Use this
    /// for hints not in [`Advice`] (e.g. `MADV_HUGEPAGE`, `MADV_COLD`).
    pub fn advise_raw(&self, advice: libc::c_int) -> Result<()> {
        // SAFETY: `ptr` is the start of a valid mapping of `len` bytes.
        let rc = unsafe { libc::madvise(self.ptr.as_ptr(), self.len, advice) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `len` match the original `mmap` call exactly. The
        // mapping has not been unmapped before. After `munmap` returns, the
        // pointer is invalid, but we never dereference it again.
        let rc = unsafe { libc::munmap(self.ptr.as_ptr(), self.len) };
        debug_assert_eq!(rc, 0, "munmap failed: {}", io::Error::last_os_error());
    }
}

impl std::fmt::Debug for Mmap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mmap")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for Mmap {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn write_temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("paddock-mmap-test-{}-{name}", std::process::id()));
        let mut f = File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        f.sync_all().unwrap();
        path
    }

    #[test]
    fn open_and_read_full_file() {
        let path = write_temp_file("read", b"PaddockKV mmap test payload");
        let m = Mmap::open(&path).unwrap();
        assert_eq!(m.len(), 27);
        assert_eq!(m.as_slice(), b"PaddockKV mmap test payload");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn deref_to_slice_works() {
        let path = write_temp_file("deref", b"hello");
        let m = Mmap::open(&path).unwrap();
        assert_eq!(&m[..], b"hello");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn advise_random_is_accepted() {
        let path = write_temp_file("advise-random", &vec![0u8; 8192]);
        let m = Mmap::open(&path).unwrap();
        m.advise(Advice::Random).unwrap();
        m.advise(Advice::WillNeed).unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn advise_range_rejects_oversized_request() {
        let path = write_temp_file("advise-range", &vec![0u8; 4096]);
        let m = Mmap::open(&path).unwrap();
        let err = m.advise_range(Advice::DontNeed, 0, 8192).unwrap_err();
        assert!(matches!(err, crate::error::Error::Io(_)));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn empty_file_is_rejected() {
        let path = write_temp_file("empty", b"");
        let err = Mmap::open(&path).unwrap_err();
        assert!(matches!(err, crate::error::Error::Io(_)));
        std::fs::remove_file(&path).ok();
    }
}
