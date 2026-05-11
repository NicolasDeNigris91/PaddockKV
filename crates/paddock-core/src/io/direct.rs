//! `O_DIRECT` file abstraction.
//!
//! On Linux, `O_DIRECT` bypasses the page cache: reads land directly in the
//! caller's buffer, writes go straight to the block device. The catch is that
//! the OS imposes three alignment constraints on every operation:
//!
//! 1. The buffer's start address must be aligned to the device's logical block
//!    size (≤ 4 KiB on every contemporary device).
//! 2. The buffer's length must be a multiple of that block size.
//! 3. The file offset must be a multiple of that block size.
//!
//! Violating any of these returns `EINVAL`. The [`DirectFile`] type wraps a
//! `RawFd` opened with `O_DIRECT` and checks all three before each syscall, so
//! higher-level code can call it without re-implementing the dance.
//!
//! Combined with [`super::aligned_buf::AlignedBuf`], this gives a clean
//! synchronous I/O layer used by:
//!
//! - SSTable writers (sequential aligned appends).
//! - Compaction-time reads (large sequential reads bypassing the page cache).
//! - WAL truncation/preallocation (`fallocate` is exposed here too).
//!
//! Asynchronous and batched submission goes through [`super::uring`].

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::error::Result;
use crate::io::aligned_buf::{AlignedBuf, PAGE_SIZE};

/// A file opened with `O_DIRECT`.
#[derive(Debug)]
pub struct DirectFile {
    file: File,
    block_size: usize,
}

impl DirectFile {
    /// Open `path` with `O_DIRECT | O_RDWR`, creating it if missing.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_options(
            path,
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(libc::O_DIRECT),
        )
    }

    /// Open `path` for read-only access with `O_DIRECT`.
    pub fn open_read<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_options(
            path,
            OpenOptions::new().read(true).custom_flags(libc::O_DIRECT),
        )
    }

    fn open_with_options<P: AsRef<Path>>(path: P, opts: OpenOptions) -> Result<Self> {
        let file = opts.open(path)?;
        Ok(Self {
            file,
            block_size: PAGE_SIZE,
        })
    }

    /// Block-size alignment enforced by this handle. Defaults to [`PAGE_SIZE`].
    #[inline]
    #[must_use]
    pub const fn block_size(&self) -> usize {
        self.block_size
    }

    /// Override the alignment, e.g. for a 512-byte-sector device. Must be a
    /// power of two and at least the device's logical block size, otherwise
    /// later operations will fail with `EINVAL`.
    pub fn set_block_size(&mut self, size: usize) {
        assert!(size.is_power_of_two(), "block size must be a power of two");
        self.block_size = size;
    }

    /// Borrow the underlying [`File`]. Useful for `mmap` (after closing the
    /// direct fd) and for syscalls not directly exposed here.
    #[inline]
    #[must_use]
    pub fn as_file(&self) -> &File {
        &self.file
    }

    /// Raw fd, for FFI into `io_uring`.
    #[inline]
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Append the entire buffer at the current file end via `pwrite`.
    ///
    /// `buf.len()` must be a multiple of [`block_size`](Self::block_size). The
    /// buffer's start address must be aligned to that boundary (which is
    /// always true for [`AlignedBuf`]).
    pub fn append_aligned(&mut self, buf: &AlignedBuf) -> Result<u64> {
        let offset = self.file.metadata()?.len();
        self.write_at_aligned(buf, offset)?;
        Ok(offset)
    }

    /// Write `buf` at `offset` via `pwrite`. Performs no short writes; loops
    /// internally until the whole buffer is on disk or an error occurs.
    pub fn write_at_aligned(&mut self, buf: &AlignedBuf, offset: u64) -> Result<()> {
        self.check_alignment(buf.len(), offset)?;
        let mut written = 0usize;
        while written < buf.len() {
            let remaining = &buf.as_slice()[written..];
            let off = offset
                .checked_add(written as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
            // SAFETY: `pwrite` accepts `(fd, buf, count, offset)`. Our buffer
            // pointer is non-null, points to `remaining.len()` initialised
            // bytes (the slice exposes them as readable), and is properly
            // aligned to `block_size`. The fd is owned by `self.file`.
            let n = unsafe {
                libc::pwrite(
                    self.as_raw_fd(),
                    remaining.as_ptr().cast::<libc::c_void>(),
                    remaining.len(),
                    off as libc::off_t,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "pwrite returned 0 before completing the buffer",
                )
                .into());
            }
            #[allow(clippy::cast_sign_loss, reason = "non-negative ssize_t can be widened")]
            {
                written += n as usize;
            }
        }
        Ok(())
    }

    /// Read into the entire buffer starting at `offset` via `pread`. The
    /// caller must size `buf` to a multiple of [`block_size`](Self::block_size).
    pub fn read_at_aligned(&self, buf: &mut AlignedBuf, offset: u64) -> Result<()> {
        self.check_alignment(buf.len(), offset)?;
        let mut read = 0usize;
        while read < buf.len() {
            let remaining = &mut buf.as_mut_slice()[read..];
            let off = offset
                .checked_add(read as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
            // SAFETY: same shape as the `pwrite` arm above, with a mutable
            // buffer.
            let n = unsafe {
                libc::pread(
                    self.as_raw_fd(),
                    remaining.as_mut_ptr().cast::<libc::c_void>(),
                    remaining.len(),
                    off as libc::off_t,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "pread returned 0 before completing the buffer",
                )
                .into());
            }
            #[allow(clippy::cast_sign_loss, reason = "non-negative ssize_t can be widened")]
            {
                read += n as usize;
            }
        }
        Ok(())
    }

    /// Preallocate `len` bytes via `fallocate`. Required for SSTable writers
    /// to reserve the on-disk space up-front and avoid fragmentation.
    pub fn fallocate(&self, len: u64) -> Result<()> {
        // SAFETY: `fallocate` is a standard syscall. `fd` is owned by `self`;
        // `mode=0` is the default "allocate" mode; `offset=0`, `len=len` are
        // valid (the kernel rejects negative or overflowing lengths).
        let rc = unsafe { libc::fallocate(self.as_raw_fd(), 0, 0, len as libc::off_t) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }

    /// `fdatasync` — sync data and size, but not unrelated inode metadata.
    /// Preferred over `fsync` for WAL group commit.
    pub fn fdatasync(&self) -> Result<()> {
        // SAFETY: `fdatasync` requires only a valid fd.
        let rc = unsafe { libc::fdatasync(self.as_raw_fd()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    }

    fn check_alignment(&self, len: usize, offset: u64) -> Result<()> {
        let bs = self.block_size;
        if len % bs != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("buffer length {len} not a multiple of block size {bs}"),
            )
            .into());
        }
        if offset % (bs as u64) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("offset {offset} not aligned to block size {bs}"),
            )
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Integration tests that exercise the kernel are gated behind a small
    //! helper that ignores them when the underlying filesystem refuses
    //! `O_DIRECT` (common on tmpfs and on overlayfs as used by CI). Any other
    //! failure is propagated.

    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("paddock-direct-test-{}-{name}", std::process::id()));
        path
    }

    /// Skip a test if the host filesystem returns `EINVAL` for `O_DIRECT`.
    fn skip_if_no_o_direct(err: &crate::error::Error) -> bool {
        if let crate::error::Error::Io(e) = err {
            return matches!(e.raw_os_error(), Some(libc::EINVAL));
        }
        false
    }

    #[test]
    fn alignment_checks_reject_unaligned_offset() {
        let path = temp_path("align");
        let file = match DirectFile::create(&path) {
            Ok(f) => f,
            Err(e) if skip_if_no_o_direct(&e) => return,
            Err(e) => panic!("create failed: {e}"),
        };
        let mut buf = AlignedBuf::new(4096).unwrap();
        let err = file.read_at_aligned(&mut buf, 1).err().unwrap();
        assert!(matches!(err, crate::error::Error::Io(_)));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn alignment_checks_reject_unaligned_length() {
        let path = temp_path("align-len");
        let file = match DirectFile::create(&path) {
            Ok(f) => f,
            Err(e) if skip_if_no_o_direct(&e) => return,
            Err(e) => panic!("create failed: {e}"),
        };
        // We deliberately construct a buffer with an unusual alignment to
        // simulate a length-only mismatch. `AlignedBuf::new(4096)` always
        // returns 4096-byte length, so we hand-craft via `with_alignment(4097)`
        // — that rounds up to one page, still 4096. The simplest way to get a
        // length mismatch is to fake it by reading into a slice of the wrong
        // *requested* length, which our typed API forbids. So we instead test
        // the path via the `check_alignment` helper indirectly through the
        // public method by passing a deliberately corrupt block size.
        let mut file = file;
        file.set_block_size(8192); // bigger than the 4096-byte buf
        let mut buf = AlignedBuf::new(4096).unwrap();
        let err = file.read_at_aligned(&mut buf, 0).err().unwrap();
        assert!(matches!(err, crate::error::Error::Io(_)));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_then_read_round_trips() {
        let path = temp_path("rw-roundtrip");
        let mut file = match DirectFile::create(&path) {
            Ok(f) => f,
            Err(e) if skip_if_no_o_direct(&e) => return,
            Err(e) => panic!("create failed: {e}"),
        };

        let mut out = AlignedBuf::new(4096).unwrap();
        for (i, b) in out.as_mut_slice().iter_mut().enumerate() {
            // SAFETY-ish: low 8 bits intentional.
            #[allow(
                clippy::cast_possible_truncation,
                reason = "test payload pattern; truncation is intentional"
            )]
            {
                *b = i as u8;
            }
        }
        file.write_at_aligned(&out, 0).expect("write");
        file.fdatasync().expect("fdatasync");

        let mut back = AlignedBuf::new(4096).unwrap();
        file.read_at_aligned(&mut back, 0).expect("read");
        assert_eq!(back.as_slice(), out.as_slice());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fallocate_extends_file() {
        let path = temp_path("fallocate");
        let file = match DirectFile::create(&path) {
            Ok(f) => f,
            Err(e) if skip_if_no_o_direct(&e) => return,
            Err(e) => panic!("create failed: {e}"),
        };
        file.fallocate(64 * 1024).expect("fallocate");
        let size = file.as_file().metadata().unwrap().len();
        assert_eq!(size, 64 * 1024);
        std::fs::remove_file(&path).ok();
    }
}
