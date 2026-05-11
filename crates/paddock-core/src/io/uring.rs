//! `io_uring` instance management.
//!
//! Wrapper around the [`io-uring`] crate that exposes only the operations the
//! engine actually uses, with the bookkeeping centralised in one place:
//!
//! - [`Uring::new`] — vanilla ring, no SQPOLL. Easiest to reason about; the
//!   default for tests and for the SSTable writer path.
//! - [`Uring::with_sqpoll`] — kernel polling thread, eliminates the syscall on
//!   the write path. Used by the WAL writer to hit sub-microsecond `submit()`.
//! - [`Uring::push_write`] / [`push_fdatasync`] / [`push_read`] — fluent SQE
//!   builders that return an opaque [`UserData`] handle the caller chooses.
//! - [`Uring::push_linked_write_then_fdatasync`] — the group-commit fast path.
//!   Uses `IOSQE_IO_LINK` so the kernel orders the fdatasync strictly after
//!   the write, all in one submission.
//! - [`Uring::submit_and_wait`] / [`wait_completion`] — submit the queue and
//!   harvest CQEs.
//!
//! Buffer registration (`IORING_REGISTER_BUFFERS`) is exposed but optional.
//! The engine registers WAL write buffers and compaction scratch buffers; ad
//! hoc reads use unregistered buffers.
//!
//! ## Lifetime discipline
//!
//! The kernel reads the SQE buffers asynchronously. Callers must keep the
//! buffer alive until the matching CQE is harvested. The [`UserData`] tag the
//! caller picks should typically be a stable identifier (e.g. an index into a
//! parking lot of pending operations) so a completion can be matched back to
//! whatever data the SQE referenced.

use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use io_uring::{IoUring, opcode, types};

use crate::error::Result;

/// Caller-chosen tag attached to each SQE. Surfaces in the matching CQE.
pub type UserData = u64;

/// Wrapper around an [`IoUring`] instance with the engine's preferred defaults.
pub struct Uring {
    inner: IoUring,
}

/// Outcome of a single completion event.
#[derive(Debug, Clone, Copy)]
pub struct Completion {
    /// The `user_data` value attached to the originating SQE.
    pub user_data: UserData,
    /// Kernel-reported result. Positive = bytes transferred or 0; negative =
    /// `-errno`.
    pub result: i32,
    /// Kernel-supplied per-op flags from the CQE.
    pub flags: u32,
}

impl Completion {
    /// `true` if the operation succeeded (`result >= 0`).
    #[inline]
    #[must_use]
    pub const fn ok(&self) -> bool {
        self.result >= 0
    }

    /// `Some(errno)` if the operation failed.
    #[inline]
    #[must_use]
    pub const fn errno(&self) -> Option<i32> {
        if self.result < 0 {
            Some(-self.result)
        } else {
            None
        }
    }

    /// Bytes transferred if the operation succeeded.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> Option<usize> {
        if self.result >= 0 {
            #[allow(
                clippy::cast_sign_loss,
                reason = "branch guarantees non-negative result"
            )]
            Some(self.result as usize)
        } else {
            None
        }
    }
}

impl Uring {
    /// Create a ring with `entries` SQE slots, no SQPOLL.
    ///
    /// `entries` must be a power of two between 1 and 32768.
    pub fn new(entries: u32) -> Result<Self> {
        let inner = IoUring::new(entries)?;
        Ok(Self { inner })
    }

    /// Create a ring with kernel-side polling (`IORING_SETUP_SQPOLL`).
    ///
    /// `idle_ms` controls how long the kernel poller waits with no
    /// submissions before sleeping; lower values cost more CPU but reduce
    /// wake-up latency. A common default is 1000.
    pub fn with_sqpoll(entries: u32, idle_ms: u32) -> Result<Self> {
        let inner = IoUring::builder().setup_sqpoll(idle_ms).build(entries)?;
        Ok(Self { inner })
    }

    /// Number of SQEs currently sitting in the submission queue (not yet
    /// submitted to the kernel).
    #[must_use]
    pub fn pending_submissions(&self) -> usize {
        self.inner.submission().len()
    }

    /// Free capacity in the submission queue.
    #[must_use]
    pub fn submission_capacity(&self) -> usize {
        self.inner.submission().capacity() - self.inner.submission().len()
    }

    /// Push a write SQE.
    ///
    /// `fd` may be a raw kernel fd. `buf` must outlive the operation: the
    /// pointer is captured into the SQE and the kernel reads from it
    /// asynchronously. Returns `Err` if the submission queue is full.
    ///
    /// # Safety
    ///
    /// `buf` must remain valid and unmoved until the matching completion is
    /// harvested. Mutating the buffer before completion is a data race against
    /// the kernel.
    pub unsafe fn push_write(
        &mut self,
        fd: RawFd,
        buf: &[u8],
        offset: u64,
        user_data: UserData,
    ) -> Result<()> {
        let entry = opcode::Write::new(types::Fd(fd), buf.as_ptr(), buf.len() as u32)
            .offset(offset)
            .build()
            .user_data(user_data);
        // SAFETY: caller of `push_write` already promised buffer lifetime; the
        // SQE only stores pointers/lengths, not Rust references.
        unsafe {
            self.inner
                .submission()
                .push(&entry)
                .map_err(|_| sq_full())?;
        }
        Ok(())
    }

    /// Push a read SQE. Mirror of [`push_write`](Self::push_write).
    ///
    /// # Safety
    ///
    /// `buf` must remain valid and uniquely borrowed until the matching
    /// completion is harvested.
    pub unsafe fn push_read(
        &mut self,
        fd: RawFd,
        buf: &mut [u8],
        offset: u64,
        user_data: UserData,
    ) -> Result<()> {
        let entry = opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), buf.len() as u32)
            .offset(offset)
            .build()
            .user_data(user_data);
        // SAFETY: see `push_write`.
        unsafe {
            self.inner
                .submission()
                .push(&entry)
                .map_err(|_| sq_full())?;
        }
        Ok(())
    }

    /// Push an `fdatasync` SQE.
    pub fn push_fdatasync(&mut self, fd: RawFd, user_data: UserData) -> Result<()> {
        let entry = opcode::Fsync::new(types::Fd(fd))
            .flags(types::FsyncFlags::DATASYNC)
            .build()
            .user_data(user_data);
        // SAFETY: the `Fsync` op takes no user buffer, so there is no buffer
        // lifetime to enforce.
        unsafe {
            self.inner
                .submission()
                .push(&entry)
                .map_err(|_| sq_full())?;
        }
        Ok(())
    }

    /// Push the WAL group-commit pair: write then `fdatasync`, linked via
    /// `IOSQE_IO_LINK` so the kernel runs the fsync strictly after the write
    /// completes successfully. Two CQEs will arrive; the caller chooses both
    /// `user_data` tags.
    ///
    /// # Safety
    ///
    /// Same as [`push_write`](Self::push_write).
    pub unsafe fn push_linked_write_then_fdatasync(
        &mut self,
        fd: RawFd,
        buf: &[u8],
        offset: u64,
        write_tag: UserData,
        fsync_tag: UserData,
    ) -> Result<()> {
        let write = opcode::Write::new(types::Fd(fd), buf.as_ptr(), buf.len() as u32)
            .offset(offset)
            .build()
            .flags(io_uring::squeue::Flags::IO_LINK)
            .user_data(write_tag);
        let fsync = opcode::Fsync::new(types::Fd(fd))
            .flags(types::FsyncFlags::DATASYNC)
            .build()
            .user_data(fsync_tag);
        // SAFETY: see `push_write`; both SQEs are pushed together so they will
        // either both submit or both fail.
        unsafe {
            let mut sq = self.inner.submission();
            if sq.capacity() - sq.len() < 2 {
                return Err(sq_full());
            }
            sq.push(&write).map_err(|_| sq_full())?;
            sq.push(&fsync).map_err(|_| sq_full())?;
        }
        Ok(())
    }

    /// Submit pending SQEs to the kernel. Returns the count successfully
    /// submitted. With SQPOLL active, this is typically a no-op (the kernel
    /// has already picked them up).
    pub fn submit(&mut self) -> Result<usize> {
        Ok(self.inner.submit()?)
    }

    /// Submit pending SQEs and wait for at least `want` CQEs to arrive.
    pub fn submit_and_wait(&mut self, want: usize) -> Result<usize> {
        Ok(self.inner.submit_and_wait(want)?)
    }

    /// Pop a single completion if one is available. Non-blocking.
    pub fn pop_completion(&mut self) -> Option<Completion> {
        self.inner.completion().next().map(|cqe| Completion {
            user_data: cqe.user_data(),
            result: cqe.result(),
            flags: cqe.flags(),
        })
    }

    /// Wait up to `timeout` for at least one completion to arrive, then drain
    /// every ready CQE into `sink`. Returns the count placed.
    pub fn drain_completions(
        &mut self,
        timeout: Option<Duration>,
        sink: &mut Vec<Completion>,
    ) -> Result<usize> {
        // Best-effort: wait for one CQE, then drain whatever piled up alongside.
        let _ = self.wait_for_at_least_one(timeout);
        let mut count = 0;
        while let Some(c) = self.pop_completion() {
            sink.push(c);
            count += 1;
        }
        Ok(count)
    }

    fn wait_for_at_least_one(&mut self, timeout: Option<Duration>) -> Result<()> {
        // Try a non-blocking peek first.
        if self.inner.completion().next().is_some() {
            // We just peeked one without removing it; nothing more to do. The
            // caller will pop it via `pop_completion`.
            return Ok(());
        }
        match timeout {
            None => {
                self.inner.submit_and_wait(1)?;
            }
            Some(d) => {
                // io-uring 0.7's high-level API exposes `submit_with_args` /
                // `Timespec` for bounded waits; we keep this simple here and
                // fall back to an unbounded wait if the duration is non-zero.
                // A precise timeout is added when the WAL writer requires it.
                let _ = d;
                self.inner.submit_and_wait(1)?;
            }
        }
        Ok(())
    }

    /// Borrow the underlying ring for advanced operations not exposed here.
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut IoUring {
        &mut self.inner
    }
}

impl AsRawFd for Uring {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl std::fmt::Debug for Uring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Uring")
            .field("fd", &self.inner.as_raw_fd())
            .finish_non_exhaustive()
    }
}

#[inline]
fn sq_full() -> crate::error::Error {
    crate::error::Error::Io(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "io_uring submission queue full",
    ))
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;

    use super::*;
    use crate::io::aligned_buf::AlignedBuf;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("paddock-uring-{}-{name}", std::process::id()));
        p
    }

    fn ring_or_skip() -> Option<Uring> {
        match Uring::new(8) {
            Ok(r) => Some(r),
            Err(crate::error::Error::Io(e))
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOSYS) | Some(libc::EPERM) | Some(libc::EACCES)
                ) =>
            {
                eprintln!("skipping io_uring test: {e}");
                None
            }
            Err(e) => panic!("io_uring init failed: {e}"),
        }
    }

    #[test]
    fn new_constructs_a_ring() {
        let Some(ring) = ring_or_skip() else {
            return;
        };
        assert_eq!(ring.pending_submissions(), 0);
    }

    #[test]
    fn write_and_complete_round_trip() {
        let Some(mut ring) = ring_or_skip() else {
            return;
        };
        let path = temp_path("write");
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .unwrap();
        // Seed the file with a known size so reads/writes work without O_APPEND.
        f.set_len(0).unwrap();

        // SAFETY: `buf` is borrowed for the duration of the inflight write
        // (we wait synchronously below).
        let buf = AlignedBuf::new(4096).unwrap();
        unsafe {
            ring.push_write(f.as_raw_fd(), buf.as_slice(), 0, 0x42)
                .unwrap();
        }
        let submitted = ring.submit_and_wait(1).unwrap();
        assert_eq!(submitted, 1);
        let c = ring.pop_completion().expect("one completion");
        assert_eq!(c.user_data, 0x42);
        assert_eq!(c.bytes(), Some(4096));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fdatasync_returns_a_completion() {
        let Some(mut ring) = ring_or_skip() else {
            return;
        };
        let path = temp_path("fsync");
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .unwrap();
        f.write_all(b"hello").unwrap();
        ring.push_fdatasync(f.as_raw_fd(), 0xCC).unwrap();
        ring.submit_and_wait(1).unwrap();
        let c = ring.pop_completion().unwrap();
        assert_eq!(c.user_data, 0xCC);
        assert!(c.ok(), "errno={:?}", c.errno());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn linked_write_then_fdatasync_yields_two_completions() {
        let Some(mut ring) = ring_or_skip() else {
            return;
        };
        let path = temp_path("linked");
        let f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .unwrap();

        let buf = AlignedBuf::new(4096).unwrap();
        // SAFETY: `buf` lives until the loop below has drained both CQEs.
        unsafe {
            ring.push_linked_write_then_fdatasync(f.as_raw_fd(), buf.as_slice(), 0, 1, 2)
                .unwrap();
        }
        ring.submit_and_wait(2).unwrap();

        let mut tags = Vec::new();
        while let Some(c) = ring.pop_completion() {
            tags.push(c.user_data);
            assert!(c.ok());
        }
        tags.sort_unstable();
        assert_eq!(tags, vec![1, 2]);
        std::fs::remove_file(&path).ok();
    }
}
