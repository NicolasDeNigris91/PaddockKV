//! Page-aligned heap buffers and pools.
//!
//! `O_DIRECT` reads and writes on Linux require buffers whose **start address,
//! length, and the file offset they target** are all multiples of the
//! underlying block device's logical sector size. In practice that is the page
//! size (4096 bytes on x86_64 and most ARM64 configurations). The Rust global
//! allocator does not, by default, guarantee any alignment stronger than that
//! of the requested type, so we go through [`std::alloc`] with an explicit
//! [`Layout`] to get this property.
//!
//! The module exposes two types:
//!
//! - [`AlignedBuf`] — a single, owned, page-aligned `[u8]` of a chosen capacity.
//! - [`BufferPool`] — a simple, single-threaded LIFO recycler so that hot
//!   write paths (WAL group commit, SSTable block flush) don't allocate on
//!   each operation. A thread-safe pool comes later when we wire compaction.
//!
//! Both types are platform-agnostic: nothing here depends on Linux. They are
//! built and tested on every supported host so that higher-level Linux-only
//! modules can rely on them.

use std::alloc::{self, Layout};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

/// Default alignment used for `O_DIRECT` I/O. Every Linux block device we
/// realistically target accepts 4 KiB-aligned buffers.
pub const PAGE_SIZE: usize = 4096;

/// A heap-allocated `[u8]` whose start address is `PAGE_SIZE`-aligned and whose
/// length is a multiple of `PAGE_SIZE`.
///
/// Use this for any buffer that will be handed to `O_DIRECT` reads/writes or
/// to `io_uring` registered buffers.
pub struct AlignedBuf {
    ptr: NonNull<u8>,
    len: usize,
    align: usize,
}

// SAFETY: `AlignedBuf` owns its allocation and exposes only `&` / `&mut` access
// to a `[u8]`. Sending it across threads is safe because the contents are raw
// bytes (`Send`), and the allocation is freed in `Drop`. The `NonNull` is
// logically a `Box<[u8]>`.
unsafe impl Send for AlignedBuf {}

// SAFETY: see the `unsafe impl Send` above; concurrent `&[u8]` access from
// multiple threads is well-defined for raw bytes.
unsafe impl Sync for AlignedBuf {}

impl AlignedBuf {
    /// Allocate a buffer of `len` bytes aligned to [`PAGE_SIZE`].
    ///
    /// `len` is rounded up to the next multiple of the alignment so that the
    /// resulting buffer is always valid for `O_DIRECT`. Returns `None` if
    /// allocation fails.
    pub fn new(len: usize) -> Option<Self> {
        Self::with_alignment(len, PAGE_SIZE)
    }

    /// Allocate `len` bytes aligned to `align`.
    ///
    /// `align` must be a power of two and at least `align_of::<u8>()` (which
    /// is trivially satisfied by any non-zero power-of-two value).
    pub fn with_alignment(len: usize, align: usize) -> Option<Self> {
        assert!(align.is_power_of_two(), "alignment must be a power of two");
        let rounded = round_up(len, align);
        if rounded == 0 {
            // Layout requires non-zero size; just allocate one page.
            return Self::with_alignment(align, align);
        }
        let layout = Layout::from_size_align(rounded, align).ok()?;
        // SAFETY: `layout` has a non-zero size (we returned early above) and a
        // power-of-two alignment. `alloc::alloc` is the documented way to
        // request raw uninitialised memory matching that layout.
        let raw = unsafe { alloc::alloc(layout) };
        let ptr = NonNull::new(raw)?;
        // Pre-zero the memory so that we have a defined value to write into
        // and so that any partial-write torn-block scenarios produce all-zero
        // tails instead of leaked uninitialised allocator memory.
        // SAFETY: `ptr` is valid for writes for `rounded` bytes (we just
        // allocated it with that layout) and not aliased.
        unsafe { ptr.as_ptr().write_bytes(0, rounded) };
        Some(Self {
            ptr,
            len: rounded,
            align,
        })
    }

    /// Borrow as an immutable byte slice.
    #[inline]
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is non-null, aligned (allocator gave it to us at the
        // requested alignment), and valid for reads of `len` bytes for the
        // lifetime tied to `&self`. The memory is initialised (we zeroed it in
        // `new`) and not aliased (we hold the only handle and return `&[u8]`).
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Borrow as a mutable byte slice.
    #[inline]
    pub const fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: same as `as_slice`, but `&mut self` proves exclusive access,
        // so a `&mut [u8]` cannot alias another reference.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Return the alignment the buffer was allocated with.
    #[inline]
    #[must_use]
    pub const fn alignment(&self) -> usize {
        self.align
    }

    /// Return the buffer length in bytes (always a multiple of [`alignment`](Self::alignment)).
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` if the buffer is zero-length.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Raw pointer for FFI (`io_uring`, `read`, `write`).
    #[inline]
    #[must_use]
    pub const fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Raw mutable pointer for FFI.
    #[inline]
    pub const fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Deref for AlignedBuf {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl DerefMut for AlignedBuf {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(self.len, self.align)
            .expect("layout cannot change after construction");
        // SAFETY: `layout` matches the one used in `with_alignment`. The pointer
        // came from the global allocator; we have not given it out anywhere
        // else; we are not aliased. After this call the pointer is invalid,
        // but we never use it again.
        unsafe { alloc::dealloc(self.ptr.as_ptr(), layout) };
    }
}

impl std::fmt::Debug for AlignedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBuf")
            .field("len", &self.len)
            .field("alignment", &self.align)
            .finish_non_exhaustive()
    }
}

/// Single-threaded LIFO pool of [`AlignedBuf`].
///
/// Use one pool per logical writer (WAL group-commit thread, SSTable flush
/// worker). Crossing threads requires an external `Mutex` or moving to a
/// crossbeam-deque-backed implementation.
pub struct BufferPool {
    free: Vec<AlignedBuf>,
    buf_size: usize,
    align: usize,
    capacity: usize,
}

impl BufferPool {
    /// Create an empty pool sized for buffers of `buf_size` bytes each, aligned
    /// to `align`. Up to `capacity` buffers are retained when returned.
    #[must_use]
    pub fn new(buf_size: usize, align: usize, capacity: usize) -> Self {
        Self {
            free: Vec::with_capacity(capacity),
            buf_size,
            align,
            capacity,
        }
    }

    /// Default-sized pool: 16 KiB buffers, 4 KiB-aligned, 64 retained.
    /// Tuned for SSTable data blocks.
    #[must_use]
    pub fn for_sstable_blocks() -> Self {
        Self::new(16 * 1024, PAGE_SIZE, 64)
    }

    /// Take a buffer from the pool, allocating fresh if the pool is empty.
    pub fn acquire(&mut self) -> Option<AlignedBuf> {
        self.free
            .pop()
            .or_else(|| AlignedBuf::with_alignment(self.buf_size, self.align))
    }

    /// Return a buffer to the pool. Buffers above the pool's capacity, or with
    /// the wrong size/alignment, are dropped instead of being retained.
    pub fn release(&mut self, buf: AlignedBuf) {
        if self.free.len() < self.capacity
            && buf.len() == self.buf_size
            && buf.alignment() == self.align
        {
            self.free.push(buf);
        }
    }

    /// Number of buffers currently parked in the pool.
    #[must_use]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::len is not yet const fn on stable; promote when MSRV bumps"
    )]
    pub fn idle_count(&self) -> usize {
        self.free.len()
    }
}

#[inline]
const fn round_up(value: usize, multiple: usize) -> usize {
    let rem = value % multiple;
    if rem == 0 {
        value
    } else {
        value + (multiple - rem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_up_handles_aligned_and_unaligned() {
        assert_eq!(round_up(0, 4096), 0);
        assert_eq!(round_up(1, 4096), 4096);
        assert_eq!(round_up(4095, 4096), 4096);
        assert_eq!(round_up(4096, 4096), 4096);
        assert_eq!(round_up(4097, 4096), 8192);
    }

    #[test]
    fn aligned_buf_pointer_is_page_aligned() {
        let buf = AlignedBuf::new(8192).unwrap();
        assert_eq!(buf.as_ptr() as usize % PAGE_SIZE, 0);
        assert_eq!(buf.len(), 8192);
        assert_eq!(buf.alignment(), PAGE_SIZE);
    }

    #[test]
    fn aligned_buf_rounds_length_up() {
        let buf = AlignedBuf::new(1).unwrap();
        assert_eq!(buf.len(), PAGE_SIZE);
        let buf = AlignedBuf::new(PAGE_SIZE + 1).unwrap();
        assert_eq!(buf.len(), 2 * PAGE_SIZE);
    }

    #[test]
    fn aligned_buf_zero_length_request_yields_one_page() {
        let buf = AlignedBuf::new(0).unwrap();
        assert_eq!(buf.len(), PAGE_SIZE);
        assert!(!buf.is_empty());
    }

    #[test]
    fn aligned_buf_is_zero_initialised() {
        let buf = AlignedBuf::new(8192).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn aligned_buf_supports_mutation_via_deref() {
        let mut buf = AlignedBuf::new(4096).unwrap();
        buf[0] = 0xAA;
        buf[4095] = 0xBB;
        assert_eq!(buf[0], 0xAA);
        assert_eq!(buf[4095], 0xBB);
    }

    #[test]
    fn aligned_buf_custom_alignment_64_is_cache_line() {
        let buf = AlignedBuf::with_alignment(128, 64).unwrap();
        assert_eq!(buf.as_ptr() as usize % 64, 0);
        assert_eq!(buf.len(), 128);
        assert_eq!(buf.alignment(), 64);
    }

    #[test]
    #[should_panic(expected = "alignment must be a power of two")]
    fn aligned_buf_rejects_non_power_of_two_alignment() {
        let _ = AlignedBuf::with_alignment(4096, 3);
    }

    #[test]
    fn buffer_pool_acquires_fresh_then_recycles() {
        let mut pool = BufferPool::new(4096, PAGE_SIZE, 4);
        assert_eq!(pool.idle_count(), 0);

        let buf_a = pool.acquire().unwrap();
        assert_eq!(buf_a.len(), 4096);
        pool.release(buf_a);
        assert_eq!(pool.idle_count(), 1);

        let buf_b = pool.acquire().unwrap();
        assert_eq!(pool.idle_count(), 0);
        pool.release(buf_b);
    }

    #[test]
    fn buffer_pool_caps_at_capacity() {
        let mut pool = BufferPool::new(4096, PAGE_SIZE, 2);
        for _ in 0..5 {
            let b = pool.acquire().unwrap();
            pool.release(b);
        }
        assert_eq!(pool.idle_count(), 1);
    }

    #[test]
    fn buffer_pool_rejects_mismatched_buffer_on_release() {
        let mut pool = BufferPool::new(4096, PAGE_SIZE, 4);
        // Wrong size.
        let foreign = AlignedBuf::new(8192).unwrap();
        pool.release(foreign);
        assert_eq!(pool.idle_count(), 0);
    }
}
