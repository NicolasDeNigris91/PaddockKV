// In this module we cast `*mut u8` (returned from
// `alloc::alloc(layout)` with a power-of-two alignment) to `*mut Slab`. The
// allocator guarantees the cast is aligned. `cast_ptr_alignment` cannot see
// past `alloc::alloc` and flags the cast pessimistically.
#![allow(clippy::cast_ptr_alignment)]
// Bump-allocator pointer arithmetic groups several `unsafe` ops that share a
// single invariant (the pointer is the start of a freshly allocated
// slab/object). Splitting them per-op would obscure the invariant rather
// than clarify it, so we keep them in shared blocks with SAFETY comments.
#![allow(clippy::multiple_unsafe_ops_per_block)]

//! Bump-allocator for skip-list nodes.
//!
//! The arena holds every byte that backs a memtable: node headers, forward
//! pointer arrays, inline keys, and inline values. When the memtable is
//! flushed and dropped, the entire arena returns its memory to the global
//! allocator in one shot — no per-node `free` calls, no fragmentation, no
//! `Drop` traversal of a million skip-list nodes.
//!
//! ## Layout
//!
//! Memory is grown as a linked list of **slabs**. Each slab is a fixed-size
//! page-aligned heap allocation. Allocations bump an offset inside the
//! current head slab; when the head slab is too full to satisfy a request,
//! the arena allocates a fresh slab (twice the size of the previous one,
//! up to a cap) and chains it in.
//!
//! ## Threading
//!
//! Phase-3 memtables have a single writer thread; allocation is therefore
//! a non-atomic bump. Reads happen on other threads but only against bytes
//! that were already allocated and published via [`Release`](std::sync::atomic::Ordering::Release)
//! stores by the writer — once published, those bytes never move and never
//! change.
//!
//! Upgrading to multi-writer allocation later is a localised change:
//! `bump_offset: usize` becomes `AtomicUsize`, and `add_slab` takes a
//! `Mutex` for the rare grow path.

use std::alloc::{self, Layout};
use std::cell::Cell;
use std::ptr::NonNull;

/// Default initial slab size: 256 KiB. Doubles up to [`MAX_SLAB_SIZE`].
pub const INITIAL_SLAB_SIZE: usize = 256 * 1024;

/// Slab growth cap: 4 MiB.
pub const MAX_SLAB_SIZE: usize = 4 * 1024 * 1024;

/// Default alignment for arena allocations: 8 bytes (sufficient for
/// `AtomicPtr<T>` and `u64`).
pub const DEFAULT_ALIGN: usize = 8;

/// Single-writer bump allocator.
///
/// `Arena` is `Send` but **not** `Sync` — only one thread allocates at a
/// time. Concurrent readers operate on `*const u8` pointers returned by the
/// writer; the arena itself is not consulted by readers.
pub struct Arena {
    /// Head of the slab list. Each slab points to the previous one.
    /// `None` means an empty arena (no allocations made yet).
    head: Cell<Option<NonNull<Slab>>>,
    /// Free byte offset within the head slab.
    bump_offset: Cell<usize>,
    /// Capacity of the next slab to allocate (doubling growth, capped).
    next_slab_size: Cell<usize>,
    /// Total user-visible bytes the arena has dispensed (excludes slab
    /// headers and unused tail bytes).
    bytes_used: Cell<usize>,
    /// Total bytes the arena holds (sum of slab capacities).
    bytes_reserved: Cell<usize>,
}

/// SAFETY: `Arena` owns its slab heap allocations; sending it across thread
/// boundaries is safe because the contents are raw bytes. It is not `Sync`
/// because allocation mutates `Cell`s.
unsafe impl Send for Arena {}

/// On-disk-style header that precedes every slab's payload. Lives at the
/// start of each slab so the list can be walked in `Drop`.
#[repr(C)]
struct Slab {
    /// Pointer to the previous slab in the list (`None` on the eldest).
    prev: Option<NonNull<Self>>,
    /// Total slab capacity in bytes, including this header.
    capacity: usize,
}

const SLAB_HEADER_SIZE: usize = std::mem::size_of::<Slab>();

impl Arena {
    /// Construct an empty arena. No memory is allocated until the first
    /// [`allocate`](Self::allocate) call.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            head: Cell::new(None),
            bump_offset: Cell::new(0),
            next_slab_size: Cell::new(INITIAL_SLAB_SIZE),
            bytes_used: Cell::new(0),
            bytes_reserved: Cell::new(0),
        }
    }

    /// Total bytes the arena has dispensed to callers.
    #[must_use]
    pub const fn bytes_used(&self) -> usize {
        self.bytes_used.get()
    }

    /// Total bytes the arena currently holds across all slabs.
    #[must_use]
    pub const fn bytes_reserved(&self) -> usize {
        self.bytes_reserved.get()
    }

    /// Allocate `size` bytes aligned to `align`.
    ///
    /// Returns a pointer valid for `size` bytes for the lifetime of the
    /// arena. The bytes are uninitialised; the caller is responsible for
    /// writing them before publishing.
    ///
    /// Panics if `align` is not a power of two.
    pub fn allocate(&self, size: usize, align: usize) -> NonNull<u8> {
        assert!(align.is_power_of_two(), "alignment must be a power of two");
        // Round size up to the alignment so the next allocation starts on a
        // multiple of `align`.
        let req = round_up(size, align).max(1);

        if let Some(slab) = self.head.get() {
            let after_header = SLAB_HEADER_SIZE;
            // SAFETY: slab pointer is valid for the lifetime of this arena.
            let slab_cap = unsafe { slab.as_ref().capacity };
            let aligned_start = round_up(after_header + self.bump_offset.get(), align);
            let end = aligned_start + req;
            if end <= slab_cap {
                self.bump_offset.set(end - after_header);
                self.bytes_used.set(self.bytes_used.get() + req);
                // SAFETY: `aligned_start..end` is within the slab.
                let ptr = unsafe { slab.as_ptr().cast::<u8>().add(aligned_start) };
                // SAFETY: pointer is non-null by construction (slab is non-null).
                return unsafe { NonNull::new_unchecked(ptr) };
            }
        }

        // Need a new slab. Grow geometrically, but ensure the new slab can
        // satisfy this allocation.
        let want = (req + SLAB_HEADER_SIZE + align).max(self.next_slab_size.get());
        let new_cap = want.min(MAX_SLAB_SIZE.max(want)); // never below `want`
        self.grow(new_cap);
        // Recursive once: now we have a head slab with enough room.
        self.allocate(size, align)
    }

    /// Bulk copy `src` into the arena, returning a pointer to the copied
    /// bytes. Useful for keys and values whose layout we do not know in
    /// advance.
    pub fn copy_bytes(&self, src: &[u8]) -> NonNull<u8> {
        let dst = self.allocate(src.len(), 1);
        // SAFETY: `dst` is valid for `src.len()` bytes (we just allocated
        // them). `src` is a valid slice. The two regions cannot overlap —
        // arena memory is freshly allocated.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_ptr(), src.len());
        }
        dst
    }

    fn grow(&self, capacity: usize) {
        // Compute layout. The slab is `Slab` header followed by `capacity -
        // SLAB_HEADER_SIZE` payload bytes; align to `DEFAULT_ALIGN`.
        let layout = Layout::from_size_align(capacity, DEFAULT_ALIGN)
            .expect("slab layout (cap and DEFAULT_ALIGN are both reasonable)");
        // SAFETY: `layout` has non-zero size (we ensured cap > SLAB_HEADER_SIZE
        // via the `want` calculation in `allocate`) and a power-of-two
        // alignment. `alloc::alloc` is the documented way to obtain a fresh
        // heap allocation.
        let raw = unsafe { alloc::alloc(layout) };
        let slab_ptr =
            NonNull::new(raw.cast::<Slab>()).expect("arena slab allocation failed (out of memory)");
        // Initialise the slab header.
        let prev = self.head.get();
        // SAFETY: `slab_ptr` is valid for writes of size `Slab` (we just
        // allocated `capacity` bytes which exceeds `SLAB_HEADER_SIZE`).
        unsafe {
            slab_ptr.as_ptr().write(Slab { prev, capacity });
        }
        self.head.set(Some(slab_ptr));
        self.bump_offset.set(0);
        self.bytes_reserved
            .set(self.bytes_reserved.get() + capacity);
        // Double the next slab size, capped.
        let next = self
            .next_slab_size
            .get()
            .saturating_mul(2)
            .min(MAX_SLAB_SIZE);
        self.next_slab_size.set(next);
    }
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        let mut cursor = self.head.get();
        while let Some(slab) = cursor {
            // SAFETY: slab pointer was allocated by `grow` with this same
            // layout; we are dropping the arena so no other reference to it
            // can exist.
            let (prev, capacity) = unsafe {
                let s = slab.as_ref();
                (s.prev, s.capacity)
            };
            let layout =
                Layout::from_size_align(capacity, DEFAULT_ALIGN).expect("layout reconstructable");
            // SAFETY: same layout used in `grow`. After `dealloc` returns,
            // `slab` is invalid, but we never use it again.
            unsafe {
                alloc::dealloc(slab.as_ptr().cast::<u8>(), layout);
            }
            cursor = prev;
        }
    }
}

impl std::fmt::Debug for Arena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Arena")
            .field("bytes_used", &self.bytes_used.get())
            .field("bytes_reserved", &self.bytes_reserved.get())
            .field("next_slab_size", &self.next_slab_size.get())
            .finish_non_exhaustive()
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
#[allow(
    clippy::cast_possible_truncation,
    reason = "test fixtures use small values where truncation cannot occur"
)]
mod tests {
    use super::*;

    #[test]
    fn empty_arena_holds_nothing() {
        let arena = Arena::new();
        assert_eq!(arena.bytes_used(), 0);
        assert_eq!(arena.bytes_reserved(), 0);
    }

    #[test]
    fn single_allocation_returns_aligned_pointer() {
        let arena = Arena::new();
        let p = arena.allocate(13, 8);
        let addr = p.as_ptr() as usize;
        assert_eq!(addr % 8, 0);
        assert!(arena.bytes_used() >= 13);
    }

    #[test]
    fn allocations_do_not_overlap() {
        let arena = Arena::new();
        let p1 = arena.allocate(100, 1);
        let p2 = arena.allocate(100, 1);
        let p3 = arena.allocate(100, 1);
        let a1 = p1.as_ptr() as usize;
        let a2 = p2.as_ptr() as usize;
        let a3 = p3.as_ptr() as usize;
        assert!(a2 >= a1 + 100);
        assert!(a3 >= a2 + 100);
    }

    #[test]
    fn copy_bytes_round_trips() {
        let arena = Arena::new();
        let src = b"hello arena, this is a test payload!";
        let p = arena.copy_bytes(src);
        // SAFETY: `p` points to `src.len()` bytes we just wrote.
        let view = unsafe { std::slice::from_raw_parts(p.as_ptr(), src.len()) };
        assert_eq!(view, src);
    }

    #[test]
    fn growth_handles_allocations_larger_than_initial_slab() {
        let arena = Arena::new();
        let big = INITIAL_SLAB_SIZE * 4;
        let p = arena.allocate(big, 8);
        assert_eq!(p.as_ptr() as usize % 8, 0);
        assert!(arena.bytes_reserved() >= big);
    }

    #[test]
    fn many_small_allocations_grow_arena() {
        let arena = Arena::new();
        for _ in 0..10_000 {
            arena.allocate(64, 8);
        }
        // 10_000 * 64 = 640_000 bytes used, which exceeds the initial slab
        // (256 KiB = 262_144 bytes). Must have grown.
        assert!(arena.bytes_reserved() > INITIAL_SLAB_SIZE);
    }

    #[test]
    fn alignment_request_is_respected_after_unaligned_allocation() {
        let arena = Arena::new();
        let _ = arena.allocate(1, 1); // unaligned
        let p = arena.allocate(8, 8);
        assert_eq!(p.as_ptr() as usize % 8, 0);
    }

    #[test]
    #[should_panic(expected = "alignment must be a power of two")]
    fn non_power_of_two_alignment_panics() {
        let arena = Arena::new();
        let _ = arena.allocate(8, 3);
    }
}
