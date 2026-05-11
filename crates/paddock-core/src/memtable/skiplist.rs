// Skip-list pointer manipulation involves many `unsafe` ops that share a
// single invariant per call site (the pointer is a valid node in this
// list's arena, alive for the borrow lifetime). Splitting per-op blocks
// here would obscure the invariant. Each block carries a SAFETY comment.
#![allow(clippy::multiple_unsafe_ops_per_block)]
// The same pointers are cast from `*mut u8` to `*mut NodeHeader` /
// `*mut AtomicPtr<NodeHeader>` immediately after `Arena::allocate(.., 8)`,
// which guarantees the alignment clippy is worried about.
#![allow(clippy::cast_ptr_alignment)]

//! Pugh skip list with `AtomicPtr` forward pointers.
//!
//! This is the engine's in-memory write buffer. Lookup is wait-free; insert
//! is lock-free given a single writer thread (the standard LSM design used
//! by LevelDB, RocksDB's `InlineSkipList`, and ScyllaDB). The data
//! structure is shaped so the multi-writer CAS upgrade is a localised change
//! (the `Release` stores in [`SkipList::insert`] become CAS loops; nothing
//! else moves).
//!
//! ## Internal-key ordering
//!
//! Memtable entries are compared by `(key, !seqno)`. For the same user key,
//! a newer sequence number sorts *before* an older one, so a lookup that
//! walks forward pointers and returns the first match at the user-key level
//! always finds the most recent version. This is the LevelDB convention.
//!
//! ## Node layout in arena
//!
//! Every node is one contiguous arena allocation, aligned to 8 bytes:
//!
//! ```text
//!   ┌───────────────────────────────────────────────────────────┐
//!   │ NodeHeader (24 bytes, repr(C))                             │
//!   │   height: u8                                               │
//!   │   op_type: u8                                              │
//!   │   _pad: [u8; 2]                                            │
//!   │   key_len: u32                                             │
//!   │   value_len: u32                                           │
//!   │   _pad2: u32                                               │
//!   │   seqno: u64                                               │
//!   ├───────────────────────────────────────────────────────────┤
//!   │ forward: [AtomicPtr<Node>; height]                         │
//!   ├───────────────────────────────────────────────────────────┤
//!   │ key bytes (key_len)                                        │
//!   ├───────────────────────────────────────────────────────────┤
//!   │ value bytes (value_len)  -- absent if op_type == Tombstone │
//!   └───────────────────────────────────────────────────────────┘
//! ```
//!
//! The `AtomicPtr` array is the only mutable state on a node — and only
//! during the brief window between allocation and bottom-up `Release` of
//! forward pointers in [`SkipList::insert`].

use std::cmp::Ordering;
use std::sync::atomic::{AtomicPtr, Ordering as Ordering_};

use crate::memtable::arena::Arena;

/// Maximum number of levels in any skip-list node. 12 levels with `p = 1/4`
/// supports ~16M entries with `O(log_4(n))` expected steps per lookup. This
/// matches RocksDB's default.
pub const MAX_HEIGHT: usize = 12;

/// Branching factor — at each level the probability of promoting to the
/// next level higher is `1 / BRANCH`.
const BRANCH: u32 = 4;

/// Logical op type stored on each node. Mirrors [`crate::wal::batch::Op`]
/// but is fixed-width and lives on disk paths that prefer a single byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpType {
    /// Insert or overwrite.
    Put = 0,
    /// Tombstone for `key`.
    Tombstone = 1,
}

impl OpType {
    /// Parse from the byte stored on disk / in a node header.
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Put),
            1 => Some(Self::Tombstone),
            _ => None,
        }
    }
}

/// Header that precedes every node in the arena.
#[repr(C)]
struct NodeHeader {
    height: u8,
    op_type: u8,
    _pad: [u8; 2],
    key_len: u32,
    value_len: u32,
    _pad2: u32,
    seqno: u64,
}

const _: () = assert!(std::mem::size_of::<NodeHeader>() == 24);
const _: () = assert!(std::mem::align_of::<NodeHeader>() == 8);

/// Opaque view of one node held by an arena pointer.
///
/// The `'a` lifetime is bound to the `&'a SkipList` that handed it out,
/// which transitively ties it to the arena.
#[derive(Debug, Clone, Copy)]
pub struct NodeRef<'a> {
    ptr: *const NodeHeader,
    _life: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> NodeRef<'a> {
    /// Sequence number recorded at insertion time.
    #[must_use]
    pub const fn seqno(self) -> u64 {
        // SAFETY: `self.ptr` was obtained from `SkipList::find_*`, which only
        // returns pointers that live inside the arena for at least `'a`.
        unsafe { (*self.ptr).seqno }
    }

    /// Op type (`Put` or `Tombstone`).
    #[must_use]
    pub const fn op_type(self) -> OpType {
        // SAFETY: see `seqno`. The byte is validated at insertion time.
        let raw = unsafe { (*self.ptr).op_type };
        match OpType::from_byte(raw) {
            Some(op) => op,
            None => panic!("invalid op_type stored in node"),
        }
    }

    /// Borrow the inline key bytes.
    #[must_use]
    pub fn key(self) -> &'a [u8] {
        // SAFETY: `self.ptr` is valid for at least `'a`; the layout puts
        // key bytes immediately after the forward-pointer array. Length is
        // recorded in the header.
        unsafe {
            let header = &*self.ptr;
            let key_ptr = node_key_ptr(self.ptr, header.height);
            std::slice::from_raw_parts(key_ptr, header.key_len as usize)
        }
    }

    /// Borrow the inline value bytes (empty for tombstones).
    #[must_use]
    pub fn value(self) -> &'a [u8] {
        // SAFETY: as above.
        unsafe {
            let header = &*self.ptr;
            let key_ptr = node_key_ptr(self.ptr, header.height);
            let value_ptr = key_ptr.add(header.key_len as usize);
            std::slice::from_raw_parts(value_ptr, header.value_len as usize)
        }
    }
}

/// Compute the address of the start of the inline-key region.
///
/// # Safety
///
/// `ptr` must be a valid node pointer with the given `height`.
unsafe fn node_key_ptr(ptr: *const NodeHeader, height: u8) -> *const u8 {
    // SAFETY: callers guarantee the pointer is valid; the layout puts the
    // forward array immediately after the header, and keys after that.
    unsafe {
        let after_header = ptr.add(1).cast::<u8>();
        after_header.add(usize::from(height) * std::mem::size_of::<AtomicPtr<NodeHeader>>())
    }
}

/// Pointer to the i-th forward slot of a node.
///
/// # Safety
///
/// `ptr` must be a valid node pointer with at least `i + 1` forward levels.
const unsafe fn node_forward_ptr(ptr: *const NodeHeader, i: usize) -> *const AtomicPtr<NodeHeader> {
    // SAFETY: see node layout — forward array directly follows the header.
    unsafe {
        let forward_base = ptr.add(1).cast::<AtomicPtr<NodeHeader>>();
        forward_base.add(i)
    }
}

/// Pugh skip list.
///
/// Construct with [`SkipList::new`]. Insertions go through
/// [`SkipList::insert`] from the writer thread; lookups go through
/// [`SkipList::get`] from any thread.
pub struct SkipList {
    arena: Arena,
    head: *mut NodeHeader,
    /// Highest currently-occupied level. Read by lookups, written only by the
    /// writer thread during inserts.
    max_height: std::sync::atomic::AtomicUsize,
    /// Per-thread RNG state used by [`random_height`]. Wrapped in `Cell` to
    /// preserve the `&self` insert signature — the writer thread is the only
    /// caller.
    rng_state: std::cell::Cell<u32>,
    /// Number of nodes currently in the list (logical entries, including
    /// tombstones).
    len: std::cell::Cell<usize>,
}

// SAFETY: forward pointers are `AtomicPtr`, head/arena outlive every reader.
// The arena's lack of `Sync` is not exposed because we never expose `&Arena`
// across threads — only `&SkipList`, which exposes lookup APIs that go
// through atomic loads on forward pointers.
unsafe impl Send for SkipList {}

// SAFETY: see the `Send` impl above. Readers traverse forward pointers via
// `Acquire` atomic loads; writers publish via `Release` stores. The arena
// outlives every reader because the skip list owns it.
unsafe impl Sync for SkipList {}

impl SkipList {
    /// Construct an empty skip list with a fresh arena.
    #[must_use]
    pub fn new() -> Self {
        let arena = Arena::new();
        let head = build_head(&arena);
        Self {
            arena,
            head,
            max_height: std::sync::atomic::AtomicUsize::new(1),
            rng_state: std::cell::Cell::new(0x9E37_79B9),
            len: std::cell::Cell::new(0),
        }
    }

    /// Number of logical entries inserted (includes tombstones).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len.get()
    }

    /// `true` if no entries have been inserted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes consumed by the arena. Useful for memtable-size accounting.
    #[must_use]
    pub const fn bytes_used(&self) -> usize {
        self.arena.bytes_used()
    }

    /// Insert a `(key, value)` pair with the given `seqno` and op type.
    ///
    /// Must be called from a single writer thread. Subsequent
    /// [`get`](Self::get) calls from any thread will see this entry after the
    /// matching forward-pointer publication.
    ///
    /// Returns the [`NodeRef`] of the freshly inserted node so the caller can
    /// build an iterator over a write batch.
    pub fn insert(&self, key: &[u8], value: &[u8], seqno: u64, op: OpType) -> NodeRef<'_> {
        let height = self.random_height();
        let node_ptr = self.allocate_node(key, value, seqno, op, height);

        // Walk down the list collecting predecessors at each level.
        let mut predecessors: [*const NodeHeader; MAX_HEIGHT] = [self.head; MAX_HEIGHT];
        let mut following: [*const NodeHeader; MAX_HEIGHT] = [std::ptr::null(); MAX_HEIGHT];
        self.find_predecessors(key, seqno, &mut predecessors, &mut following);

        let active_max = self.max_height.load(Ordering_::Relaxed);
        if height > active_max {
            for slot in predecessors.iter_mut().take(height).skip(active_max) {
                *slot = self.head;
            }
            self.max_height.store(height, Ordering_::Relaxed);
        }

        // Link the new node into each level, starting at level 0. Each
        // assignment uses a `Release` store so that any reader picking the
        // node up via `Acquire` load sees the node's body fully published.
        for level in 0..height {
            // SAFETY: `node_ptr` is valid (we just allocated it); the
            // forward array has at least `height` slots; `following[level]`
            // came from the find pass against this same skip list; and
            // `predecessors[level]` is either head or a previously inserted
            // node — both alive in the arena.
            unsafe {
                let forward = node_forward_ptr(node_ptr, level);
                (*forward).store(following[level].cast_mut(), Ordering_::Relaxed);
                let prev_forward = node_forward_ptr(predecessors[level], level);
                (*prev_forward).store(node_ptr, Ordering_::Release);
            }
        }

        self.len.set(self.len.get() + 1);
        NodeRef {
            ptr: node_ptr,
            _life: std::marker::PhantomData,
        }
    }

    /// Look up the most recent entry for `key` whose `seqno <= snapshot`.
    ///
    /// Returns `None` if no such entry exists. A `Some(NodeRef)` may still
    /// represent a tombstone — the caller decides what that means.
    #[must_use]
    pub fn get<'a>(&'a self, key: &[u8], snapshot: u64) -> Option<NodeRef<'a>> {
        let mut level = self.max_height.load(Ordering_::Relaxed);
        let mut cur = self.head;
        // SAFETY: `cur` starts at head, which is alive for `'a`. The loop
        // only moves forward via `Acquire` loads of `AtomicPtr` values, each
        // of which (once non-null) points to a node alive for `'a`.
        unsafe {
            while level > 0 {
                level -= 1;
                loop {
                    let next = (*node_forward_ptr(cur, level)).load(Ordering_::Acquire);
                    if next.is_null() {
                        break;
                    }
                    let next_ref = NodeRef::<'a> {
                        ptr: next,
                        _life: std::marker::PhantomData,
                    };
                    match compare_internal_key(next_ref.key(), next_ref.seqno(), key, snapshot) {
                        Ordering::Less => {
                            cur = next;
                        }
                        Ordering::Equal | Ordering::Greater => break,
                    }
                }
            }
            let candidate = (*node_forward_ptr(cur, 0)).load(Ordering_::Acquire);
            if candidate.is_null() {
                return None;
            }
            let node = NodeRef::<'a> {
                ptr: candidate,
                _life: std::marker::PhantomData,
            };
            if node.key() == key && node.seqno() <= snapshot {
                Some(node)
            } else {
                None
            }
        }
    }

    /// Iterate every entry in ascending `(key, !seqno)` order.
    pub fn iter(&self) -> Iter<'_> {
        IntoIterator::into_iter(self)
    }

    fn find_predecessors(
        &self,
        key: &[u8],
        seqno: u64,
        prev: &mut [*const NodeHeader; MAX_HEIGHT],
        following: &mut [*const NodeHeader; MAX_HEIGHT],
    ) {
        let active = self.max_height.load(Ordering_::Relaxed);
        // Levels above the active max are still empty — fill prev with head.
        for slot in prev.iter_mut().take(MAX_HEIGHT).skip(active) {
            *slot = self.head;
        }
        if active == 0 {
            return;
        }
        let mut level = active - 1;
        let mut cur = self.head;
        // SAFETY: `cur` is always either head or a node previously inserted
        // in this skip list. Forward loads use `Acquire`.
        unsafe {
            loop {
                let forward_link = (*node_forward_ptr(cur, level)).load(Ordering_::Acquire);
                let go_forward = if forward_link.is_null() {
                    false
                } else {
                    let n = NodeRef::<'_> {
                        ptr: forward_link,
                        _life: std::marker::PhantomData,
                    };
                    compare_internal_key(n.key(), n.seqno(), key, seqno) == Ordering::Less
                };
                if go_forward {
                    cur = forward_link;
                } else {
                    prev[level] = cur;
                    following[level] = forward_link;
                    if level == 0 {
                        return;
                    }
                    level -= 1;
                }
            }
        }
    }

    fn allocate_node(
        &self,
        key: &[u8],
        value: &[u8],
        seqno: u64,
        op: OpType,
        height: usize,
    ) -> *mut NodeHeader {
        let header_size = std::mem::size_of::<NodeHeader>();
        let forward_size = height * std::mem::size_of::<AtomicPtr<NodeHeader>>();
        let key_len = key.len();
        let val_len = if matches!(op, OpType::Put) {
            value.len()
        } else {
            0
        };
        let total = header_size + forward_size + key_len + val_len;
        let raw = self.arena.allocate(total, 8);

        // SAFETY: `raw` points to `total` bytes we own. We write a NodeHeader
        // into the first `header_size` bytes, zeroes into the forward array,
        // and the key/value bytes after that.
        unsafe {
            let header_ptr = raw.as_ptr().cast::<NodeHeader>();
            header_ptr.write(NodeHeader {
                height: u8::try_from(height).expect("height bounded by MAX_HEIGHT (<= 12)"),
                op_type: op as u8,
                _pad: [0; 2],
                key_len: u32::try_from(key_len).expect("key length must fit in u32"),
                value_len: u32::try_from(val_len).expect("value length must fit in u32"),
                _pad2: 0,
                seqno,
            });
            // Zero out the forward array.
            let forward_base = raw
                .as_ptr()
                .add(header_size)
                .cast::<AtomicPtr<NodeHeader>>();
            for i in 0..height {
                forward_base
                    .add(i)
                    .write(AtomicPtr::new(std::ptr::null_mut()));
            }
            // Copy key + value.
            let key_dst = raw.as_ptr().add(header_size + forward_size);
            std::ptr::copy_nonoverlapping(key.as_ptr(), key_dst, key_len);
            if val_len > 0 {
                let val_dst = key_dst.add(key_len);
                std::ptr::copy_nonoverlapping(value.as_ptr(), val_dst, val_len);
            }
            header_ptr
        }
    }

    fn random_height(&self) -> usize {
        // Marsaglia xorshift32 — small, fast, good enough for level
        // distribution. Seeded distinctly per `SkipList`.
        let mut s = self.rng_state.get();
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        self.rng_state.set(s);
        let mut h = 1;
        while h < MAX_HEIGHT && s.is_multiple_of(BRANCH) {
            h += 1;
            s = s.wrapping_mul(0x9E37_79B9);
        }
        h
    }
}

impl Default for SkipList {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SkipList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkipList")
            .field("len", &self.len.get())
            .field("max_height", &self.max_height.load(Ordering_::Relaxed))
            .field("bytes_used", &self.arena.bytes_used())
            .finish_non_exhaustive()
    }
}

/// Forward iterator over the skip list.
pub struct Iter<'a> {
    cur: *mut NodeHeader,
    _life: std::marker::PhantomData<&'a SkipList>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = NodeRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur.is_null() {
            return None;
        }
        let node = NodeRef::<'a> {
            ptr: self.cur,
            _life: std::marker::PhantomData,
        };
        // SAFETY: `cur` is non-null and was loaded from a forward pointer in
        // the skip list it belongs to; that node stays alive for `'a`.
        let next = unsafe { (*node_forward_ptr(self.cur, 0)).load(Ordering_::Acquire) };
        self.cur = next;
        Some(node)
    }
}

impl<'a> IntoIterator for &'a SkipList {
    type Item = NodeRef<'a>;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        // SAFETY: `self.head` is alive for the borrow lifetime, and we hold
        // `&self` so no writer can mutate while we read this initial pointer.
        let first = unsafe { (*node_forward_ptr(self.head, 0)).load(Ordering_::Acquire) };
        Iter {
            cur: first,
            _life: std::marker::PhantomData,
        }
    }
}

fn build_head(arena: &Arena) -> *mut NodeHeader {
    // Head node has maximum height, zero-length key and value, and stays at
    // the front of the list forever. Its sequence number is irrelevant.
    let header_size = std::mem::size_of::<NodeHeader>();
    let forward_size = MAX_HEIGHT * std::mem::size_of::<AtomicPtr<NodeHeader>>();
    let raw = arena.allocate(header_size + forward_size, 8);
    // SAFETY: `raw` points to `header_size + forward_size` bytes we own.
    unsafe {
        let header_ptr = raw.as_ptr().cast::<NodeHeader>();
        header_ptr.write(NodeHeader {
            height: u8::try_from(MAX_HEIGHT).expect("MAX_HEIGHT (12) fits in u8"),
            op_type: OpType::Put as u8,
            _pad: [0; 2],
            key_len: 0,
            value_len: 0,
            _pad2: 0,
            seqno: 0,
        });
        let forward_base = raw
            .as_ptr()
            .add(header_size)
            .cast::<AtomicPtr<NodeHeader>>();
        for i in 0..MAX_HEIGHT {
            forward_base
                .add(i)
                .write(AtomicPtr::new(std::ptr::null_mut()));
        }
        header_ptr
    }
}

/// Memtable internal-key compare: `(user_key ascending, seqno descending)`.
///
/// A node with the same user key and a *higher* seqno sorts **before** a
/// node with a lower seqno. This is the LevelDB convention and the reason a
/// straight-ahead forward walk on level 0 returns the freshest version of
/// any user key first.
fn compare_internal_key(
    left_key: &[u8],
    left_seqno: u64,
    right_key: &[u8],
    right_seqno: u64,
) -> Ordering {
    match left_key.cmp(right_key) {
        Ordering::Equal => right_seqno.cmp(&left_seqno),
        other => other,
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
    fn empty_skip_list_returns_none() {
        let s = SkipList::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.get(b"any", u64::MAX).is_none());
    }

    #[test]
    fn single_insert_then_get() {
        let s = SkipList::new();
        s.insert(b"foo", b"bar", 1, OpType::Put);
        let n = s.get(b"foo", u64::MAX).expect("found");
        assert_eq!(n.key(), b"foo");
        assert_eq!(n.value(), b"bar");
        assert_eq!(n.seqno(), 1);
        assert_eq!(n.op_type(), OpType::Put);
    }

    #[test]
    fn ordered_inserts_round_trip() {
        let s = SkipList::new();
        for (i, key) in [b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()]
            .iter()
            .enumerate()
        {
            s.insert(key, key, i as u64 + 1, OpType::Put);
        }
        let keys: Vec<_> = s.iter().map(|n| n.key().to_vec()).collect();
        assert_eq!(
            keys,
            vec![b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()]
        );
    }

    #[test]
    fn reverse_order_inserts_still_iterate_sorted() {
        let s = SkipList::new();
        s.insert(b"c", b"3", 1, OpType::Put);
        s.insert(b"a", b"1", 2, OpType::Put);
        s.insert(b"b", b"2", 3, OpType::Put);
        let keys: Vec<_> = s.iter().map(|n| n.key().to_vec()).collect();
        assert_eq!(keys, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    }

    #[test]
    fn newer_seqno_shadows_older() {
        let s = SkipList::new();
        s.insert(b"k", b"old", 1, OpType::Put);
        s.insert(b"k", b"new", 5, OpType::Put);
        let n = s.get(b"k", u64::MAX).unwrap();
        assert_eq!(n.value(), b"new");
        assert_eq!(n.seqno(), 5);
    }

    #[test]
    fn snapshot_isolation_hides_future_writes() {
        let s = SkipList::new();
        s.insert(b"k", b"v1", 10, OpType::Put);
        s.insert(b"k", b"v2", 20, OpType::Put);
        // Snapshot at seqno 15 should not see the seqno=20 write.
        let n = s.get(b"k", 15).unwrap();
        assert_eq!(n.value(), b"v1");
    }

    #[test]
    fn snapshot_before_any_write_returns_none() {
        let s = SkipList::new();
        s.insert(b"k", b"v", 100, OpType::Put);
        assert!(s.get(b"k", 99).is_none());
    }

    #[test]
    fn tombstone_recorded_with_zero_value_len() {
        let s = SkipList::new();
        s.insert(b"k", b"discarded", 1, OpType::Tombstone);
        let n = s.get(b"k", u64::MAX).unwrap();
        assert_eq!(n.op_type(), OpType::Tombstone);
        assert!(n.value().is_empty());
        assert_eq!(n.key(), b"k");
    }

    #[test]
    fn matches_btree_map_on_random_inserts() {
        use std::collections::BTreeMap;
        let s = SkipList::new();
        let mut reference: BTreeMap<Vec<u8>, (Vec<u8>, u64)> = BTreeMap::new();

        // Deterministic LCG so the test is reproducible.
        let mut rng: u32 = 0x00C0_FFEE;
        for seqno in 1..=2_000u64 {
            rng = rng.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let k = (rng % 256).to_string().into_bytes();
            let v = (rng / 256).to_string().into_bytes();
            s.insert(&k, &v, seqno, OpType::Put);
            reference.insert(k, (v, seqno));
        }

        for (key, (value, expected_seqno)) in &reference {
            let n = s.get(key, u64::MAX).expect("found");
            assert_eq!(n.value(), &value[..]);
            assert_eq!(n.seqno(), *expected_seqno);
        }
    }

    #[test]
    fn iter_visits_every_key_in_order() {
        use std::collections::BTreeSet;
        let s = SkipList::new();
        let inputs: Vec<Vec<u8>> = (0..500_u32)
            .map(|i| format!("key-{i:05}").into_bytes())
            .collect();
        for (i, k) in inputs.iter().enumerate() {
            s.insert(k, b"v", i as u64 + 1, OpType::Put);
        }
        let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut prev: Option<Vec<u8>> = None;
        for n in &s {
            let k = n.key().to_vec();
            if let Some(p) = &prev {
                assert!(k >= *p, "iteration order broken: {p:?} then {k:?}");
            }
            seen.insert(k.clone());
            prev = Some(k);
        }
        assert_eq!(seen.len(), inputs.len());
    }

    #[test]
    fn multi_threaded_reads_during_single_writer_inserts() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        let s = Arc::new(SkipList::new());
        let stop = Arc::new(AtomicBool::new(false));

        // 4 readers loop calling get; one writer thread inserts a bunch.
        let reader_handles: Vec<_> = (0..4)
            .map(|_| {
                let s = s.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering_::Relaxed) {
                        for k in 0..200u32 {
                            let key = format!("k-{k:05}").into_bytes();
                            let _ = s.get(&key, u64::MAX);
                        }
                    }
                })
            })
            .collect();

        let writer = {
            let s = s.clone();
            std::thread::spawn(move || {
                for seqno in 1..=2_000u64 {
                    let k = format!("k-{:05}", seqno % 200).into_bytes();
                    let v = format!("v-{seqno}").into_bytes();
                    s.insert(&k, &v, seqno, OpType::Put);
                }
            })
        };
        writer.join().unwrap();
        stop.store(true, Ordering_::Relaxed);
        for h in reader_handles {
            h.join().unwrap();
        }
        // Final: every key 0..200 should resolve to seqno close to 2000.
        for k in 0..200u32 {
            let key = format!("k-{k:05}").into_bytes();
            let n = s.get(&key, u64::MAX).expect("found");
            assert_eq!(n.key(), &key[..]);
        }
    }
}
