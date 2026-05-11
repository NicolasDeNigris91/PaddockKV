//! I/O primitives.
//!
//! This module hosts the low-level abstractions the engine uses to talk to
//! storage. The real implementations target Linux exclusively (`mmap`, `madvise`,
//! `O_DIRECT`, `io_uring`); on other operating systems only the platform-
//! agnostic types — the page-aligned buffer allocator and the [`vfs`] testing
//! seam — are available. This keeps the crate compilable on a developer's
//! workstation while making the production target unambiguous.
//!
//! ## Layout
//!
//! - [`aligned_buf`] — `Box<[u8]>` allocator that returns memory whose start
//!   address is a multiple of the system page size. Required for `O_DIRECT`
//!   and used pervasively by the WAL writer, SSTable writer, and compaction.
//! - [`vfs`] — a small trait that real I/O code is written against. An
//!   in-memory implementation makes higher-level modules unit-testable
//!   without touching disk.
//! - [`mmap`] *(Linux)* — read-only mmap regions used by SSTable point-read
//!   paths, with `madvise` hint helpers.
//! - [`direct`] *(Linux)* — `O_DIRECT` file abstraction used by SSTable
//!   writers and compaction-time bulk reads.
//! - [`uring`] *(Linux)* — `io_uring` instance management, SQPOLL setup,
//!   linked-SQE helpers for write+fdatasync group commit.
//!
//! ## Why no portable abstraction
//!
//! PaddockKV's performance claims rest on Linux-specific primitives that have
//! no faithful equivalents on other systems. A portable abstraction would
//! either lie about its semantics or force callers to test capability bits at
//! every call site. We pick neither and instead route every production-target
//! code path through `#[cfg(target_os = "linux")]`.

pub mod aligned_buf;
pub mod vfs;

#[cfg(target_os = "linux")]
pub mod direct;
#[cfg(target_os = "linux")]
pub mod mmap;
#[cfg(target_os = "linux")]
pub mod uring;
