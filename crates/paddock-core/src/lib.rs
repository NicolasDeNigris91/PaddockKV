//! `paddock-core` — the PaddockKV LSM-tree engine.
//!
//! This crate is the storage engine. It is organized into modules that mirror
//! the layered architecture described in `docs/ARCHITECTURE.md`:
//!
//! - [`encoding`] — variable-length integers and prefix-shared byte encoding.
//! - [`checksum`] — CRC32C and XXH3-64 wrappers used by WAL and SSTable formats.
//! - [`error`]    — error tree shared by every module.
//!
//! Higher layers (`memtable`, `wal`, `sstable`, `filter`, `io`, `compaction`,
//! `manifest`, `cache`, `crypto`) come online in subsequent phases of the
//! implementation roadmap.
//!
//! Public surface is intentionally small in Phase 0; only the foundational
//! primitives are exposed so that downstream modules can be built and tested
//! incrementally.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod checksum;
pub mod encoding;
pub mod error;

pub use error::{Error, Result};
