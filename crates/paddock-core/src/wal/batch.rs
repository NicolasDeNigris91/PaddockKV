//! `WriteBatch` — the unit of durability the WAL records.
//!
//! A batch carries one or more *operations* against the key-value store:
//! puts and deletes. The engine assigns each batch a monotonic sequence
//! number; the WAL persists the encoded batch bytes as the payload of one
//! logical record.
//!
//! The wire encoding is compact and self-describing:
//!
//! ```text
//!   varint  op_count
//!   for each op:
//!     u8     op_type            (0 = Put, 1 = Delete)
//!     varint key_len
//!     bytes  key
//!     varint value_len           (Put only)
//!     bytes  value               (Put only)
//! ```
//!
//! Lengths are LEB128 varints because keys and values are typically much
//! smaller than 128 bytes — saving the four prefix bytes per op matters in
//! the hot WAL append path.

use crate::encoding::varint::{MAX_VARINT_U32_BYTES, decode_u32, encode_u32};
use crate::error::{DecodeError, Error, Result};

/// Maximum number of operations we accept in a single batch. Anything larger
/// is a bug in the caller — the engine fragments before reaching this.
pub const MAX_OPS_PER_BATCH: u32 = 1 << 20;

/// On-disk tag for [`Op::Put`].
pub const OP_PUT: u8 = 0;

/// On-disk tag for [`Op::Delete`].
pub const OP_DELETE: u8 = 1;

/// A single operation inside a [`WriteBatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Insert or overwrite the value for `key`.
    Put {
        /// Key bytes.
        key: Vec<u8>,
        /// Value bytes.
        value: Vec<u8>,
    },
    /// Tombstone for `key`.
    Delete {
        /// Key bytes.
        key: Vec<u8>,
    },
}

impl Op {
    /// Approximate encoded size (cheap; overestimates by at most 4 bytes).
    const fn encoded_size_hint(&self) -> usize {
        match self {
            Self::Put { key, value } => {
                1 + MAX_VARINT_U32_BYTES + key.len() + MAX_VARINT_U32_BYTES + value.len()
            }
            Self::Delete { key } => 1 + MAX_VARINT_U32_BYTES + key.len(),
        }
    }
}

/// A batch of operations that will be applied atomically: either every op in
/// the batch is durable, or none of them are.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteBatch {
    ops: Vec<Op>,
}

impl WriteBatch {
    /// Construct an empty batch.
    #[must_use]
    pub const fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Append a put.
    pub fn put(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> &mut Self {
        self.ops.push(Op::Put {
            key: key.into(),
            value: value.into(),
        });
        self
    }

    /// Append a delete.
    pub fn delete(&mut self, key: impl Into<Vec<u8>>) -> &mut Self {
        self.ops.push(Op::Delete { key: key.into() });
        self
    }

    /// Number of ops in the batch.
    #[must_use]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::len is not yet const fn on stable"
    )]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// `true` if the batch carries zero ops.
    #[must_use]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "Vec::is_empty is not yet const fn on stable"
    )]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Borrow the operations.
    #[must_use]
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    /// Encode the batch into a heap-allocated `Vec<u8>`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut hint = MAX_VARINT_U32_BYTES;
        for op in &self.ops {
            hint += op.encoded_size_hint();
        }
        let mut out = Vec::with_capacity(hint);
        self.encode_into(&mut out);
        out
    }

    /// Encode the batch into the supplied buffer (appended to whatever is
    /// already there).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut scratch = [0u8; MAX_VARINT_U32_BYTES];
        let count = u32::try_from(self.ops.len())
            .expect("op count never exceeds u32::MAX in any realistic batch");
        let n = encode_u32(count, &mut scratch).expect("u32 always fits");
        out.extend_from_slice(&scratch[..n]);
        for op in &self.ops {
            match op {
                Op::Put { key, value } => {
                    out.push(OP_PUT);
                    let klen = u32::try_from(key.len()).expect("key len fits in u32");
                    let n = encode_u32(klen, &mut scratch).expect("u32 always fits");
                    out.extend_from_slice(&scratch[..n]);
                    out.extend_from_slice(key);
                    let vlen = u32::try_from(value.len()).expect("value len fits in u32");
                    let n = encode_u32(vlen, &mut scratch).expect("u32 always fits");
                    out.extend_from_slice(&scratch[..n]);
                    out.extend_from_slice(value);
                }
                Op::Delete { key } => {
                    out.push(OP_DELETE);
                    let klen = u32::try_from(key.len()).expect("key len fits in u32");
                    let n = encode_u32(klen, &mut scratch).expect("u32 always fits");
                    out.extend_from_slice(&scratch[..n]);
                    out.extend_from_slice(key);
                }
            }
        }
    }

    /// Decode a batch from `bytes`. Returns an error if the bytes are
    /// truncated, have an unknown op tag, or claim a key/value length the
    /// remaining buffer cannot satisfy.
    pub fn decode(mut bytes: &[u8]) -> Result<Self> {
        let (op_count, consumed) = decode_u32(bytes)?;
        if op_count > MAX_OPS_PER_BATCH {
            return Err(Error::InvalidFormat {
                context: "WriteBatch",
                reason: format!("op_count {op_count} exceeds limit {MAX_OPS_PER_BATCH}"),
            });
        }
        bytes = &bytes[consumed..];

        let mut ops = Vec::with_capacity(op_count as usize);
        for _ in 0..op_count {
            let (tag, rest) = bytes
                .split_first()
                .ok_or(DecodeError::UnexpectedEof { needed: 1 })?;
            bytes = rest;
            match *tag {
                OP_PUT => {
                    let (klen, c) = decode_u32(bytes)?;
                    bytes = &bytes[c..];
                    let (key, rest) = take(bytes, usize_from_u32(klen))?;
                    bytes = rest;
                    let (vlen, c) = decode_u32(bytes)?;
                    bytes = &bytes[c..];
                    let (value, rest) = take(bytes, usize_from_u32(vlen))?;
                    bytes = rest;
                    ops.push(Op::Put {
                        key: key.to_vec(),
                        value: value.to_vec(),
                    });
                }
                OP_DELETE => {
                    let (klen, c) = decode_u32(bytes)?;
                    bytes = &bytes[c..];
                    let (key, rest) = take(bytes, usize_from_u32(klen))?;
                    bytes = rest;
                    ops.push(Op::Delete { key: key.to_vec() });
                }
                tag => {
                    return Err(Error::InvalidFormat {
                        context: "WriteBatch",
                        reason: format!("unknown op tag {tag:#04x}"),
                    });
                }
            }
        }

        if !bytes.is_empty() {
            return Err(Error::InvalidFormat {
                context: "WriteBatch",
                reason: format!("{} trailing bytes after final op", bytes.len()),
            });
        }
        Ok(Self { ops })
    }
}

fn take(bytes: &[u8], n: usize) -> Result<(&[u8], &[u8])> {
    if bytes.len() < n {
        return Err(DecodeError::UnexpectedEof {
            needed: n - bytes.len(),
        }
        .into());
    }
    Ok(bytes.split_at(n))
}

/// Convert a `u32` byte length to `usize`. On the engine's 64-bit targets this
/// is lossless; the helper exists so the cast site is explicit and clippy can
/// be calmed without scattering `#[allow]` attributes through the decoder.
#[inline]
const fn usize_from_u32(v: u32) -> usize {
    v as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(batch: &WriteBatch) {
        let encoded = batch.encode();
        let decoded = WriteBatch::decode(&encoded).expect("decode");
        assert_eq!(&decoded, batch);
    }

    #[test]
    fn empty_batch_encodes_to_one_byte() {
        let b = WriteBatch::new();
        let bytes = b.encode();
        assert_eq!(bytes, vec![0]);
        round_trip(&b);
    }

    #[test]
    fn put_round_trip() {
        let mut b = WriteBatch::new();
        b.put(b"hello".to_vec(), b"world".to_vec());
        round_trip(&b);
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn mixed_ops_round_trip() {
        let mut b = WriteBatch::new();
        b.put(b"a".to_vec(), b"1".to_vec())
            .delete(b"b".to_vec())
            .put(b"c".to_vec(), b"3".to_vec());
        round_trip(&b);
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn large_value_round_trip() {
        let mut b = WriteBatch::new();
        b.put(vec![0; 1024], vec![0xCC; 65_536]);
        round_trip(&b);
    }

    #[test]
    fn decode_rejects_unknown_tag() {
        // op_count=1, tag=0x7F (invalid)
        let bytes = [0x01, 0x7F];
        let err = WriteBatch::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat { .. }));
    }

    #[test]
    fn decode_rejects_truncated_key() {
        // op_count=1, tag=Put(0), key_len=5, but no key bytes
        let bytes = [0x01, OP_PUT, 0x05];
        let err = WriteBatch::decode(&bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Decode(DecodeError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut b = WriteBatch::new();
        b.put(b"k".to_vec(), b"v".to_vec());
        let mut bytes = b.encode();
        bytes.push(0xFF);
        let err = WriteBatch::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat { .. }));
    }

    #[test]
    fn decode_rejects_excessive_op_count() {
        // varint encoding of MAX_OPS_PER_BATCH + 1
        let bad = MAX_OPS_PER_BATCH + 1;
        let mut buf = [0u8; MAX_VARINT_U32_BYTES];
        let n = encode_u32(bad, &mut buf).unwrap();
        let err = WriteBatch::decode(&buf[..n]).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat { .. }));
    }

    proptest::proptest! {
        #[test]
        fn prop_round_trip(ops in proptest::collection::vec(any_op(), 0..32)) {
            let mut batch = WriteBatch::new();
            for op in ops {
                match op {
                    Op::Put { key, value } => { batch.put(key, value); }
                    Op::Delete { key }     => { batch.delete(key); }
                }
            }
            let encoded = batch.encode();
            let decoded = WriteBatch::decode(&encoded).expect("decode");
            assert_eq!(decoded, batch);
        }

        #[test]
        fn prop_decoder_never_panics(bytes: Vec<u8>) {
            let _ = WriteBatch::decode(&bytes);
        }
    }

    proptest::prop_compose! {
        fn any_op()(
            tag in proptest::bool::ANY,
            key in proptest::collection::vec(proptest::num::u8::ANY, 0..32),
            value in proptest::collection::vec(proptest::num::u8::ANY, 0..128),
        ) -> Op {
            if tag {
                Op::Put { key, value }
            } else {
                Op::Delete { key }
            }
        }
    }
}
