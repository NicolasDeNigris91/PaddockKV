//! LEB128 variable-length unsigned integer codec.
//!
//! Each 7-bit group is emitted little-endian, with the most significant bit
//! used as a continuation flag. Worst-case sizes:
//!
//! | Type  | Bytes |
//! |-------|-------|
//! | `u32` |   5   |
//! | `u64` |  10   |
//!
//! All entry points are zero-allocation and `#[inline]` so the codec inlines
//! into hot loops in WAL record framing and SSTable block scans.

use crate::error::{DecodeError, Result};

/// Maximum bytes a `u32` ever occupies in LEB128 form.
pub const MAX_VARINT_U32_BYTES: usize = 5;

/// Maximum bytes a `u64` ever occupies in LEB128 form.
pub const MAX_VARINT_U64_BYTES: usize = 10;

/// Returns the number of bytes required to encode `value` as a varint.
#[inline]
#[must_use]
pub const fn varint_u64_len(value: u64) -> usize {
    // ceil(bit_length(value) / 7), with a minimum of 1.
    let bits = 64 - value.leading_zeros() as usize;
    if bits == 0 { 1 } else { bits.div_ceil(7) }
}

/// Encode `value` into `buf`, returning the number of bytes written.
///
/// Returns `None` if `buf` is too short. The caller is expected to size `buf`
/// at [`MAX_VARINT_U64_BYTES`] for the worst case.
#[inline]
#[allow(
    clippy::cast_possible_truncation,
    reason = "we explicitly want the low 8 bits — the high bits are shifted out on the next iteration"
)]
pub fn encode_u64(mut value: u64, buf: &mut [u8]) -> Option<usize> {
    let mut i = 0;
    while value >= 0x80 {
        if i >= buf.len() {
            return None;
        }
        buf[i] = (value as u8) | 0x80;
        value >>= 7;
        i += 1;
    }
    if i >= buf.len() {
        return None;
    }
    buf[i] = value as u8;
    Some(i + 1)
}

/// Encode `value` into `buf`, returning the number of bytes written.
#[inline]
pub fn encode_u32(value: u32, buf: &mut [u8]) -> Option<usize> {
    encode_u64(u64::from(value), buf)
}

/// Decode a `u64` varint from the front of `input`.
///
/// Returns the decoded value and the consumed byte count. Errors:
///
/// - [`DecodeError::UnexpectedEof`] if the input ends before the terminator.
/// - [`DecodeError::VarintOverflow`] if more than ten bytes have the continuation
///   bit set, or if the tenth byte sets bits beyond `u64::MAX`.
#[inline]
pub fn decode_u64(input: &[u8]) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;

    for (i, &byte) in input.iter().enumerate().take(MAX_VARINT_U64_BYTES) {
        // Top bit is the continuation flag; lower 7 are payload.
        let payload = u64::from(byte & 0x7F);

        // On the 10th byte the only legal payload bits are the lowest one (since
        // 9 * 7 = 63, leaving room for exactly 1 more bit before overflowing u64).
        if i == MAX_VARINT_U64_BYTES - 1 && payload > 0x01 {
            return Err(DecodeError::VarintOverflow {
                max_bytes: MAX_VARINT_U64_BYTES,
            }
            .into());
        }

        result |= payload << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }

    if input.len() < MAX_VARINT_U64_BYTES {
        Err(DecodeError::UnexpectedEof {
            needed: MAX_VARINT_U64_BYTES - input.len(),
        }
        .into())
    } else {
        Err(DecodeError::VarintOverflow {
            max_bytes: MAX_VARINT_U64_BYTES,
        }
        .into())
    }
}

/// Decode a `u32` varint from the front of `input`.
///
/// Returns the decoded value and the consumed byte count. Errors mirror
/// [`decode_u64`] but with a 5-byte limit.
#[inline]
pub fn decode_u32(input: &[u8]) -> Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;

    for (i, &byte) in input.iter().enumerate().take(MAX_VARINT_U32_BYTES) {
        let payload = u32::from(byte & 0x7F);

        // On the 5th byte only the bottom 4 bits are legal payload (since
        // 4 * 7 = 28, leaving room for exactly 4 more bits before overflowing u32).
        if i == MAX_VARINT_U32_BYTES - 1 && payload > 0x0F {
            return Err(DecodeError::VarintOverflow {
                max_bytes: MAX_VARINT_U32_BYTES,
            }
            .into());
        }

        result |= payload << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }

    if input.len() < MAX_VARINT_U32_BYTES {
        Err(DecodeError::UnexpectedEof {
            needed: MAX_VARINT_U32_BYTES - input.len(),
        }
        .into())
    } else {
        Err(DecodeError::VarintOverflow {
            max_bytes: MAX_VARINT_U32_BYTES,
        }
        .into())
    }
}

/// Decode and require the varint to be canonical (no trailing zero
/// continuation byte that wastes a byte).
///
/// A trailing zero terminator byte after a continuation byte means the value
/// could have been encoded one byte shorter.
pub fn decode_u64_canonical(input: &[u8]) -> Result<(u64, usize)> {
    let (value, consumed) = decode_u64(input)?;
    if consumed > 1 && input[consumed - 1] == 0 {
        return Err(DecodeError::NonCanonicalVarint.into());
    }
    Ok((value, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn round_trip_known_u64() {
        let cases: &[u64] = &[
            0,
            1,
            0x7F,
            0x80,
            0x3FFF,
            0x4000,
            0xFFFF_FFFF,
            0x1_0000_0000,
            u64::MAX,
        ];
        for &v in cases {
            let mut buf = [0u8; MAX_VARINT_U64_BYTES];
            let n = encode_u64(v, &mut buf).expect("encode fits");
            assert_eq!(n, varint_u64_len(v), "size prediction mismatch for {v}");
            let (decoded, consumed) = decode_u64(&buf[..n]).expect("decode ok");
            assert_eq!(decoded, v, "round-trip mismatch for {v}");
            assert_eq!(consumed, n);
        }
    }

    #[test]
    fn varint_u64_len_matches_actual_encoding() {
        for v in [0_u64, 1, 127, 128, 16_383, 16_384, u64::MAX, u64::MAX - 1] {
            let mut buf = [0u8; MAX_VARINT_U64_BYTES];
            let n = encode_u64(v, &mut buf).unwrap();
            assert_eq!(n, varint_u64_len(v));
        }
    }

    #[test]
    fn encode_returns_none_when_buffer_too_short() {
        let mut buf = [0u8; 1];
        assert_eq!(encode_u64(0x80, &mut buf), None);
    }

    #[test]
    fn decode_rejects_unterminated_run() {
        // Ten continuation-bit bytes; the 11th terminator would be required but
        // never arrives.
        let bytes = [0xFF_u8; MAX_VARINT_U64_BYTES];
        let err = decode_u64(&bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Decode(DecodeError::VarintOverflow { .. })
        ));
    }

    #[test]
    fn decode_rejects_overflow_on_tenth_byte() {
        // Nine continuation bytes carrying 7 bits each (63 bits), then a tenth
        // byte with payload > 1 — this would set bit 64+, overflowing u64.
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];
        let err = decode_u64(&bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Decode(DecodeError::VarintOverflow { .. })
        ));
    }

    #[test]
    fn decode_accepts_u64_max() {
        // u64::MAX as canonical 10-byte varint: nine 0xFF bytes then 0x01.
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        let (v, n) = decode_u64(&bytes).unwrap();
        assert_eq!(v, u64::MAX);
        assert_eq!(n, MAX_VARINT_U64_BYTES);
    }

    #[test]
    fn decode_eof_when_input_empty() {
        let err = decode_u64(&[]).unwrap_err();
        assert!(matches!(
            err,
            Error::Decode(DecodeError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn decode_eof_when_continuation_runs_out() {
        // Two bytes both with continuation set; third byte never arrives.
        let err = decode_u64(&[0xFF, 0xFF]).unwrap_err();
        assert!(matches!(
            err,
            Error::Decode(DecodeError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn u32_round_trip_and_overflow() {
        let cases: &[u32] = &[0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, u32::MAX, u32::MAX - 1];
        for &v in cases {
            let mut buf = [0u8; MAX_VARINT_U32_BYTES];
            let n = encode_u32(v, &mut buf).unwrap();
            let (decoded, consumed) = decode_u32(&buf[..n]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, n);
        }
    }

    #[test]
    fn u32_decode_rejects_overflow_on_fifth_byte() {
        // Four continuation bytes (28 bits), then a fifth with payload > 0x0F →
        // bits 32+ would be set, overflowing u32.
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0x10];
        let err = decode_u32(&bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Decode(DecodeError::VarintOverflow { .. })
        ));
    }

    #[test]
    fn canonical_decoder_rejects_padded_encoding() {
        // 0 encoded with a wasted byte: 0x80 0x00 (continuation set, then zero).
        let bytes = [0x80, 0x00];
        let err = decode_u64_canonical(&bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Decode(DecodeError::NonCanonicalVarint)
        ));
    }

    #[test]
    fn canonical_decoder_accepts_genuine_zero() {
        // A single 0x00 byte is the canonical encoding of zero.
        let (v, n) = decode_u64_canonical(&[0]).unwrap();
        assert_eq!(v, 0);
        assert_eq!(n, 1);
    }

    // ----- property tests -----

    proptest::proptest! {
        #[test]
        fn prop_u64_round_trip(v: u64) {
            let mut buf = [0u8; MAX_VARINT_U64_BYTES];
            let n = encode_u64(v, &mut buf).unwrap();
            let (decoded, consumed) = decode_u64(&buf[..n]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, n);
            assert_eq!(n, varint_u64_len(v));
        }

        #[test]
        fn prop_u32_round_trip(v: u32) {
            let mut buf = [0u8; MAX_VARINT_U32_BYTES];
            let n = encode_u32(v, &mut buf).unwrap();
            let (decoded, consumed) = decode_u32(&buf[..n]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(consumed, n);
        }

        #[test]
        fn prop_decoder_never_panics_on_random_bytes(bytes: Vec<u8>) {
            // Either Ok or Err — but never panic.
            let _ = decode_u64(&bytes);
            let _ = decode_u32(&bytes);
            let _ = decode_u64_canonical(&bytes);
        }

        #[test]
        fn prop_encoded_bytes_have_continuation_pattern(v: u64) {
            let mut buf = [0u8; MAX_VARINT_U64_BYTES];
            let n = encode_u64(v, &mut buf).unwrap();
            // All but the last byte have the high bit set; the last does not.
            for &b in &buf[..n.saturating_sub(1)] {
                assert!(b & 0x80 != 0, "byte should have continuation bit set");
            }
            assert!(buf[n - 1] & 0x80 == 0, "last byte should clear continuation bit");
        }
    }
}
