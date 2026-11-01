//! Independently authored reconstruction of the node #94 integer-varint core.
//!
//! The encode and size operations cover the observed u32/u64 paths. Decoding
//! covers the u64 slice fast path and the separate u32/u64 Reader operations.

#![forbid(unsafe_code)]

use core::fmt;

const U16_MARKER: u8 = 0xfb;
const U32_MARKER: u8 = 0xfc;
const U64_MARKER: u8 = 0xfd;
const U128_MARKER: u8 = 0xfe;
const FAST_PATH_MINIMUM_REMAINING: usize = 9;

/// Byte order used for the payload following a varint marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadOrder {
    /// Least-significant payload byte first.
    Little,
    /// Most-significant payload byte first.
    Big,
}

/// Successful result from the evidence-backed u64 slice fast path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedU64 {
    /// Decoded unsigned value.
    pub value: u64,
    /// Number of input bytes consumed by the selected arm.
    pub consumed: usize,
}

/// Outcomes for inputs outside the established u64 slice fast path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The target uses a separate reader slow path at this remaining length.
    FastPathUnavailable { remaining: usize },
    /// The target fast path reaches an error arm for this marker.
    RejectedMarker { marker: u8 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FastPathUnavailable { remaining } => write!(
                formatter,
                "u64 slice fast path requires more than 8 bytes; {remaining} remain"
            ),
            Self::RejectedMarker { marker } => {
                write!(
                    formatter,
                    "node #94 u64 fast path rejects marker 0x{marker:02x}"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Logical errors from the node #94 u32/u64 Reader operations.
///
/// These names and the safe Rust representation are chosen for this API.
/// The numeric type codes are retained as observed, without asserting the
/// target's source enum, result layout, or padding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderError {
    /// The input lacks this many bytes for the selected operation.
    UnexpectedEnd { additional: usize },
    /// The marker reaches the shared raw-code error builder.
    RejectedMarker { expected_code: u8, found_code: u8 },
}

impl fmt::Display for ReaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd { additional } => {
                write!(formatter, "Reader needs {additional} additional bytes")
            }
            Self::RejectedMarker {
                expected_code,
                found_code,
            } => write!(
                formatter,
                "Reader rejects integer type code {found_code}; expected code {expected_code}"
            ),
        }
    }
}

impl std::error::Error for ReaderError {}

/// Returns the observed encoded length for a u32 value.
#[must_use]
pub const fn encoded_len_u32(value: u32) -> usize {
    if value < U16_MARKER as u32 {
        1
    } else if value <= u16::MAX as u32 {
        3
    } else {
        5
    }
}

/// Returns the observed encoded length for a u64 value.
#[must_use]
pub const fn encoded_len_u64(value: u64) -> usize {
    if value < U16_MARKER as u64 {
        1
    } else if value <= u16::MAX as u64 {
        3
    } else if value <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

/// Appends the observed minimal u32 representation and returns its length.
pub fn encode_u32(value: u32, order: PayloadOrder, output: &mut Vec<u8>) -> usize {
    let encoded_len = encoded_len_u32(value);
    match encoded_len {
        1 => output.push(value as u8),
        3 => {
            output.push(U16_MARKER);
            append_u16(value as u16, order, output);
        }
        5 => {
            output.push(U32_MARKER);
            append_u32(value, order, output);
        }
        _ => unreachable!("u32 varint length is one of 1, 3 or 5"),
    }
    encoded_len
}

/// Appends the observed minimal u64 representation and returns its length.
pub fn encode_u64(value: u64, order: PayloadOrder, output: &mut Vec<u8>) -> usize {
    let encoded_len = encoded_len_u64(value);
    match encoded_len {
        1 => output.push(value as u8),
        3 => {
            output.push(U16_MARKER);
            append_u16(value as u16, order, output);
        }
        5 => {
            output.push(U32_MARKER);
            append_u32(value as u32, order, output);
        }
        9 => {
            output.push(U64_MARKER);
            append_u64(value, order, output);
        }
        _ => unreachable!("u64 varint length is one of 1, 3, 5 or 9"),
    }
    encoded_len
}

/// Decodes only the node #94 little-endian u64 slice fast path.
///
/// The target enters this path only when more than eight bytes remain. Shorter
/// inputs are returned as [`DecodeError::FastPathUnavailable`] without reading
/// their tag. Use [`decode_u64_reader`] for the separate Reader operation.
pub fn decode_u64_slice_fast(input: &[u8]) -> Result<DecodedU64, DecodeError> {
    if input.len() < FAST_PATH_MINIMUM_REMAINING {
        return Err(DecodeError::FastPathUnavailable {
            remaining: input.len(),
        });
    }

    let tag = input[0];
    let decoded = match tag {
        0..=0xfa => DecodedU64 {
            value: u64::from(tag),
            consumed: 1,
        },
        U16_MARKER => DecodedU64 {
            value: u64::from(u16::from_le_bytes([input[1], input[2]])),
            consumed: 3,
        },
        U32_MARKER => DecodedU64 {
            value: u64::from(u32::from_le_bytes([input[1], input[2], input[3], input[4]])),
            consumed: 5,
        },
        U64_MARKER => DecodedU64 {
            value: u64::from_le_bytes([
                input[1], input[2], input[3], input[4], input[5], input[6], input[7], input[8],
            ]),
            consumed: 9,
        },
        U128_MARKER | 0xff => return Err(DecodeError::RejectedMarker { marker: tag }),
    };

    Ok(decoded)
}

/// Decodes the node #94 u32 Reader operation and advances the borrowed slice.
///
/// An empty slice returns `UnexpectedEnd { additional: 1 }` without advancing.
/// Otherwise the tag is consumed before any error: a short payload and a
/// rejected marker leave all payload bytes available in `input`. Successful
/// payload reads consume their full 3- or 5-byte representation. Nonminimal
/// representations are accepted. `byte_order_flag == 0` selects little-endian;
/// every nonzero flag selects big-endian, matching the target's raw `dl` test.
///
/// This is a logical result/cursor API, not a reconstruction of target ABI or
/// outer slice-decoder budget accounting.
pub fn decode_u32_reader(input: &mut &[u8], byte_order_flag: u8) -> Result<u32, ReaderError> {
    match take_reader_tag(input)? {
        tag @ 0..=0xfa => Ok(u32::from(tag)),
        U16_MARKER => {
            let bytes = take_reader_payload(input)?;
            Ok(u32::from(if byte_order_flag == 0 {
                u16::from_le_bytes(bytes)
            } else {
                u16::from_be_bytes(bytes)
            }))
        }
        U32_MARKER => {
            let bytes = take_reader_payload(input)?;
            Ok(if byte_order_flag == 0 {
                u32::from_le_bytes(bytes)
            } else {
                u32::from_be_bytes(bytes)
            })
        }
        U64_MARKER => Err(reader_marker_error(2, 3)),
        U128_MARKER => Err(reader_marker_error(2, 4)),
        0xff => Err(reader_marker_error(2, 12)),
    }
}

/// Decodes the node #94 u64 Reader operation and advances the borrowed slice.
///
/// Cursor and byte-order rules are the same as [`decode_u32_reader`]. Marker
/// `0xfd` reads eight payload bytes, consuming nine bytes on success. Markers
/// `0xfe` and `0xff` return raw expected code 3 with found code 4 or 12 after
/// consuming only their tag. No u128 payload is read.
pub fn decode_u64_reader(input: &mut &[u8], byte_order_flag: u8) -> Result<u64, ReaderError> {
    match take_reader_tag(input)? {
        tag @ 0..=0xfa => Ok(u64::from(tag)),
        U16_MARKER => {
            let bytes = take_reader_payload(input)?;
            Ok(u64::from(if byte_order_flag == 0 {
                u16::from_le_bytes(bytes)
            } else {
                u16::from_be_bytes(bytes)
            }))
        }
        U32_MARKER => {
            let bytes = take_reader_payload(input)?;
            Ok(u64::from(if byte_order_flag == 0 {
                u32::from_le_bytes(bytes)
            } else {
                u32::from_be_bytes(bytes)
            }))
        }
        U64_MARKER => {
            let bytes = take_reader_payload(input)?;
            Ok(if byte_order_flag == 0 {
                u64::from_le_bytes(bytes)
            } else {
                u64::from_be_bytes(bytes)
            })
        }
        U128_MARKER => Err(reader_marker_error(3, 4)),
        0xff => Err(reader_marker_error(3, 12)),
    }
}

fn take_reader_tag(input: &mut &[u8]) -> Result<u8, ReaderError> {
    let Some((&tag, tail)) = input.split_first() else {
        return Err(ReaderError::UnexpectedEnd { additional: 1 });
    };
    *input = tail;
    Ok(tag)
}

fn take_reader_payload<const WIDTH: usize>(input: &mut &[u8]) -> Result<[u8; WIDTH], ReaderError> {
    if input.len() < WIDTH {
        return Err(ReaderError::UnexpectedEnd {
            additional: WIDTH - input.len(),
        });
    }
    let (payload, tail) = input.split_at(WIDTH);
    let mut bytes = [0; WIDTH];
    bytes.copy_from_slice(payload);
    *input = tail;
    Ok(bytes)
}

fn reader_marker_error(expected_code: u8, found_code: u8) -> ReaderError {
    ReaderError::RejectedMarker {
        expected_code,
        found_code,
    }
}

fn append_u16(value: u16, order: PayloadOrder, output: &mut Vec<u8>) {
    match order {
        PayloadOrder::Little => output.extend_from_slice(&value.to_le_bytes()),
        PayloadOrder::Big => output.extend_from_slice(&value.to_be_bytes()),
    }
}

fn append_u32(value: u32, order: PayloadOrder, output: &mut Vec<u8>) {
    match order {
        PayloadOrder::Little => output.extend_from_slice(&value.to_le_bytes()),
        PayloadOrder::Big => output.extend_from_slice(&value.to_be_bytes()),
    }
}

fn append_u64(value: u64, order: PayloadOrder, output: &mut Vec<u8>) {
    match order {
        PayloadOrder::Little => output.extend_from_slice(&value.to_le_bytes()),
        PayloadOrder::Big => output.extend_from_slice(&value.to_be_bytes()),
    }
}
