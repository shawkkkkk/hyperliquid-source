use hl_bincode_varint::{ReaderError, decode_u32_reader, decode_u64_reader};

// Expected cursor/error rules are established at node #94 Reader VAs
// 0x466d850..0x466d975 and 0x466d980..0x466dabc, not by the Rust encoder.
#[test]
fn short_payload_retains_payload_for_the_next_read() {
    let bytes = [0xfb, 0x34];
    let mut remaining = bytes.as_slice();
    assert_eq!(
        decode_u32_reader(&mut remaining, 0),
        Err(ReaderError::UnexpectedEnd { additional: 1 })
    );
    assert_eq!(remaining.as_ptr(), bytes[1..].as_ptr());
    assert_eq!(remaining, &[0x34]);
    assert_eq!(decode_u32_reader(&mut remaining, 0), Ok(0x34));
    assert!(remaining.is_empty());
    assert_eq!(
        decode_u32_reader(&mut remaining, 0),
        Err(ReaderError::UnexpectedEnd { additional: 1 })
    );
    assert!(remaining.is_empty());
}

#[test]
fn rejected_width_preserves_the_payload_and_raw_codes() {
    let bytes = [0xfd, 1, 2, 3, 4, 5, 6, 7, 8];
    let mut remaining = bytes.as_slice();
    assert_eq!(
        decode_u32_reader(&mut remaining, 255),
        Err(ReaderError::RejectedMarker {
            expected_code: 2,
            found_code: 3,
        })
    );
    assert_eq!(remaining.as_ptr(), bytes[1..].as_ptr());
    assert_eq!(remaining, &bytes[1..]);
    assert_eq!(decode_u64_reader(&mut remaining, 255), Ok(1));
    assert_eq!(remaining, &bytes[2..]);
}

#[test]
fn u64_reader_error_uses_expected_code_three() {
    let mut remaining = &[0xfe, 0x42][..];
    assert_eq!(
        decode_u64_reader(&mut remaining, 0),
        Err(ReaderError::RejectedMarker {
            expected_code: 3,
            found_code: 4,
        })
    );
    assert_eq!(remaining, &[0x42]);
}
