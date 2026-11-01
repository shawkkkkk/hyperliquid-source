# Node #94 bincode varint component

This directory contains an independently authored Rust implementation of the
bounded integer-varint behavior established by the static RE-005 evidence. It
targets Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The unlicensed reference tree was not used as implementation source.

## Evidence-backed contract

The retained packet at
`research/work-items/RE-005-bincode-varint/` establishes these operations:

- u32 encoding and size selection at virtual addresses
  `0x27ab0a0..0x27ab2f5` and `0x4aa9ae0..0x4aa9c86`;
- u64 encoding and size selection at `0x27ab300..0x27ab64b` and
  `0x4aa9f80..0x4aaa2cb`;
- the u64 slice decoder fast path at `0x466bd10..0x466bdf5`, with a second
  inlined copy at `0x2558ee0..0x2559404`.

The observed encoding is minimal:

| value | bytes | encoded length |
| --- | --- | ---: |
| `0..=250` | the value byte | 1 |
| `251..=65_535` | `0xfb` + u16 payload | 3 |
| `65_536..=u32::MAX` | `0xfc` + u32 payload | 5 |
| `u32::MAX + 1..=u64::MAX` | `0xfd` + u64 payload | 9 |

The encode bodies conditionally byte-swap each multibyte payload. The Rust API
therefore exposes explicit little- and big-endian payload order. Marker bytes
do not change with payload order. The size operation is order-independent.

The little-endian u64 *slice fast path* is
entered only when `input.len() > 8`. It accepts tags below `0xfb`, reads u16,
u32 or u64 payloads for `0xfb`, `0xfc` or `0xfd`, and reports 1, 3, 5 or 9
consumed bytes. The observed straight-line arms perform no minimal-encoding
check, so non-minimal representations are accepted on this path. Markers
`0xfe` and `0xff` reach distinct target error construction paths; this
component reports both as rejected without assigning an unproved target error
type. The separate Reader API below retains the raw Reader error codes.

## u32 and u64 Reader operations

`decode_u32_reader` and `decode_u64_reader` implement the complete operations at
node #94 virtual addresses `0x466d850..0x466d975` (293 bytes) and
`0x466d980..0x466dabc` (316 bytes), with the shared 14-byte raw-code error
builder at `0x466dac0..0x466dace`. The static packet
`research/work-items/RE-005-bincode-slow-widths/` and the new reconstruction
packet `research/work-items/RE-005-reader-reconstruction-94/` bind the scope to
the target digest above. All three ranges total 623 bytes and 188 instruction
rows; this is a bounded semantic reconstruction, with no compiled-byte match
claimed.

Both functions take `&mut &[u8]` and a raw byte-order flag. Flag zero selects
little-endian; every nonzero byte selects big-endian. The mutable slice exposes
the observed cursor transition on success and error:

- Empty input needs one additional byte and consumes none.
- A present tag is consumed immediately. Tags below `0xfb` return their value.
- Marker `0xfb` needs three original bytes; `0xfc` needs five. The u64 Reader
  also accepts `0xfd`, requiring nine. A short payload reports the total
  required minus the original length and leaves the payload unconsumed.
- A successful payload read consumes its full representation. Wider encodings
  of small values are accepted.
- The u32 Reader rejects `0xfd`, `0xfe`, and `0xff`, with raw expected code 2
  and found codes 3, 4, and 12. The u64 Reader rejects `0xfe` and `0xff`, with
  raw expected code 3 and found codes 4 and 12. Rejection consumes only the tag.

`ReaderError` is a chosen safe API representation. Its names do not assert a
recovered target enum, result layout, ABI, or padding. The logical target result
tags observed are 18 (success), 0 (short input), and 3 (raw-code error).

The existing `decode_u64_slice_fast` entrypoint still returns
`FastPathUnavailable` when eight bytes or fewer remain. It continues to model
only the separate fast-path contract. Outer decoder budget accounting and its
different raw error codes remain outside this Reader reconstruction.

## Deliberately unsupported behavior

The component does not implement a standalone u16 decoder, u128 or signed/zigzag
encoding, fixed-width mode, serde integration, the complete outer slice decoder,
target error enum values, or caller/type mappings. It makes no binary-identity or
full-serialization-recovery claim and does not advance a progress gate.

## Intended API and build scope

The component is a standalone, dependency-free library crate rather than a
root workspace. Its public surface is limited to:

- `encoded_len_u32` and `encoded_len_u64`;
- `encode_u32` and `encode_u64`, appending to a caller-owned `Vec<u8>`;
- `decode_u64_slice_fast`, returning the decoded value and consumed length;
- `decode_u32_reader` and `decode_u64_reader`, updating a caller-owned slice;
- explicit `PayloadOrder`, `DecodeError`, and `ReaderError` types.

The crate uses the repository-pinned Rust toolchain. Once the implementation
is present, build it from the repository root with:

```sh
cargo build --locked --manifest-path src/bincode-varint/Cargo.toml
cargo test --locked --manifest-path src/bincode-varint/Cargo.toml
cargo clippy --locked --manifest-path src/bincode-varint/Cargo.toml --all-targets -- -D warnings
```

The integration vectors are not produced by the reconstructed encoder. Their
expected marker, width, byte order and consumed length are transcribed from the
following independently verified node #94 instructions:

| property | target evidence |
| --- | --- |
| value `< 251` is one byte | `0x27ab0aa..0x27ab0c3`, `0x27ab30b..0x27ab325` |
| `0xfb` + u16 payload | `0x27ab0cf..0x27ab0fc`, `0x27ab331..0x27ab36f` |
| `0xfc` + u32 payload | `0x27ab128..0x27ab13a`, `0x27ab397..0x27ab3b9` |
| `0xfd` + u64 payload | `0x27ab3d4..0x27ab3f7` |
| 1/3/5/9 size thresholds | `0x27ab5b1..0x27ab623` |
| little-endian u16/u32/u64 loads | `0x466bd76`, `0x466bd8e`, `0x466bd82` |
| consumed 1/3/5/9 | `0x466bd53`, `0x466bd7a`, `0x466bd91`, `0x466bd86` |
| fast path requires more than 8 bytes | `0x466bd3d..0x466bd41` |
| `0xfe` and out-of-range error arms | `0x466bdc5`, `0x466bddd` |

`research/work-items/RE-005-bincode-varint/verify.py` authenticates those bytes
against the captured artifact before the Rust test results are interpreted.

The Reader bridge at `examples/reader_oracle.rs` reads tab-separated
`WIDTH`, `RAW_DL`, and `INPUT_HEX` fields from stdin, where width is 32 or 64
and the flag is a decimal byte. Empty hex input is allowed. It emits one of:

```text
ok<TAB>VALUE<TAB>CONSUMED<TAB>REMAINING<TAB>TAIL_HEX
end<TAB>ADDITIONAL<TAB>CONSUMED<TAB>REMAINING<TAB>TAIL_HEX
type<TAB>EXPECTED<TAB>FOUND<TAB>CONSUMED<TAB>REMAINING<TAB>TAIL_HEX
```

Numbers are decimal and `TAIL_HEX` is lowercase, including an empty final field
for an empty tail. The bridge executes the reconstructed Rust only. Its
8,364-case mathematical corpus was frozen independently before these Reader
functions were authored; the reconstruction packet retains its inputs,
expectations, generator, hashes, actual comparisons, and limitations.
