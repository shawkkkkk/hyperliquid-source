# RE-005: reconstruct the complete node #94 u32/u64 Reader operations

- Component: serialization, RE-005.
- Target: node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `3324e50333042b391312515e542279ca21f63dc8`.
  Reviewed implementation and actual experiment commit:
  `0d95779e941ecc06544047b831881b8f102131ae`.
- Claim: independently authored, buildable Rust for the logical result and
  cursor semantics of three complete native ranges. Function/type names are
  inferred labels; the safe public representation is newly chosen.
- No component gate, target compiled-byte match, whole-node build, ABI/padding
  equivalence, or captured execution is claimed.

## Bounded gap and result

The existing `src/bincode-varint` crate covered encode/length operations and
the u64 slice fast path, which requires at least nine remaining bytes. Accepted
PR #253 supplied static evidence for two Reader bodies and their error helper,
but there was no Rust implementation of their cursor/error behavior.

The new `decode_u32_reader` and `decode_u64_reader` take `&mut &[u8]` and a raw
byte-order flag. Empty input returns a one-byte shortage without advancing.
Every present tag is consumed before dispatch: a rejected marker or short
payload leaves the payload intact. For example, `[fb,34]` reports one additional
byte and leaves `[34]`, which the next Reader call can decode as value 52.

| Complete native range, ELF VA | File offset | Bytes | Instruction rows |
| --- | --- | ---: | ---: |
| u32 Reader `0x466d850..0x466d975` | `0x466c850` | 293 | 88 |
| u64 Reader `0x466d980..0x466dabc` | `0x466c980` | 316 | 95 |
| shared error builder `0x466dac0..0x466dace` | `0x466cac0` | 14 | 5 |
| **Three disjoint complete ranges** | | **623** | **188** |

The fresh native review authenticates the full capture, exact FDE/CIE records,
all contiguous instruction bytes in these ranges, both jump tables, and the
three Reader/helper GOT RELA records. Original bytes and GNU disassembly with
stderr are retained in `native/`. `peer/READER-NATIVE-REVIEW.json` is an explicit
Reader-only selection of the peer's joint native review, with its origin hash.
No original machine bytes are linked into the Rust implementation.

## Native relation and mathematical authority

`reader623-proof.md` partitions every possible tag and finite slice length.
Both Readers first test the original length, then consume one tag byte if it
exists. Tags below 251 return their numeric value. Markers 251 and 252 accept
two and four payload bytes; u64 also accepts marker 253 with eight payload
bytes. Their required original totals are 3, 5, and 9. A shortfall is the
required total minus the original length, while the cursor remains advanced
by exactly one. On success the complete representation is consumed.

Raw `dl == 0` selects little-endian; **every** nonzero byte selects big-endian.
There is no minimal-width check, so wider encodings of small values are accepted.
The u32 Reader rejects markers 253/254/255 with raw expected code 2 and found
codes 3/4/12. The u64 Reader rejects 254/255 with expected code 3 and found
codes 4/12. No u128 payload is read. The shared helper writes logical result tag
3 and the low bytes of expected/found; native success and shortage tags are
18 and 0. These observations do not establish the target's source enum or
undefined result padding.

The root and peer rechecked the accepted #253 listing against the admitted
capture. The pre-source independent authority used that listing at the base
revision, SHA-256
`0a8b937e511c334bc640b417042359a864051e8b758de85b5aeadefbe1e9eb03`.
`generate_reader.py` expresses a direct base-256 polynomial and finite
partitions. It imports no repository module or Rust implementation and does
not evaluate instructions, registers, or a program counter.

Before the Reader Rust was authored, a separate worker froze 8,364 distinct
complete inputs and expected results. The independent source peer recomputed
all expectations with `int.from_bytes`, separately from the generator's
polynomial. The corpus covers every tag, six representative flags across all
tags, all 256 flag bytes with asymmetric payloads, every short total, extra
suffixes, nonminimal representations, zero/max payloads, and exact residual
slice contents. Its logical result counts are 7,784 successes, 132 shortages,
and 448 raw-code errors.

| Frozen input | SHA-256 |
| --- | --- |
| `reader623-corpus.json` | `da6d136c6904f2f63505f598a6812d19b9398174b133d50a4067d918113be4e7` |
| `reader623-input.tsv` | `753dcb283332640126eaf157c763144c91c750cd5b4b5e8ef940be7832fa26f6` |
| `reader623-expected.tsv` | `0a6dca7c361155644ac21bc1952b8c748079379738f38ab9408eb5d4f78c1500` |
| `generate_reader.py` | `d28f8cf4951d75193a34fe6514b7c02095828dbe772ad19dbba0c770afb0179f` |

## Real build and comparison

The existing dependency-free manifest and Cargo.lock remain unchanged. The
Rust implementation, bridge, and focused sequential-cursor tests are under
`src/bincode-varint`. All new code is independently authored MIT code; the
unlicensed can1357 reference source was not used or copied. Imported captures
retain their original rights.

The actual Linux x86-64 experiment used official Rust **1.94.1**, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM **21.1.8** as a research
compiler. This does not identify the captured node's compiler. The authenticated
rustc/std archives, installer manifests, licenses, and all **103 installed
payload hashes** are described in `toolchain/PROVIDER-AUDIT.json`; no toolchain
payloads are vendored here. Python was 3.12.14, GNU objdump 2.44, GNU Make 4.4.1,
and Git 2.52.0. Actual host GCC/ld.bfd versions and hashes are in the report.

The complete experiment command, from the repository root, was:

```sh
python3 -I -B research/work-items/RE-005-reader-reconstruction-94/reproduce.py \
  --rustc /tmp/hl-resume-20261101/toolchain/prefix/bin/rustc \
  --provider-audit /tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json \
  --out work/reader623-validation
```

The output directory must be new. The recipe intentionally requires the
authenticated provider audit and its recorded installation prefix; it neither
downloads nor installs a compiler. It records every actual argv and exit code
incrementally, keeps all streams, and stops on failed guards. Its Rust argv
uses edition 2024, target `x86_64-unknown-linux-gnu`, warnings denied,
optimization 3, one codegen unit, no debug information, `/usr/bin/gcc`, and
`-fuse-ld=bfd`. No Cargo hook or captured executable is invoked.

At the clean implementation commit, two separate output directories each
built the real rlib, input-only bridge, existing integration tests, and new
Reader tests. The guards rehashed every one of **9,157 physical root tracked
inputs**, all seven genuine submodule HEAD/status records, all 103 provider
payloads, actual host compiler/linker, target, sources, and frozen corpus.
Inputs, HEAD, and status were identical before/after. The same inputs were
unchanged across the later four repository checks.

| Actual observation | Result |
| --- | --- |
| Each clean-build bridge versus frozen oracle | **8,364/8,364 exact rows**; zero mismatches |
| Exact compared fields | status, value/shortage/raw codes, consumed length, remaining length, full tail hex |
| Existing integration tests per build | **12 passed** |
| New Reader integration tests per build | **3 passed** |
| Own rlib, bridge, old/new test binaries across directories | **4/4 raw artifact hashes equal**, no normalization |
| Separately compiled value corruption | **8,352/8,364 mismatches**, normal complete output |
| Separately compiled shortage corruption | **120/8,364 mismatches**, normal complete output |
| Separately compiled u64 raw-code corruption | **12/8,364 mismatches**, normal complete output |
| Missing/extra row controls | Both detected |

All 23 subprocess commands exited zero. The 46 stdout/stderr streams, raw
actual corpus outputs, complete unedited experiment ledger, and mutant Rust
sources are in `observed/`. The four rebuilt artifacts' equality is only
repeatability of this new Rust build: **no original-to-rebuilt code-byte
comparison was performed** and no byte window is registered.

The source peer independently checked all streams, exact source/freeze hashes,
the complete output denominators, controls, and raw artifact equalities. It
also replayed both already-built clients against a corpus sealed before
reading Rust: **93 reordered/duplicate rows representing 90 new complete
inputs**, with zero overlap with public complete inputs. Both clients matched
independent expectations. Changing wrong-neighbor answer files did not change
the client output; this is an observed data-flow check, not a filesystem
sandbox. Public-safe counts, identities, and receipt hashes are in
`peer/READER-PRIVATE-PUBLIC-SUMMARY.json`; private inputs and answers are not
published. No rebuild was needed for that replay.

## Repository checks and limits

At implementation commit `0d95779e941ecc06544047b831881b8f102131ae`, these exact
checks each exited zero, with 9,157 inputs and clean HEAD/status unchanged:

```sh
make doctor
make verify
make catalogue-check
make reproduce
```

Actual raw stdout/stderr and command/exit/hash records are retained under
`repository-checks/`. Doctor reports static `analysis_ready: true` and
`exact_rebuild_ready: false`; its rustup toolchain discovery does not discover
the separately authenticated direct-rustc research prefix. The real component
build above is established by observed commands, not that discovery field.

**NOT RUN:** the current expanded `make test` suite (not authorized in this
session), Cargo, clippy, rustfmt, hosted CI, containers, Ghidra, and captured
native execution. The scoped direct-rustc tests above do not substitute for
the full repository suite. This remains a draft contribution with that gap.

The outer slice decoder/budget checks, separate fast-path error codes, other
Readers, caller/type mappings, target padding/ABI, full dependency graph, and
whole-ELF identity remain outside scope. The existing fast-path API remains
separate and its established contract is preserved. All serialization gates
remain false. The mathematical proof establishes the stated logical relation
from complete static bodies; finite test counts and tooling checks alone do
not establish target equivalence.

Next question: establish the outer decoder's budget transitions and its
different raw error codes before offering a unified slice-decoder API.
