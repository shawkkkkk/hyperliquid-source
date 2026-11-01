# RE-005: outer slice adapters retain a charge on limit failure

- Component: serialization, RE-005; bounded static state relation.
- Target: node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `3324e50333042b391312515e542279ca21f63dc8`.
  Reviewed checker/authority experiment commit:
  `a6b3dc61d53724cdd1126919f52ae8aad9cc7ac3`.
- Publication recheck observed main at
  `d3af75257a396c85d20857f421c370ddb8cb40e5` and #1325 merged. Validation is
  explicitly on the task-start base/experiment commit above; no newer-base
  check or unrelated source adoption is claimed. Existing repository files
  are unchanged by this packet-only contribution.
- Result: a complete static normal-return relation for two outer adapters.
  No new Rust API, target ABI/source-enum identity, captured execution,
  machine-code reconstruction, or component gate is claimed.

## Concrete gap and observations

Accepted #253 maps these functions' slow gates and tag dispatch. The new
question is their **whole state transition**, including the counter stores
before parsing and length-dependent rejected-marker behavior. PR #1325 covers
direct Readers and explicitly excludes the original wrapper's selection/state;
this packet does not implement or re-claim those Reader operations.

| Primary function, ELF VA | File offset | Bytes | Complete GNU instruction rows |
| --- | --- | ---: | ---: |
| u32 `0x466bc10..0x466bd03` | `0x466ac10` | 243 | 73 |
| u64 `0x466bd10..0x466bdf5` | `0x466ad10` | 229 | 69 |
| **Two disjoint complete primary bodies** | | **472** | **142** |

In the valid-state projection, the raw state has a DWORD `m` at offset 0,
QWORD `L` at +8, pointer/remaining words `p,n` at +16/+24, and QWORD `c` at
+32. Calling `c` a counter and `L` a budget limit is an inference from the
unsigned comparisons; this is not a recovered Rust struct or ABI.

Let `W` be 4 for u32 or 8 for u64, and `M = 2^64 - 1`:

| Condition | Observed counter effect | Cursor effect / result |
| --- | --- | --- |
| `m != 1` | No counter load/store or limit check | Continue to length selection |
| `m == 1` and `c > M-W` | **No counter store** | Preserve `p,n`; return raw tag 2 |
| `m == 1`, no overflow, `c+W > L` | **Store and retain `c+W`** | Preserve `p,n`; return raw tag 2 |
| `m == 1`, no overflow, `c+W <= L` | Store `c+W` | Continue to length selection |

The comparison is exactly DWORD equality with 1. Other nonzero modes bypass
the whole sequence. The charge is fixed 4/8, independent of encoded width,
and precedes empty, truncated, rejected, and successful parsing. Equality at
`c=M-W` and `c+W=L` is accepted. A limit failure has no rollback.

After a permitted continuation, `n <= W` selects the direct Reader, passing
the actual +16/+24 state pair and forcing `dl=0` (little-endian). `n > W`
selects the fast path; its gate guarantees enough bytes for every allowed
payload. Successful arms consume 1/3/5/(u64-only)9 bytes and preserve the
exact suffix. Nonminimal payload representations are accepted.

The error routes have observable differences:

| Route after budget continuation | Rejected markers | Cursor on rejection | Raw expected code |
| --- | --- | --- | ---: |
| u32 Reader, `n <= 4` | FD / FE / FF | Consume only tag | 2 |
| u32 fast, `n > 4` | FD / FE / FF | Consume nothing | 2 |
| u64 Reader, `n <= 8` | FE / FF | Consume only tag | **3** |
| u64 fast, `n > 8` | FE / FF | Consume nothing | **2** |

Found codes are 3 for rejected FD, 4 for FE, and 12 for FF. Reader empty
input needs one additional byte without cursor movement; its truncated
payload needs `required_total-original_n` after consuming the tag. A prior
counter failure prevents either decode route. Only raw tag 2 is qualified for
the outer counter rejection; inactive payload bytes and padding are excluded.

For example, with `m=1,c=0,L=8`, one-byte FE on u64 charges 8, selects the
Reader, returns codes 3/4, and consumes the tag. Nine-byte FE plus a suffix
also charges 8, selects fast, returns codes 2/4, and preserves all nine bytes.
With `m=1,c=0,L=7`, both instead return tag 2 with counter 8 retained and
the entire cursor preserved. These are static relation consequences, not
captured execution observations.

## Native evidence and helper closure

`native/` retains both complete raw ranges, fresh GNU objdump listings/stderr,
their independent receipt, and a separate root admission. The checker binds
the whole capture digest, exact ELF PT_LOAD mappings, CIE/FDE records and
extents, every contiguous instruction-byte row, actual jump tables
`0x6f6e98` / `0x6f6ea8`, and qualified immediate fields.

All **seven** indirect calls in the primary bodies are closed through actual
RELA bindings: `0x5775138 -> 0x466d850`, `0x57745e0 -> 0x466d980`, and
`0x57745e8 -> 0x466dac0`. The separate **623-byte / 188-row** Reader/error-builder
context is retained in `helper/` with complete bytes, FDE/CIE, its two tables,
all five further calls to the 14-byte error builder, and the same actual
bindings. That context is an existing dependency theorem, not additional new
primary-byte credit or a new Reader implementation. No caller census or
whole-module denominator is asserted.

`PROOF.md` is the peer's independent complete case proof. Its normal-state
domain requires readable nonwrapping input, valid suitably separated state,
output, input, stack and return storage, ordinary helper returns, and no
concurrent mutation. Faults/unwind, aliases, undefined padding, hidden register
effects and concrete original ABI/compiler identity remain outside scope.

## Independent authority, actual checks and controls

Before the new checker/model was authored, an independent worker sealed
**6,716 distinct complete state inputs**, also distinct after removing IDs and
pointer labels. `FREEZE.json` SHA-256
`0f8cbac0cdb676458cbf71e373a60c5123fe0d1418a300a1063ce4dab9b85eb8`
binds `freeze.py`, `inputs.tsv`, `expected.jsonl` and `authority.json`.
The proof/native/freezing handoff is retained unchanged. These are integer
inequalities and byte-value equations, with no new model read, repository
imports, instruction interpreter, PC/register evaluation, or native execution.

The cases cover counter/limit equality, one-below/above and overflow boundaries;
mode equality versus odd/high DWORD modes; every tag at fast/slow lengths;
critical tags at every length 0..10; empty/nonminimal/asymmetric payloads; and
the complete resulting counter/write flag, logical result, route, pointer
label, consumed length, remaining length and suffix. The new relation function
receives each case and independently qualified literal parameters; a separate
comparison step reads the frozen expected records.

The real scoped command, from the repository root, is reproducible with a new
ignored output directory:

```sh
python3 -I -B research/work-items/RE-005-slice-adapter-budget-94/verify.py \
  --out work/outer-budget-check
```

Actual results at the clean experiment commit:

| Observation | Result |
| --- | --- |
| Frozen state comparison | **6,716/6,716 exact full records**, byte-identical JSONL |
| Paths: overflow / retained over-limit / fast / Reader | **220 / 560 / 2,257 / 3,679** |
| Raw result tags 0 / 18 / 2 / 3 | **964 / 2,796 / 780 / 2,176** |
| All native byte/FDE/table/RELA/call guards | PASS, complete primary **472B/142 rows** |

Seven mathematical counterfactuals each emit the complete 6,716-record output:

| Wrong relation | Mismatched full records |
| --- | ---: |
| Treat any nonzero mode as charged | 3,240 |
| Charge one byte instead of fixed 4/8 | 1,134 |
| Write wrapped counter on overflow | 220 |
| Roll counter back on limit failure | 560 |
| Consume a fast rejected tag | 1,204 |
| Use expected code 3 in u64 fast errors | 472 |
| Use big-endian on the forced-little Reader route | 717 |

Seven separate actual-byte counterfactuals change the mode immediate, overflow
threshold, counter-store opcode, forced-endian instruction, u64 fast error-code
immediate, jump-table entry, and FDE extent. Each is rejected **below** the
whole-file digest gate by the complete native structure checks. No altered
capture is executed or emulated. These controls validate data sensitivity;
they do not themselves prove the mathematical/native relation.

`observed/REPORT.json`, `actual.jsonl`, original command streams and full input
audit preserve the measured results. The seven full mathematical-control JSONL
streams are retained losslessly as `.jsonl.zlib`; `COMPRESSED-CONTROLS.json`
records compressed and original hashes/lengths. They are data, not executable
code. Recover a stream with Python's standard `zlib.decompress(path.read_bytes())`.

The scoped command and `make doctor`, `make verify`, `make catalogue-check`,
and `make reproduce` each exited zero. `observed/AUDIT.json` records the exact
argv, all raw stream hashes, Python 3.12.14/Linux x86-64 identity, clean source
commit, **9,176 root physical input hashes**, and all **seven** genuine submodule
HEAD/status records; every input was unchanged before/after. GNU objdump is
2.44, GNU Make 4.4.1, and Git 2.52.0. No compiler or linker was invoked for this
static finding.

## Limits and next question

**NOT RUN:** the current expanded `make test` suite, which is not authorized in
this session; hosted CI, containers, captured execution, and Rust builds are
not claimed. The four scoped static repository checks and finite mathematical
comparison do not replace the full suite or establish target equivalence.

The range mapping itself already exists in #253; the new finding is the exact
precharge/store/limit relation and its coupling to fast/slow error cursors.
No reconstructed source bytes are compared with the target, and no byte window,
component/progress record, imported input, manifest, lockfile or existing Rust
API is changed. All serialization gates remain false.

Next question: validate an owning caller's initialization and interpretation of
the mode, counter, and limit before integrating a budgeted slice API with a
reviewed Reader implementation.
