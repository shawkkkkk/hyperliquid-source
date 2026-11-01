# Independent complete outer-adapter state proof

Fresh target identity: node94,91774280 bytes,SHA256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
The complete two primary FDE bodies are u32 ELF VA466bc10..466bd03,
243 bytes/73 GNU rows, and u64 VA466bd10..466bdf5,229 bytes/69 rows.
They total472 bytes/142 rows without overlap. The independently authenticated
body hashes are9e1325517b785daba397193914a99a3c119b1b7dc9603cda4df553c46f0485a8
andfca33a99b93d22ee7cde15b995c1faf05b6fc7f4967c1489ecaf77030d0f6f5e.
NATIVE-REVIEW.json binds their exact CIE/FDE records, full contiguous raw
instruction tilings and actual relative jump tables6f6e98/6f6ea8. No target,
PC/register evaluator, new Rust or new mathematical checker ran for this proof.
Stdlib static collection and bounded GNU objdump did run, with actual outputs
retained. This proof and the6716-case corpus precede reading a new checker.

## Scope, observations and labels

Consider a valid, separated output record and native state region. Its observed
DWORD at offset0 is m, QWORD at+8 is L, pointer/remaining words at+16/+24 are
p,n, and QWORD at+32 is c. These are raw offsets and widths, not a recovered
Rust struct or ABI. Calling c a counter and L a budget limit is an inferred
semantic label. Input bytes b of length n are valid where the selected local
path reads them; code, return slots, state, output and input are suitably
separated and nonwrapping. Helpers return ordinarily under the separately
proved Reader/error-builder contracts. Exclude faults/unwind, arbitrary aliases,
concurrent mutation, undefined result padding and hidden register effects.

The source peer freshly authenticated the separate623-byte Reader/helper ranges
and actual Reader/error-builder RELA bindings in the earlier native receipt
bbb9bdb2f6b5cf70619a777e00a3563b15ad503eb5cb1db41f845ddbc558db51.
Those are dependencies, not additional primary-byte credit or new Reader Rust.
The logical result uses observed raw tags18(success),0(shortage),3(type error)
and2(the outer counter rejection). No source enum identity follows.

## Optional fixed counter charge

Let W=4 for u32 or8 for u64 and M=2^64-1. Atbc11/bd11 the native equality
comparison is precisely DWORD m==1, not a low-bit, nonzero or Boolean test.
If m!=1, the entire counter/limit sequence is skipped: c remains unchanged.

If m==1,bc16/bd16 load c. The following unsigned comparisons test c>M-W:
u32's sign-extended immediate isfffffffffffffffb=M-4, u64's is
fffffffffffffff7=M-8. The JA overflow branch runs before the L load, ADD,
counter store or any cursor access. It writes only observed result tag2 and
returns. Thus c is unchanged and the cursor remains(p,n).

Otherwise c+W is a mathematical nonoverflowing unsigned64 sum, including c=M-W
which yields M. Atbc28/bd28 the native code stores this sum to state+32 BEFORE
comparing it with L. The following unsigned JBE continues exactly when c+W<=L.
If c+W>L, result tag2 returns with the charged counter still stored and cursor
unchanged. There is no rollback. Equality with L succeeds. This order matters
even for an empty input or a later rejected/truncated marker.

The two disjoint m==1 failures are therefore: overflow without a counter store;
or stored charge exceeding the limit. Every successful continuation has counter
c+W if m==1 and c otherwise. The charge is fixed4/8, not the encoded byte count,
and occurs before all success/error parsing outcomes.

## Length-selected direct Reader path

After successful counter handling,bc39/bd39 load original n. The exact unsigned
tests choose the direct Reader iff n<=W; otherwise they choose the fast path.
The slow call passes state+16, that is the actual pointer/remaining pair, and
sets EDX to zero. It therefore forces the Reader's rawDL=0 little-endian branch.
The three real slots5775138,57745e0,57745e8 bind the independently checked u32,
u64 Reader and raw-code error builder, respectively.

Consequently slow-path n=0 yields tag0,additional1 and consumes0. If n>0, the
Reader consumes the tag first. A short permitted payload yields
additional=required_total-n while consuming only1 and preserving all payload
bytes. A rejected marker also consumes1. Success consumes the complete1,3,5,
or(u64 only)9-byte representation. The u32 Reader's raw expected code is2;
the u64 Reader's is3. Found codes are3 for u32 FD,4 for FE,and12 for FF.
The already charged counter is not changed again by these Reader outcomes.

## Fast path and its error cursor

The u32 fast gate n>4 implies at least5 available bytes; u64 n>8 implies at
least9. Thus every permitted payload load is in bounds for a valid slice:
tag<FB uses1 byte; FB uses3; FC uses5; FD is permitted only for u64 and uses9.
The actual table targets map these cases exactly. The observed loads are
little-endian and do not test minimality. No byte-order parameter is read here.

Only the successful arms reachbc8e..bc98 orbd97..bda1, which store p+used and
n-used before writing tag18 and the result value. These stores produce the
exact residual tail b[used:]. The domain's nonwrapping valid allocation covers
the pointer arithmetic. For scalar tags,used=1; payload tags use3/5/9.

All fast error arms branch before those cursor stores. u32 FD,FE,FF return
raw expected2 with found3,4,12; u64 FE,FF return raw expected2 with found4,12.
They consume0 and leave the whole input intact. This is intentionally different
from the length-selected Reader path: both consume a tag on error there, and
u64's Reader expected code is3 rather than the fast arm's2. The helper writes
the exact low-byte codes and tag3; original result padding remains unqualified.

For example, after a successful u64 counter check, one-byte FE selects the
Reader, returns expected3/found4 and leaves an empty tail. Nine-byte FE plus
eight suffix bytes selects fast, returns expected2/found4 and preserves all
nine bytes. Both counter charges are8 when m==1. A failed counter check instead
prevents both decoding outcomes and leaves the entire cursor untouched.

## Exhaustiveness and independent finite corroboration

The proof partitions m into exactly1 and all other DWORDs; then c into
overflow/nonoverflow, the stored sum into above/not-above L, n into <=W/>W,
and a present tag into0..FA,FB,FC,FD,FE,FF. Every native branch and normal
return belongs to these cases. The Reader theorem closes the slow path, while
the fast gate proves all payload widths sufficient. No missing normal case
requires executing instructions or assuming the inferred reference source.

The independent corpus has6716 distinct complete logical inputs, even after
removing both case IDs and pointer labels:5400 counter/mode/limit boundary
rows,308 critical-tag/all-length rows and1008 further all-tag fast/slow rows,
with duplicates removed across families. All256 tag bytes appear at both fast
and slow lengths. Non-one odd and high DWORD modes distinguish equality from
bit tests. Exact c=M-W and c=M-W+1, stored-sum limit equality/one-below/one-above,
empty slices, nonminimal payloads, endian-asymmetric payloads and full tails
are retained. Paths number220 overflow,560 stored-over-limit,2257 fast and
3679 forced-little Reader. Raw result tags0/18/2/3 number964/2796/780/2176.

The oracle is an independently authored integer-inequality and byte-value
relation. It imports no repository module and reads no new model or Rust.
The future input-only checker receives only width,m,c,L,p and raw input bytes;
IDs are opaque. Native result padding, real pointer identity, invalid memory,
original ABI/compiler/bytes and full-component gates remain outside its scope.

Live PR1325 explicitly implements direct Readers and excludes the original
wrapper's fast/slow selection and whole-wrapper/caller state. Its623-byte scope
does not cover these472 bytes or their precharge ordering. This is new bounded
static state evidence only; it supplies no duplicate Reader Rust implementation,
original machine-byte reconstruction or complete serialization qualification.
