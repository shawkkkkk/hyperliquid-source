# Reader623 independent pre-source mathematical authority

Basis: accepted #253 full native listing now present at current main
`3324e50333042b391312515e542279ca21f63dc8`,
`research/work-items/RE-005-bincode-slow-widths/objdump-excerpts.txt`,
SHA-256 `0a8b937e511c334bc640b417042359a864051e8b758de85b5aeadefbe1e9eb03`.
Target node#94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This proof and its corpus are new observations of published static evidence,
not recovered historical output or native execution. Full raw capture admission
is required separately before implementation claims.

The scope is exactly u32 Reader VA `0x466d850..0x466d975` (293 bytes), u64
Reader `0x466d980..0x466dabc` (316 bytes), and the 14-byte shared raw-code error
builder `0x466dac0..0x466dace`: 623 bytes in three disjoint ranges. Jump tables
at `0x6f6ec8` and `0x6f6ed8` are supporting inputs. The outer slice decoder,
budget accounting, u64 fast path, other Readers, padding and private ABI are
excluded. No component gate or byte-identity advance is requested.

Let n be the original slice length and b its bytes. If n=0, return logical
UnexpectedEnd(1), consume0 and leave the empty tail. If n>0, read b0 then
immediately consume exactly one byte. All following error results retain that
one-byte consumption, with payload untouched. This follows the stores at
d869/d86c and d999/d99c, before dispatch, and the absence of later reader
stores on error branches.

For b0<251, return logical success with value b0 and consume1. Marker251
declares a two-byte payload/total3; marker252 a four-byte payload/total5.
Marker253 declares an eight-byte payload/total9 only for u64. If n<total,
return UnexpectedEnd(total-n); consumption remains1. The comparisons use the
original n (rax), not the already decremented reader length. On success consume
total and leave b[total:]. For payload digits d0..dk-1, value is the positional
base256 polynomial in their wire order when rawDL!=0 and their reversed order
when rawDL=0. Therefore every nonzero rawDL byte selects big-endian; the zero
byte selects little-endian. Noncanonical wider encodings of small values are
accepted without an extra size/minimality check.

u32 marker253 returns raw type codes expected2/found3; u32 marker254 returns
2/4; u32 marker255 returns2/12. u64 marker254 returns3/4; u64 marker255 returns
3/12. These failures happen after tag consumption regardless of remaining
payload length. No u128 payload is read. These are raw numeric code claims,
not an asserted recovered source enum. The shared builder writes logical
result tag3, then the low8 of expected and found. Native success writes tag18;
UnexpectedEnd writes tag0. Undefined result padding is outside the bridge.

Exhaustiveness follows from partitioning b0 into [0,250],251,252,253,254,255
and n into zero, positive-short, and sufficient for each allowed payload.
The u32 table arms and error paths are d8b7,d8c4,d945,d92d,d95d; the u64
arms are d9e7,da01,d9f4,da8c,daa4. Each allowed arm has exactly one size
condition, one endian condition and one cursor store sequence. This finite
case proof covers every finite admitted slice, all256 rawDL bytes and both
widths without a captured instruction evaluator.

The 8,364-case frozen corpus separately exercises all256 marker bytes, all256
rawDL bytes with asymmetric payloads, every short total, zero/noncanonical/
maximum payloads, sufficient/extra bytes and exact preserved tail contents.
`generate_reader.py` uses only a direct mathematical polynomial and partitions;
it imports no repository code. The runner receives only width, rawDL and raw
hex bytes. Expected records live in a separate file, and native logical tags
are represented by stable names ok/end/type. This proves the chosen logical
slice interface only. Target compiler identity and real native execution remain
unclaimed.
