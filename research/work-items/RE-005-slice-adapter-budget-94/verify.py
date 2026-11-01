#!/usr/bin/env python3
"""Static byte/FDE/helper checks and a pure mathematical slice-state relation.

No captured instruction, PC/register evaluator, or reconstructed Rust is run.
"""

import argparse
import collections
import hashlib
import json
import pathlib
import re
import struct
import sys

PACKET = pathlib.Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
MAX = (1 << 64) - 1
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
NATIVE_SHA = "7848bfb0cfdcf4273d1904abaecb82607ac7f0e39528d7495aceabadbd0a0e0e"
HELPER_SHA = "a8ecd49f000a9156f8d8b5380610bf037fc133f62c5d56efc0f39868e1841ede"
FREEZE_SHA = "0f8cbac0cdb676458cbf71e373a60c5123fe0d1418a300a1063ce4dab9b85eb8"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pinned_json(path, expected):
    data = path.read_bytes()
    require(digest(data) == expected, f"pinned receipt changed: {path.name}")
    return json.loads(data)


def load_view(data):
    require(data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64")
    require(struct.unpack_from("<H", data, 18)[0] == 62, "expected x86-64")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    require(size == 56, "unexpected program header size")
    loads = [struct.unpack_from("<IIQQQQQQ", data, offset + index * size) for index in range(count)]
    loads = [entry for entry in loads if entry[0] == 1]

    def view(va, length):
        matches = [entry for entry in loads if entry[3] <= va and va + length <= entry[3] + entry[5]]
        require(len(matches) == 1, "VA range must have one file-backed PT_LOAD")
        file_offset = matches[0][2] + va - matches[0][3]
        require(file_offset + length <= len(data), "range exceeds file")
        return data[file_offset:file_offset + length]

    return view


def admit(data, *, require_whole_digest=True):
    # The test-only argument isolates below-digest structural corruption controls.
    # Every ordinary invocation requires the whole original capture digest.
    if require_whole_digest:
        require(len(data) == 91774280 and digest(data) == TARGET_SHA, "target identity mismatch")
    native = pinned_json(PACKET / "native/NATIVE-REVIEW.json", NATIVE_SHA)
    helper = pinned_json(PACKET / "helper/READER-NATIVE-REVIEW.json", HELPER_SHA)
    view = load_view(data)
    cie = helper["actual_CIE"]
    cie_va = int(cie["va"], 16)
    require(view(cie_va, len(bytes.fromhex(cie["raw"]))) == bytes.fromhex(cie["raw"]), "CIE changed")
    parameters, calls, helper_calls, primary_rows = {}, [], [], 0
    for record in native["functions"] + helper["functions"]:
        primary = "FDE" in record
        directory = PACKET / ("native" if primary else "helper")
        start, end = int(record["start"], 16), int(record["end"], 16)
        code = view(start, end - start)
        require(digest(code) == record["body_sha256"], "complete function bytes changed")
        require(code == (directory / (record["name"] + ".raw")).read_bytes(), "raw export differs")
        fde_va = record["FDE"]["va"] if primary else int(record["FDE_VA"], 16)
        fde = bytes.fromhex(record["FDE"]["raw"] if primary else record["FDE_raw"])
        require(view(fde_va, len(fde)) == fde, "FDE changed")
        require(fde_va + 4 - struct.unpack_from("<I", fde, 4)[0] == cie_va, "FDE/CIE relation changed")
        require(fde_va + 8 + struct.unpack_from("<i", fde, 8)[0] == start, "FDE start changed")
        require(struct.unpack_from("<I", fde, 12)[0] == end - start, "FDE extent changed")
        listing = (directory / (record["name"] + ".objdump.txt")).read_bytes()
        require(digest(listing) == record["objdump_sha256"], "native listing changed")
        require((directory / (record["name"] + ".objdump.stderr")).read_bytes() == b"", "nonempty native stderr")
        position, rows = start, 0
        for line in listing.decode().splitlines():
            match = re.fullmatch(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.+)", line)
            if not match:
                continue
            va, instruction = int(match[1], 16), bytes.fromhex(match[2])
            require(va == position and 1 <= len(instruction) <= 15, "incomplete or overlapping instruction rows")
            require(view(va, len(instruction)) == instruction, "listing instruction bytes differ")
            position += len(instruction)
            rows += 1
            if match[3].lstrip().startswith("call"):
                require(instruction[:2] == b"\xff\x15" and len(instruction) == 6, "unexpected indirect call shape")
                slot = va + 6 + struct.unpack_from("<i", instruction, 2)[0]
                require(hex(slot) in helper["relocations"], "outer call not closed")
                call = {"va": hex(va), "slot": hex(slot), "target": helper["relocations"][hex(slot)]["addend"]}
                (calls if primary else helper_calls).append(call)
        require(position == end and rows == record["rows"], "complete native row denominator changed")
        if primary:
            primary_rows += rows
            width = 32 if record["name"] == "u32-outer" else 64
            # Read only these statically qualified immediate fields. This is
            # an ELF/literal checker, not an instruction interpreter.
            charge = code[0x17]
            mode = code[3]
            threshold = struct.unpack("b", code[0x0d:0x0e])[0] & MAX
            fast_gt = code[0x30]
            require(charge == fast_gt == width // 8 and mode == 1, "outer immediate relation differs")
            require(threshold == MAX - charge, "overflow threshold differs")
            parameters[width] = {"charge": charge, "charged_mode": mode, "overflow_threshold": threshold, "fast_remaining_gt": fast_gt}
    require(primary_rows == 142 and len(calls) == 7, "primary 472B/142-row/call denominator differs")
    require(len(helper_calls) == 5 and all(call["target"] == "0x466dac0" for call in helper_calls), "Reader normal-return helper calls not closed")
    for table in list(native["tables"].values()) + list(helper["tables"].values()):
        va, expected = int(table["va"], 16), bytes.fromhex(table["raw"])
        actual = view(va, len(expected))
        require(actual == expected, "relative jump table changed")
        require([hex(va + offset) for offset in struct.unpack("<4i", actual)] == table["targets"], "table targets changed")
    for slot, record in helper["relocations"].items():
        offset = int(record["file_offset"], 16)
        actual = data[offset:offset + 24]
        require(actual == bytes.fromhex(record["raw"]), "actual helper RELA record changed")
        location, info, addend = struct.unpack("<QQq", actual)
        require(location == int(slot, 16) and info == 8 and addend == int(record["addend"], 16), "helper RELA binding changed")
    return parameters, calls, helper_calls


def relation(case, parameters, mutation=None):
    """Pure case equations over integers/byte strings; never native execution."""
    identifier, width, mode, counter, limit, pointer, raw_hex = case
    raw = bytes.fromhex(raw_hex)
    p = parameters[width]
    require(0 <= mode < 1 << 32 and 0 <= counter <= MAX and 0 <= limit <= MAX, "state outside integer domain")
    require(0 <= pointer <= MAX - len(raw), "nonwrapping readable-slice projection required")
    after, written, consumed = counter, False, 0

    def result(path, payload):
        return {"id": identifier, "path": path, "result": payload, "counter_after": after, "counter_written": written, "consumed": consumed, "remaining": len(raw) - consumed, "pointer_after": pointer + consumed, "tail_hex": raw[consumed:].hex()}

    charged = mode != 0 if mutation == "mode-nonzero" else mode == p["charged_mode"]
    charge = 1 if mutation == "charge-one" else p["charge"]
    if charged:
        if counter > MAX - charge:
            if mutation == "overflow-store":
                after, written = (counter + charge) & MAX, True
            return result("counter-overflow", {"tag": 2})
        after, written = counter + charge, True
        if after > limit:
            if mutation == "limit-rollback":
                after, written = counter, False
            return result("over-limit-after-store", {"tag": 2})
    fast = len(raw) > p["fast_remaining_gt"]
    path = "fast" if fast else "slow-forced-little"
    if not raw:
        return result(path, {"tag": 0, "additional": 1})
    marker = raw[0]
    if marker < 251:
        consumed = 1
        return result(path, {"tag": 18, "value": marker})
    allowed = {251: 2, 252: 4}
    if width == 64:
        allowed[253] = 8
    if marker not in allowed:
        consumed = 1 if not fast or mutation == "fast-consumes-tag" else 0
        expected = 2 if fast or width == 32 else 3
        if mutation == "u64-fast-code-three" and fast and width == 64:
            expected = 3
        return result(path, {"tag": 3, "expected": expected, "found": {253: 3, 254: 4, 255: 12}[marker]})
    required = allowed[marker] + 1
    if len(raw) < required:
        consumed = 1
        return result(path, {"tag": 0, "additional": required - len(raw)})
    consumed = required
    payload = raw[1:required]
    if mutation == "slow-big-endian" and not fast:
        payload = payload[::-1]
    value = sum(byte << (8 * index) for index, byte in enumerate(payload))
    return result(path, {"tag": 18, "value": value})


def load_cases():
    freeze = pinned_json(PACKET / "FREEZE.json", FREEZE_SHA)
    for name, record in freeze["files"].items():
        data = (PACKET / name).read_bytes()
        require(len(data) == record["bytes"] and digest(data) == record["sha256"], "independent frozen authority changed")
    cases = []
    for line in (PACKET / "inputs.tsv").read_text().splitlines():
        fields = line.split("\t")
        require(len(fields) == 7, "input record arity changed")
        cases.append((fields[0], *map(int, fields[1:6]), fields[6]))
    expected = [json.loads(line) for line in (PACKET / "expected.jsonl").read_text().splitlines()]
    require(len(cases) == len(expected) == 6716, "case denominator changed")
    return cases, expected, freeze


def check(target, output):
    require(not output.exists(), "output directory must be new")
    output.mkdir(parents=True)
    data = target.read_bytes()
    parameters, calls, helper_calls = admit(data)
    cases, expected, freeze = load_cases()
    actual = [relation(case, parameters) for case in cases]
    actual_bytes = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in actual)
    (output / "actual.jsonl").write_bytes(actual_bytes)
    require(actual == expected and actual_bytes == (PACKET / "expected.jsonl").read_bytes(), "frozen mathematical state relation mismatch")
    controls = []
    for mutation in ("mode-nonzero", "charge-one", "overflow-store", "limit-rollback", "fast-consumes-tag", "u64-fast-code-three", "slow-big-endian"):
        changed = [relation(case, parameters, mutation) for case in cases]
        mismatches = [index for index, pair in enumerate(zip(changed, expected)) if pair[0] != pair[1]]
        require(len(changed) == 6716 and mismatches, "mathematical corruption control missed")
        raw = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in changed)
        (output / (mutation + ".jsonl")).write_bytes(raw)
        controls.append({"mutation": mutation, "rows": len(changed), "mismatches": len(mismatches), "actual_sha256": digest(raw), "first_case": cases[mismatches[0]][0]})
    view = load_view(data)
    byte_controls = []
    # Exact actual byte counterfactuals, never executed. Validation below the
    # whole-file gate must still reject every changed native structure.
    for name, va in (("mode", 0x466bc13), ("overflow-threshold", 0x466bc1d), ("counter-store", 0x466bc28), ("slow-endian", 0x466bcae), ("fast-error-code", 0x466bdc9), ("jump-table", 0x6f6e98), ("FDE", 0xef1e80)):
        original = view(va, 1)
        # Resolve an original byte to its unique file-backed location.
        headers = struct.unpack_from("<Q", data, 32)[0]
        count = struct.unpack_from("<H", data, 56)[0]
        entries = [struct.unpack_from("<IIQQQQQQ", data, headers + 56 * index) for index in range(count)]
        entry = next(item for item in entries if item[0] == 1 and item[3] <= va < item[3] + item[5])
        offset = entry[2] + va - entry[3]
        changed = bytearray(data)
        changed[offset] ^= 1
        try:
            admit(changed, require_whole_digest=False)
        except ValueError as error:
            byte_controls.append({"name": name, "va": hex(va), "original": original.hex(), "changed": bytes(changed[offset:offset + 1]).hex(), "rejected": str(error)})
        else:
            raise ValueError("native structural corruption control missed")
    report = {"schema": 1, "target_sha256": digest(data), "primary_bytes": 472, "primary_rows": 142, "helper_context_bytes": 623, "parameters": parameters, "outer_calls": calls, "Reader_context_calls": helper_calls, "cases": 6716, "exact_rows": len(actual), "actual_sha256": digest(actual_bytes), "path_counts": dict(collections.Counter(row["path"] for row in actual)), "result_tag_counts": dict(collections.Counter(row["result"]["tag"] for row in actual)), "math_corruption_controls": controls, "native_structural_controls": byte_controls, "pre_model_freeze_sha256": FREEZE_SHA, "native_receipt_sha256": NATIVE_SHA, "helper_receipt_sha256": HELPER_SHA, "native_execution_or_evaluator": False, "Rust_implementation_claimed": False, "full_repository_suite": "NOT_RUN: current expanded suite not authorized"}
    (output / "REPORT.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print("PASS: complete outer472B/142rows; all seven calls closed; 6716 exact independent state cases; seven mathematical and seven native-structure corruptions rejected; no captured execution")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=pathlib.Path, default=ROOT / "artifacts/node/94/hl-node")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        check(args.target, args.out)
    except (ValueError, OSError, struct.error) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
