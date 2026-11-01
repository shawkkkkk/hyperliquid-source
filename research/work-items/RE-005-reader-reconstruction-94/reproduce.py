#!/usr/bin/env python3
"""Build only the independent Rust component and compare frozen logical rows.

No captured executable, emulator, instruction evaluator, repository module,
network service, Cargo hook, or external Python dependency is invoked.
"""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


PACKET = pathlib.Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
COMPONENT = ROOT / "src/bincode-varint"
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PROVIDER_SHA = "56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6"
FROZEN = {
    "reader623-corpus.json": "da6d136c6904f2f63505f598a6812d19b9398174b133d50a4067d918113be4e7",
    "reader623-input.tsv": "753dcb283332640126eaf157c763144c91c750cd5b4b5e8ef940be7832fa26f6",
    "reader623-expected.tsv": "0a6dca7c361155644ac21bc1952b8c748079379738f38ab9408eb5d4f78c1500",
    "generate_reader.py": "d28f8cf4951d75193a34fe6514b7c02095828dbe772ad19dbba0c770afb0179f",
    "reader623-proof.md": "10d25cac06c253e120f0009ab472bd86bfbd7779da3d90e27ff706a0242375e7",
}
SOURCES = {
    "src/lib.rs": "c36b803002df599caf92e36744240f753ce160138d8a895855d5fbcd1f54a947",
    "examples/reader_oracle.rs": "c45d2b9e7eba4d7a0eb15da78b685cd5741acbbb6d7132ea4035b1387e61ff68",
    "tests/reader_vectors.rs": "b74970b2bb659081bf4695040002b77808074c238e97bb4518da3a2dfe0bc37b",
    "Cargo.toml": "fc634395ea9e215282c5662b66a03cd128cebae4bf4f238482e213adbf95eefb",
    "Cargo.lock": "963f32e54bf1d7ba345e383184b5516162a6cb3b1063c91bf61f7b5c2815345c",
}


def sha(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def capture(argv):
    return subprocess.check_output(argv, cwd=ROOT, text=True).strip()


def snapshot():
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).split(b"\0")
    files = {}
    for name in sorted(set(names) - {b""}):
        path = ROOT / name.decode()
        if path.is_file():
            files[name.decode()] = sha(path)
    pins = capture(["git", "submodule", "status", "--recursive"])
    require(len(pins.splitlines()) == 7, "expected all seven submodule pins")
    require(all(line[:1] not in "+-U" for line in pins.splitlines()), "submodule pin mismatch")
    pin_states = {}
    for line in pins.splitlines():
        path = line.split()[1]
        status = capture(["git", "-C", str(ROOT / path), "status", "--porcelain=v1", "--untracked-files=all"])
        require(not status, f"dirty submodule: {path}")
        pin_states[path] = {"head": capture(["git", "-C", str(ROOT / path), "rev-parse", "HEAD"]), "status": status}
    return {
        "head": capture(["git", "rev-parse", "HEAD"]),
        "status": capture(["git", "status", "--porcelain=v1", "--untracked-files=all"]),
        "submodule_pins": pins,
        "submodule_states": pin_states,
        "files": files,
    }


def provider_snapshot(audit_path):
    require(sha(audit_path) == PROVIDER_SHA, "research provider audit digest mismatch")
    audit = json.loads(audit_path.read_text())
    prefix = pathlib.Path(audit["prefix"])
    require(len(audit["payloads"]) == 103, "provider must cover 103 payloads")
    payloads = {entry["path"]: sha(prefix / entry["path"]) for entry in audit["payloads"]}
    for entry in audit["payloads"]:
        require(payloads[entry["path"]] == entry["sha256"], "provider payload mismatch")
    return payloads


def command(argv, stem, records, *, input_bytes=None):
    with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
        result = subprocess.run(argv, cwd=ROOT, input=input_bytes, stdout=out, stderr=err, check=False)
    records.append({"argv": list(map(str, argv)), "exit_code": result.returncode, "log_stem": str(stem)})
    (stem.parent.parent / "COMMANDS.json").write_text(json.dumps(records, indent=2) + "\n")
    require(result.returncode == 0, f"command failed; see {stem}.stderr")
    return stem.with_suffix(".stdout").read_bytes()


def compare(actual, expected):
    left, right = actual.splitlines(), expected.splitlines()
    return sum(a != b for a, b in zip(left, right)) + abs(len(left) - len(right))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", required=True, type=pathlib.Path)
    parser.add_argument("--provider-audit", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.out = args.out.resolve()
    require(not args.out.exists(), "output directory must be new")
    args.out.mkdir(parents=True)
    for name, expected_sha in FROZEN.items():
        require(sha(PACKET / name) == expected_sha, f"frozen input mismatch: {name}")
    for name, expected_sha in SOURCES.items():
        require(sha(COMPONENT / name) == expected_sha, f"source mismatch: {name}")
    require(sha(ROOT / "artifacts/node/94/hl-node") == TARGET_SHA, "target digest mismatch")
    provider_before = provider_snapshot(args.provider_audit)
    rustc = args.rustc.resolve()
    provider = json.loads(args.provider_audit.read_text())
    require(rustc == pathlib.Path(provider["prefix"]) / "bin/rustc", "unexpected compiler path")
    require(capture([str(rustc), "-vV"]) + "\n" == provider["rustc_vV"], "compiler identity mismatch")
    host_tools = {}
    for path in (pathlib.Path("/usr/bin/gcc"), pathlib.Path("/usr/bin/ld.bfd")):
        actual_path = path.resolve()
        host_tools[str(path)] = {"resolved": str(actual_path), "sha256": sha(actual_path), "version": capture([str(path), "--version"])}
    before = snapshot()
    records, builds = [], []
    inputs = (PACKET / "reader623-input.tsv").read_bytes()
    expected = (PACKET / "reader623-expected.tsv").read_bytes()
    require(len(inputs.splitlines()) == 8364 == len(expected.splitlines()), "corpus denominator mismatch")
    common = [str(rustc), "--edition=2024", "--target=x86_64-unknown-linux-gnu", "-Dwarnings", "-Copt-level=3", "-Ccodegen-units=1", "-Cdebuginfo=0", "-Clinker=/usr/bin/gcc", "-Clink-arg=-fuse-ld=bfd"]

    def build(source, directory, tests):
        directory.mkdir()
        library = directory / "libhl_bincode_varint.rlib"
        command(common + ["--crate-name=hl_bincode_varint", "--crate-type=rlib", str(source), "-o", str(library)], directory / "library", records)
        extern = ["--extern", f"hl_bincode_varint={library}"]
        runner = directory / "reader_oracle"
        command(common + [str(COMPONENT / "examples/reader_oracle.rs"), *extern, "-o", str(runner)], directory / "runner-build", records)
        actual = command([str(runner)], directory / "corpus", records, input_bytes=inputs)
        require(len(actual.splitlines()) == 8364, "runner must emit all 8364 corpus rows")
        if tests:
            require(compare(actual, expected) == 0 and actual == expected, "frozen corpus mismatch")
            for test in ("evidence_vectors", "reader_vectors"):
                executable = directory / test
                command(common + ["--test", str(COMPONENT / f"tests/{test}.rs"), *extern, "-o", str(executable)], directory / f"{test}-build", records)
                command([str(executable), "--test-threads=1"], directory / f"{test}-run", records)
        return {"artifacts": {p.name: sha(p) for p in directory.iterdir() if p.suffix not in (".stdout", ".stderr")}, "actual_sha256": hashlib.sha256(actual).hexdigest(), "mismatch_rows": compare(actual, expected)}

    for name in ("build-a", "build-b"):
        builds.append(build(COMPONENT / "src/lib.rs", args.out / name, True))
    require(builds[0]["artifacts"] == builds[1]["artifacts"], "independent output-directory rebuild differs")
    controls = []
    source = (COMPONENT / "src/lib.rs").read_text()
    for name, old, new in (
        ("value", "    Ok(tag)\n", "    Ok(tag ^ 1)\n"),
        ("shortage", "additional: WIDTH - input.len(),", "additional: WIDTH - input.len() + 1,"),
        ("raw-code", "U128_MARKER => Err(reader_marker_error(3, 4)),", "U128_MARKER => Err(reader_marker_error(2, 4)),"),
    ):
        require(source.count(old) == 1, f"mutation site not unique: {name}")
        mutant = args.out / f"{name}.rs"
        mutant.write_text(source.replace(old, new))
        result = build(mutant, args.out / f"control-{name}", False)
        require(result["mismatch_rows"] > 0, f"source corruption not detected: {name}")
        controls.append({"name": name, "source_sha256": sha(mutant), **result})
    actual = (args.out / "build-a/corpus.stdout").read_bytes()
    require(compare(actual + b"extra\n", expected) > 0, "extra-row control missed")
    require(compare(b"\n".join(actual.splitlines()[1:]) + b"\n", expected) > 0, "missing-row control missed")
    after = snapshot()
    provider_after = provider_snapshot(args.provider_audit)
    require(before == after, "worktree inputs/head/status/pins changed during validation")
    require(provider_before == provider_after, "research compiler payload changed during validation")
    require(all(sha(pathlib.Path(entry["resolved"])) == entry["sha256"] for entry in host_tools.values()), "host compiler/linker changed during validation")
    report = {"schema": 1, "scope": "Reader623 logical Rust reconstruction only", "target_sha256": TARGET_SHA, "corpus_cases": 8364, "corpus_mismatches": [b["mismatch_rows"] for b in builds], "builds": builds, "source_controls": controls, "row_count_controls": ["extra rejected", "missing rejected"], "sources": SOURCES, "frozen": FROZEN, "before": before, "after": after, "provider_audit_sha256": PROVIDER_SHA, "provider_payloads_before": provider_before, "provider_payloads_after": provider_after, "host_tools": host_tools, "commands": records, "captured_native_execution": False, "cargo_clippy_rustfmt": "NOT_RUN: unavailable authenticated tools", "full_repository_suite": "NOT_RUN: current expanded suite not authorized"}
    (args.out / "REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS: Reader623; 8364/8364 exact rows in each of two builds; three source corruptions and two row-count corruptions detected; inputs unchanged")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
