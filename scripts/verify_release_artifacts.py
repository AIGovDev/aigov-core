#!/usr/bin/env python3
"""Verify release artifacts: SBOMs against the official CycloneDX schema, dependency completeness, recorded checksums, and
the absence of fault-injection code in the release binary.

Needs the `cyclonedx-python-lib[json-validation]` package (for the bundled official schemas).

Usage: verify_release_artifacts.py --sbom-dir <dir> --provenance <json> [--rust-dir rust] [--pyproject python/pyproject.toml]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def validate_schema(path: Path) -> str | None:
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    return None if JsonStrictValidator(SchemaVersion.V1_5).validate_str(path.read_text()) is None else "schema validation failed"


def rust_completeness(sbom: dict, rust_dir: Path) -> list[str]:
    lock = tomllib.loads((rust_dir / "Cargo.lock").read_text())
    locked = {(p["name"], p["version"]) for p in lock.get("package", []) if p.get("source")}
    in_sbom = {(c["name"], c["version"]) for c in sbom["components"]}
    problems = []
    if locked - in_sbom:
        problems.append(f"Rust packages in Cargo.lock but not in the SBOM: {sorted(locked - in_sbom)[:5]}")
    if in_sbom - locked:
        problems.append(f"Rust components in the SBOM but not in Cargo.lock: {sorted(in_sbom - locked)[:5]}")
    return problems


def python_completeness(sbom: dict, pyproject: Path) -> list[str]:
    data = tomllib.loads(pyproject.read_text())
    names = {c["name"].lower().replace("_", "-") for c in sbom["components"]}
    problems = []
    for req in data["project"]["dependencies"]:
        name = re.split(r"[\s;<>=!~\[(]", req.strip(), maxsplit=1)[0].lower().replace("_", "-")
        if name not in names:
            problems.append(f"declared dependency {name} is not in the SBOM")
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sbom-dir", type=Path, required=True)
    ap.add_argument("--provenance", type=Path, required=True)
    ap.add_argument("--rust-dir", type=Path, default=REPO / "rust")
    ap.add_argument("--pyproject", type=Path, default=REPO / "python" / "pyproject.toml")
    ap.add_argument("--artifact-dir", type=Path, action="append", default=[], help="extra directory to find artifacts (for example the wheel)")
    args = ap.parse_args(argv)
    failures: list[str] = []

    print("1. SBOMs against the official CycloneDX 1.5 schema")
    for name in ("aigov-core-rust.cdx.json", "aigov-py-python.cdx.json"):
        p = args.sbom_dir / name
        err = validate_schema(p)
        print(f"   {'ok ' if err is None else 'FAIL'} {name}")
        if err:
            failures.append(f"{name}: {err}")

    print("2. Dependency completeness")
    rust_sbom = json.loads((args.sbom_dir / "aigov-core-rust.cdx.json").read_text())
    py_sbom = json.loads((args.sbom_dir / "aigov-py-python.cdx.json").read_text())
    for problem in rust_completeness(rust_sbom, args.rust_dir) + python_completeness(py_sbom, args.pyproject):
        failures.append(problem)
        print(f"   FAIL {problem}")
    if not any("SBOM" in f for f in failures):
        print(f"   ok   {len(rust_sbom['components'])} Rust components match Cargo.lock; every declared Python dependency is in the SBOM")

    print("3. Recorded checksums")
    record = json.loads(args.provenance.read_text())
    for label, entry in record["artifacts"].items():
        path = Path(entry["path"])
        candidates = [REPO / path, args.sbom_dir / path, REPO / "rust" / path] + [d / path.name for d in args.artifact_dir]
        found = next((c for c in candidates if c.exists()), None)
        if found is None:
            print(f"   skip {label}: {entry['path']} not present in this checkout")
            continue
        ok = _sha256(found) == entry["sha256"]
        print(f"   {'ok  ' if ok else 'FAIL'} {label}")
        if not ok:
            failures.append(f"checksum changed for {label}")

    print("4. Fault-injection code absent from the release binary")
    binary = next((REPO / a["path"] for a in record["artifacts"].values() if a["path"].endswith("aigov_audit")), None)
    if binary is None or not binary.exists():
        print("   skip: release binary not present")
    else:
        r = subprocess.run([sys.executable, str(REPO / "scripts" / "check_no_fault_injection.py"), str(binary)], capture_output=True, text=True)
        print("   " + (r.stdout.strip() or r.stderr.strip()))
        if r.returncode != 0:
            failures.append("fault-injection names present in the release binary")

    print()
    if failures:
        print("RESULT: FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("RESULT: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
