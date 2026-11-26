#!/usr/bin/env python3
"""Generate CycloneDX 1.5 SBOMs for the Rust and Python dependencies of the release.

Rust: from `cargo metadata --locked` for rust/, with the SHA-256 of each registry crate taken from rust/Cargo.lock.
Python: the dependency closure of `aigov-py`, read from the installed distributions' metadata. Run this with the interpreter
that has aigov-py installed (or the target directory it was installed into, via PYTHONPATH).

The output is machine-readable and is not signed. See docs/release/release-artifacts.md for what it does and does not prove.

Usage: generate_sbom.py --rust-dir rust --out-dir <dir> [--python-root-package aigov-py]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
import uuid
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path


def _rust_components(rust_dir: Path) -> list[dict]:
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked"],
            cwd=rust_dir,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    lock = tomllib.loads((rust_dir / "Cargo.lock").read_text())
    checksums = {(p["name"], p["version"]): p.get("checksum") for p in lock.get("package", []) if p.get("checksum")}
    root_ids = set(meta.get("workspace_members", []))
    components = []
    for pkg in sorted(meta["packages"], key=lambda p: (p["name"], p["version"])):
        if pkg["id"] in root_ids:
            continue
        comp = {
            "type": "library",
            "bom-ref": f"pkg:cargo/{pkg['name']}@{pkg['version']}",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:cargo/{pkg['name']}@{pkg['version']}",
        }
        if pkg.get("license"):
            comp["licenses"] = [{"expression": pkg["license"]}]
        checksum = checksums.get((pkg["name"], pkg["version"]))
        if checksum:
            comp["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        if pkg.get("source"):
            comp["externalReferences"] = [{"type": "distribution", "url": pkg["source"]}]
        components.append(comp)
    return components


def _requirement_name(req: str) -> str:
    return re.split(r"[\s;<>=!~\[(]", req.strip(), maxsplit=1)[0].lower().replace("_", "-")


def _python_components(root: str) -> list[dict]:
    dists = {}
    for d in metadata.distributions():
        name = (d.metadata["Name"] or "").lower().replace("_", "-")
        if name and name not in dists:
            dists[name] = d
    if root not in dists:
        raise SystemExit(f"{root} is not installed in this interpreter")
    closure, todo = set(), [root]
    while todo:
        name = todo.pop()
        if name in closure or name not in dists:
            continue
        closure.add(name)
        for req in dists[name].requires or []:
            if "extra ==" in req:
                continue  # optional extras are not part of the default install
            todo.append(_requirement_name(req))
    components = []
    for name in sorted(closure):
        d = dists[name]
        version = d.version
        comp = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{name}@{version}",
            "name": d.metadata["Name"],
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
        }
        expr = d.metadata.get("License-Expression")
        lic = expr or d.metadata.get("License")
        if lic and lic != "UNKNOWN":
            comp["licenses"] = [{"expression": lic}] if expr else [{"license": {"name": lic}}]
        components.append(comp)
    return components


def _bom(components: list[dict], subject: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, subject + json.dumps([c['bom-ref'] for c in components]))}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "name": subject, "bom-ref": subject},
            "tools": [{"name": "scripts/generate_sbom.py"}],
        },
        "components": components,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rust-dir", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--python-root-package", default="aigov-py")
    args = ap.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    rust = _bom(_rust_components(args.rust_dir), "aigov-core-rust")
    py = _bom(_python_components(args.python_root_package.lower()), "aigov-py-python")
    (args.out_dir / "aigov-core-rust.cdx.json").write_text(json.dumps(rust, indent=2) + "\n")
    (args.out_dir / "aigov-py-python.cdx.json").write_text(json.dumps(py, indent=2) + "\n")
    print(f"rust components: {len(rust['components'])}, python components: {len(py['components'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
