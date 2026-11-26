#!/usr/bin/env python3
"""Write a build-provenance record for a release candidate: source commit, toolchains, pinned base images, and the SHA-256
of each artifact. The record is not signed, and it is not an in-toto or SLSA attestation. It is what a reviewer needs to
match an artifact to the commit and the inputs that produced it.

Usage: release_provenance.py --binary rust/target/release/aigov_audit --wheel <wheel> --sbom-dir <dir> --out <json>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(*args: str) -> str:
    return subprocess.run(args, cwd=REPO, check=True, capture_output=True, text=True).stdout.strip()


def _base_images() -> list[str]:
    text = (REPO / "rust" / "Dockerfile").read_text()
    return sorted(set(re.findall(r"^FROM (\S+)", text, flags=re.MULTILINE)))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--wheel", type=Path)
    ap.add_argument("--sbom-dir", type=Path)
    ap.add_argument("--reproducibility", default="", help="how the binary was rebuilt and compared, and the result")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    artifacts = {"aigov_audit (release binary)": {"path": str(args.binary.relative_to(REPO)) if args.binary.is_absolute() and REPO in args.binary.parents else str(args.binary), "sha256": _sha256(args.binary)}}
    if args.wheel:
        artifacts["aigov_py wheel"] = {"path": args.wheel.name, "sha256": _sha256(args.wheel)}
    if args.sbom_dir:
        for p in sorted(args.sbom_dir.glob("*.cdx.json")):
            artifacts[f"SBOM {p.name}"] = {"path": p.name, "sha256": _sha256(p)}
    for rel in ("rust/Cargo.lock", "python/pyproject.toml", "rust/Dockerfile"):
        artifacts[rel] = {"path": rel, "sha256": _sha256(REPO / rel)}

    record = {
        "schema": "govai.release_provenance.v1",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {
            "commit": _run("git", "rev-parse", "HEAD"),
            "branch": _run("git", "rev-parse", "--abbrev-ref", "HEAD"),
            "working_tree_clean": _run("git", "status", "--porcelain") == "",
        },
        "toolchain": {
            "rustc": _run("rustc", "-V"),
            "cargo": _run("cargo", "-V"),
            "python": sys.version.split()[0],
        },
        "base_images_pinned_by_digest": _base_images(),
        "build_commands": [
            "cargo build --locked --release --bin aigov_audit",
            "cargo build --locked --release --features fault-injection --bin aigov_audit --target-dir ../target-fault  (test only, never released)",
            "python -m build --wheel python",
            "python scripts/generate_sbom.py --rust-dir rust --out-dir <dir>",
        ],
        "reproducibility": args.reproducibility,
        "artifacts": artifacts,
        "not_proven": [
            "that the artifacts were built on an isolated or hardened builder",
            "that the record is authentic: it is not signed",
            "that the dependency sources were not altered after the lock was written, beyond the lockfile checksums",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2) + "\n")
    print(f"wrote {args.out} ({len(artifacts)} artifacts)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
