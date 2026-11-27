"""Sync and validate the static Hugging Face Space package."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples/reconstructible-agent-demo/viewer/index.html"
SPACE = ROOT / "spaces/aigov-core-evidence-viewer"
TARGET = SPACE / "index.html"
README = SPACE / "README.md"
SAMPLE = SPACE / "sample-evidence-export.json"
FORBIDDEN = ("innerhtml", "outerhtml", "xmlhttprequest", "<script src=")


def check() -> list[str]:
    errors = []
    source = SOURCE.read_text(encoding="utf-8")
    if not TARGET.is_file() or TARGET.read_text(encoding="utf-8") != source:
        errors.append("Space index.html is not synchronized with the canonical viewer")
    lowered = source.lower()
    for pattern in FORBIDDEN:
        if pattern in lowered:
            errors.append(
                "Canonical viewer contains a disallowed HTML sink or external request: "
                f"{pattern}"
            )
    for required in (
        "crypto.subtle.digest",
        '"GENESIS"',
        "MAX_FILE_BYTES",
        "MAX_ROWS",
        'mode: "same-origin"',
        'credentials: "omit"',
        'redirect: "error"',
    ):
        if required not in source:
            errors.append(f"Canonical viewer is missing expected behavior: {required}")
    readme = README.read_text(encoding="utf-8")
    for required in ("sdk: static", "app_file: index.html"):
        if required not in readme:
            errors.append(f"Space README is missing configuration: {required}")
    if not SAMPLE.is_file():
        errors.append("Space sample evidence export is missing")
    else:
        try:
            import json

            sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
            if not isinstance(sample, dict) or not sample.get("evidence_events"):
                errors.append("Space sample export must contain evidence_events")
            if not sample.get("evidence_hashes", {}).get("log_chain"):
                errors.append("Space sample export must contain a log_chain")
        except (ValueError, OSError) as exc:
            errors.append(f"Space sample export is not valid JSON: {exc}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the package is stale or unsafe",
    )
    args = parser.parse_args(argv)
    if not args.check:
        SPACE.mkdir(parents=True, exist_ok=True)
        TARGET.write_text(SOURCE.read_text(encoding="utf-8"), encoding="utf-8")
    errors = check()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("Hugging Face static Space package is synchronized and passed safety checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
