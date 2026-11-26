#!/usr/bin/env python3
"""Fail if a release artifact contains fault-injection crash points.

The crash points exist only in a build with the `fault-injection` Cargo feature. Their names are compiled into that build
and nowhere else. This check reads a binary as bytes and looks for the names. It is a strings check, so it cannot prove
that no crash code exists. It does catch the feature being enabled by mistake, which is the failure it is for.

Usage: check_no_fault_injection.py <binary> [<binary> ...]
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# Names that exist only in the fault-injection build. Core's `crash_point` calls use these.
CRASH_POINT_NAMES = (b"after_sign_before_response", b"after_append_before_sign")


def check(path: Path) -> list[str]:
    data = path.read_bytes()
    return [name.decode() for name in CRASH_POINT_NAMES if name in data]


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    failed = False
    for arg in argv:
        path = Path(arg)
        found = check(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if found:
            failed = True
            print(f"FAIL {path} sha256={digest} contains crash points: {found}")
        else:
            print(f"ok   {path} sha256={digest} contains no crash-point names")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
