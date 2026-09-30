#!/usr/bin/env python3
"""Hash-chain verification benchmark: full linear verification over in-memory chains.

Writes benchmark-runs/latest/hash-chain-benchmarks.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import empirical_benchmark_lib as lib

QUICK_CHAIN_LENGTHS = (1_000, 10_000)
FULL_CHAIN_LENGTHS = (1_000, 10_000, 100_000, 1_000_000)


def run_one(length: int) -> dict:
    chain = lib.build_synthetic_chain(length, payload_bytes=256)

    start = lib.timer()
    ok, broken_at = lib.verify_chain(chain)
    verify_s = lib.elapsed_ms(start) / 1000.0

    return {
        "chain_length": length,
        "verification_seconds": round(verify_s, 6),
        "us_per_event": round((verify_s * 1_000_000) / length, 3) if length else None,
        "events_per_sec": round(length / verify_s, 3) if verify_s > 0 else None,
        "chain_valid": ok,
        "broken_at_index": broken_at,
    }


def main() -> int:
    quick = lib.quick_mode()
    lengths = QUICK_CHAIN_LENGTHS if quick else FULL_CHAIN_LENGTHS

    runs = [run_one(n) for n in lengths]

    result = {
        "benchmark": "hash_chain_verification",
        "methodology": "docs/research/load-testing-methodology.md",
        "environment": lib.env_metadata(),
        "runs": runs,
    }
    path = lib.write_artifact("hash-chain-benchmarks.json", result)
    print(json.dumps({"ok": True, "artifact": str(path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
