#!/usr/bin/env python3
"""Export/compression benchmark: json.dumps plus gzip.compress over a synthetic chain.

Writes benchmark-runs/latest/export-benchmarks.json.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import empirical_benchmark_lib as lib

QUICK_EVENT_COUNTS = (1_000, 10_000)
FULL_EVENT_COUNTS = (1_000, 10_000, 100_000)


def run_one(event_count: int) -> dict:
    chain = lib.build_synthetic_chain(event_count, payload_bytes=256)
    events = [json.loads(r["event_json"]) for r in chain]
    export_doc = {"schema_version": "aigov.audit_export.v1", "events": events}

    start = lib.timer()
    serialized = json.dumps(export_doc, separators=(",", ":"), sort_keys=True).encode("utf-8")
    serialize_ms = lib.elapsed_ms(start)

    start = lib.timer()
    compressed = gzip.compress(serialized)
    compress_ms = lib.elapsed_ms(start)

    return {
        "event_count": event_count,
        "serialize_seconds": round(serialize_ms / 1000.0, 6),
        "compress_seconds": round(compress_ms / 1000.0, 6),
        "uncompressed_bytes": len(serialized),
        "compressed_bytes": len(compressed),
        "compression_ratio": round(len(serialized) / len(compressed), 3) if compressed else None,
    }


def main() -> int:
    quick = lib.quick_mode()
    event_counts = QUICK_EVENT_COUNTS if quick else FULL_EVENT_COUNTS

    runs = [run_one(n) for n in event_counts]

    result = {
        "benchmark": "export_compression",
        "methodology": "docs/research/load-testing-methodology.md",
        "environment": lib.env_metadata(),
        "runs": runs,
    }
    path = lib.write_artifact("export-benchmarks.json", result)
    print(json.dumps({"ok": True, "artifact": str(path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
