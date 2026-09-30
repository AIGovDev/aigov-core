#!/usr/bin/env python3
"""Storage projections: measured avg bytes/event + analytical growth projections.

Per docs/research/storage-analysis.md: multipliers below (index overhead,
checkpoint overhead) are documented assumptions, not measured from a live
Postgres instance — only average_bytes_per_event is an actual measurement.
Writes benchmark-runs/latest/storage-benchmarks.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import empirical_benchmark_lib as lib

SAMPLE_CHAIN_LENGTH = 10_000
PAYLOAD_BYTES = 256

# Documented assumptions (not measured) — see docs/research/storage-analysis.md.
INDEX_OVERHEAD_MULTIPLIER = 1.3
CHECKPOINT_OVERHEAD_MULTIPLIER = 1.1
PROJECTION_EVENTS_PER_DAY = (1_000, 100_000, 10_000_000)


def main() -> int:
    chain = lib.build_synthetic_chain(SAMPLE_CHAIN_LENGTH, payload_bytes=PAYLOAD_BYTES)
    total_bytes = sum(len(r["event_json"].encode("utf-8")) + 64 + 64 for r in chain)  # + prev_hash + record_hash hex
    avg_bytes_per_event = total_bytes / SAMPLE_CHAIN_LENGTH

    projections = []
    for events_per_day in PROJECTION_EVENTS_PER_DAY:
        raw_daily_bytes = avg_bytes_per_event * events_per_day
        raw_monthly_bytes = raw_daily_bytes * 30
        projected_monthly_bytes = raw_monthly_bytes * INDEX_OVERHEAD_MULTIPLIER * CHECKPOINT_OVERHEAD_MULTIPLIER
        projections.append(
            {
                "events_per_day": events_per_day,
                "raw_monthly_bytes": round(raw_monthly_bytes),
                "projected_monthly_bytes_with_overhead": round(projected_monthly_bytes),
                "projected_monthly_gib_with_overhead": round(projected_monthly_bytes / (1024**3), 4),
            }
        )

    result = {
        "benchmark": "storage_projection",
        "methodology": "docs/research/storage-analysis.md",
        "environment": lib.env_metadata(),
        "measured": {
            "sample_chain_length": SAMPLE_CHAIN_LENGTH,
            "payload_bytes": PAYLOAD_BYTES,
            "average_bytes_per_event": round(avg_bytes_per_event, 2),
        },
        "assumptions": {
            "index_overhead_multiplier": INDEX_OVERHEAD_MULTIPLIER,
            "checkpoint_overhead_multiplier": CHECKPOINT_OVERHEAD_MULTIPLIER,
            "note": "Overhead multipliers are documented assumptions, not measured from a live Postgres instance.",
        },
        "projections": projections,
    }
    path = lib.write_artifact("storage-benchmarks.json", result)
    print(json.dumps({"ok": True, "artifact": str(path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
