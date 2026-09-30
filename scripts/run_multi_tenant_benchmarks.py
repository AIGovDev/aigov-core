#!/usr/bin/env python3
"""Multi-tenant synthetic load: sequential tenant-scoped workloads.

Per docs/research/scalability-analysis.md: models logical isolation
(distinct run_id namespaces processed sequentially in one process), not
network-isolated processes. Writes
benchmark-runs/latest/multi-tenant-benchmarks.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import empirical_benchmark_lib as lib

QUICK_TENANT_COUNTS = (1, 10, 100)
FULL_TENANT_COUNTS = (1, 10, 100, 1_000)
EVENTS_PER_TENANT = 50
PAYLOAD_BYTES = 256


def run_one(tenant_count: int) -> dict:
    start = lib.timer()
    for tenant_idx in range(tenant_count):
        prev_hash = "0" * 64
        for i in range(EVENTS_PER_TENANT):
            event_json = lib.synthetic_event(f"tenant-{tenant_idx}", i, PAYLOAD_BYTES)
            prev_hash = lib.compute_record_hash(prev_hash, event_json)
    total_s = lib.elapsed_ms(start) / 1000.0

    total_events = tenant_count * EVENTS_PER_TENANT
    return {
        "tenant_count": tenant_count,
        "events_per_tenant": EVENTS_PER_TENANT,
        "total_events": total_events,
        "total_seconds": round(total_s, 6),
        "throughput_events_per_sec": round(total_events / total_s, 3) if total_s > 0 else None,
    }


def main() -> int:
    quick = lib.quick_mode()
    tenant_counts = QUICK_TENANT_COUNTS if quick else FULL_TENANT_COUNTS

    runs = [run_one(n) for n in tenant_counts]

    baseline = next((r for r in runs if r["tenant_count"] == tenant_counts[0]), runs[0])
    baseline_per_event_s = baseline["total_seconds"] / baseline["total_events"] if baseline["total_events"] else None
    for r in runs:
        per_event_s = r["total_seconds"] / r["total_events"] if r["total_events"] else None
        r["baseline_relative_slowdown"] = (
            round(per_event_s / baseline_per_event_s, 4) if per_event_s and baseline_per_event_s else None
        )

    result = {
        "benchmark": "multi_tenant_sequential_load",
        "methodology": "docs/research/scalability-analysis.md",
        "environment": lib.env_metadata(),
        "runs": runs,
    }
    path = lib.write_artifact("multi-tenant-benchmarks.json", result)
    print(json.dumps({"ok": True, "artifact": str(path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
