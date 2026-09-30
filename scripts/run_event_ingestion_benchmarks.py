#!/usr/bin/env python3
"""Event ingestion pipeline benchmark: JSON construction + SHA-256 record hashing per event.

Per docs/research/load-testing-methodology.md's workload model. Writes
benchmark-runs/latest/event-ingestion-benchmarks.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import empirical_benchmark_lib as lib

QUICK_PAYLOAD_SIZES_BYTES = (1024, 4096)
FULL_PAYLOAD_SIZES_BYTES = (1024, 4096, 16384, 65536)
QUICK_EVENT_COUNTS = (1_000, 10_000)
FULL_EVENT_COUNTS = (1_000, 10_000, 100_000)


def run_one(payload_bytes: int, event_count: int) -> dict:
    prev_hash = "0" * 64
    samples_ms: list[float] = []
    for i in range(event_count):
        start = lib.timer()
        event_json = lib.synthetic_event("ingest-bench", i, payload_bytes)
        prev_hash = lib.compute_record_hash(prev_hash, event_json)
        samples_ms.append(lib.elapsed_ms(start))

    total_s = sum(samples_ms) / 1000.0
    return {
        "payload_bytes": payload_bytes,
        "event_count": event_count,
        "total_seconds": round(total_s, 6),
        "throughput_events_per_sec": round(event_count / total_s, 3) if total_s > 0 else None,
        "per_event_latency_ms": lib.stats(samples_ms),
    }


def maybe_http_probe() -> dict:
    if not lib.http_probe_enabled():
        return {"enabled": False}
    try:
        import os
        import urllib.request

        endpoint = os.environ.get("GOVAI_AUDIT_BASE_URL", "http://127.0.0.1:8088").rstrip("/") + "/evidence"
        api_key = os.environ.get("GOVAI_API_KEY", "")
        payload = lib.synthetic_event("http-probe", 0, 256).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
        start = lib.timer()
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        return {"enabled": True, "latency_ms": round(lib.elapsed_ms(start), 3)}
    except Exception as e:  # noqa: BLE001 - best-effort optional probe, must never fail the suite
        return {"enabled": True, "error": str(e)}


def main() -> int:
    quick = lib.quick_mode()
    payload_sizes = QUICK_PAYLOAD_SIZES_BYTES if quick else FULL_PAYLOAD_SIZES_BYTES
    event_counts = QUICK_EVENT_COUNTS if quick else FULL_EVENT_COUNTS

    runs = [run_one(p, n) for p in payload_sizes for n in event_counts]

    result = {
        "benchmark": "event_ingestion",
        "methodology": "docs/research/load-testing-methodology.md",
        "environment": lib.env_metadata(),
        "http_probe": maybe_http_probe(),
        "runs": runs,
    }
    path = lib.write_artifact("event-ingestion-benchmarks.json", result)
    print(json.dumps({"ok": True, "artifact": str(path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
