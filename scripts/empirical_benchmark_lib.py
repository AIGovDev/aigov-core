#!/usr/bin/env python3
"""Shared harness for the empirical benchmark suite (docs/research/empirical-evaluation.md).

Provides: quick/full mode selection, descriptive statistics matching
docs/research/statistical-methodology.md exactly (count, mean_ms, median_ms,
stdev_ms, min_ms, max_ms, p50/p95/p99 via linear interpolation on the sorted
sample), the record-hash construction mirrored from rust/src/audit_store.rs
(compute_record_hash: sha256(prev_hash_bytes + b"\n" + event_json_bytes)),
and a writer for benchmark-runs/latest/<name>.json.

All measurements here are real wall-clock timings of real Python/stdlib
operations (hashlib, json, gzip) on the machine running the harness — see
"Threats to validity" in docs/research/load-testing-methodology.md for what
that does and doesn't tell you about the Rust server's own performance.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import sys
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_RUNS_DIR = ROOT / "benchmark-runs" / "latest"


def quick_mode() -> bool:
    """CI enables quick mode by default; set GOVAI_EMPIRICAL_QUICK=0 for full mode."""
    return os.environ.get("GOVAI_EMPIRICAL_QUICK", "1").strip() != "0"


def http_probe_enabled() -> bool:
    return os.environ.get("GOVAI_BENCHMARK_HTTP", "0").strip() == "1"


def env_metadata() -> dict[str, Any]:
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "govai_empirical_quick": quick_mode(),
    }


def stats(samples_ms: list[float]) -> dict[str, Any]:
    """Descriptive statistics per docs/research/statistical-methodology.md.

    Population standard deviation; p50/p95/p99 via linear interpolation on
    the sorted sample (same method as Python's statistics.quantiles with
    method="inclusive", implemented directly to avoid version drift).
    """
    n = len(samples_ms)
    if n == 0:
        return {"count": 0, "mean_ms": None, "median_ms": None, "stdev_ms": None,
                "min_ms": None, "max_ms": None, "p50_ms": None, "p95_ms": None, "p99_ms": None}

    ordered = sorted(samples_ms)
    mean = sum(ordered) / n

    def _percentile(p: float) -> float:
        if n == 1:
            return ordered[0]
        rank = p * (n - 1)
        lo = math.floor(rank)
        hi = math.ceil(rank)
        if lo == hi:
            return ordered[int(rank)]
        frac = rank - lo
        return ordered[lo] + (ordered[hi] - ordered[lo]) * frac

    variance = sum((x - mean) ** 2 for x in ordered) / n
    stdev = math.sqrt(variance)

    return {
        "count": n,
        "mean_ms": round(mean, 6),
        "median_ms": round(_percentile(0.5), 6),
        "stdev_ms": round(stdev, 6),
        "min_ms": round(ordered[0], 6),
        "max_ms": round(ordered[-1], 6),
        "p50_ms": round(_percentile(0.50), 6),
        "p95_ms": round(_percentile(0.95), 6),
        "p99_ms": round(_percentile(0.99), 6),
    }


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_record_hash(prev_hash: str, event_json: str) -> str:
    """Mirrors rust/src/audit_store.rs::compute_record_hash exactly."""
    payload = prev_hash.encode("utf-8") + b"\n" + event_json.encode("utf-8")
    return sha256_hex(payload)


def synthetic_event(run_id: str, seq: int, payload_bytes: int) -> str:
    """Deterministic synthetic evidence-event JSON of approximately payload_bytes size."""
    # pad field absorbs the size target; rest mirrors real EvidenceEvent shape (schema.rs)
    base = {
        "event_id": f"bench-{run_id}-{seq}",
        "event_type": "evaluation_reported",
        "ts_utc": "2026-01-01T00:00:00Z",
        "actor": "benchmark_harness",
        "system": "empirical_benchmark_lib",
        "run_id": run_id,
        "payload": {"seq": seq, "pad": ""},
    }
    overhead = len(json.dumps(base, separators=(",", ":")))
    pad_len = max(0, payload_bytes - overhead)
    base["payload"]["pad"] = "x" * pad_len
    return json.dumps(base, separators=(",", ":"), sort_keys=True)


def build_synthetic_chain(length: int, payload_bytes: int = 256, seed: int = 1337) -> list[dict[str, str]]:
    """Builds an in-memory, hash-chained list of {prev_hash, record_hash, event_json}."""
    run_id = str(uuid.UUID(int=seed))
    records: list[dict[str, str]] = []
    prev_hash = "0" * 64
    for i in range(length):
        event_json = synthetic_event(run_id, i, payload_bytes)
        record_hash = compute_record_hash(prev_hash, event_json)
        records.append({"prev_hash": prev_hash, "record_hash": record_hash, "event_json": event_json})
        prev_hash = record_hash
    return records


def verify_chain(records: list[dict[str, str]]) -> tuple[bool, int]:
    """Full linear verification; returns (ok, first_broken_index or -1)."""
    prev_hash = "0" * 64
    for i, rec in enumerate(records):
        if rec["prev_hash"] != prev_hash:
            return False, i
        expected = compute_record_hash(rec["prev_hash"], rec["event_json"])
        if expected != rec["record_hash"]:
            return False, i
        prev_hash = rec["record_hash"]
    return True, -1


def timer() -> float:
    return time.perf_counter()


def elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


def write_artifact(name: str, data: dict[str, Any]) -> Path:
    BENCHMARK_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    path = BENCHMARK_RUNS_DIR / name
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)
