#!/usr/bin/env python3
"""Failure detection benchmark: time to detect an invalid chain, and to classify stub policy states.

Writes benchmark-runs/latest/failure-benchmarks.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import empirical_benchmark_lib as lib

CHAIN_LENGTH = 10_000
TAMPER_POSITIONS_FRACTIONS = (0.01, 0.5, 0.99)  # near start, middle, near end

# Mirrors the event_type dispatch in rust/src/policy.rs::enforce (stub classification only).
KNOWN_EVENT_TYPES = (
    "data_registered",
    "model_trained",
    "evaluation_reported",
    "risk_recorded",
    "risk_mitigated",
    "risk_reviewed",
    "human_approved",
    "model_promoted",
)
CLASSIFICATION_SAMPLE_SIZE = 100_000


def tamper_detection_runs() -> list[dict]:
    runs = []
    for frac in TAMPER_POSITIONS_FRACTIONS:
        chain = lib.build_synthetic_chain(CHAIN_LENGTH, payload_bytes=256)
        idx = min(CHAIN_LENGTH - 1, max(0, int(CHAIN_LENGTH * frac)))
        chain[idx]["event_json"] = chain[idx]["event_json"].replace('"seq":', '"seq_tampered":')

        start = lib.timer()
        ok, detected_at = lib.verify_chain(chain)
        detect_s = lib.elapsed_ms(start) / 1000.0

        runs.append(
            {
                "chain_length": CHAIN_LENGTH,
                "tampered_index": idx,
                "detected": not ok,
                "detected_at_index": detected_at,
                "detection_seconds": round(detect_s, 6),
            }
        )
    return runs


def classify(event_type: str) -> str:
    return "known" if event_type in KNOWN_EVENT_TYPES else "unknown_passthrough"


def stub_policy_classification_run() -> dict:
    # Deterministic synthetic mix: known types cycle, every 7th is an unknown passthrough type.
    labels = []
    for i in range(CLASSIFICATION_SAMPLE_SIZE):
        labels.append(KNOWN_EVENT_TYPES[i % len(KNOWN_EVENT_TYPES)] if i % 7 else "custom_event_type")

    start = lib.timer()
    results = [classify(t) for t in labels]
    total_s = lib.elapsed_ms(start) / 1000.0

    return {
        "sample_size": CLASSIFICATION_SAMPLE_SIZE,
        "total_seconds": round(total_s, 6),
        "classifications_per_sec": round(CLASSIFICATION_SAMPLE_SIZE / total_s, 3) if total_s > 0 else None,
        "known_count": sum(1 for r in results if r == "known"),
        "unknown_passthrough_count": sum(1 for r in results if r == "unknown_passthrough"),
    }


def main() -> int:
    result = {
        "benchmark": "failure_detection",
        "methodology": "docs/research/empirical-evaluation.md",
        "environment": lib.env_metadata(),
        "invalid_chain_detection": tamper_detection_runs(),
        "stub_policy_classification": stub_policy_classification_run(),
    }
    path = lib.write_artifact("failure-benchmarks.json", result)
    print(json.dumps({"ok": True, "artifact": str(path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
