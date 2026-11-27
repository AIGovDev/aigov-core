"""Bind caller-reported evaluation results to immutable evidence references."""
from __future__ import annotations

import hmac
import math
import re
from typing import Any

from .huggingface_provenance import manifest_digest

_SCHEMA = "aigov.huggingface.evaluation.v1"
_SHA = re.compile(r"[0-9a-f]{64}")


def build_evaluation_evidence(
    *, model_manifest_sha256: str, dataset_manifest_sha256: str,
    policy_sha256: str, configuration_sha256: str,
    run_id: str, metrics: dict[str, float],
) -> dict[str, Any]:
    """Record reported metrics; does not execute or attest an evaluation."""
    refs = {
        "model_manifest_sha256": model_manifest_sha256,
        "dataset_manifest_sha256": dataset_manifest_sha256,
        "policy_sha256": policy_sha256,
        "configuration_sha256": configuration_sha256,
    }
    if any(not isinstance(v, str) or not _SHA.fullmatch(v) for v in refs.values()):
        raise ValueError("Invalid evidence digest")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("Missing run identifier")
    if not isinstance(metrics, dict) or not metrics:
        raise ValueError("Missing metrics")
    for name, value in metrics.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Invalid metric name")
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError("Invalid metric value")
    return {"schema": _SCHEMA, **refs, "run_id": run_id,
            "metrics": dict(metrics), "measurement": "caller_reported"}


def verify_evaluation_evidence(
    record: dict[str, Any], *, expected_sha256: str,
) -> bool:
    """Verify structure and integrity against an independently trusted digest."""
    try:
        if not isinstance(expected_sha256, str) or not _SHA.fullmatch(expected_sha256):
            return False
        rebuilt = build_evaluation_evidence(
            **{k: record[k] for k in (
                "model_manifest_sha256", "dataset_manifest_sha256",
                "policy_sha256", "configuration_sha256", "run_id", "metrics",
            )}
        )
        return (record == rebuilt and
                hmac.compare_digest(manifest_digest(record), expected_sha256))
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
