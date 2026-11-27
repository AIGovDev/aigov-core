"""Adapt scalar Evaluate results to caller-reported governance evidence."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .huggingface_evaluation import build_evaluation_evidence


def capture_evaluate_result(
    result: Mapping[str, Any], *, run_id: str,
    model_manifest_sha256: str, dataset_manifest_sha256: str,
    policy_sha256: str, configuration_sha256: str,
) -> dict[str, Any]:
    """Accept an existing metric.compute() result without executing remote code.

    Only scalar numeric metrics are supported. The configuration digest should
    bind the metric implementation, version and evaluation parameters.
    """
    if not isinstance(result, Mapping):
        raise ValueError("Expected a mapping of scalar metrics")
    return build_evaluation_evidence(
        run_id=run_id, model_manifest_sha256=model_manifest_sha256,
        dataset_manifest_sha256=dataset_manifest_sha256,
        policy_sha256=policy_sha256, configuration_sha256=configuration_sha256,
        metrics=dict(result),
    )
