import pytest

from aigov_py.huggingface_evaluation import (
    build_evaluation_evidence, verify_evaluation_evidence,
)
from aigov_py.huggingface_provenance import manifest_digest


def record():
    return build_evaluation_evidence(
        model_manifest_sha256="a"*64, dataset_manifest_sha256="b"*64,
        policy_sha256="c"*64, configuration_sha256="d"*64,
        run_id="run-1", metrics={"accuracy": 0.8},
    )


def test_integrity():
    value = record()
    anchor = manifest_digest(value)
    assert verify_evaluation_evidence(value, expected_sha256=anchor)
    value["metrics"]["accuracy"] = 0.9
    assert not verify_evaluation_evidence(value, expected_sha256=anchor)


@pytest.mark.parametrize("key", ["model_manifest_sha256", "dataset_manifest_sha256",
                                "policy_sha256", "configuration_sha256", "run_id"])
def test_reference_substitution(key):
    value = record()
    anchor = manifest_digest(value)
    value[key] = "e"*64
    assert not verify_evaluation_evidence(value, expected_sha256=anchor)


@pytest.mark.parametrize("bad", [True, float("nan"), float("inf"), "0.8"])
def test_invalid_metric(bad):
    value = record()
    value["metrics"]["accuracy"] = bad
    assert not verify_evaluation_evidence(value, expected_sha256="a"*64)


def test_malformed():
    assert not verify_evaluation_evidence({}, expected_sha256="a"*64)
