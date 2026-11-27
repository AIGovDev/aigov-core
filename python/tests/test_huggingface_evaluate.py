import pytest

from aigov_py.huggingface_evaluate import capture_evaluate_result
from aigov_py.huggingface_evaluation import verify_evaluation_evidence
from aigov_py.huggingface_provenance import manifest_digest

REFS = dict(run_id="eval-1", model_manifest_sha256="a"*64,
            dataset_manifest_sha256="b"*64, policy_sha256="c"*64,
            configuration_sha256="d"*64)


def test_scalar_results():
    result = {"accuracy": 0.75, "f1": 0.7}
    evidence = capture_evaluate_result(result, **REFS)
    assert verify_evaluation_evidence(evidence, expected_sha256=manifest_digest(evidence))
    result["accuracy"] = 1.0
    assert evidence["metrics"]["accuracy"] == 0.75


@pytest.mark.parametrize("result", [[], {}, {"x": [1]}, {"x": True}, {"x": float("inf")}])
def test_unsupported_results(result):
    with pytest.raises(ValueError):
        capture_evaluate_result(result, **REFS)
