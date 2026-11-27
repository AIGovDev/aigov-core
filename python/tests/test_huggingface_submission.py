from unittest.mock import patch

import pytest

from aigov_py.huggingface_evaluation import build_evaluation_evidence
from aigov_py.huggingface_provenance import manifest_digest
from aigov_py.huggingface_submission import submit_observed_evaluation


def test_observation_is_not_evaluation_gate():
    record = build_evaluation_evidence(
        model_manifest_sha256="a"*64, dataset_manifest_sha256="b"*64,
        policy_sha256="c"*64, configuration_sha256="d"*64,
        run_id="run", metrics={"accuracy": 1.0})
    anchor = manifest_digest(record)
    with patch("aigov_py.huggingface_submission.post_evidence_json", return_value={"ok": True}) as post:
        submit_observed_evaluation(record, expected_sha256=anchor, actor="agent", system="hf")
        event = post.call_args.args[1]
        assert event["event_type"] == "huggingface_evaluation_observed"
        assert "passed" not in event["payload"]
        record["metrics"]["accuracy"] = 0.0
        with pytest.raises(ValueError):
            submit_observed_evaluation(record, expected_sha256=anchor, actor="agent", system="hf")
        assert post.call_count == 1
