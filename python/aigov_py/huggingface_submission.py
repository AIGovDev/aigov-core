"""Submit observational evidence without asserting a passed evaluation."""
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ._evidence_http import audit_evidence_url, post_evidence_json
from .huggingface_evaluation import verify_evaluation_evidence


def submit_observed_evaluation(
    record: dict[str, Any], *, expected_sha256: str, actor: str, system: str
) -> dict[str, Any]:
    if not verify_evaluation_evidence(record, expected_sha256=expected_sha256):
        raise ValueError("Invalid evaluation evidence")
    if not actor.strip() or not system.strip():
        raise ValueError("Actor and system required")
    event = {
        "event_id": str(uuid4()),
        "event_type": "huggingface_evaluation_observed",
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "system": system,
        "run_id": record["run_id"],
        "payload": {"record": record, "record_sha256": expected_sha256,
                    "measurement": "caller_reported"},
    }
    response = post_evidence_json(audit_evidence_url(), event)
    if not isinstance(response, dict) or response.get("ok") is not True:
        raise RuntimeError("Core did not confirm evidence acceptance")
    return response
