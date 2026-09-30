from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict


def audit_evidence_url(env_names: tuple = ("GOVAI_AUDIT_BASE_URL", "AIGOV_AUDIT_ENDPOINT", "AIGOV_AUDIT_URL")) -> str:
    """Resolve the audit service's /evidence endpoint from the first set env var in env_names."""
    endpoint = ""
    for name in env_names:
        endpoint = os.getenv(name, "").strip()
        if endpoint:
            break
    endpoint = (endpoint or "http://127.0.0.1:8088").rstrip("/")
    return f"{endpoint}/evidence"


def post_evidence_json(url: str, payload: Dict[str, Any], *, treat_409_as_idempotent: bool = False) -> Dict[str, Any]:
    """POST a single evidence event, authenticating with GOVAI_API_KEY/GOVAI_PROJECT if set.

    Shared by approve.py, promote.py, and ai_discovery_completed.py so the auth-header
    logic exists in exactly one place (a missing Authorization header here silently
    401s against any API-key-protected server).
    """
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    headers = {"Content-Type": "application/json"}

    api_key = os.environ.get("GOVAI_API_KEY", "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    project = os.environ.get("GOVAI_PROJECT", "").strip()
    if project:
        headers["X-GovAI-Project"] = project

    req = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # The ledger rejects duplicate event_id for a run_id with HTTP 409.
        if treat_409_as_idempotent and int(getattr(e, "code", 0) or 0) == 409:
            return {"ok": True, "idempotent": True, "status_code": 409}
        raise
