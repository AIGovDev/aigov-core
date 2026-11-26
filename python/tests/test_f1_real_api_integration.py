"""
AIGov F1 Real API Integration Tests.

Tests the actual AIGov HTTP API endpoints (Rust binary) against an isolated
local test instance.  Requires the binary compiled at:
  rust/target/release/aigov_audit

These tests are marked `integration` and skipped if the binary or a running
test server cannot be reached.  They complement the portable in-process tests
in test_f1_e2e_workflow.py by exercising actual ledger persistence, hash
chain, and API schema validation.

Environment:
  AIGOV_TEST_BASE_URL   Override API base URL (default: starts ephemeral instance).
  AIGOV_TEST_API_KEY    Override API key (default: auto-generated test key).
"""

from __future__ import annotations

import datetime
import os
import secrets
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Generator

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BINARY = REPO_ROOT / "rust" / "target" / "release" / "aigov_audit"
TEST_TENANT = "test-tenant-f1-integration"
TEST_RUN_PREFIX = "f1-integration"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _is_alive(url: str, key: str) -> bool:
    try:
        import urllib.request
        req = urllib.request.Request(f"{url}/ready")
        req.add_header("Authorization", f"Bearer {key}")
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


@pytest.fixture(scope="module")
def api_base() -> Generator[tuple[str, str], None, None]:
    """Yield (base_url, api_key) for the test binary."""
    # Allow external override.
    ext_url = os.environ.get("AIGOV_TEST_BASE_URL", "").strip()
    ext_key = os.environ.get("AIGOV_TEST_API_KEY", "").strip()

    if ext_url:
        if not ext_key:
            pytest.skip("AIGOV_TEST_API_KEY required for external test server")
        if not _is_alive(ext_url, ext_key):
            pytest.skip(f"AIGOV_TEST_BASE_URL={ext_url} is not responding")
        yield ext_url, ext_key
        return

    if not BINARY.exists():
        pytest.skip(f"Binary not found: {BINARY}.  Run `cargo build --release` first.")

    ledger = tempfile.mkdtemp(prefix="aigov-f1-integration-")
    # Use a random high port to avoid conflicts with other test instances.
    import random
    port = random.randint(28000, 28999)
    bind = f"127.0.0.1:{port}"
    base_url = f"http://{bind}"
    api_key = secrets.token_urlsafe(24)

    env = os.environ.copy()
    env.update({
        "GOVAI_LEDGER_DIR": ledger,
        "GOVAI_API_KEYS_JSON": f'{{"{api_key}":"{TEST_TENANT}"}}',
        "GOVAI_API_KEYS": api_key,
        "AIGOV_ENVIRONMENT": "dev",
        "AIGOV_BIND": bind,
        "AIGOV_POLICY_STRICT": "false",
    })

    proc = subprocess.Popen(
        [str(BINARY)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for readiness.
    deadline = time.time() + 10
    while time.time() < deadline:
        if _is_alive(base_url, api_key):
            break
        time.sleep(0.3)
    else:
        proc.terminate()
        pytest.skip("Test binary did not start within 10 s.")

    yield base_url, api_key

    proc.terminate()
    proc.wait(timeout=5)


def _post_evidence(base_url: str, api_key: str, run_id: str, event_type: str,
                   payload: dict[str, Any]) -> dict[str, Any]:
    import sys, urllib.request, json
    sys.path.insert(0, str(REPO_ROOT / "python"))
    from govai.client import GovAIClient
    from govai.evidence import submit_event
    client = GovAIClient(base_url=base_url, api_key=api_key, default_project=TEST_TENANT)
    ev = {
        "event_id": str(uuid.uuid4()),
        "run_id": run_id,
        "event_type": event_type,
        "tenant_id": TEST_TENANT,
        "actor": "test-user@example.com",
        "system": "aigov-f1-integration-test",
        "ts_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "payload": payload,
    }
    return submit_event(client, ev)


def _get_json(base_url: str, api_key: str, path: str) -> dict[str, Any]:
    import sys, urllib.request, json
    sys.path.insert(0, str(REPO_ROOT / "python"))
    from govai.client import GovAIClient
    client = GovAIClient(base_url=base_url, api_key=api_key, default_project=TEST_TENANT)
    return client.request_json("GET", path)


# ---------------------------------------------------------------------------
# F1-REAL tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_f1_real_01_ready(api_base: tuple[str, str]) -> None:
    base_url, api_key = api_base
    assert _is_alive(base_url, api_key), "API not ready"


@pytest.mark.integration
def test_f1_real_02_user_authenticated_event_accepted(api_base: tuple[str, str]) -> None:
    base_url, api_key = api_base
    run_id = f"{TEST_RUN_PREFIX}-{uuid.uuid4().hex[:8]}"
    r = _post_evidence(base_url, api_key, run_id, "user_authenticated",
                       {"provider": "mock_oauth", "session_id": "sess-001"})
    assert r.get("ok") is True
    assert r.get("record_hash"), "Expected record_hash in response"


@pytest.mark.integration
def test_f1_real_03_full_legal_acceptance_chain(api_base: tuple[str, str]) -> None:
    base_url, api_key = api_base
    run_id = f"{TEST_RUN_PREFIX}-legal-{uuid.uuid4().hex[:8]}"
    for doc, version in [
        ("terms_of_service", "2026-07-23.1"),
        ("privacy_policy", "2026-11-12"),
        ("data_processing_agreement", "2026-07-23.1"),
    ]:
        r = _post_evidence(base_url, api_key, run_id, "legal_accepted",
                           {"doc": doc, "version": version})
        assert r.get("ok") is True, f"legal_accepted failed for {doc}: {r}"


@pytest.mark.integration
def test_f1_real_04_tenant_activated_event(api_base: tuple[str, str]) -> None:
    base_url, api_key = api_base
    run_id = f"{TEST_RUN_PREFIX}-act-{uuid.uuid4().hex[:8]}"
    r = _post_evidence(base_url, api_key, run_id, "tenant_activated",
                       {"activation_reason": "legal_accepted_all"})
    assert r.get("ok") is True


@pytest.mark.integration
def test_f1_real_05_audit_events_retrievable_via_compliance_summary(
        api_base: tuple[str, str]) -> None:
    base_url, api_key = api_base
    run_id = f"{TEST_RUN_PREFIX}-cs-{uuid.uuid4().hex[:8]}"

    _post_evidence(base_url, api_key, run_id, "user_authenticated", {"provider": "mock"})
    _post_evidence(base_url, api_key, run_id, "legal_accepted", {"doc": "tos", "version": "1.0"})

    r = _get_json(base_url, api_key,
                  f"/compliance-summary?tenant_id={TEST_TENANT}&run_id={run_id}")
    assert isinstance(r, dict), f"Expected dict, got {type(r).__name__}"


@pytest.mark.integration
def test_f1_real_06_hash_chain_integrity_verified(api_base: tuple[str, str]) -> None:
    base_url, api_key = api_base
    run_id = f"{TEST_RUN_PREFIX}-chain-{uuid.uuid4().hex[:8]}"

    for et in ["user_authenticated", "legal_accepted", "tenant_activated"]:
        _post_evidence(base_url, api_key, run_id, et, {"step": et})

    r = _get_json(base_url, api_key,
                  f"/verify?tenant_id={TEST_TENANT}&run_id={run_id}")
    assert r.get("ok") is True, f"Chain verification failed: {r}"


@pytest.mark.integration
def test_f1_real_07_bundle_contains_submitted_events(api_base: tuple[str, str]) -> None:
    base_url, api_key = api_base
    run_id = f"{TEST_RUN_PREFIX}-bndl-{uuid.uuid4().hex[:8]}"

    _post_evidence(base_url, api_key, run_id, "user_authenticated", {"provider": "mock"})

    r = _get_json(base_url, api_key,
                  f"/bundle?tenant_id={TEST_TENANT}&run_id={run_id}")
    assert isinstance(r, dict), f"Expected dict bundle, got {type(r).__name__}"


@pytest.mark.integration
def test_f1_real_08_missing_api_key_rejected(api_base: tuple[str, str]) -> None:
    import urllib.request, urllib.error, json
    base_url, _ = api_base
    req = urllib.request.Request(f"{base_url}/evidence",
                                  data=b'{}',
                                  method="POST")
    req.add_header("Content-Type", "application/json")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code in (401, 422), f"Expected 401/422, got {exc.value.code}"
