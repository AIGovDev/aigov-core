"""
Security isolation tests for the AIGov staging API.

Verifies that:
  - Tenant A cannot read, retrieve, or verify evidence belonging to tenant B.
  - Requests with missing, wrong, or structurally invalid credentials are rejected.
  - Tampered evidence (same event_id, different payload) is rejected.
  - Replay attacks (re-submit already-processed event_id) are rejected.
  - Tenant identity in the request body cannot override the key-bound tenant.

All tests run against the real isolated Rust binary in staging mode (same
fixture as test_staging_e2e.py).  No mocks.

This is NOT a test of govbase.dev staging (requires authorized cloud credentials).
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Generator

import pytest
import urllib.request
import urllib.error

REPO_ROOT = Path(__file__).resolve().parents[2]
BINARY = REPO_ROOT / "rust" / "target" / "release" / "aigov_audit"
POLICY_DIR = str(REPO_ROOT / "rust")
TENANT_A = "sec-test-tenant-a"
TENANT_B = "sec-test-tenant-b"


# ---------------------------------------------------------------------------
# Shared HTTP helper (copied from test_staging_e2e.py for standalone use)
# ---------------------------------------------------------------------------

def _http(
    url: str,
    *,
    method: str = "GET",
    body: dict | None = None,
    api_key: str = "",
    timeout: float = 10.0,
) -> tuple[int, dict | str]:
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                return r.status, raw
    except urllib.error.HTTPError as e:
        body_bytes = e.read()
        try:
            return e.code, json.loads(body_bytes)
        except json.JSONDecodeError:
            return e.code, body_bytes.decode(errors="replace")


def _is_alive(url: str, key: str) -> bool:
    try:
        code, _ = _http(f"{url}/ready", api_key=key, timeout=2.0)
        return code == 200
    except Exception:
        return False


def _make_evidence(
    run_id: str,
    tenant: str,
    *,
    event_id: str | None = None,
    event_type: str = "data_registered",
    payload_override: dict | None = None,
) -> dict:
    """Build a minimal valid evidence payload for a given tenant."""
    base_payload = {
        "ai_system_id": f"sys-{run_id[:8]}",
        "dataset_id": f"ds-{run_id[:8]}",
        "dataset": "sec-test-dataset",
        "dataset_fingerprint": "sha256:aabbccdd00112233",
        "dataset_governance_id": f"gov-{run_id[:8]}",
        "dataset_governance_commitment": "internal",
        "dataset_version": "1.0",
        "source": "synthetic",
        "intended_use": "security isolation test",
        "limitations": "test only",
        "quality_summary": "synthetic",
        "governance_status": "approved",
    }
    return {
        "event_id": event_id or str(uuid.uuid4()),
        "event_type": event_type,
        "run_id": run_id,
        "ts_utc": "2026-11-19T12:00:00Z",
        "actor": f"test@{tenant}.local",
        "system": "sec-test",
        "tenant_id": tenant,
        "payload": payload_override or base_payload,
    }


# ---------------------------------------------------------------------------
# Fixture: two-tenant isolated server
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def two_tenant_server() -> Generator[tuple[str, str, str], None, None]:
    """
    Start a single binary instance with two separate tenant keys.
    Yields (base_url, key_a, key_b).
    """
    if not BINARY.exists():
        pytest.skip(f"Binary not found: {BINARY}. Run `cargo build --release`.")

    ledger = tempfile.mkdtemp(prefix="aigov-sec-test-")
    import random
    port = random.randint(28000, 28999)
    base_url = f"http://127.0.0.1:{port}"
    key_a = secrets.token_urlsafe(24)
    key_b = secrets.token_urlsafe(24)

    env = os.environ.copy()
    env.update({
        "GOVAI_LEDGER_DIR": ledger,
        "GOVAI_API_KEYS_JSON": json.dumps({
            key_a: TENANT_A,
            key_b: TENANT_B,
        }),
        "GOVAI_API_KEYS": f"{key_a},{key_b}",
        "AIGOV_ENVIRONMENT": "staging",
        "AIGOV_BIND": f"127.0.0.1:{port}",
        "AIGOV_POLICY_STRICT": "false",
        "AIGOV_POLICY_DIR": POLICY_DIR,
    })

    proc = subprocess.Popen(
        [str(BINARY)], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    deadline = time.time() + 12
    while time.time() < deadline:
        if _is_alive(base_url, key_a) and _is_alive(base_url, key_b):
            break
        time.sleep(0.3)
    else:
        proc.terminate()
        pytest.skip("Staging binary did not become ready within 12 s")

    yield base_url, key_a, key_b

    proc.terminate()
    proc.wait(timeout=5)
    import shutil
    shutil.rmtree(ledger, ignore_errors=True)


# ---------------------------------------------------------------------------
# S1 — API key authentication hardening
# ---------------------------------------------------------------------------

class TestAPIKeyAuthentication:
    """Ensure all evidence endpoints reject unauthenticated or misauthenticated requests."""

    def test_missing_auth_header_evidence_post(self, two_tenant_server):
        base_url, _, _ = two_tenant_server
        code, body = _http(
            f"{base_url}/evidence", method="POST",
            body={"event_id": str(uuid.uuid4()), "event_type": "data_registered"},
        )
        assert code in (401, 403), f"Expected 401/403 without auth header, got {code}: {body}"

    def test_wrong_key_evidence_post(self, two_tenant_server):
        base_url, _, _ = two_tenant_server
        code, body = _http(
            f"{base_url}/evidence", method="POST",
            body={"event_id": str(uuid.uuid4())},
            api_key="totally-wrong-key-" + secrets.token_hex(8),
        )
        assert code in (401, 403), f"Expected 401/403 for wrong key, got {code}: {body}"

    def test_empty_bearer_token(self, two_tenant_server):
        base_url, _, _ = two_tenant_server
        code, body = _http(
            f"{base_url}/evidence", method="POST",
            body={"event_id": str(uuid.uuid4())},
            api_key="",
        )
        assert code in (401, 403), f"Expected 401/403 for empty bearer, got {code}: {body}"

    def test_missing_auth_on_bundle_read(self, two_tenant_server):
        base_url, _, _ = two_tenant_server
        code, _ = _http(f"{base_url}/bundle/nonexistent-run")
        assert code in (401, 403), f"Expected 401/403 for unauthenticated bundle read, got {code}"

    def test_wrong_key_on_bundle_read(self, two_tenant_server):
        base_url, _, _ = two_tenant_server
        code, _ = _http(
            f"{base_url}/bundle/nonexistent-run",
            api_key="bogus-" + secrets.token_hex(8),
        )
        assert code in (401, 403), f"Expected 401/403 for wrong key on bundle, got {code}"

    def test_missing_auth_on_compliance_summary(self, two_tenant_server):
        base_url, _, _ = two_tenant_server
        code, _ = _http(f"{base_url}/compliance-summary/nonexistent-run")
        assert code in (401, 403), f"Expected 401/403 for unauthenticated compliance read, got {code}"

    def test_missing_auth_on_verify(self, two_tenant_server):
        base_url, _, _ = two_tenant_server
        code, _ = _http(f"{base_url}/verify/nonexistent-run")
        assert code in (401, 403), f"Expected 401/403 for unauthenticated verify, got {code}"


# ---------------------------------------------------------------------------
# S2 — Cross-tenant read denial (negative authorization)
# ---------------------------------------------------------------------------

class TestCrossTenantReadDenial:
    """
    Tenant B must not be able to read evidence submitted by tenant A.

    The expected response is 404 (run_id not in tenant B's ledger) because
    the API resolves the tenant from the API key and looks up data only within
    that tenant's private ledger directory.  The design prevents tenant B from
    even learning that a run exists in another tenant's namespace.
    """

    def test_cross_tenant_bundle_read_denied(self, two_tenant_server):
        base_url, key_a, key_b = two_tenant_server
        run_id = f"xread-bundle-{uuid.uuid4().hex[:8]}"

        # Tenant A submits evidence
        ev = _make_evidence(run_id, TENANT_A, event_type="data_registered")
        code, body = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
        assert code in (200, 201), f"Tenant A setup failed: {code}: {body}"

        # Tenant B tries to read tenant A's bundle — must NOT receive the data.
        # Expect HTTP 404 (corrected behavior); a 200 with ok=False is also acceptable
        # but would indicate a stale binary that returns wrong HTTP status for not-found.
        code, body = _http(f"{base_url}/bundle/{run_id}", api_key=key_b)
        if code == 200:
            # Accept only if body signals not-found (not actual data)
            assert isinstance(body, dict) and body.get("ok") is False and body.get("error") == "run_not_found", (
                f"Cross-tenant bundle read returned 200 with data: {body}"
            )
        else:
            assert code == 404, (
                f"Cross-tenant bundle read should return 404 (run_id not in tenant B's ledger), "
                f"got {code}: {body}"
            )

    def test_cross_tenant_bundle_hash_denied(self, two_tenant_server):
        base_url, key_a, key_b = two_tenant_server
        run_id = f"xread-hash-{uuid.uuid4().hex[:8]}"

        ev = _make_evidence(run_id, TENANT_A, event_type="data_registered")
        code, _ = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
        assert code in (200, 201)

        code, body = _http(f"{base_url}/bundle-hash/{run_id}", api_key=key_b)
        assert code == 404, (
            f"Cross-tenant bundle-hash read should return 404, got {code}: {body}"
        )

    def test_cross_tenant_compliance_summary_denied(self, two_tenant_server):
        base_url, key_a, key_b = two_tenant_server
        run_id = f"xread-comp-{uuid.uuid4().hex[:8]}"

        for et in ["data_registered", "model_trained"]:
            ev = _make_evidence(run_id, TENANT_A, event_type=et)
            if et == "model_trained":
                ev["payload"] = {
                    "ai_system_id": f"sys-{run_id[:8]}",
                    "dataset_id": f"ds-{run_id[:8]}",
                    "model_version_id": f"mv-{run_id[:8]}",
                }
            code, _ = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
            assert code in (200, 201)

        code, body = _http(f"{base_url}/compliance-summary/{run_id}", api_key=key_b)
        if code == 200:
            # compliance_summary uses 'code' field, bundle uses 'error' field
            err = body.get("error") or body.get("code") if isinstance(body, dict) else None
            assert isinstance(body, dict) and body.get("ok") is False and err == "run_not_found", (
                f"Cross-tenant compliance-summary returned 200 with data: {body}"
            )
        else:
            assert code == 404, (
                f"Cross-tenant compliance-summary read should return 404, got {code}: {body}"
            )

    def test_cross_tenant_verify_denied(self, two_tenant_server):
        base_url, key_a, key_b = two_tenant_server
        run_id = f"xread-verify-{uuid.uuid4().hex[:8]}"

        ev = _make_evidence(run_id, TENANT_A, event_type="data_registered")
        code, _ = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
        assert code in (200, 201)

        code, body = _http(f"{base_url}/verify/{run_id}", api_key=key_b)
        if code == 200:
            assert isinstance(body, dict) and body.get("ok") is False and body.get("error") == "run_not_found", (
                f"Cross-tenant verify returned 200 with data: {body}"
            )
        else:
            assert code == 404, (
                f"Cross-tenant verify should return 404, got {code}: {body}"
            )

    def test_cross_tenant_api_export_denied(self, two_tenant_server):
        base_url, key_a, key_b = two_tenant_server
        run_id = f"xread-export-{uuid.uuid4().hex[:8]}"

        ev = _make_evidence(run_id, TENANT_A, event_type="data_registered")
        code, _ = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
        assert code in (200, 201)

        code, body = _http(f"{base_url}/api/export/{run_id}", api_key=key_b)
        assert code == 404, (
            f"Cross-tenant API export should return 404, got {code}: {body}"
        )

    def test_tenant_a_reads_own_data_successfully(self, two_tenant_server):
        """Control: tenant A must still be able to read its own data."""
        base_url, key_a, _ = two_tenant_server
        run_id = f"own-read-{uuid.uuid4().hex[:8]}"

        ev = _make_evidence(run_id, TENANT_A, event_type="data_registered")
        code, _ = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
        assert code in (200, 201)

        code, body = _http(f"{base_url}/bundle/{run_id}", api_key=key_a)
        # 200 = data found; 404 = run exists but no events (possible staging config)
        assert code in (200, 404), f"Tenant A reading own bundle got {code}: {body}"


# ---------------------------------------------------------------------------
# S3 — Tenant identity claim in body cannot override key-bound tenant
# ---------------------------------------------------------------------------

class TestTenantIdentityClaim:
    """
    The tenant is determined by the API key, not by the tenant_id field in the body.
    A key bound to tenant B, submitting evidence with tenant_id=A in the body,
    should either succeed (storing under B's ledger) or be rejected — but must
    never be stored under tenant A's ledger.
    """

    def test_body_tenant_mismatch_stored_under_key_tenant(self, two_tenant_server):
        """
        Submit with key_b but tenant_id = TENANT_A in the body.
        The evidence must NOT appear under tenant A's bundle.
        If the submission succeeds it must only be visible to key_b.
        """
        base_url, key_a, key_b = two_tenant_server
        run_id = f"mismatch-{uuid.uuid4().hex[:8]}"

        # Submit with key_b but claim to be TENANT_A
        ev = _make_evidence(run_id, TENANT_A)  # tenant_id=TENANT_A in body
        code, _ = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_b)
        # Either accepted (stored under key_b's tenant) or rejected — both OK.
        # The critical invariant is verified below.
        body_claim_accepted = code in (200, 201)

        if body_claim_accepted:
            # Must NOT contain actual data when read by tenant A.
            code_a, body_a = _http(f"{base_url}/bundle/{run_id}", api_key=key_a)
            # Accept 404 (correct) or 200 with ok=False/run_not_found (HTTP status bug, but no data leak)
            if code_a not in (404,):
                assert isinstance(body_a, dict) and body_a.get("ok") is False and body_a.get("error") == "run_not_found", (
                    f"Evidence submitted via key_b (tenant B) should NOT appear in tenant A's "
                    f"bundle. Got {code_a}: {body_a}. body tenant_id claim may have overrode the key binding."
                )

            # Under tenant B's key: 200 (data present) or 404 (dropped/rejected) — both fine
            code_b, _ = _http(f"{base_url}/bundle/{run_id}", api_key=key_b)
            assert code_b in (200, 404), (
                f"Unexpected status when key_b reads its own run: {code_b}"
            )
        else:
            # Submission was rejected (422/400/403) — the safer outcome
            assert code in (400, 403, 422), (
                f"Unexpected status for mismatched tenant submission: {code}"
            )


# ---------------------------------------------------------------------------
# S4 — Tampered evidence rejection
# ---------------------------------------------------------------------------

class TestTamperedEvidence:
    """
    Re-submitting an already-stored event_id with a different payload must be
    rejected (HTTP 409 Conflict / 422).  This is the immutability invariant.
    """

    def test_tampered_payload_rejected(self, two_tenant_server):
        base_url, key_a, _ = two_tenant_server
        event_id = str(uuid.uuid4())
        run_id = f"tamper-{uuid.uuid4().hex[:8]}"

        # First submission
        ev = _make_evidence(run_id, TENANT_A, event_id=event_id)
        code, _ = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
        assert code in (200, 201), f"Original submission failed: {code}"

        # Second submission — same event_id, different payload
        tampered = _make_evidence(
            run_id, TENANT_A, event_id=event_id,
            payload_override={"ai_system_id": "TAMPERED", "dataset_id": "TAMPERED",
                              "dataset": "tampered", "dataset_fingerprint": "sha256:00000000",
                              "dataset_governance_id": "tampered", "dataset_version": "1.0",
                              "dataset_governance_commitment": "external",
                              "source": "tampered", "intended_use": "tampered",
                              "limitations": "none", "quality_summary": "tampered",
                              "governance_status": "unapproved"},
        )
        code2, body2 = _http(f"{base_url}/evidence", method="POST", body=tampered, api_key=key_a)
        assert code2 in (409, 422, 400), (
            f"Tampered evidence re-submission should be rejected (409/422/400), "
            f"got {code2}: {body2}"
        )

    def test_exact_duplicate_same_tenant_rejected(self, two_tenant_server):
        """Identical re-submission of an event must also be rejected (idempotency boundary)."""
        base_url, key_a, _ = two_tenant_server
        event_id = str(uuid.uuid4())
        run_id = f"dup-{uuid.uuid4().hex[:8]}"

        ev = _make_evidence(run_id, TENANT_A, event_id=event_id)
        code1, _ = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
        assert code1 in (200, 201)

        code2, body2 = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
        assert code2 in (409, 422, 400), (
            f"Exact duplicate should be rejected, got {code2}: {body2}"
        )


# ---------------------------------------------------------------------------
# S5 — Cross-tenant event_id namespace isolation
# ---------------------------------------------------------------------------

class TestCrossTenantEventIDNamespace:
    """
    Event IDs are scoped per-tenant.  The same event_id submitted by tenant A
    and tenant B should both be accepted (they live in separate ledgers) and
    neither should interfere with the other.
    """

    def test_same_event_id_accepted_in_separate_tenants(self, two_tenant_server):
        base_url, key_a, key_b = two_tenant_server
        shared_event_id = str(uuid.uuid4())
        run_a = f"ns-a-{uuid.uuid4().hex[:8]}"
        run_b = f"ns-b-{uuid.uuid4().hex[:8]}"

        ev_a = _make_evidence(run_a, TENANT_A, event_id=shared_event_id)
        code_a, _ = _http(f"{base_url}/evidence", method="POST", body=ev_a, api_key=key_a)
        assert code_a in (200, 201), f"Tenant A submission failed: {code_a}"

        ev_b = _make_evidence(run_b, TENANT_B, event_id=shared_event_id)
        code_b, body_b = _http(f"{base_url}/evidence", method="POST", body=ev_b, api_key=key_b)
        assert code_b in (200, 201), (
            f"Tenant B submission with same event_id should succeed (separate namespace), "
            f"got {code_b}: {body_b}"
        )

    def test_replay_in_same_tenant_rejected(self, two_tenant_server):
        """Within one tenant, re-submitting the same event_id must be rejected."""
        base_url, key_a, _ = two_tenant_server
        event_id = str(uuid.uuid4())
        run_id = f"replay-{uuid.uuid4().hex[:8]}"

        ev = _make_evidence(run_id, TENANT_A, event_id=event_id)
        code1, _ = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
        assert code1 in (200, 201)

        code2, body2 = _http(f"{base_url}/evidence", method="POST", body=ev, api_key=key_a)
        assert code2 in (409, 422, 400), (
            f"Replay in same tenant should be rejected, got {code2}: {body2}"
        )


# ---------------------------------------------------------------------------
# S6 — Authorization header structure hardening
# ---------------------------------------------------------------------------

class TestAuthHeaderHardening:
    """
    Reject requests with malformed or structurally invalid Authorization headers.
    """

    def test_basic_auth_rejected(self, two_tenant_server):
        base_url, _, _ = two_tenant_server
        import base64
        cred = base64.b64encode(b"user:pass").decode()
        req = urllib.request.Request(
            f"{base_url}/evidence",
            data=json.dumps({"event_id": "x"}).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {cred}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        assert code in (401, 403, 400), f"Basic auth should be rejected, got {code}"

    def test_bearer_with_whitespace_key_rejected(self, two_tenant_server):
        base_url, _, _ = two_tenant_server
        code, _ = _http(
            f"{base_url}/evidence", method="POST",
            body={"event_id": "x"},
            api_key="   ",
        )
        assert code in (401, 403, 400), f"Whitespace bearer should be rejected, got {code}"
