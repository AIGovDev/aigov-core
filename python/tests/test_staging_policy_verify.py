"""Unit tests for scripts/staging_policy_verify.py.

These cover the harness's own decisions: the staging-host guard, the blocked-versus-failed
semantics for live checks, the evidence schema, and the bundle helpers. Binary-backed scenarios
run in the harness itself (see the staging-policy-verify workflow), not here.
"""

import base64
import importlib.util
import json
from pathlib import Path

import pytest
from aigov_py.policy_bundle_signing import TrustEd25519, verify_policy_bundle_ed25519
from nacl.signing import SigningKey

_SPEC = importlib.util.spec_from_file_location(
    "staging_policy_verify",
    Path(__file__).resolve().parents[2] / "scripts" / "staging_policy_verify.py",
)
svf = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(svf)


@pytest.mark.parametrize(
    "host,expected",
    [
        ("govai-staging.example.com", True),
        ("staging.example.com", True),
        ("api.stg.example.com", True),
        ("api.test.example.com", True),
        ("prod.example.com", False),
        ("api.example.com", False),
        (
            "teststaging.example.com",
            False,
        ),  # a label must match exactly, not as a substring
        ("example.com", False),
    ],
)
def test_staging_host_requires_an_exact_label(host, expected):
    assert svf._host_is_staging(host) is expected


def _live_args(**overrides):
    import argparse

    base = {
        "base_url": "",
        "api_key_env": "GOVAI_STAGING_API_KEY",
        "target_kind": "remote",
        "container": "",
        "image": "",
        "manifest": "",
        "fixtures": "",
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_live_checks_are_blocked_not_passed_without_configuration(monkeypatch):
    monkeypatch.delenv("GOVAI_STAGING_BASE_URL", raising=False)
    monkeypatch.delenv("GOVAI_STAGING_API_KEY", raising=False)
    ev = svf.Evidence(mode="live")
    svf.run_live_target(ev, _live_args())
    assert ev.checks, "live checks must be recorded even when not configured"
    assert {c["status"] for c in ev.checks} == {"blocked"}
    assert {c["scope"] for c in ev.checks} == {"live_staging"}


def test_remote_target_refuses_a_non_staging_host(monkeypatch):
    monkeypatch.setenv("GOVAI_STAGING_API_KEY", "not-a-real-key")
    ev = svf.Evidence(mode="live")
    svf.run_live_target(
        ev, _live_args(base_url="https://api.example.com", target_kind="remote")
    )
    target = next(c for c in ev.checks if c["id"] == "live.target")
    assert target["status"] == "failed"
    assert "refused host api.example.com" in target["observed"]
    assert not any(c["id"] == "live.health" for c in ev.checks), (
        "no request may be sent to a refused host"
    )


def test_remote_target_refuses_loopback(monkeypatch):
    monkeypatch.setenv("GOVAI_STAGING_API_KEY", "not-a-real-key")
    ev = svf.Evidence(mode="live")
    svf.run_live_target(
        ev, _live_args(base_url="http://127.0.0.1:9", target_kind="remote")
    )
    assert next(c for c in ev.checks if c["id"] == "live.target")["status"] == "failed"


def test_container_target_refuses_a_non_loopback_host(monkeypatch):
    monkeypatch.setenv("GOVAI_STAGING_API_KEY", "not-a-real-key")
    ev = svf.Evidence(mode="live")
    svf.run_live_target(
        ev,
        _live_args(
            base_url="https://api.staging.example.com", target_kind="local_container"
        ),
    )
    target = next(c for c in ev.checks if c["id"] == "live.target")
    assert target["status"] == "failed"
    assert target["scope"] == "local_container"


def test_unverified_bundle_blocks_bundle_dependent_checks(monkeypatch):
    """Without a verified deployed bundle, bundle-dependent behavior must not be reported as passed."""
    monkeypatch.setenv("GOVAI_STAGING_API_KEY", "not-a-real-key")
    ev = svf.Evidence(mode="live")
    # Port 9 is closed, so infrastructure checks fail; the bundle gate must still block the rest.
    svf.run_live_target(
        ev, _live_args(base_url="http://127.0.0.1:9", target_kind="local_container")
    )
    dep = next(c for c in ev.checks if c["id"] == "live.bundle_dependent_checks")
    assert dep["status"] == "blocked"
    assert not any(c["id"] == "http.evidence.unauthenticated" for c in ev.checks)


def test_require_live_exits_2_when_blocked(monkeypatch, tmp_path):
    monkeypatch.delenv("GOVAI_STAGING_BASE_URL", raising=False)
    monkeypatch.delenv("GOVAI_STAGING_API_KEY", raising=False)
    out = tmp_path / "evidence.json"
    rc = svf.main(["--skip-local", "--require-live", "--out", str(out)])
    assert rc == 2
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["summary"]["live_staging"]["blocked"] > 0
    assert doc["summary"]["live_staging"]["failed"] == 0


def test_evidence_document_schema_and_summary_are_consistent():
    ev = svf.Evidence(mode="local")
    ev.record("a", "local_simulation", "d", "e", "o", "passed")
    ev.record("b", "live_staging", "d", "e", "o", "blocked")
    ev.record("c", "local_simulation", "d", "e", "o", "failed")
    doc = ev.document()
    assert doc["schema"] == "govai.staging_policy_verification.v1"
    assert doc["summary"]["total"] == 3
    assert (
        doc["summary"]["passed"] == 1
        and doc["summary"]["failed"] == 1
        and doc["summary"]["blocked"] == 1
    )
    assert doc["summary"]["local_simulation"] == {
        "passed": 1,
        "failed": 1,
        "blocked": 0,
    }
    assert doc["summary"]["live_staging"] == {"passed": 0, "failed": 0, "blocked": 1}
    assert set(doc["summary"]) >= {"local_container"}


def test_prepare_never_writes_the_signing_seed(tmp_path):
    manifest = svf.prepare(tmp_path / "bundle", expires_days=1)
    files = [p for p in (tmp_path / "bundle").rglob("*") if p.is_file()]
    assert files, "prepare must write the bundle, trust store, fixtures, and manifest"
    names = {p.name for p in files}
    assert {
        "policy.bundle.staging.json",
        "trust.json",
        "expected-manifest.json",
    } <= names
    assert {"expired.json", "untrusted.json", "tampered.json", "unsigned.json"} <= names
    for p in files:
        text = p.read_text(encoding="utf-8", errors="ignore")
        assert "private" not in text.lower()
    assert manifest["bundle_sha256"] == svf._sha256_file(
        tmp_path / "bundle" / "policy.bundle.staging.json"
    )


def test_record_rejects_unknown_status_or_scope():
    ev = svf.Evidence(mode="local")
    with pytest.raises(AssertionError):
        ev.record("x", "local_simulation", "d", "e", "o", "maybe")
    with pytest.raises(AssertionError):
        ev.record("x", "production", "d", "e", "o", "passed")


def test_signed_bundle_helper_produces_a_bundle_the_python_verifier_accepts(tmp_path):
    sk = SigningKey.generate()
    seed = base64.b64encode(bytes(sk)).decode("ascii")
    pub = base64.b64encode(bytes(sk.verify_key)).decode("ascii")
    bundle = svf.write_signed_bundle(
        tmp_path / "b.json", svf.synthetic_policy(), seed_b64=seed, expires=svf.FUTURE
    )
    doc = json.loads(bundle.read_text(encoding="utf-8"))
    trust = [TrustEd25519(issuer_id=svf.ISSUER, pubkeys_base64=(pub,))]
    verify_policy_bundle_ed25519(doc, trust=trust)


def test_v1_record_with_expiry_is_refused_by_the_python_verifier(tmp_path):
    sk = SigningKey.generate()
    seed = base64.b64encode(bytes(sk)).decode("ascii")
    pub = base64.b64encode(bytes(sk.verify_key)).decode("ascii")
    path = svf.write_v1_record_with_expiry(
        tmp_path / "v1.json", svf.synthetic_policy(), seed_b64=seed, expires=svf.FUTURE
    )
    doc = json.loads(path.read_text(encoding="utf-8"))
    trust = [TrustEd25519(issuer_id=svf.ISSUER, pubkeys_base64=(pub,))]
    with pytest.raises(ValueError, match="cannot carry expires_at_utc"):
        verify_policy_bundle_ed25519(doc, trust=trust)


def test_refusal_message_reads_the_gate_text_from_the_error_body():
    body = {
        "code": "human_approved",
        "error": {"message": "policy_violation: human_approved approver 'x'"},
    }
    assert "approver 'x'" in svf._refusal_message(body)
    assert svf._refusal_message({"message": "plain"}) == "plain"
    assert svf._refusal_message({}) == ""
