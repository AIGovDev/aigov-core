"""Python mirror of rust/tests/export_signature_binding.rs (audit export signature binding).

TEST-ONLY seed. Verifies signer, creation time and expiry are covered by the signature, expiry is
enforced, legacy (unversioned) records keep verifying, and digests match the Rust vector.
"""

import base64
import json

import pytest
from nacl.signing import SigningKey

from aigov_py.audit_export_signing import (
    audit_export_payload_digest_sha256_hex,
    audit_export_signing_digest_v2,
    sign_audit_export_ed25519,
    verify_audit_export_ed25519_signature,
)
from aigov_py.policy_bundle_signing import TrustEd25519

ISSUER = "govai-export-signer"
SEED = bytes([0x33] * 32)
SEED_B64 = base64.b64encode(SEED).decode("ascii")


def _export(run_id="run-bind-py"):
    events = [{
        "event_id": f"{run_id}-e1", "event_type": "ai_discovery_reported",
        "ts_utc": "2026-01-01T00:00:01Z", "actor": "test", "system": "test", "run_id": run_id,
        "payload": {"openai": False, "transformers": False, "model_artifacts": False},
    }]
    return {
        "ok": True,
        "schema_version": "aigov.audit_export.v1",
        "policy_version": "test-policy",
        "environment": "dev",
        "run": {"run_id": run_id},
        "evidence_hashes": {
            "bundle_sha256": "a" * 64,
            "events_content_sha256": _events_digest(run_id, events),
            "chain_head_record_sha256": "b" * 64,
            "log_chain": [],
        },
        "decision": {"verdict": "BLOCKED"},
        "evidence_events": events,
    }


def _events_digest(run_id, events):
    # Use the module's own helper so the event digest matches the verifier exactly.
    from aigov_py.portable_evidence_digest import portable_evidence_digest_v1

    return portable_evidence_digest_v1(run_id, events)


def _trust():
    vk = bytes(SigningKey(SEED).verify_key)
    return [TrustEd25519(issuer_id=ISSUER, pubkeys_base64=(base64.b64encode(vk).decode("ascii"),))]


def _sign(tmp_path, run_id="run-bind-py", expires=None):
    src = tmp_path / "export.json"
    src.write_text(json.dumps(_export(run_id)), encoding="utf-8")
    out = tmp_path / "signed.json"
    sign_audit_export_ed25519(
        src, out_path=out, issuer_id=ISSUER, signer="ci-signer",
        private_key_base64=SEED_B64, created_at_utc="2026-01-01T00:00:00Z", expires_at_utc=expires,
    )
    return json.loads(out.read_text(encoding="utf-8"))


def test_positive_control_unexpired_signature_verifies(tmp_path):
    doc = _sign(tmp_path, expires="2999-01-01T00:00:00Z")
    verify_audit_export_ed25519_signature(doc, trust=_trust())


def test_tampering_signer_invalidates(tmp_path):
    doc = _sign(tmp_path)
    doc["signatures"][0]["signer"] = "attacker"
    with pytest.raises(ValueError):
        verify_audit_export_ed25519_signature(doc, trust=_trust())


def test_tampering_creation_time_invalidates(tmp_path):
    doc = _sign(tmp_path)
    doc["signatures"][0]["created_at_utc"] = "2030-06-01T00:00:00Z"
    with pytest.raises(ValueError):
        verify_audit_export_ed25519_signature(doc, trust=_trust())


def test_extending_expiry_invalidates(tmp_path):
    doc = _sign(tmp_path, expires="2020-01-01T00:00:00Z")
    doc["signatures"][0]["expires_at_utc"] = "2999-01-01T00:00:00Z"
    with pytest.raises(ValueError):
        verify_audit_export_ed25519_signature(doc, trust=_trust())


def test_expired_signature_rejected(tmp_path):
    doc = _sign(tmp_path, expires="2020-01-01T00:00:00Z")
    with pytest.raises(ValueError, match="expired"):
        verify_audit_export_ed25519_signature(doc, trust=_trust())


def test_legacy_record_with_expiry_rejected(tmp_path):
    doc = _export("run-bind-py-v1")
    digest = audit_export_payload_digest_sha256_hex(doc)
    sig = SigningKey(SEED).sign(digest.encode("utf-8")).signature
    doc["signatures"] = [{
        "kind": "ed25519", "issuer_id": ISSUER, "signer": "ci-signer",
        "created_at_utc": "2026-01-01T00:00:00Z", "expires_at_utc": "2020-01-01T00:00:00Z",
        "payload_digest_sha256": digest,
        "signature": {"encoding": "base64", "value": base64.b64encode(sig).decode("ascii")},
    }]
    with pytest.raises(ValueError, match="legacy"):
        verify_audit_export_ed25519_signature(doc, trust=_trust())


def test_legacy_record_without_expiry_still_verifies(tmp_path):
    doc = _export("run-bind-py-legacy")
    digest = audit_export_payload_digest_sha256_hex(doc)
    sig = SigningKey(SEED).sign(digest.encode("utf-8")).signature
    doc["signatures"] = [{
        "kind": "ed25519", "issuer_id": ISSUER, "signer": "ci-signer",
        "created_at_utc": "2026-01-01T00:00:00Z", "expires_at_utc": None,
        "payload_digest_sha256": digest,
        "signature": {"encoding": "base64", "value": base64.b64encode(sig).decode("ascii")},
    }]
    verify_audit_export_ed25519_signature(doc, trust=_trust())


def test_v2_digest_matches_rust_vector():
    doc = {
        "schema_version": "aigov.audit_export.v1", "policy_version": "p", "environment": "dev",
        "run": {"run_id": "run-vec"},
        "evidence_hashes": {"bundle_sha256": "a" * 64, "events_content_sha256": "b" * 64,
                            "chain_head_record_sha256": "c" * 64, "log_chain": []},
        "decision": {"verdict": "BLOCKED"},
    }
    assert audit_export_signing_digest_v2(
        doc, issuer_id=ISSUER, signer="ci-signer", created_at_utc="2026-01-01T00:00:00Z",
        expires_at_utc="2999-01-01T00:00:00Z",
    ) == "ca0228a1e586093c8e247659445625bcf56b82d09654ad5b19c29582378a47f1"
    assert audit_export_signing_digest_v2(
        doc, issuer_id=ISSUER, signer="ci-signer", created_at_utc="2026-01-01T00:00:00Z",
        expires_at_utc=None,
    ) == "fd92abcaebb77df2ab4f3f2f724ff88fec346d10bfcb3d231be9212348021a24"


def test_tampering_unsigned_evidence_fields_invalidates(tmp_path):
    doc = _sign(tmp_path, expires=None)
    doc["evidence_hashes"]["log_chain"] = [{"record_hash": "forged"}]
    with pytest.raises(ValueError):
        verify_audit_export_ed25519_signature(doc, trust=_trust())


def test_signing_a_document_with_floats_is_refused(tmp_path):
    doc = _export("run-bind-py-float")
    doc["run"]["score"] = 0.5
    src = tmp_path / "export.json"
    src.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ValueError, match="floating-point"):
        sign_audit_export_ed25519(
            src, out_path=tmp_path / "out.json", issuer_id=ISSUER, signer="ci-signer",
            private_key_base64=SEED_B64, created_at_utc="2026-01-01T00:00:00Z", expires_at_utc=None,
        )
