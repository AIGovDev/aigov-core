"""Regression: policy bundle signatures (v2) bind signing metadata and enforce expiry.

Before v2 the signed digest covered only the document, so the signer label, creation time and
expiry in the record were unsigned. A v1 record also had no way to carry a trustworthy expiry.

The seed is a fixed TEST-ONLY value. The vectors are pinned in
rust/src/policy_signing.rs (`policy_signature_digest_v2_matches_python_mirror_vector`).
"""

import base64

import pytest
from aigov_py.policy_bundle_signing import (
    POLICY_PAYLOAD_VERSION_V2,
    TrustEd25519,
    policy_payload_digest_sha256_hex,
    policy_signature_digest_v2,
    verify_policy_bundle_ed25519,
)
from nacl.signing import SigningKey

SEED = bytes([0x66] * 32)
ISSUER = "policy-issuer-test"
CREATED = "2026-01-01T00:00:00Z"
FUTURE = "2999-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"


def _trust():
    vk = SigningKey(SEED).verify_key
    return [TrustEd25519(issuer_id=ISSUER, pubkeys_base64=(base64.b64encode(bytes(vk)).decode("ascii"),))]


def _doc():
    return {
        "schema": "govai.policy.v1",
        "policy_id": "p",
        "version": "1",
        "issuer": {"issuer_id": ISSUER},
        "selectors": {"tenants": ["*"], "environments": ["*"]},
        "ingest_rules": {"unknown_event_types": {"behavior": "reject"}, "event_types": {}},
        "verdict_rules": {"required_evidence_codes": [], "invalid_conditions": []},
        "signatures": [],
    }


def _sign_v2(doc, *, signer="ci", created=CREATED, expires=FUTURE):
    digest = policy_signature_digest_v2(
        policy_digest_sha256=policy_payload_digest_sha256_hex(doc),
        issuer_id=ISSUER,
        signer=signer,
        created_at_utc=created,
        expires_at_utc=expires,
    )
    sig = SigningKey(SEED).sign(digest.encode("utf-8")).signature
    doc["signatures"] = [{
        "kind": "ed25519",
        "payload_version": POLICY_PAYLOAD_VERSION_V2,
        "signer": signer,
        "created_at_utc": created,
        "expires_at_utc": expires,
        "payload_digest_sha256": digest,
        "signature": {"encoding": "base64", "value": base64.b64encode(sig).decode("ascii")},
        "sigstore": None,
    }]
    return doc


def test_v2_digest_matches_rust_vectors():
    assert policy_signature_digest_v2(
        policy_digest_sha256="a" * 64, issuer_id="iss", signer="ci",
        created_at_utc=CREATED, expires_at_utc=FUTURE,
    ) == "f038c7ff58adc61c0bbb1c4803f7aaf87e01f78a55dd118ae5409ab91a4a4466"
    assert policy_signature_digest_v2(
        policy_digest_sha256="a" * 64, issuer_id="iss", signer="ci",
        created_at_utc=CREATED, expires_at_utc=None,
    ) == "4921b668db2abb463a835ab0165f9694ba966a204c400205b0cbf3bbb4bf5da7"


def test_positive_control_v2_verifies():
    verify_policy_bundle_ed25519(_sign_v2(_doc()), trust=_trust())


@pytest.mark.parametrize("field,value", [
    ("signer", "attacker"),
    ("created_at_utc", "2030-06-01T00:00:00Z"),
    ("expires_at_utc", "2999-12-31T00:00:00Z"),
])
def test_tampering_signed_metadata_invalidates_v2(field, value):
    doc = _sign_v2(_doc(), expires=PAST)
    doc["signatures"][0][field] = value
    with pytest.raises(ValueError, match="payload_digest_sha256 mismatch"):
        verify_policy_bundle_ed25519(doc, trust=_trust())


def test_expired_v2_is_refused():
    with pytest.raises(ValueError, match="expired"):
        verify_policy_bundle_ed25519(_sign_v2(_doc(), expires=PAST), trust=_trust())


def test_v1_record_with_expiry_is_refused():
    doc = _doc()
    digest = policy_payload_digest_sha256_hex(doc)
    sig = SigningKey(SEED).sign(digest.encode("utf-8")).signature
    doc["signatures"] = [{
        "kind": "ed25519",
        "signer": "ci",
        "created_at_utc": CREATED,
        "expires_at_utc": PAST,
        "payload_digest_sha256": digest,
        "signature": {"encoding": "base64", "value": base64.b64encode(sig).decode("ascii")},
        "sigstore": None,
    }]
    with pytest.raises(ValueError, match="cannot carry expires_at_utc"):
        verify_policy_bundle_ed25519(doc, trust=_trust())


def test_modified_document_invalidates_v2():
    doc = _sign_v2(_doc())
    doc["ingest_rules"]["unknown_event_types"]["behavior"] = "allow"
    with pytest.raises(ValueError, match="payload_digest_sha256 mismatch"):
        verify_policy_bundle_ed25519(doc, trust=_trust())


def test_unknown_payload_version_is_refused():
    doc = _sign_v2(_doc())
    doc["signatures"][0]["payload_version"] = 3
    with pytest.raises(ValueError, match="unsupported policy signature payload_version"):
        verify_policy_bundle_ed25519(doc, trust=_trust())


def test_unknown_key_is_refused():
    other = SigningKey(bytes([0x77] * 32))
    doc = _doc()
    digest = policy_signature_digest_v2(
        policy_digest_sha256=policy_payload_digest_sha256_hex(doc), issuer_id=ISSUER,
        signer="ci", created_at_utc=CREATED, expires_at_utc=FUTURE,
    )
    sig = other.sign(digest.encode("utf-8")).signature
    doc["signatures"] = [{
        "kind": "ed25519", "payload_version": 2, "signer": "ci", "created_at_utc": CREATED,
        "expires_at_utc": FUTURE, "payload_digest_sha256": digest,
        "signature": {"encoding": "base64", "value": base64.b64encode(sig).decode("ascii")},
    }]
    with pytest.raises(ValueError, match="forged or corrupt|no valid|verification failed"):
        verify_policy_bundle_ed25519(doc, trust=_trust())
