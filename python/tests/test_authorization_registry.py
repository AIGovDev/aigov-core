"""Execution authorizations verified through the trusted key registry.

Covers: a current key, a rotated key (historical authorization still verifies), a compromised key, a missing key id, a
cross-purpose signature, and an authorization whose signed time falls after the key was retired.
"""

from __future__ import annotations

import base64
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from aigov_py.trusted import keys as K
from aigov_py.trusted.authorization import Refused, verify_authorization_with_registry
from aigov_py.trusted.keys import DOMAINS


@pytest.fixture
def world():
    with tempfile.TemporaryDirectory(prefix="auth-registry-") as d:
        reg = K.KeyRegistry(Path(d) / "registry.json")
        admin_seed, admin_pub = K.new_signing_seed()
        reg.install_operator("ops-admin", admin_pub, ("keyadmin", "revoker"))
        yield reg, admin_seed


def _register_and_activate(reg, admin, kid, purpose, pub):
    req = K.KeyRegistry.new_request(op="register", actor="ops-admin", expected_version=reg.version,
                                    kid=kid, purpose=purpose, public_key_b64=pub, owner="team")
    reg.register(K.KeyRegistry.sign_request(req, admin))
    req = K.KeyRegistry.new_request(op="activate", actor="ops-admin", expected_version=reg.version, kid=kid)
    reg.activate(K.KeyRegistry.sign_request(req, admin))


def _authorization(seed_b64: str, *, kid: str | None, issued: datetime, purpose: str = "execution_authorization"):
    payload = {
        "schema": "govai.execution_authorization.v1",
        "authorization_id": "auth-" + issued.strftime("%H%M%S%f"),
        "run_id": "run-1",
        "tool_name": "refund",
        "args_binding_hash": "a" * 64,
        "policy_revision": "rev-1",
        "executor_audience": "executor",
        "approval_event_id": "evt-1",
        "consequential_record_hash": "b" * 64,
        "issued_at_utc": issued.isoformat(),
        "expires_at_utc": (issued + timedelta(seconds=60)).isoformat(),
    }
    if kid is not None:
        payload["signing_key_id"] = kid
    from aigov_py.canonical_json import canonical_bytes

    sk = SigningKey(base64.b64decode(seed_b64))
    sig = base64.b64encode(sk.sign(DOMAINS[purpose] + canonical_bytes(payload)).signature).decode()
    return {"payload": payload, "signature": sig}


def test_current_key_verifies(world):
    reg, admin = world
    seed, pub = K.new_signing_seed()
    _register_and_activate(reg, admin, "exe-1", "execution_authorization", pub)
    signed = _authorization(seed, kid="exe-1", issued=datetime.now(UTC))
    assert verify_authorization_with_registry(signed, reg) == "exe-1"


def test_authorization_from_before_an_ordinary_rotation_still_verifies(world):
    reg, admin = world
    seed_a, pub_a = K.new_signing_seed()
    _, pub_b = K.new_signing_seed()
    _register_and_activate(reg, admin, "exe-a", "execution_authorization", pub_a)
    old = _authorization(seed_a, kid="exe-a", issued=datetime.now(UTC))
    req = K.KeyRegistry.new_request(op="register", actor="ops-admin", expected_version=reg.version,
                                    kid="exe-b", purpose="execution_authorization", public_key_b64=pub_b, owner="t")
    reg.register(K.KeyRegistry.sign_request(req, admin))
    req = K.KeyRegistry.new_request(op="rotate", actor="ops-admin", expected_version=reg.version,
                                    kid="exe-a", purpose="execution_authorization", successor_kid="exe-b")
    reg.rotate(K.KeyRegistry.sign_request(req, admin))
    assert verify_authorization_with_registry(old, reg) == "exe-a"


def test_authorization_signed_by_a_compromised_key_is_refused_after_compromise(world):
    reg, admin = world
    seed, pub = K.new_signing_seed()
    _register_and_activate(reg, admin, "exe-c", "execution_authorization", pub)
    issued = datetime.now(UTC)
    signed = _authorization(seed, kid="exe-c", issued=issued)
    req = K.KeyRegistry.new_request(op="revoke", actor="ops-admin", expected_version=reg.version, kid="exe-c",
                                    reason="exposed", compromised_from_utc=(issued - timedelta(minutes=1)).isoformat())
    reg.revoke(K.KeyRegistry.sign_request(req, admin))
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, reg)
    assert exc.value.reason == "authorization_key_untrusted"


def test_uncertain_authorization_is_refused_by_default(world):
    reg, admin = world
    seed, pub = K.new_signing_seed()
    _register_and_activate(reg, admin, "exe-u", "execution_authorization", pub)
    issued = datetime.now(UTC)
    signed = _authorization(seed, kid="exe-u", issued=issued)
    req = K.KeyRegistry.new_request(op="revoke", actor="ops-admin", expected_version=reg.version, kid="exe-u",
                                    reason="exposed", compromised_from_utc=(issued + timedelta(minutes=5)).isoformat())
    reg.revoke(K.KeyRegistry.sign_request(req, admin))
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, reg)
    assert exc.value.reason == "authorization_key_untrusted"


def test_authorization_without_a_key_id_is_refused_on_the_registry_path(world):
    reg, admin = world
    seed, pub = K.new_signing_seed()
    _register_and_activate(reg, admin, "exe-n", "execution_authorization", pub)
    signed = _authorization(seed, kid=None, issued=datetime.now(UTC))
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, reg)
    assert exc.value.reason == "authorization_key_id_missing"


def test_cross_purpose_signature_is_refused(world):
    reg, admin = world
    seed, pub = K.new_signing_seed()
    _register_and_activate(reg, admin, "pol-x", "policy_bundle", pub)
    signed = _authorization(seed, kid="pol-x", issued=datetime.now(UTC), purpose="policy_bundle")
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, reg)
    assert exc.value.reason == "authorization_key_purpose_mismatch"


def test_tampered_authorization_fails_signature_check(world):
    reg, admin = world
    seed, pub = K.new_signing_seed()
    _register_and_activate(reg, admin, "exe-t", "execution_authorization", pub)
    signed = _authorization(seed, kid="exe-t", issued=datetime.now(UTC))
    signed["payload"]["tool_name"] = "transfer_all_funds"
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, reg)
    assert exc.value.reason == "authorization_signature_invalid"


def test_a_stale_registry_instance_sees_a_revocation_made_elsewhere(world):
    # Two processes share the registry: the executor loaded it before the revocation was written by the other.
    reg, admin = world
    seed, pub = K.new_signing_seed()
    _register_and_activate(reg, admin, "exe-s", "execution_authorization", pub)
    issued = datetime.now(UTC)
    signed = _authorization(seed, kid="exe-s", issued=issued)
    executor_view = K.KeyRegistry(reg._path)  # loaded before the revocation
    assert verify_authorization_with_registry(signed, executor_view) == "exe-s"
    operator_view = K.KeyRegistry(reg._path)
    req = K.KeyRegistry.new_request(op="revoke", actor="ops-admin", expected_version=operator_view.version,
                                    kid="exe-s", reason="exposed",
                                    compromised_from_utc=(issued - timedelta(minutes=1)).isoformat())
    operator_view.revoke(K.KeyRegistry.sign_request(req, admin))
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, executor_view)
    assert exc.value.reason == "authorization_key_untrusted"

