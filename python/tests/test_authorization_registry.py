"""Execution authorizations verified through the trusted key registry (format v2).

Covers: a current key, a rotated key (historical authorization still verifies), a compromised key, a missing key id, a
cross-purpose signature, a tampered payload, and a stale reader that must see a revocation through the anchor.
"""

from __future__ import annotations

import base64
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from _registry_world import World
from nacl.signing import SigningKey

from aigov_py.trusted import keys as K
from aigov_py.trusted.authorization import Refused, verify_authorization_with_registry


@pytest.fixture
def world():
    with tempfile.TemporaryDirectory(prefix="auth-registry-") as d:
        w = World(Path(d))
        w.install_operator("ops-admin")
        yield w


from aigov_py.canonical_json import canonical_bytes  # noqa: E402


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

    sk = SigningKey(base64.b64decode(seed_b64))
    sig = base64.b64encode(sk.sign(K.DOMAINS[purpose] + canonical_bytes(payload)).signature).decode()
    return {"payload": payload, "signature": sig}


def test_current_key_verifies(world):
    world.register_active("exe-1")
    signed = _authorization(world.keys["exe-1"][0], kid="exe-1", issued=datetime.now(UTC))
    assert verify_authorization_with_registry(signed, world.reader()) == "exe-1"


def test_authorization_from_before_an_ordinary_rotation_still_verifies(world):
    world.register_active("exe-a")
    old = _authorization(world.keys["exe-a"][0], kid="exe-a", issued=datetime.now(UTC))
    world.rotate("exe-a", "exe-b")
    assert verify_authorization_with_registry(old, world.reader()) == "exe-a"


def test_authorization_signed_by_a_compromised_key_is_refused_after_compromise(world):
    world.register_active("exe-c")
    issued = datetime.now(UTC)
    signed = _authorization(world.keys["exe-c"][0], kid="exe-c", issued=issued)
    world.revoke("exe-c", compromised_from=(issued - timedelta(minutes=1)).isoformat())
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, world.reader())
    assert exc.value.reason == "authorization_key_untrusted"


def test_uncertain_authorization_is_refused_by_default(world):
    world.register_active("exe-u")
    issued = datetime.now(UTC)
    signed = _authorization(world.keys["exe-u"][0], kid="exe-u", issued=issued)
    world.revoke("exe-u", compromised_from=(issued + timedelta(minutes=5)).isoformat())
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, world.reader())
    assert exc.value.reason == "authorization_key_untrusted"


def test_authorization_without_a_key_id_is_refused_on_the_registry_path(world):
    world.register_active("exe-n")
    signed = _authorization(world.keys["exe-n"][0], kid=None, issued=datetime.now(UTC))
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, world.reader())
    assert exc.value.reason == "authorization_key_id_missing"


def test_cross_purpose_signature_is_refused(world):
    seed, pub = world.new_key("pol-x")
    world.op("ops-admin", "register", kid="pol-x", purpose="policy_bundle", public_key_b64=pub, owner="t")
    world.op("ops-admin", "activate", kid="pol-x")
    signed = _authorization(seed, kid="pol-x", issued=datetime.now(UTC), purpose="policy_bundle")
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, world.reader())
    assert exc.value.reason == "authorization_key_purpose_mismatch"


def test_tampered_authorization_fails_signature_check(world):
    world.register_active("exe-t")
    signed = _authorization(world.keys["exe-t"][0], kid="exe-t", issued=datetime.now(UTC))
    signed["payload"]["tool_name"] = "transfer_all_funds"
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, world.reader())
    assert exc.value.reason == "authorization_signature_invalid"


def test_a_stale_registry_instance_sees_a_revocation_made_elsewhere(world):
    # Two processes share the registry: the executor loaded it before the revocation was written by the other.
    world.register_active("exe-s")
    issued = datetime.now(UTC)
    signed = _authorization(world.keys["exe-s"][0], kid="exe-s", issued=issued)
    executor_view = world.reader()  # loaded before the revocation
    assert verify_authorization_with_registry(signed, executor_view) == "exe-s"
    world.revoke("exe-s", compromised_from=(issued - timedelta(minutes=1)).isoformat())
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, executor_view)
    assert exc.value.reason == "authorization_key_untrusted"


def test_a_registry_whose_anchor_disagrees_is_refused_by_the_verifier(world):
    world.register_active("exe-v")
    signed = _authorization(world.keys["exe-v"][0], kid="exe-v", issued=datetime.now(UTC))
    reader = world.reader()
    # The log is rolled back under the reader, while the anchor still records the later state.
    events = world.events()
    world.register_pending("exe-w")
    world.write_events(events)
    with pytest.raises(Refused) as exc:
        verify_authorization_with_registry(signed, reader)
    assert exc.value.reason == "registry_anchor_log_behind"
