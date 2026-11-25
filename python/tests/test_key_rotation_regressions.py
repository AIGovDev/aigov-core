"""Regressions: key rotation and revocation against execution authorizations.

Each test drives a real ``Executor`` that verifies through the trusted key registry, against the file-backed Core stand-in,
and counts the side effects that actually happened. Covered:

- an authorization already executed cannot run again after its key is rotated (replay protection);
- an outstanding authorization survives ordinary rotation (historical verification);
- an outstanding authorization signed before a compromise is refused (uncertain, refused by default);
- an outstanding authorization signed after a compromise is refused (untrusted).

Policy revision anchors are covered by ``rust/src/policy_anchor.rs`` (module ``rotation_regressions``): the anchor decision
takes no key identity, so rotation cannot change it.
"""

from __future__ import annotations

import base64
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import _lifecycle_harness as h
import pytest
from nacl.signing import SigningKey

from aigov_py.canonical_json import canonical_bytes
from aigov_py.trusted import keys as K
from aigov_py.trusted.authorization import AUTH_DOMAIN, AUTH_SCHEMA
from aigov_py.trusted.executor import Executor
from aigov_py.trusted.store import ExecutionStore
from aigov_py.trusted.store_admin import migrate


@pytest.fixture
def world():
    with tempfile.TemporaryDirectory(prefix="key-rotation-regr-") as d:
        root = Path(d)
        db = root / "executor.sqlite"
        migrate(db, backup_dir=None)
        reg = K.KeyRegistry(root / "registry.json")
        admin_seed, admin_pub = K.new_signing_seed()
        reg.install_operator("ops-admin", admin_pub, ("keyadmin", "revoker"))
        yield {"root": root, "db": db, "core": h.FileCore(root / "core.json"),
               "effects": root / "effects.log", "reg": reg, "admin": admin_seed}


def _register_activate(w, kid, seed_b64_pub):
    reg, admin = w["reg"], w["admin"]
    req = K.KeyRegistry.new_request(op="register", actor="ops-admin", expected_version=reg.version,
                                    kid=kid, purpose="execution_authorization", public_key_b64=seed_b64_pub, owner="t")
    reg.register(K.KeyRegistry.sign_request(req, admin))
    req = K.KeyRegistry.new_request(op="activate", actor="ops-admin", expected_version=reg.version, kid=kid)
    reg.activate(K.KeyRegistry.sign_request(req, admin))


def _rotate(w, old, new):
    reg, admin = w["reg"], w["admin"]
    req = K.KeyRegistry.new_request(op="register", actor="ops-admin", expected_version=reg.version, kid=new,
                                    purpose="execution_authorization", public_key_b64=w["_pubs"][new], owner="t")
    reg.register(K.KeyRegistry.sign_request(req, admin))
    req = K.KeyRegistry.new_request(op="rotate", actor="ops-admin", expected_version=reg.version, kid=old,
                                    purpose="execution_authorization", successor_kid=new)
    reg.rotate(K.KeyRegistry.sign_request(req, admin))


def _revoke(w, kid, compromised_from: datetime):
    reg, admin = w["reg"], w["admin"]
    req = K.KeyRegistry.new_request(op="revoke", actor="ops-admin", expected_version=reg.version, kid=kid,
                                    reason="suspected exposure", compromised_from_utc=compromised_from.isoformat())
    reg.revoke(K.KeyRegistry.sign_request(req, admin))


def _authorization(seed_hex: str, kid: str, issued: datetime) -> dict:
    """A signed authorization that names its signing key, as the registry path requires."""
    key = SigningKey(bytes.fromhex(seed_hex))
    payload = {
        "schema": AUTH_SCHEMA,
        "authorization_id": f"auth_{uuid.uuid4().hex}",
        "run_id": h.RUN,
        "tool_name": h.TOOL.name,
        "args_binding_hash": h.args_binding_hash(h.TOOL, h.ARGS),
        "policy_revision": "rev-1",
        "executor_audience": h.AUDIENCE,
        "approval_event_id": f"human_approved-{uuid.uuid4().hex}",
        "consequential_record_hash": "f" * 64,
        "issued_at_utc": issued.isoformat(),
        "expires_at_utc": (issued + timedelta(hours=1)).isoformat(),
        "signing_key_id": kid,
    }
    sig = key.sign(AUTH_DOMAIN + canonical_bytes(payload)).signature
    return {"payload": payload, "signature": base64.b64encode(sig).decode("ascii")}


def _executor(w, worker: str) -> Executor:
    return Executor(
        core=w["core"],
        public_key_b64=None,
        registry=w["reg"],
        audience=h.AUDIENCE,
        store=ExecutionStore(w["db"]),
        tools=h.TOOLS,
        performer=h.SideEffects(w["effects"]).performer(),
        worker_id=worker,
    )


def _key(w, kid: str) -> tuple[str, str]:
    seed, pub = h.new_authorization_key()
    w.setdefault("_pubs", {})[kid] = pub
    w.setdefault("_seeds", {})[kid] = seed
    return seed, pub


def test_an_executed_authorization_cannot_run_again_after_its_key_is_rotated(world):
    w = world
    seed_a, pub_a = _key(w, "exe-a")
    _key(w, "exe-b")
    _register_activate(w, "exe-a", pub_a)
    auth = _authorization(seed_a, "exe-a", datetime.now(UTC))
    first = _executor(w, "worker-1").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert first.executed
    assert h.SideEffects(w["effects"]).count() == 1

    _rotate(w, "exe-a", "exe-b")
    again = _executor(w, "worker-2").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert not again.executed, "rotation must not re-open a consumed authorization"
    assert h.SideEffects(w["effects"]).count() == 1


def test_an_outstanding_authorization_survives_ordinary_rotation(world):
    w = world
    seed_a, pub_a = _key(w, "exe-a")
    _key(w, "exe-b")
    _register_activate(w, "exe-a", pub_a)
    auth = _authorization(seed_a, "exe-a", datetime.now(UTC))
    _rotate(w, "exe-a", "exe-b")
    result = _executor(w, "worker-1").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert result.executed, result.reason
    assert h.SideEffects(w["effects"]).count() == 1


def test_an_outstanding_authorization_signed_after_compromise_is_refused_and_performs_nothing(world):
    w = world
    seed, pub = _key(w, "exe-c")
    _register_activate(w, "exe-c", pub)
    issued = datetime.now(UTC)
    auth = _authorization(seed, "exe-c", issued)
    _revoke(w, "exe-c", compromised_from=issued - timedelta(minutes=1))
    result = _executor(w, "worker-1").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert not result.executed
    assert result.reason == "authorization_key_untrusted"
    assert h.SideEffects(w["effects"]).count() == 0


def test_an_outstanding_authorization_signed_before_an_uncertain_compromise_is_refused_by_default(world):
    w = world
    seed, pub = _key(w, "exe-u")
    _register_activate(w, "exe-u", pub)
    issued = datetime.now(UTC)
    auth = _authorization(seed, "exe-u", issued)
    _revoke(w, "exe-u", compromised_from=issued + timedelta(minutes=5))
    result = _executor(w, "worker-1").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert not result.executed
    assert result.reason == "authorization_key_untrusted"
    assert h.SideEffects(w["effects"]).count() == 0


def test_rotation_and_revocation_leave_the_operator_history_verifiable(world):
    w = world
    seed_a, pub_a = _key(w, "exe-a")
    _key(w, "exe-b")
    _register_activate(w, "exe-a", pub_a)
    _rotate(w, "exe-a", "exe-b")
    reloaded = K.KeyRegistry(w["root"] / "registry.json")
    assert reloaded.verify_integrity()["chain_verified"] is True
    assert reloaded.get("exe-a").status == "retired"
    assert reloaded.get("exe-b").status == "active"
