"""Regressions: key rotation, revocation, and root rotation against execution authorizations (registry format v2).

Each test drives a real ``Executor`` that verifies through the trusted key registry, against the file-backed Core stand-in,
and counts the side effects that actually happened. Covered:

- an authorization already executed cannot run again after its key is rotated (replay protection);
- an outstanding authorization survives ordinary rotation (historical verification);
- an outstanding authorization signed after a compromise is refused (untrusted), and one signed before is refused by default
  (uncertain), both with no side effect;
- the operator history stays verifiable after rotation;
- replay protection is still in force after the root key is rotated.
"""

from __future__ import annotations

import base64
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import _lifecycle_harness as h
import pytest
from _registry_world import World, write_secret_file
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
        w = World(root)
        w.install_operator("ops-admin")
        yield {"root": root, "db": db, "core": h.FileCore(root / "core.json"),
               "effects": root / "effects.log", "world": w}


def _key(w, kid: str) -> str:
    """Create a key for ``kid`` in the world and return its seed (base64)."""
    seed, _ = w["world"].new_key(kid)
    return seed


def _authorization(seed_b64: str, kid: str, issued: datetime) -> dict:
    """A signed authorization that names its signing key, as the registry path requires."""
    key = SigningKey(base64.b64decode(seed_b64))
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
        registry=w["world"].reader(),
        audience=h.AUDIENCE,
        store=ExecutionStore(w["db"]),
        tools=h.TOOLS,
        performer=h.SideEffects(w["effects"]).performer(),
        worker_id=worker,
    )


def test_an_executed_authorization_cannot_run_again_after_its_key_is_rotated(world):
    w = world
    seed_a = _key(w, "exe-a")
    _key(w, "exe-b")
    w["world"].register_active("exe-a")
    auth = _authorization(seed_a, "exe-a", datetime.now(UTC))
    first = _executor(w, "worker-1").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert first.executed
    assert h.SideEffects(w["effects"]).count() == 1

    w["world"].rotate("exe-a", "exe-b")
    again = _executor(w, "worker-2").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert not again.executed, "rotation must not re-open a consumed authorization"
    assert h.SideEffects(w["effects"]).count() == 1


def test_an_outstanding_authorization_survives_ordinary_rotation(world):
    w = world
    seed_a = _key(w, "exe-a")
    _key(w, "exe-b")
    w["world"].register_active("exe-a")
    auth = _authorization(seed_a, "exe-a", datetime.now(UTC))
    w["world"].rotate("exe-a", "exe-b")
    result = _executor(w, "worker-1").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert result.executed, result.reason
    assert h.SideEffects(w["effects"]).count() == 1


def test_an_outstanding_authorization_signed_after_compromise_is_refused_and_performs_nothing(world):
    w = world
    seed = _key(w, "exe-c")
    w["world"].register_active("exe-c")
    issued = datetime.now(UTC)
    auth = _authorization(seed, "exe-c", issued)
    w["world"].revoke("exe-c", compromised_from=(issued - timedelta(minutes=1)).isoformat())
    result = _executor(w, "worker-1").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert not result.executed
    assert result.reason == "authorization_key_untrusted"
    assert h.SideEffects(w["effects"]).count() == 0


def test_an_outstanding_authorization_signed_before_an_uncertain_compromise_is_refused_by_default(world):
    w = world
    seed = _key(w, "exe-u")
    w["world"].register_active("exe-u")
    issued = datetime.now(UTC)
    auth = _authorization(seed, "exe-u", issued)
    w["world"].revoke("exe-u", compromised_from=(issued + timedelta(minutes=5)).isoformat())
    result = _executor(w, "worker-1").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert not result.executed
    assert result.reason == "authorization_key_untrusted"
    assert h.SideEffects(w["effects"]).count() == 0


def test_rotation_and_revocation_leave_the_operator_history_verifiable(world):
    w = world
    _key(w, "exe-a")
    _key(w, "exe-b")
    w["world"].register_active("exe-a")
    w["world"].rotate("exe-a", "exe-b")
    reloaded = w["world"].reader()
    assert reloaded.verify_integrity()["anchored"] is True
    assert reloaded.get("exe-a").status == "retired"
    assert reloaded.get("exe-b").status == "active"


def test_replay_protection_survives_a_root_rotation(world):
    w = world
    seed_a = _key(w, "exe-a")
    w["world"].register_active("exe-a")
    auth = _authorization(seed_a, "exe-a", datetime.now(UTC))
    assert _executor(w, "worker-1").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth).executed
    # Root rotation: root-a is retired after the current sequence, and a new root is current.
    world = w["world"]
    bound = world.reg.version
    new_root_seed, new_root_pub = K.new_signing_seed()
    doc = dict(world.trust_doc)
    doc["roots"] = [
        {"kid": "root-a", "public_key_b64": world.root_pub, "status": "retired", "retired_after_seq": bound},
        {"kid": "root-b", "public_key_b64": new_root_pub, "status": "current"},
    ]
    write_secret_file(world.trust_path, __import__("json").dumps(doc))
    world.trust = K.TrustConfig.load(world.trust_path)
    result = _executor(w, "worker-2").execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=auth)
    assert not result.executed, "a root rotation must not re-open a consumed authorization"
    assert h.SideEffects(w["effects"]).count() == 1
