"""Explicit migration of a v1 registry to v2 without silently trusting its unsigned history.

The v1 registries are built with the test-only v1 writer (``_legacy_v1_keys``, commit eaab53f). The migration is one
root-signed ``legacy_import`` event. The imported keys carry the ``legacy_v1_unsigned`` provenance, and their verdicts are
at most ``uncertain``.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import _legacy_v1_keys as V1
import pytest

from aigov_py.trusted import keys as K
from _sqlite_anchor import SqliteAnchor


@pytest.fixture
def migration():
    with tempfile.TemporaryDirectory(prefix="registry-migration-") as d:
        root = Path(d)
        # A v1 registry, built with the v1 writer: ops-admin, exe-a (rotated to exe-b; exe-a retired).
        v1 = V1.KeyRegistry(root / "v1.json")
        admin_seed, admin_pub = V1.new_signing_seed()
        v1.install_operator("ops-admin", admin_pub, ("keyadmin", "revoker"))
        a_seed, a_pub = V1.new_signing_seed()
        b_seed, b_pub = V1.new_signing_seed()
        v1.register(V1.KeyRegistry.sign_request(V1.KeyRegistry.new_request(
            op="register", actor="ops-admin", expected_version=v1.version, kid="exe-a",
            purpose="execution_authorization", public_key_b64=a_pub, owner="authz"), admin_seed))
        v1.activate(V1.KeyRegistry.sign_request(V1.KeyRegistry.new_request(
            op="activate", actor="ops-admin", expected_version=v1.version, kid="exe-a"), admin_seed))
        a_active_at = datetime.now(UTC)
        v1.register(V1.KeyRegistry.sign_request(V1.KeyRegistry.new_request(
            op="register", actor="ops-admin", expected_version=v1.version, kid="exe-b",
            purpose="execution_authorization", public_key_b64=b_pub, owner="authz"), admin_seed))
        v1.rotate(V1.KeyRegistry.sign_request(V1.KeyRegistry.new_request(
            op="rotate", actor="ops-admin", expected_version=v1.version, kid="exe-a",
            purpose="execution_authorization", successor_kid="exe-b"), admin_seed))

        # The v2 trust file pins root-a. The root holder performs the migration.
        root_seed, root_pub = K.new_signing_seed()
        trust_doc = {"schema": K.TRUST_SCHEMA, "registry_id": "migrated",
                     "roots": [{"kid": "root-a", "public_key_b64": root_pub, "status": "current"}]}
        (root / "trust.json").write_text(json.dumps(trust_doc))
        trust = K.TrustConfig.from_dict(trust_doc)
        anchor = SqliteAnchor(root / "v2-anchor.sqlite", "migrated")
        yield {"root": root, "v1": root / "v1.json", "v2": root / "v2.json", "trust": trust, "trust_doc": trust_doc,
               "anchor": anchor, "root_seed": root_seed, "root_pub": root_pub, "admin_seed": admin_seed,
               "a_seed": a_seed, "b_seed": b_seed, "a_active_at": a_active_at}


def _migrate(m, **overrides):
    args = dict(trust=m["trust"], anchor=m["anchor"], root_kid="root-a", root_seed_b64=m["root_seed"])
    args.update(overrides)
    return K.migrate_v1(m["v1"], m["v2"], **args)


def test_migration_imports_the_v1_state_under_one_root_signature(migration):
    m = migration
    result = _migrate(m)
    assert result["imported_keys"] == 2 and result["imported_operators"] == 1
    reader = K.KeyRegistry(m["v2"], trust=m["trust"], anchor=m["anchor"])
    assert reader.events[0]["request"]["payload"]["op"] == "legacy_import"
    assert reader.get("exe-a").status == "retired"
    assert reader.get("exe-b").status == "active"
    assert reader.get("exe-a").provenance == K.PROVENANCE_LEGACY_V1
    assert reader.state.operators["ops-admin"]["status"] == "active"


def test_historical_v1_signatures_are_never_more_than_uncertain(migration):
    m = migration
    _migrate(m)
    import base64

    from nacl.signing import SigningKey
    payload = b"evidence-made-while-exe-a-was-active"
    sig = base64.b64encode(SigningKey(base64.b64decode(m["a_seed"])).sign(K.DOMAINS["execution_authorization"] + payload)
                           .signature).decode()
    reader = K.KeyRegistry(m["v2"], trust=m["trust"], anchor=m["anchor"])
    a = reader.assess(purpose="execution_authorization", kid="exe-a", payload=payload, signature_b64=sig,
                      signed_at_utc=m["a_active_at"].isoformat())
    assert a.signature_valid
    assert a.verdict == "uncertain"
    assert "legacy_unsigned_history" in a.reasons
    assert not a.accepted()
    assert a.accepted(accept_uncertain=True)


def test_operations_continue_after_migration_under_the_imported_operator(migration):
    m = migration
    _migrate(m)
    reader = K.KeyRegistry(m["v2"], trust=m["trust"], anchor=m["anchor"])
    c_seed, c_pub = K.new_signing_seed()
    reader.register(K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="register", actor="ops-admin", expected_version=reader.version, kid="exe-c",
        purpose="execution_authorization", public_key_b64=c_pub, owner="authz"), m["admin_seed"]))
    reader.rotate(K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="rotate", actor="ops-admin", expected_version=reader.version, kid="exe-b", successor_kid="exe-c"),
        m["admin_seed"]))
    assert K.KeyRegistry(m["v2"], trust=m["trust"], anchor=m["anchor"]).active_for("execution_authorization").kid == "exe-c"


def test_migration_refuses_a_root_that_is_not_current(migration):
    m = migration
    with pytest.raises(K.KeyRegistryError) as exc:
        _migrate(m, root_kid="root-unknown")
    assert exc.value.code == "root_not_authorized"
    assert not m["v2"].exists()


def test_migration_refuses_an_existing_target(migration):
    m = migration
    m["v2"].write_text("")
    m["v2"].with_name(m["v2"].name + ".events.jsonl").write_text("")
    with pytest.raises(K.KeyRegistryError) as exc:
        _migrate(m)
    assert exc.value.code == "migration_target_exists"


def test_migration_refuses_an_altered_v1_log(migration):
    m = migration
    events_path = m["v1"].with_name(m["v1"].name + ".events.jsonl")
    lines = events_path.read_text().splitlines()
    doc = json.loads(lines[1])
    doc["kid"] = "exe-forged"
    lines[1] = json.dumps(doc, sort_keys=True)
    events_path.write_text("\n".join(lines) + "\n")
    with pytest.raises(K.KeyRegistryError) as exc:
        _migrate(m)
    assert exc.value.code == "event_altered"
    assert not m["v2"].with_name(m["v2"].name + ".events.jsonl").exists()


def test_migration_refuses_an_anchor_that_is_already_initialized(migration):
    m = migration
    m["anchor"].init()
    with pytest.raises(K.KeyRegistryError) as exc:
        _migrate(m)
    assert exc.value.code == "anchor_exists"


def test_a_v1_log_is_not_accepted_as_v2_without_migration(migration):
    m = migration
    m["anchor"].init()
    shutil.copy(m["v1"].with_name(m["v1"].name + ".events.jsonl"), m["v2"].with_name(m["v2"].name + ".events.jsonl"))
    with pytest.raises(K.KeyRegistryError) as exc:
        K.KeyRegistry(m["v2"], trust=m["trust"], anchor=m["anchor"])
    assert exc.value.code == "event_schema"
