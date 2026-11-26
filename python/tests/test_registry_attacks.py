"""Registry trust boundary: attacks on the log, the anchor, the trust file, and concurrent writers.

Each test states the attack, runs it against the real registry code (both writers and readers), and asserts the refusal.
The two attacks from the review (unauthorized substitution of a whole log, and rollback that resurrects a revoked key) are
reproduced against the committed implementation in the audit report; these tests are the corrected behaviour.
"""

from __future__ import annotations

import copy
import json
import os
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest
from _registry_world import REGISTRY_ID, World, _commit_worker, settle_anchor, write_secret_file

from aigov_py.trusted import keys as K
from _sqlite_anchor import SqliteAnchor
from aigov_py.trusted.registry_anchor import AnchorState


@pytest.fixture
def world():
    with tempfile.TemporaryDirectory(prefix="registry-attacks-") as d:
        w = World(Path(d))
        w.install_operator("ops-admin")
        w.register_active("exe-a")
        yield w


def _refuse_code(fn) -> str:
    with pytest.raises(K.KeyRegistryError) as exc:
        fn()
    return exc.value.code


def _forge(events: list[dict], request: dict) -> dict:
    """A correctly hashed event for ``request`` after ``events``. The hash chain is valid; the signature is the only check."""
    prev = events[-1]["hash"] if events else None
    body = {"schema": K.EVENT_SCHEMA, "seq": len(events) + 1, "prev_hash": prev, "request": request}
    return {**body, "hash": K._event_hash(body)}


# --- unauthorized insertion and substitution ---------------------------------------------------------------------------


def test_a_writer_of_the_log_without_an_operator_key_cannot_insert_a_key(world):
    attacker_seed, attacker_pub = K.new_signing_seed()
    forged = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="register", actor="ops-admin", expected_version=len(world.events()), kid="exe-evil",
        purpose="execution_authorization", public_key_b64=attacker_pub, owner="attacker"), attacker_seed)
    events = world.events() + [_forge(world.events(), forged)]
    world.write_events(events)
    # Replay verifies the signature before the anchor is compared, so the forged request is refused for what it is.
    assert _refuse_code(world.reader) == "request_signature_invalid"
    # Even with the anchor moved to match the forged log, replay still refuses the signature.
    settle_anchor(world)
    assert _refuse_code(world.reader) == "request_signature_invalid"


def test_an_operator_cannot_sign_a_root_operation(world):
    op_seed = world.operators["ops-admin"]
    req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="operator_install", actor="root-a", expected_version=len(world.events()),
        identity="ops-evil", public_key_b64=K.new_signing_seed()[1], roles=["keyadmin"]), op_seed)
    assert _refuse_code(lambda: world.reg.apply(req)) == "request_signature_invalid"
    settle_anchor(world)
    forged = _forge(world.events(), req)
    world.write_events(world.events() + [forged])
    settle_anchor(world)
    assert _refuse_code(world.reader) == "request_signature_invalid"


def test_a_role_without_the_needed_authority_cannot_act(world):
    world.install_operator("auditor", roles=("reconciler",))
    req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="revoke", actor="auditor", expected_version=world.reg.version, kid="exe-a",
        reason="not allowed", compromised_from_utc="2026-11-26T00:00:00+00:00"), world.operators["auditor"])
    assert _refuse_code(lambda: world.reg.apply(req)) == "operator_not_authorized"


def test_a_whole_log_substituted_by_another_registry_is_refused_by_the_anchor(world):
    other = World(world.root / "other")
    other.install_operator("ops-admin")
    other.register_active("exe-evil")
    world.registry_path.with_name(world.registry_path.name + ".events.jsonl").write_text(
        other.registry_path.with_name(other.registry_path.name + ".events.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
    # The other registry is signed by its own root, which is not in this trust file.
    # The other registry's root has the same kid but another key, so its signature fails against the pinned key.
    assert _refuse_code(world.reader) in ("request_signature_invalid", "root_not_authorized", "anchor_head_mismatch")


def test_a_substituted_log_under_the_same_root_is_refused_by_the_anchor_head(world):
    # Same root, different history: an equal-length log with a different head.
    alt = World(world.root / "alt", registry_id=world.registry_id)
    alt.root_seed, alt.root_pub = world.root_seed, world.root_pub
    alt.trust_doc, alt.trust = world.trust_doc, world.trust
    alt.reg = K.KeyRegistry(alt.registry_path, trust=world.trust, anchor=alt.anchor)
    alt.install_operator("ops-admin")
    alt.register_active("exe-evil")
    world.write_events(alt.events())
    assert _refuse_code(world.reader) == "anchor_head_mismatch"


def test_a_trust_file_that_others_can_read_is_refused(world):
    os.chmod(world.trust_path, 0o644)
    with pytest.raises(K.KeyRegistryError) as exc:
        K.TrustConfig.load(world.trust_path)
    assert exc.value.code == "trust_config_permissions"


def test_a_trust_file_that_pins_no_current_root_is_refused(world):
    doc = copy.deepcopy(world.trust_doc)
    doc["roots"][0]["status"] = "retired"
    doc["roots"][0]["retired_after_seq"] = 3
    write_secret_file(world.trust_path, json.dumps(doc))
    with pytest.raises(K.KeyRegistryError) as exc:
        K.TrustConfig.load(world.trust_path)
    assert exc.value.code == "trust_config_invalid"


# --- rollback and resurrection -----------------------------------------------------------------------------------------


def test_a_rollback_to_before_a_revocation_is_refused_and_the_key_stays_revoked(world):
    before = world.events()
    world.revoke("exe-a")
    assert world.reader().get("exe-a").status == "revoked"
    # The writer restores the earlier log, so the revocation is gone from the file.
    world.write_events(before)
    assert _refuse_code(world.reader) == "anchor_log_behind"


def test_an_anchor_moved_back_is_detected_as_a_log_ahead_of_it(world):
    # Moving the anchor back is a change to the anchor store, which is the residual threat in the runbook. This layer can
    # still detect it: the log is then one event ahead of the anchor, and readers refuse until the anchor is reconciled.
    world.revoke("exe-a")
    events = world.events()
    old = AnchorState(len(events) - 1, events[-2]["hash"])
    with world.anchor.exclusive() as tx:
        cur = tx.current()
        tx.set(old, expected=cur)
    assert _refuse_code(world.reader) == "anchor_log_ahead"


# --- deletion, modification, reordering, replay -------------------------------------------------------------------------


def test_a_deleted_event_breaks_the_chain_even_if_the_anchor_is_moved_to_match(world):
    world.revoke("exe-a")
    events = world.events()
    del events[1]
    world.write_events(events)
    settle_anchor(world)
    assert _refuse_code(world.reader) in ("event_sequence_broken", "event_chain_broken")


def test_a_modified_request_fails_its_signature_even_with_a_recomputed_hash(world):
    events = world.events()
    tampered = copy.deepcopy(events)
    tampered[1]["request"]["payload"]["kid"] = "exe-b"  # the event now claims a different key
    body = {k: v for k, v in tampered[1].items() if k != "hash"}
    tampered[1]["hash"] = K._event_hash(body)
    # Rechain the rest so only the signature is wrong.
    for i in range(2, len(tampered)):
        tampered[i]["prev_hash"] = tampered[i - 1]["hash"]
        b = {k: v for k, v in tampered[i].items() if k != "hash"}
        tampered[i]["hash"] = K._event_hash(b)
    world.write_events(tampered)
    settle_anchor(world)
    assert _refuse_code(world.reader) == "request_signature_invalid"


def test_reordered_events_break_the_sequence(world):
    world.register_pending("exe-b")
    events = world.events()
    events[1], events[2] = events[2], events[1]
    world.write_events(events)
    settle_anchor(world)
    assert _refuse_code(world.reader) in ("event_sequence_broken", "event_chain_broken", "expected_version_mismatch")


def test_a_valid_request_replayed_as_a_new_event_is_refused(world):
    events = world.events()
    replay = _forge(events, events[1]["request"])  # the same signed request, appended again
    world.write_events(events + [replay])
    settle_anchor(world)
    assert _refuse_code(world.reader) in ("replayed_nonce", "expected_version_mismatch")


def test_an_old_request_is_refused_after_rotation_moves_the_version(world):
    world.reg.refresh()
    old_req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="revoke", actor="ops-admin", expected_version=world.reg.version, kid="exe-a",
        reason="stale", compromised_from_utc="2026-11-26T00:00:00+00:00"), world.operators["ops-admin"])
    world.register_pending("exe-b")
    assert _refuse_code(lambda: world.reg.apply(old_req)) == "version_conflict"


# --- operator and root rotation -------------------------------------------------------------------------------------------


def test_revoking_an_operator_stops_its_later_requests_and_keeps_its_earlier_history(world):
    earlier = world.reader().version
    world.root_op("operator_revoke", identity="ops-admin", reason="operator left")
    stale = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="revoke", actor="ops-admin", expected_version=world.reg.version, kid="exe-a",
        reason="late", compromised_from_utc="2026-11-26T00:00:00+00:00"), world.operators["ops-admin"])
    assert _refuse_code(lambda: world.reg.apply(stale)) == "operator_not_authorized"
    world.install_operator("ops-admin-2")
    world.op("ops-admin-2", "revoke", kid="exe-a", reason="rotated operator", compromised_from_utc="2026-11-26T00:00:00+00:00")
    reader = world.reader()
    assert reader.get("exe-a").status == "revoked"
    assert reader.version > earlier


def test_root_rotation_keeps_history_verifiable_and_stops_the_old_root_after_its_bound(world):
    # Rotation: root-a is retired after the current sequence, root-b becomes current, and the trust file says so.
    bound = world.reg.version
    root_b_seed, root_b_pub = K.new_signing_seed()
    doc = copy.deepcopy(world.trust_doc)
    doc["roots"][0] = {"kid": "root-a", "public_key_b64": world.root_pub, "status": "retired", "retired_after_seq": bound}
    doc["roots"].append({"kid": "root-b", "public_key_b64": root_b_pub, "status": "current"})
    write_secret_file(world.trust_path, json.dumps(doc))
    world.trust = K.TrustConfig.load(world.trust_path)
    # Historical events signed by root-a still verify under the new trust file.
    reader = world.reader()
    assert reader.version == bound
    # root-a cannot sign past its bound.
    late = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="operator_install", actor="root-a", expected_version=bound, identity="ops-late",
        public_key_b64=K.new_signing_seed()[1], roles=["keyadmin"]), world.root_seed)
    world.reg = K.KeyRegistry(world.registry_path, trust=world.trust, anchor=world.anchor)
    assert _refuse_code(lambda: world.reg.apply(late)) == "root_not_authorized"
    # root-b can.
    req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="operator_install", actor="root-b", expected_version=bound, identity="ops-new",
        public_key_b64=K.new_signing_seed()[1], roles=["keyadmin"]), root_b_seed)
    world.reg.apply(req)
    assert "ops-new" in world.reader().state.operators


def test_a_retired_root_with_a_bound_is_refused_once_its_bound_is_passed_in_the_log(world):
    doc = copy.deepcopy(world.trust_doc)
    doc["roots"][0] = {"kid": "root-a", "public_key_b64": world.root_pub, "status": "retired", "retired_after_seq": 0}
    doc["roots"].append({"kid": "root-b", "public_key_b64": K.new_signing_seed()[1], "status": "current"})
    write_secret_file(world.trust_path, json.dumps(doc))
    world.trust = K.TrustConfig.load(world.trust_path)
    # The first operator was installed at sequence 1 by root-a, after its bound of 0: the log no longer verifies.
    assert _refuse_code(world.reader) == "root_not_authorized"


# --- concurrency -------------------------------------------------------------------------------------------------------


def test_concurrent_revocations_apply_exactly_once(world):
    seed = world.operators["ops-admin"]
    args = [(str(world.root), "ops-admin", seed, "exe-a", "", REGISTRY_ID)] * 6
    with ProcessPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(_commit_worker, args))
    assert outcomes.count("applied") == 1, outcomes
    assert all(o in ("applied", "version_conflict", "illegal_transition") for o in outcomes), outcomes
    reader = world.reader()
    assert reader.get("exe-a").status == "revoked"
    assert len(world.events()) == reader.version


def test_concurrent_rotation_and_revocation_leave_one_consistent_outcome(world):
    world.register_pending("exe-c")
    seed = world.operators["ops-admin"]
    # Both attempts were made against the same version: one applies, the other is a conflict, never both.
    world.reg.refresh()
    v = world.reg.version
    rot = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="rotate", actor="ops-admin", expected_version=v, kid="exe-a", successor_kid="exe-c"), seed)
    rev = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="revoke", actor="ops-admin", expected_version=v, kid="exe-a", reason="race",
        compromised_from_utc="2026-11-26T00:00:00+00:00"), seed)
    world.reg.apply(rot)
    assert _refuse_code(lambda: world.reg.apply(rev)) == "version_conflict"
    assert world.reader().active_for("execution_authorization").kid == "exe-c"


# --- crash consistency between the log and the anchor ------------------------------------------------------------------


def test_a_crash_between_the_append_and_the_anchor_commit_is_refused_until_reconciled(world):
    class Crash(RuntimeError):
        pass

    def boom():
        raise Crash("power loss")

    world.reg.refresh()
    req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="revoke", actor="ops-admin", expected_version=world.reg.version, kid="exe-a", reason="crash",
        compromised_from_utc="2026-11-26T00:00:00+00:00"), world.operators["ops-admin"])
    with pytest.raises(Crash):
        world.reg._submit(req, hook=boom)
    # The append happened, the anchor did not move: readers refuse.
    assert len(world.events()) == world.anchor.current().seq + 1
    assert _refuse_code(world.reader) == "anchor_log_ahead"
    # Writers refuse too, rather than appending on top of an unreconciled log.
    assert _refuse_code(lambda: world.reg.apply(req)) == "anchor_log_ahead"
    # Reconciliation anchors the one extra event, after it verifies.
    world.reg.reconcile()
    assert world.reader().get("exe-a").status == "revoked"


def test_reconcile_refuses_when_there_is_nothing_to_reconcile_or_the_log_is_two_ahead(world):
    assert _refuse_code(world.reg.reconcile) == "nothing_to_reconcile"
    world.revoke("exe-a")
    settle_anchor(world)
    events = world.events()
    world.write_events(events + [copy.deepcopy(events[-1]), copy.deepcopy(events[-1])])
    # Two events beyond the anchor are not a crash; they need an investigation, so reconcile does not guess.
    assert _refuse_code(world.reg.reconcile) == "nothing_to_reconcile"


def test_an_anchor_with_no_row_refuses_every_read(world):
    missing = SqliteAnchor(world.root / "no-row.sqlite", world.registry_id)  # a new file: the anchor was never initialized
    assert missing.current() is None
    assert _refuse_code(lambda: K.KeyRegistry(world.registry_path, trust=world.trust, anchor=missing)) == "anchor_missing"
