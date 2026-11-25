"""Executor lifecycle, crash recovery, reconciliation, migrations, and history. No live Core: the Core is a file-backed
stand-in, and the crashes are real process terminations (``os._exit``) in child processes.

The live counterpart runs against a real Core and PostgreSQL in ``scripts/executor_recovery_live.py``.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path

import pytest
from aigov_py.trusted.lifecycle import InvalidTransition
from aigov_py.trusted.receipts import deliver_pending
from aigov_py.trusted.reconcile import (
    RECON_DOMAIN,
    ReconcilerRegistry,
    ReconciliationRefused,
    apply_escalation,
    apply_reconciliation,
    escalation_payload,
    make_payload,
    sign_evidence,
)
from aigov_py.trusted.store import (
    ExecutionStore,
    ExecutionStoreError,
    SchemaMissing,
    SchemaVersionMismatch,
)
from aigov_py.trusted.store_admin import migrate
from aigov_py.trusted.visibility import report
from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _lifecycle_harness as h


def exit_at(point: str):  # type: ignore[no-untyped-def]
    """An in-process fault hook: leaves the step at ``point`` by raising SystemExit, as a crash would skip cleanup."""

    def hook(name: str) -> None:
        if name == point:
            raise SystemExit(f"crash at {point}")

    return hook


def _fresh(tmp: Path) -> tuple[Path, Path, Path, str, str]:
    """A migrated store, a Core file, an effects file, and a key pair for the Core's authorizations."""
    db = tmp / "executor.sqlite"
    migrate(db, backup_dir=None)
    seed, pub = h.new_authorization_key()
    return db, tmp / "core.json", tmp / "effects.log", seed, pub


def _job(
    step: str,
    db: Path,
    core: Path,
    effects: Path,
    pub: str,
    signed: dict | None = None,
    **extra,
) -> dict:
    return {
        "step": step,
        "db": str(db),
        "core": str(core),
        "effects": str(effects),
        "public_key": pub,
        "run_id": h.RUN,
        "arguments": h.ARGS,
        "signed": signed,
        **extra,
    }


# --- schema: ownership, detection, upgrade ------------------------------------------------------------------------


def test_a_missing_store_is_refused_and_not_created():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "nope.sqlite"
        with pytest.raises(SchemaMissing, match="migrate"):
            ExecutionStore(path)
        assert not path.exists(), "opening a missing store must not create it"


def test_migrate_creates_the_current_schema_and_is_idempotent():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "x.sqlite"
        first = migrate(db, backup_dir=None)
        assert first["from_version"] == 0 and first["to_version"] == 2
        assert first["applied"] == [
            "0001_executor_store.sql",
            "0002_executor_lifecycle.sql",
        ]
        second = migrate(db, backup_dir=None)
        assert second["applied"] == [] and second["to_version"] == 2
        assert ExecutionStore(db).verify_history()[0]


def _legacy_v1(path: Path) -> None:
    """A store written by the SDK as it shipped in #511: schema 0001, no version stamp, rows in every v1 state."""
    sql = (
        files("aigov_py.trusted") / "migrations" / "0001_executor_store.sql"
    ).read_text(encoding="utf-8")
    conn = sqlite3.connect(path)
    conn.executescript(sql)

    def signed(audience: str, policy: str) -> str:
        return json.dumps(
            {
                "payload": {"executor_audience": audience, "policy_revision": policy},
                "signature": "x",
            }
        )

    rows = [
        # reserved and never finished: its side effect may have run
        (
            "auth_v1_reserved",
            "run-v1",
            "create_file",
            "d1",
            "reserved",
            "2026-11-20T10:00:00+00:00",
            None,
            None,
            None,
            None,
            signed("executor:ref", "rev-a"),
        ),
        # executed with a receipt: a success that was recorded
        (
            "auth_v1_ok",
            "run-v1",
            "create_file",
            "d2",
            "executed",
            "2026-11-20T10:01:00+00:00",
            "2026-11-20T10:01:02+00:00",
            "success",
            "r2",
            "receipt_v1_ok",
            signed("executor:ref", "rev-a"),
        ),
        # executed without a receipt: a success whose receipt never reached Core
        (
            "auth_v1_norcpt",
            "run-v1",
            "create_file",
            "d3",
            "executed",
            "2026-11-20T10:02:00+00:00",
            "2026-11-20T10:02:01+00:00",
            "success",
            "r3",
            None,
            signed("executor:ref", "rev-a"),
        ),
        # failed before doing anything
        (
            "auth_v1_failed",
            "run-v1",
            "create_file",
            "d4",
            "failed",
            "2026-11-20T10:03:00+00:00",
            "2026-11-20T10:03:00+00:00",
            "blocked:policy",
            None,
            None,
            signed("executor:ref", "rev-b"),
        ),
    ]
    conn.executemany(
        "INSERT INTO executions (authorization_id, run_id, tool_name, args_digest, state, reserved_at_utc, "
        "finished_at_utc, outcome, result_digest, receipt_event_id, signed_authorization_json) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    conn.close()


def test_a_v1_store_is_refused_until_it_is_upgraded():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "legacy.sqlite"
        _legacy_v1(db)
        with pytest.raises(SchemaVersionMismatch, match="Upgrade in place"):
            ExecutionStore(db)


def test_upgrade_preserves_every_v1_record_relabels_it_and_keeps_a_backup():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "legacy.sqlite"
        backups = Path(tmp) / "backups"
        _legacy_v1(db)
        before = (
            sqlite3.connect(db)
            .execute(
                "SELECT authorization_id, args_digest, reserved_at_utc, outcome, result_digest, receipt_event_id "
                "FROM executions ORDER BY authorization_id"
            )
            .fetchall()
        )

        result = migrate(db, backup_dir=backups)
        assert result["from_version"] == 0 and result["applied"] == [
            "0002_executor_lifecycle.sql"
        ]
        assert result["backup"] and Path(result["backup"]).exists(), (
            "a backup is taken before any change"
        )

        after = (
            sqlite3.connect(db)
            .execute(
                "SELECT authorization_id, args_digest, reserved_at_utc, outcome, result_digest, receipt_event_id "
                "FROM executions ORDER BY authorization_id"
            )
            .fetchall()
        )
        assert after == before, "no v1 field is rewritten or lost"

        store = ExecutionStore(db)
        states = {
            r["authorization_id"]: (r["state"], r["receipt_state"])
            for r in store.all_rows()
        }
        assert states == {
            "auth_v1_reserved": ("reconciliation_required", "none"),
            "auth_v1_ok": ("succeeded", "recorded"),
            "auth_v1_norcpt": ("succeeded", "none"),
            "auth_v1_failed": ("failed", "none"),
        }
        bindings = {
            r["authorization_id"]: (r["executor_identity"], r["policy_revision"])
            for r in store.all_rows()
        }
        assert bindings["auth_v1_ok"] == ("executor:ref", "rev-a")
        assert bindings["auth_v1_failed"] == ("executor:ref", "rev-b")

        history = store.events("auth_v1_ok")
        assert [e["event"] for e in history] == ["migrated_from_v1"]
        assert history[0]["actor"] == "migration-0002"
        assert store.verify_history()[0], (
            "migrated entries are unhashed and do not break the chain"
        )

        missing = {r["authorization_id"] for r in store.missing_receipts()}
        assert missing == {"auth_v1_norcpt", "auth_v1_failed"}, (
            "legacy rows without receipts are reported, not hidden"
        )


def test_a_newer_schema_is_refused():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "future.sqlite"
        migrate(db, backup_dir=None)
        conn = sqlite3.connect(db)
        conn.execute("PRAGMA user_version = 3")
        conn.commit()
        conn.close()
        with pytest.raises(SchemaVersionMismatch, match="newer SDK"):
            ExecutionStore(db)


def test_a_failed_upgrade_leaves_the_file_unchanged():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "legacy.sqlite"
        _legacy_v1(db)
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE execution_events (broken INTEGER)"
        )  # collides with the v2 table
        conn.commit()
        conn.close()
        before = (
            sqlite3.connect(db).execute("SELECT COUNT(*) FROM executions").fetchone()[0]
        )
        with pytest.raises(sqlite3.Error):
            migrate(db, backup_dir=Path(tmp) / "b")
        conn = sqlite3.connect(db)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM executions").fetchone()[0] == before
        conn.close()


# --- history: append-only and tamper-evident ----------------------------------------------------------------------


def _one_execution(tmp: Path):  # type: ignore[no-untyped-def]
    db, core_path, effects, seed, pub = _fresh(tmp)
    core = h.FileCore(core_path)
    signed = h.signed_authorization(seed)
    perform = h.SideEffects(effects).performer()
    ex = h.make_executor(db=db, core=core, public_key=pub, performer=perform)
    out = ex.execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=signed)
    return db, core, out, signed, ex


def test_a_normal_execution_leaves_an_ordered_hashed_history():
    with tempfile.TemporaryDirectory() as tmp:
        db, core, out, _signed, _ = _one_execution(Path(tmp))
        assert (
            out.executed and out.receipt_recorded and out.execution_state == "succeeded"
        )
        store = ExecutionStore(db)
        events = [e["event"] for e in store.events(out.authorization_id)]
        assert events == ["reserved", "started", "finished", "receipt_recorded"]
        ok, _detail = store.verify_history()
        assert ok
        assert len(core.receipts_for(out.authorization_id)) == 1


def test_history_cannot_be_updated_or_deleted():
    with tempfile.TemporaryDirectory() as tmp:
        db, _, _out, _, _ = _one_execution(Path(tmp))
        conn = sqlite3.connect(db, isolation_level=None)
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("UPDATE execution_events SET actor = 'someone-else'")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM execution_events")
        conn.close()


def test_altering_history_outside_the_store_is_detected():
    with tempfile.TemporaryDirectory() as tmp:
        db, _, _out, _, _ = _one_execution(Path(tmp))
        conn = sqlite3.connect(db, isolation_level=None)
        conn.execute(
            "DROP TRIGGER execution_events_no_update"
        )  # an administrator bypassing the guard
        conn.execute(
            "UPDATE execution_events SET detail_json = '{\"outcome\":\"forged\"}' WHERE event = 'finished'"
        )
        conn.close()
        ok, detail = ExecutionStore(db).verify_history()
        assert not ok and "does not match its hash" in detail


def test_an_illegal_transition_is_refused_inside_the_store():
    with tempfile.TemporaryDirectory() as tmp:
        db, _, _, _, _ = _one_execution(Path(tmp))
        store = ExecutionStore(db)
        store.reserve(
            authorization_id="auth_t",
            run_id="r",
            tool="create_file",
            digest="d",
            signed_json="{}",
            now=datetime.now(UTC).isoformat(),
        )
        with pytest.raises(InvalidTransition):
            store.mark_outcome_unknown(
                authorization_id="auth_t",
                now=datetime.now(UTC).isoformat(),
                actor="x",
                reason="never started",
            )
        assert store.row("auth_t")["state"] == "reserved", (
            "a refused transition writes nothing"
        )


# --- in-process behaviour -----------------------------------------------------------------------------------------


def test_a_second_worker_cannot_start_or_reserve_the_same_execution():
    with tempfile.TemporaryDirectory() as tmp:
        db, core_path, effects, seed, pub = _fresh(Path(tmp))
        core = h.FileCore(core_path)
        signed = h.signed_authorization(seed)
        first = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(),
            worker_id="worker-a",
        )
        second = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(),
            worker_id="worker-b",
        )
        assert first.execute(
            run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=signed
        ).executed
        again = second.execute(
            run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=signed
        )
        # Core already records a receipt for this authorization, so its status check refuses the second use before
        # the local reservation is even attempted. Both refusals are correct; the status check is the earlier one.
        assert (
            not again.executed and again.reason == "authorization_receipt_recorded"
        ), again.reason
        assert h.SideEffects(effects).count() == 1


def test_an_ambiguous_outcome_is_never_retried():
    with tempfile.TemporaryDirectory() as tmp:
        db, core_path, effects, seed, pub = _fresh(Path(tmp))
        core = h.FileCore(core_path)
        signed = h.signed_authorization(seed)
        ex = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(raise_inside=True),
        )
        out = ex.execute(
            run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=signed
        )
        assert (
            out.reason == "outcome_unknown"
            and out.execution_state == "reconciliation_required"
        )
        assert h.SideEffects(effects).count() == 1
        actions = ex.recover()
        assert [a.action for a in actions] == ["awaiting_reconciliation"]
        assert h.SideEffects(effects).count() == 1, (
            "recovery must not repeat an unknown outcome"
        )
        assert (
            ExecutionStore(db).row(out.authorization_id)["state"]
            == "reconciliation_required"
        )


def test_a_revoked_reservation_is_closed_without_any_action():
    with tempfile.TemporaryDirectory() as tmp:
        db, core_path, effects, seed, pub = _fresh(Path(tmp))
        core = h.FileCore(core_path)
        signed = h.signed_authorization(seed)
        clock = {"t": time.time()}
        ex = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(),
            clock=lambda: clock["t"],
        )
        h_crashed = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(),
            fault=exit_at("after_reserve"),
        )
        with pytest.raises(SystemExit):
            h_crashed.execute(
                run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=signed
            )
        core.revoke(signed["payload"]["authorization_id"])
        actions = ex.recover()
        assert [a.action for a in actions] == ["closed_without_action"]
        assert h.SideEffects(effects).count() == 0
        row = ExecutionStore(db).row(signed["payload"]["authorization_id"])
        assert row["state"] == "failed" and row["outcome"].startswith("not_executed:")
        assert (
            ExecutionStore(db).row(signed["payload"]["authorization_id"])[
                "receipt_state"
            ]
            == "recorded"
        )


def test_stored_arguments_that_do_not_match_the_digest_are_never_performed():
    with tempfile.TemporaryDirectory() as tmp:
        db, core_path, effects, seed, pub = _fresh(Path(tmp))
        core = h.FileCore(core_path)
        signed = h.signed_authorization(seed)
        ex = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(),
            fault=exit_at("after_reserve"),
        )
        with pytest.raises(SystemExit):
            ex.execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=signed)
        conn = sqlite3.connect(db)
        conn.execute(
            "UPDATE executions SET arguments_json = ? ",
            ('{"repo_id":"acme/app","path":"x","content":"evil"}',),
        )
        conn.commit()
        conn.close()
        clean = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(),
        )
        actions = clean.recover()
        assert (
            actions[0].action == "closed_without_action"
            and actions[0].detail == "stored_arguments_unavailable"
        )
        assert h.SideEffects(effects).count() == 0


def test_core_unavailable_during_recovery_performs_nothing():
    with tempfile.TemporaryDirectory() as tmp:
        db, core_path, effects, seed, pub = _fresh(Path(tmp))
        core = h.FileCore(core_path)
        signed = h.signed_authorization(seed)
        crashed = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(),
            fault=exit_at("after_reserve"),
        )
        with pytest.raises(SystemExit):
            crashed.execute(
                run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=signed
            )
        core.set_down(True)
        ex = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(),
        )
        actions = ex.recover()
        assert [a.action for a in actions] == ["deferred"]
        assert h.SideEffects(effects).count() == 0, (
            "authorization cannot be checked, so nothing may run"
        )
        core.set_down(False)
        assert [a.action for a in ex.recover()] == ["resumed_once"]
        assert h.SideEffects(effects).count() == 1


def test_a_live_worker_is_not_mistaken_for_a_dead_one():
    with tempfile.TemporaryDirectory() as tmp:
        db, core_path, effects, seed, pub = _fresh(Path(tmp))
        core = h.FileCore(core_path)
        signed = h.signed_authorization(seed)
        crashed = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(),
            lease_seconds=300,
            fault=exit_at("before_side_effect"),
        )
        with pytest.raises(SystemExit):
            crashed.execute(
                run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=signed
            )
        other = h.make_executor(
            db=db,
            core=core,
            public_key=pub,
            performer=h.SideEffects(effects).performer(),
        )
        actions = other.recover()
        assert [a.action for a in actions] == ["skipped"], (
            "the lease has not expired, so recovery must wait"
        )
        assert (
            ExecutionStore(db).row(signed["payload"]["authorization_id"])["state"]
            == "started"
        )


# --- crash recovery at every boundary: real process termination ---------------------------------------------------


def _crash_then_recover(
    tmp: Path,
    crash_at: str,
    *,
    lease: int = 1,
    performer_crash: bool = False,
    raise_inside: bool = False,
):  # type: ignore[no-untyped-def]
    db, core_path, effects, seed, pub = _fresh(tmp)
    core = h.FileCore(core_path)
    signed = h.signed_authorization(seed)
    auth = signed["payload"]["authorization_id"]
    crash_job = _job(
        "execute",
        db,
        core_path,
        effects,
        pub,
        signed,
        crash_at=crash_at,
        lease=lease,
        crash_inside=performer_crash,
        raise_inside=raise_inside,
    )
    code, _ = h.run_child(crash_job, tmp)
    return db, core, effects, pub, auth, code


def test_crash_before_reservation_leaves_nothing_and_a_retry_runs_once():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, core_path, effects, seed, pub = _fresh(tmp)
        signed = h.signed_authorization(seed)
        auth = signed["payload"]["authorization_id"]
        crash = _job(
            "execute", db, core_path, effects, pub, signed, crash_at="before_reserve"
        )
        code, _ = h.run_child(crash, tmp)
        assert code == 137 and ExecutionStore(db).row(auth) is None
        assert h.SideEffects(effects).count() == 0
        code2, out = h.run_child(
            _job("execute", db, core_path, effects, pub, signed), tmp
        )
        assert code2 == 0 and json.loads(out)["executed"] is True
        assert h.SideEffects(effects).count() == 1


def test_crash_after_reservation_is_resumed_exactly_once():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, core, effects, pub, auth, code = _crash_then_recover(tmp, "after_reserve")
        assert code == 137
        assert ExecutionStore(db).row(auth)["state"] == "reserved"
        code2, out = h.run_child(
            _job("recover", db, tmp / "core.json", effects, pub), tmp
        )
        assert code2 == 0 and json.loads(out)["actions"][0]["action"] == "resumed_once"
        assert h.SideEffects(effects).count() == 1
        assert ExecutionStore(db).row(auth)["state"] == "succeeded"
        assert len(core.receipts_for(auth)) == 1
        again = h.run_child(_job("recover", db, tmp / "core.json", effects, pub), tmp)
        assert json.loads(again[1])["actions"] == []
        assert h.SideEffects(effects).count() == 1


def test_crash_immediately_before_the_side_effect_is_an_unknown_outcome_not_a_retry():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, _core, effects, pub, auth, code = _crash_then_recover(
            tmp, "before_side_effect", lease=1
        )
        assert code == 137
        assert ExecutionStore(db).row(auth)["state"] == "started"
        time.sleep(2.2)  # the dead worker's lease expires
        code2, out = h.run_child(
            _job("recover", db, tmp / "core.json", effects, pub), tmp
        )
        assert (
            code2 == 0 and json.loads(out)["actions"][0]["action"] == "outcome_unknown"
        )
        row = ExecutionStore(db).row(auth)
        assert row["state"] == "reconciliation_required"
        assert h.SideEffects(effects).count() == 0, (
            "the side effect never began, and recovery still does not run it"
        )


def test_crash_during_the_external_side_effect_is_unknown_and_not_retried():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, _core, effects, pub, auth, code = _crash_then_recover(
            tmp, "none", lease=1, performer_crash=True
        )
        assert code == 137
        assert h.SideEffects(effects).count() == 1, (
            "the side effect began before the process died"
        )
        time.sleep(2.2)
        _code2, out = h.run_child(
            _job("recover", db, tmp / "core.json", effects, pub), tmp
        )
        assert json.loads(out)["actions"][0]["action"] == "outcome_unknown"
        assert ExecutionStore(db).row(auth)["state"] == "reconciliation_required"
        assert h.SideEffects(effects).count() == 1, (
            "an unknown outcome is never repeated"
        )


def test_crash_after_the_side_effect_but_before_the_outcome_is_recorded_is_unknown():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, _core, effects, pub, auth, code = _crash_then_recover(
            tmp, "after_side_effect_before_finish", lease=1
        )
        assert code == 137 and h.SideEffects(effects).count() == 1
        time.sleep(2.2)
        _code2, out = h.run_child(
            _job("recover", db, tmp / "core.json", effects, pub), tmp
        )
        assert json.loads(out)["actions"][0]["action"] == "outcome_unknown"
        assert ExecutionStore(db).row(auth)["state"] == "reconciliation_required"
        assert h.SideEffects(effects).count() == 1


def test_crash_after_the_outcome_but_before_the_receipt_is_sent_resends_only_evidence():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, core, effects, pub, auth, code = _crash_then_recover(
            tmp, "after_finish_before_receipt_submit"
        )
        assert code == 137
        row = ExecutionStore(db).row(auth)
        assert row["state"] == "succeeded" and row["receipt_state"] == "pending"
        assert core.receipts_for(auth) == []
        code2, out = h.run_child(
            _job("recover", db, tmp / "core.json", effects, pub), tmp
        )
        assert (
            code2 == 0 and json.loads(out)["actions"][0]["action"] == "receipt_recorded"
        )
        assert h.SideEffects(effects).count() == 1, (
            "the receipt is resent; the action is not repeated"
        )
        assert len(core.receipts_for(auth)) == 1


def test_crash_after_core_stored_the_receipt_is_settled_from_the_export_without_a_duplicate():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, core, effects, pub, auth, code = _crash_then_recover(
            tmp, "after_receipt_submitted_before_ack"
        )
        assert code == 137
        assert ExecutionStore(db).row(auth)["receipt_state"] == "pending"
        assert len(core.receipts_for(auth)) == 1, (
            "Core did store it; the executor just did not learn so"
        )
        _code2, out = h.run_child(
            _job("recover", db, tmp / "core.json", effects, pub), tmp
        )
        assert json.loads(out)["actions"][0]["action"] == "receipt_recorded"
        assert ExecutionStore(db).row(auth)["receipt_state"] == "recorded"
        assert len(core.receipts_for(auth)) == 1, "no duplicate receipt was sent"
        assert h.SideEffects(effects).count() == 1


def test_crash_during_recovery_is_itself_recovered_without_repeating_the_action():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, _core, effects, pub, auth, code = _crash_then_recover(tmp, "after_reserve")
        assert code == 137
        code_r, _ = h.run_child(
            _job(
                "recover",
                db,
                tmp / "core.json",
                effects,
                pub,
                crash_at="recovery_before_resume",
            ),
            tmp,
        )
        assert code_r == 137
        assert ExecutionStore(db).row(auth)["state"] == "reserved"
        _code2, out = h.run_child(
            _job("recover", db, tmp / "core.json", effects, pub), tmp
        )
        assert json.loads(out)["actions"][0]["action"] == "resumed_once"
        assert h.SideEffects(effects).count() == 1


def test_recovery_of_a_pending_receipt_is_idempotent_across_restarts():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, core, effects, pub, auth, _code = _crash_then_recover(
            tmp, "after_finish_before_receipt_submit"
        )
        for _ in range(3):
            h.run_child(_job("recover", db, tmp / "core.json", effects, pub), tmp)
        assert len(core.receipts_for(auth)) == 1
        assert h.SideEffects(effects).count() == 1


def test_many_processes_racing_for_one_authorization_perform_it_once():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, core_path, effects, seed, pub = _fresh(tmp)
        signed = h.signed_authorization(seed)
        procs = []
        for i in range(8):
            job = _job(
                "execute", db, core_path, effects, pub, signed, worker=f"racer-{i}"
            )
            job_path = tmp / f"race-{i}.json"
            job_path.write_text(json.dumps(job))
            code = f"import sys; sys.path.insert(0, {str(Path(h.__file__).resolve().parent)!r}); import _lifecycle_harness as h; sys.exit(h.child_main({str(job_path)!r}))"
            procs.append(
                subprocess.Popen(
                    [sys.executable, "-c", code], stdout=subprocess.PIPE, text=True
                )
            )
        results = [json.loads(p.communicate(timeout=120)[0]) for p in procs]
        executed = [r for r in results if r["executed"]]
        assert len(executed) == 1, results
        assert h.SideEffects(effects).count() == 1, (
            "exactly one process performed the action"
        )
        reasons = sorted(r["reason"] for r in results)
        allowed = {
            "executed",
            "authorization_replayed",
            "authorization_already_started",
            "authorization_receipt_recorded",
        }
        assert set(reasons) <= allowed, reasons


# --- reconciliation -----------------------------------------------------------------------------------------------


def _unknown_execution(tmp: Path):  # type: ignore[no-untyped-def]
    db, core_path, effects, seed, pub = _fresh(tmp)
    core = h.FileCore(core_path)
    signed = h.signed_authorization(seed)
    ex = h.make_executor(
        db=db,
        core=core,
        public_key=pub,
        performer=h.SideEffects(effects).performer(raise_inside=True),
    )
    out = ex.execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=signed)
    return db, core, effects, pub, out.authorization_id


def _registry(identity: str, seed_b64: str) -> ReconcilerRegistry:
    pub = base64.b64encode(
        bytes(SigningKey(base64.b64decode(seed_b64)).verify_key)
    ).decode("ascii")
    return ReconcilerRegistry(keys={identity: pub})


def _operator_key() -> tuple[str, str]:
    sk = SigningKey.generate()
    return "ops@acme.example", base64.b64encode(bytes(sk)).decode("ascii")


def _evidence(
    db: Path,
    auth: str,
    seed_b64: str,
    identity: str,
    outcome: str = "succeeded",
    **overrides,
):  # type: ignore[no-untyped-def]
    row = ExecutionStore(db).row(auth)
    payload = make_payload(
        row,
        outcome=outcome,
        external_reference="order-7781",
        external_evidence=b"bank statement line 42: paid",
        reconciler=identity,
        observed_at_utc=datetime.now(UTC).isoformat(),
    )
    payload.update(overrides)
    return sign_evidence(payload, seed_b64)


def test_valid_signed_evidence_reconciles_and_the_receipt_follows():
    with tempfile.TemporaryDirectory() as tmp:
        db, core, effects, _pub, auth = _unknown_execution(Path(tmp))
        identity, seed = _operator_key()
        registry = _registry(identity, seed)
        signed = _evidence(db, auth, seed, identity, outcome="succeeded")
        evidence = apply_reconciliation(
            ExecutionStore(db),
            signed,
            registry,
            receipt_event_id="execution_receipt-rec1",
        )
        assert evidence["outcome"] == "succeeded"
        row = ExecutionStore(db).row(auth)
        assert row["state"] == "reconciled" and row["receipt_state"] == "pending"
        assert [r["recorded"] for r in deliver_pending(ExecutionStore(db), core)] == [
            True
        ]
        receipt = core.receipts_for(auth)[0]["payload"]
        assert receipt["outcome"] == "reconciled:succeeded"
        history = [e["event"] for e in ExecutionStore(db).events(auth)]
        assert history.index("outcome_unknown") < history.index("reconciled"), (
            "the earlier entries are kept"
        )
        assert h.SideEffects(effects).count() == 1, (
            "reconciliation never performs the action"
        )


def test_forged_evidence_claiming_a_registered_reconciler_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        db, _core, _effects, _pub, auth = _unknown_execution(Path(tmp))
        identity, seed = _operator_key()
        registry = _registry(identity, seed)
        _, attacker_seed = _operator_key()
        forged = _evidence(db, auth, attacker_seed, identity)
        with pytest.raises(ReconciliationRefused) as exc:
            apply_reconciliation(
                ExecutionStore(db),
                forged,
                registry,
                receipt_event_id="execution_receipt-x",
            )
        assert exc.value.reason == "reconciliation_signature_invalid"
        assert ExecutionStore(db).row(auth)["state"] == "reconciliation_required"


def test_altered_evidence_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        db, _core, _effects, _pub, auth = _unknown_execution(Path(tmp))
        identity, seed = _operator_key()
        registry = _registry(identity, seed)
        signed = _evidence(db, auth, seed, identity, outcome="failed")
        signed["payload"]["outcome"] = "succeeded"
        with pytest.raises(ReconciliationRefused) as exc:
            apply_reconciliation(
                ExecutionStore(db),
                signed,
                registry,
                receipt_event_id="execution_receipt-x",
            )
        assert exc.value.reason == "reconciliation_signature_invalid"


def test_an_unlisted_reconciler_is_not_authorized_even_with_a_valid_key():
    with tempfile.TemporaryDirectory() as tmp:
        db, _core, _effects, _pub, auth = _unknown_execution(Path(tmp))
        identity, seed = _operator_key()
        registry = _registry("someone-else@acme.example", seed)
        signed = _evidence(db, auth, seed, identity)
        with pytest.raises(ReconciliationRefused) as exc:
            apply_reconciliation(
                ExecutionStore(db),
                signed,
                registry,
                receipt_event_id="execution_receipt-x",
            )
        assert exc.value.reason == "reconciler_not_authorized"


def test_evidence_bound_to_another_execution_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        db, _core, _effects, _pub, auth = _unknown_execution(Path(tmp))
        identity, seed = _operator_key()
        registry = _registry(identity, seed)
        signed = _evidence(db, auth, seed, identity, tool_name="delete_everything")
        signed = sign_evidence(
            signed["payload"], seed
        )  # signed correctly, but the binding is wrong
        with pytest.raises(ReconciliationRefused) as exc:
            apply_reconciliation(
                ExecutionStore(db),
                signed,
                registry,
                receipt_event_id="execution_receipt-x",
            )
        assert exc.value.reason == "reconciliation_binding_mismatch"


def test_the_same_evidence_cannot_be_applied_twice():
    with tempfile.TemporaryDirectory() as tmp:
        db, _core, _effects, _pub, auth = _unknown_execution(Path(tmp))
        identity, seed = _operator_key()
        registry = _registry(identity, seed)
        signed = _evidence(db, auth, seed, identity)
        apply_reconciliation(
            ExecutionStore(db), signed, registry, receipt_event_id="execution_receipt-a"
        )
        with pytest.raises(ReconciliationRefused) as exc:
            apply_reconciliation(
                ExecutionStore(db),
                signed,
                registry,
                receipt_event_id="execution_receipt-b",
            )
        assert exc.value.reason == "reconciliation_not_required"


def test_a_not_executed_finding_closes_the_authorization_without_repeating_it():
    with tempfile.TemporaryDirectory() as tmp:
        db, core, effects, _pub, auth = _unknown_execution(Path(tmp))
        identity, seed = _operator_key()
        registry = _registry(identity, seed)
        signed = _evidence(db, auth, seed, identity, outcome="not_executed")
        apply_reconciliation(
            ExecutionStore(db), signed, registry, receipt_event_id="execution_receipt-n"
        )
        deliver_pending(ExecutionStore(db), core)
        assert (
            core.receipts_for(auth)[0]["payload"]["outcome"]
            == "reconciled:not_executed"
        )
        assert h.SideEffects(effects).count() == 1, (
            "not_executed does not run the action again"
        )


def test_evidence_observed_before_the_reservation_or_in_the_future_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        db, _core, _effects, _pub, auth = _unknown_execution(Path(tmp))
        identity, seed = _operator_key()
        registry = _registry(identity, seed)
        early = _evidence(
            db, auth, seed, identity, observed_at_utc="2001-01-01T00:00:00+00:00"
        )
        with pytest.raises(ReconciliationRefused) as exc:
            apply_reconciliation(
                ExecutionStore(db),
                early,
                registry,
                receipt_event_id="execution_receipt-e",
            )
        assert exc.value.reason == "reconciliation_timestamp_invalid"
        future = _evidence(
            db,
            auth,
            seed,
            identity,
            observed_at_utc=(datetime.now(UTC) + timedelta(days=1)).isoformat(),
        )
        with pytest.raises(ReconciliationRefused) as exc2:
            apply_reconciliation(
                ExecutionStore(db),
                future,
                registry,
                receipt_event_id="execution_receipt-f",
            )
        assert exc2.value.reason == "reconciliation_timestamp_invalid"


def test_reconciliation_interrupted_before_commit_applies_nothing_and_a_retry_applies_once():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, _core, effects, _pub, auth = _unknown_execution(tmp)
        identity, seed = _operator_key()
        registry = _registry(identity, seed)
        signed = _evidence(db, auth, seed, identity)
        job = {
            "step": "reconcile",
            "db": str(db),
            "envelope": signed,
            "registry": {"reconcilers": registry.keys},
        }
        code, _ = h.run_child({**job, "crash_at": "reconcile_before_commit"}, tmp)
        assert code == 137, "the process died inside the reconciliation transaction"
        assert ExecutionStore(db).row(auth)["state"] == "reconciliation_required"
        assert "reconciled" not in [e["event"] for e in ExecutionStore(db).events(auth)]
        assert ExecutionStore(db).verify_history()[0]
        code2, out = h.run_child(job, tmp)
        assert code2 == 0 and json.loads(out)["reconciled"] == auth
        assert ExecutionStore(db).row(auth)["state"] == "reconciled"
        assert [e["event"] for e in ExecutionStore(db).events(auth)].count(
            "reconciled"
        ) == 1
        assert h.SideEffects(effects).count() == 1


def test_signed_escalation_is_recorded_and_changes_no_state():
    with tempfile.TemporaryDirectory() as tmp:
        db, _core, _effects, _pub, auth = _unknown_execution(Path(tmp))
        identity, seed = _operator_key()
        registry = _registry(identity, seed)
        payload = escalation_payload(
            ExecutionStore(db).row(auth),
            reason="bank says two payments exist",
            reconciler=identity,
            observed_at_utc=datetime.now(UTC).isoformat(),
        )
        apply_escalation(ExecutionStore(db), sign_evidence(payload, seed), registry)
        assert ExecutionStore(db).row(auth)["state"] == "reconciliation_required"
        assert "escalated" in [e["event"] for e in ExecutionStore(db).events(auth)]
        with pytest.raises(ReconciliationRefused):
            apply_escalation(
                ExecutionStore(db), sign_evidence(payload, _operator_key()[1]), registry
            )


def test_the_reconciliation_domain_is_not_the_authorization_domain():
    assert RECON_DOMAIN != b"govai.execution_authorization.v1\x00"


# --- visibility ----------------------------------------------------------------------------------------------------


def test_the_report_counts_every_state_and_measures_latency_from_history():
    with tempfile.TemporaryDirectory() as tmp:
        db, _core, _effects, _pub, auth = _unknown_execution(Path(tmp))
        r = report(ExecutionStore(db))
        assert r["by_state"] == {"reconciliation_required": 1}
        assert r["unknown_outcomes"] == 0 and r["reconciliation_backlog"] == 1
        assert r["history"]["chain_verified"] is True
        assert r["unresolved"][0]["authorization_id"] == auth
        assert r["latency_ms"]["execution"]["count"] == 0, (
            "no execution finished, so none is measured"
        )


def test_a_store_error_for_an_unknown_authorization_is_explicit():
    with tempfile.TemporaryDirectory() as tmp:
        db, *_ = _fresh(Path(tmp))
        with pytest.raises(ExecutionStoreError):
            ExecutionStore(db).finish(
                authorization_id="auth_none",
                outcome="success",
                result_digest_hex=None,
                now=datetime.now(UTC).isoformat(),
                receipt_event_id="r",
            )


# --- the projection check and the operator command line -----------------------------------------------------------


def test_an_edited_execution_row_disagrees_with_its_history():
    with tempfile.TemporaryDirectory() as tmp:
        db, _, out, _, _ = _one_execution(Path(tmp))
        assert ExecutionStore(db).verify_projection()[0]
        conn = sqlite3.connect(db)
        conn.execute(
            "UPDATE executions SET state = 'failed', outcome = 'blocked:forged' WHERE authorization_id = ?",
            (out.authorization_id,),
        )
        conn.commit()
        conn.close()
        ok, detail = ExecutionStore(db).verify_projection()
        assert not ok and out.authorization_id in detail


def _cli(*args: str) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, "-m", "aigov_py.trusted.store_admin", *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=tempfile.gettempdir(),
    )
    body = proc.stdout.strip()
    return proc.returncode, (
        json.loads(body)
        if body.startswith("{")
        else {"raw": body, "stderr": proc.stderr}
    )


def test_the_operator_command_line_reconciles_signed_evidence_and_refuses_forgery():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, core, effects, pub, auth = _unknown_execution(tmp)
        identity, seed = _operator_key()
        seed_file = tmp / "reconciler.json"
        seed_file.write_text(json.dumps({"identity": identity, "seed_b64": seed}))
        registry = tmp / "registry.json"
        registry.write_text(
            json.dumps(
                {"reconcilers": {identity: _registry(identity, seed).keys[identity]}}
            )
        )
        proof = tmp / "proof.txt"
        proof.write_text("bank statement: paid")

        code, signed = _cli(
            "sign-evidence",
            "--db",
            str(db),
            "--seed-file",
            str(seed_file),
            "--authorization-id",
            auth,
            "--outcome",
            "succeeded",
            "--external-reference",
            "order-1",
            "--evidence-file",
            str(proof),
        )
        assert code == 0
        env = tmp / "signed.json"
        env.write_text(json.dumps(signed))
        code, applied = _cli(
            "reconcile",
            "--db",
            str(db),
            "--registry",
            str(registry),
            "--evidence-file",
            str(env),
        )
        assert code == 0 and applied["outcome"] == "succeeded"

        # a second execution, and an envelope signed by a key the registry does not hold
        db2, *_rest = _unknown_execution(tmp / "second")
        auth2 = ExecutionStore(db2).unresolved()[0]["authorization_id"]
        _, attacker = _operator_key()
        forged_file = tmp / "forged-seed.json"
        forged_file.write_text(json.dumps({"identity": identity, "seed_b64": attacker}))
        code_forged, forged_env = _cli(
            "sign-evidence",
            "--db",
            str(db2),
            "--seed-file",
            str(forged_file),
            "--authorization-id",
            auth2,
            "--outcome",
            "succeeded",
            "--external-reference",
            "x",
            "--evidence-file",
            str(proof),
        )
        forged = tmp / "forged.json"
        forged.write_text(json.dumps(forged_env))
        code_refused, refused = _cli(
            "reconcile",
            "--db",
            str(db2),
            "--registry",
            str(registry),
            "--evidence-file",
            str(forged),
        )
        assert (
            code_forged == 0
            and code_refused == 2
            and refused["refused"] == "reconciliation_signature_invalid"
        )
        assert ExecutionStore(db2).row(auth2)["state"] == "reconciliation_required"


def test_the_operator_command_line_reports_status_and_refuses_a_missing_store():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "fresh.sqlite"
        code, _ = _cli("status", "--db", str(db))
        assert code != 0 and not db.exists(), "status must not create a store"
        code, _ = _cli("migrate", "--db", str(db))
        assert code == 0
        code, status = _cli("status", "--db", str(db))
        assert code == 0 and status["current"] is True and status["schema_version"] == 2
        code, rep = _cli("report", "--db", str(db))
        assert code == 0 and rep["history"]["projection_agrees"] is True


def test_the_performer_receives_a_stable_idempotency_key_for_each_authorization():
    from aigov_py.trusted.executor import execution_key

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        db, core_path, effects, seed, pub = _fresh(tmp)
        core = h.FileCore(core_path)
        signed = h.signed_authorization(seed)
        auth = signed["payload"]["authorization_id"]
        seen: list[str] = []

        def recording(tool, arguments, execution_id):  # type: ignore[no-untyped-def]
            seen.append(execution_id)
            return {"success": True, "data": {}, "blocked_reason": None}

        crashed = h.make_executor(db=db, core=core, public_key=pub, performer=recording, fault=exit_at("after_reserve"))
        with pytest.raises(SystemExit):
            crashed.execute(run_id=h.RUN, tool=h.TOOL.name, arguments=h.ARGS, signed=signed)
        h.make_executor(db=db, core=core, public_key=pub, performer=recording).recover()
        assert seen == [execution_key(auth)], "the resumed call carries the same key the first attempt would have"
        assert execution_key(auth).startswith("exe_") and len(execution_key(auth)) == 36
