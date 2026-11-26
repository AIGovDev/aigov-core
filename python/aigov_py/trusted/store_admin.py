"""The operator tool for the executor store: schema migrations, inspection, reconciliation, and receipt resubmission.

    python -m aigov_py.trusted.store_admin migrate --db executor.sqlite --backup-dir backups/
    python -m aigov_py.trusted.store_admin status --db executor.sqlite
    python -m aigov_py.trusted.store_admin report --db executor.sqlite
    python -m aigov_py.trusted.store_admin pending --db executor.sqlite
    python -m aigov_py.trusted.store_admin inspect --db executor.sqlite --authorization-id auth_...
    python -m aigov_py.trusted.store_admin sign-evidence --db ... --seed-file reconciler.json --authorization-id auth_...
        --outcome succeeded --external-reference "order 123" --evidence-file proof.pdf
    python -m aigov_py.trusted.store_admin reconcile --db ... --registry registry.json --evidence-file signed.json
    python -m aigov_py.trusted.store_admin sign-escalation --db ... --seed-file reconciler.json --authorization-id auth_... --reason "..."
    python -m aigov_py.trusted.store_admin escalate --db ... --registry registry.json --evidence-file signed.json
    python -m aigov_py.trusted.store_admin resubmit-receipts --db ... --core-url http://... --executor-key-env GOVAI_EXECUTOR_KEY

What this tool does not do: it never runs a side effect, never sets an outcome without signed evidence, and never
changes an execution except through the store's transitions. There is no force-execute or force-success command.

Exit codes: 0 success; 1 error; 2 refused (evidence rejected, or a transition not permitted).
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import uuid
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from .reconcile import (
    ReconcilerRegistry,
    ReconciliationRefused,
    apply_escalation,
    apply_reconciliation,
    escalation_payload,
    make_payload,
    sign_evidence,
)
from .store import SCHEMA_VERSION, ExecutionStore, ExecutionStoreError
from .visibility import report as build_report

MIGRATIONS: tuple[tuple[int, str], ...] = (
    (1, "0001_executor_store.sql"),
    (2, "0002_executor_lifecycle.sql"),
)


def _migration_text(name: str) -> str:
    return (files("aigov_py.trusted") / "migrations" / name).read_text(encoding="utf-8")


def _inspect_file(path: Path) -> tuple[int, bool]:
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        version = c.execute("PRAGMA user_version").fetchone()[0]
        has_table = (
            c.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='executions'"
            ).fetchone()
            is not None
        )
    finally:
        c.close()
    return version, has_table


def migrate(db: Path, *, backup_dir: Path | None) -> dict[str, Any]:
    """Bring the file to ``SCHEMA_VERSION``. Takes a backup first whenever the file already has schema.

    A fresh path is created. A file at version 0 that already has the executions table is a legacy v1 store: only the
    version-2 migration is applied. The version-2 file is one transaction, so a failure leaves the file unchanged.
    """
    exists = db.exists()
    version, has_table = _inspect_file(db) if exists else (0, False)
    if version > SCHEMA_VERSION:
        raise ExecutionStoreError(
            f"file is schema version {version}; this tool knows up to {SCHEMA_VERSION}"
        )
    if version == SCHEMA_VERSION:
        return {
            "from_version": version,
            "applied": [],
            "to_version": version,
            "backup": None,
        }

    backup_path: str | None = None
    if exists and (version > 0 or has_table):
        if backup_dir is None:
            raise ExecutionStoreError(
                "upgrading an existing store needs --backup-dir; a backup is taken first"
            )
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        dest = backup_dir / f"{db.stem}-v{version}-{stamp}.sqlite"
        src_c = sqlite3.connect(db)
        dst_c = sqlite3.connect(dest)
        try:
            src_c.backup(dst_c)
        finally:
            dst_c.close()
            src_c.close()
        backup_path = str(dest)

    if version == 0 and not has_table:
        plan = [1, 2]
    elif version == 0 and has_table:
        plan = [2]  # legacy v1 store
    else:
        plan = [v for v, _ in MIGRATIONS if v > version]

    db.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(db, isolation_level=None)
    try:
        for target in plan:
            name = dict(MIGRATIONS)[target]
            try:
                c.executescript(_migration_text(name))
                if target == 1:
                    c.execute("PRAGMA user_version = 1")
            except sqlite3.Error:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise
        final = c.execute("PRAGMA user_version").fetchone()[0]
    finally:
        c.close()
    if final != SCHEMA_VERSION:
        raise ExecutionStoreError(
            f"migration ended at version {final}, expected {SCHEMA_VERSION}"
        )
    ok, detail = ExecutionStore(db).verify_history()
    return {
        "from_version": version,
        "applied": [dict(MIGRATIONS)[v] for v in plan],
        "to_version": final,
        "backup": backup_path,
        "history": {"chain_verified": ok, "detail": detail},
    }


def _load_seed(path: Path) -> tuple[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["identity"], data["seed_b64"]


def _emit(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def _now() -> str:
    return datetime.now(UTC).isoformat()


def cmd_migrate(args: argparse.Namespace) -> int:
    _emit(
        migrate(
            Path(args.db), backup_dir=Path(args.backup_dir) if args.backup_dir else None
        )
    )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    version, has_table = _inspect_file(Path(args.db))
    _emit(
        {
            "db": args.db,
            "schema_version": version,
            "expected": SCHEMA_VERSION,
            "has_executions_table": has_table,
            "current": version == SCHEMA_VERSION,
        }
    )
    return 0 if version == SCHEMA_VERSION else 1


def cmd_verify_history(args: argparse.Namespace) -> int:
    ok, detail = ExecutionStore(Path(args.db)).verify_history()
    _emit({"chain_verified": ok, "detail": detail})
    return 0 if ok else 2


def cmd_verify_projection(args: argparse.Namespace) -> int:
    ok, detail = ExecutionStore(Path(args.db)).verify_projection()
    _emit({"projection_agrees": ok, "detail": detail})
    return 0 if ok else 2


def cmd_report(args: argparse.Namespace) -> int:
    _emit(build_report(ExecutionStore(Path(args.db))))
    return 0


def cmd_pending(args: argparse.Namespace) -> int:
    store = ExecutionStore(Path(args.db))
    _emit(
        {
            "unresolved": store.unresolved(),
            "pending_receipts": store.pending_receipts(),
            "missing_receipts": store.missing_receipts(),
        }
    )
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    store = ExecutionStore(Path(args.db))
    row = store.row(args.authorization_id)
    if row is None:
        _emit({"error": "authorization_not_found"})
        return 1
    row.pop("signed_authorization_json", None)
    row.pop("arguments_json", None)
    _emit({"execution": row, "history": store.events(args.authorization_id)})
    return 0


def cmd_sign_evidence(args: argparse.Namespace) -> int:
    store = ExecutionStore(Path(args.db))
    row = store.row(args.authorization_id)
    if row is None:
        _emit({"error": "authorization_not_found"})
        return 1
    identity, seed = _load_seed(Path(args.seed_file))
    payload = make_payload(
        row,
        outcome=args.outcome,
        external_reference=args.external_reference,
        external_evidence=Path(args.evidence_file).read_bytes(),
        reconciler=identity,
        observed_at_utc=args.observed_at or _now(),
    )
    _emit(sign_evidence(payload, seed))
    return 0


def cmd_reconcile(args: argparse.Namespace) -> int:
    store = ExecutionStore(Path(args.db))
    registry = ReconcilerRegistry.from_json(
        Path(args.registry).read_text(encoding="utf-8")
    )
    signed = json.loads(Path(args.evidence_file).read_text(encoding="utf-8"))
    receipt_id = "execution_receipt-" + uuid.uuid4().hex
    try:
        evidence = apply_reconciliation(
            store, signed, registry, receipt_event_id=receipt_id
        )
    except ReconciliationRefused as exc:
        _emit({"refused": exc.reason})
        return 2
    _emit(
        {
            "reconciled": evidence["authorization_id"],
            "outcome": evidence["outcome"],
            "receipt_event_id": receipt_id,
            "receipt": "pending; run resubmit-receipts to deliver",
        }
    )
    return 0


def cmd_sign_escalation(args: argparse.Namespace) -> int:
    store = ExecutionStore(Path(args.db))
    row = store.row(args.authorization_id)
    if row is None:
        _emit({"error": "authorization_not_found"})
        return 1
    identity, seed = _load_seed(Path(args.seed_file))
    payload = escalation_payload(
        row, reason=args.reason, reconciler=identity, observed_at_utc=_now()
    )
    _emit(sign_evidence(payload, seed))
    return 0


def cmd_escalate(args: argparse.Namespace) -> int:
    store = ExecutionStore(Path(args.db))
    registry = ReconcilerRegistry.from_json(
        Path(args.registry).read_text(encoding="utf-8")
    )
    signed = json.loads(Path(args.evidence_file).read_text(encoding="utf-8"))
    try:
        payload = apply_escalation(store, signed, registry)
    except ReconciliationRefused as exc:
        _emit({"refused": exc.reason})
        return 2
    _emit({"escalated": payload["authorization_id"], "state_changed": False})
    return 0


def cmd_resubmit_receipts(args: argparse.Namespace) -> int:
    from aigov_py.trusted.core import CoreClient

    from .receipts import deliver_pending

    key = os.environ.get(args.executor_key_env)
    if not key:
        _emit({"error": f"environment variable {args.executor_key_env} is not set"})
        return 1
    store = ExecutionStore(Path(args.db))
    core = CoreClient(args.core_url, key, actor="executor", system="aigov-operator")
    results = deliver_pending(store, core, run_id=args.run_id)
    _emit(
        {
            "results": results,
            "recorded": sum(1 for r in results if r["recorded"]),
            "still_pending": sum(1 for r in results if not r["recorded"]),
        }
    )
    return 0


def cmd_missing_receipts(args: argparse.Namespace) -> int:
    _emit({"missing_receipts": ExecutionStore(Path(args.db)).missing_receipts()})
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m aigov_py.trusted.store_admin",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(
        name: str, fn, *extra: tuple[str, dict[str, Any]]
    ) -> argparse.ArgumentParser:
        sp = sub.add_parser(name)
        sp.add_argument("--db", required=True)
        for flag, kw in extra:
            sp.add_argument(flag, **kw)
        sp.set_defaults(func=fn)
        return sp

    def add_pg(name: str, fn) -> None:
        sp = sub.add_parser(name)
        sp.add_argument("--url", required=True, help="PostgreSQL URL (the database that holds the shared executor store)")
        sp.set_defaults(func=fn)

    add_pg("migrate-pg", cmd_migrate_pg)
    add_pg("status-pg", cmd_status_pg)
    add("migrate", cmd_migrate, ("--backup-dir", {}))
    add("status", cmd_status)
    add("verify-history", cmd_verify_history)
    add("verify-projection", cmd_verify_projection)
    add("report", cmd_report)
    add("pending", cmd_pending)
    add("missing-receipts", cmd_missing_receipts)
    add("inspect", cmd_inspect, ("--authorization-id", {"required": True}))
    add(
        "sign-evidence",
        cmd_sign_evidence,
        ("--seed-file", {"required": True}),
        ("--authorization-id", {"required": True}),
        (
            "--outcome",
            {"required": True, "choices": ["succeeded", "failed", "not_executed"]},
        ),
        ("--external-reference", {"required": True}),
        ("--evidence-file", {"required": True}),
        ("--observed-at", {}),
    )
    add(
        "reconcile",
        cmd_reconcile,
        ("--registry", {"required": True}),
        ("--evidence-file", {"required": True}),
    )
    add(
        "sign-escalation",
        cmd_sign_escalation,
        ("--seed-file", {"required": True}),
        ("--authorization-id", {"required": True}),
        ("--reason", {"required": True}),
    )
    add(
        "escalate",
        cmd_escalate,
        ("--registry", {"required": True}),
        ("--evidence-file", {"required": True}),
    )
    add(
        "resubmit-receipts",
        cmd_resubmit_receipts,
        ("--core-url", {"required": True}),
        ("--executor-key-env", {"required": True}),
        ("--run-id", {}),
    )
    return p


# --- PostgreSQL (the shared executor store) ----------------------------------------------------------------------------

PG_MIGRATIONS: tuple[tuple[int, str], ...] = ((1, "pg/0001_executor_pg.sql"),)
PG_MIGRATION_LOCK = 0x67_6F76_6D6967  # held while migrating: two operators cannot apply migrations at once


def _pg_connect(url: str) -> Any:
    try:
        import psycopg  # optional extra: runs-postgres
    except ImportError as exc:
        raise ExecutionStoreError("psycopg is not installed (pip install 'psycopg[binary]')") from exc
    return psycopg.connect(url, autocommit=False, connect_timeout=5)


def _pg_applied(cur: Any) -> set[int]:
    cur.execute("SELECT to_regclass('public.executor_schema_migrations') IS NOT NULL")
    if not cur.fetchone()[0]:
        return set()
    cur.execute("SELECT version FROM executor_schema_migrations")
    return {int(r[0]) for r in cur.fetchall()}


def cmd_migrate_pg(args: argparse.Namespace) -> int:
    """Apply every pending PostgreSQL migration, in order, each in one transaction, under an advisory lock.

    Operator-controlled: the executor never runs this. Run it before starting executors on a new database, and after
    upgrading the SDK. It is safe to re-run: applied versions are skipped.
    """
    conn = _pg_connect(args.url)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (PG_MIGRATION_LOCK,))
            applied = _pg_applied(cur)
            plan = [(v, name) for v, name in PG_MIGRATIONS if v not in applied]
            for _version, name in plan:
                cur.execute(_migration_text(name))
            cur.execute("SELECT COALESCE(MAX(version), 0) FROM executor_schema_migrations")
            final = int(cur.fetchone()[0])
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    print(json.dumps({"applied": [n for _, n in plan], "schema_version": final}))
    return 0


def cmd_status_pg(args: argparse.Namespace) -> int:
    conn = _pg_connect(args.url)
    try:
        with conn.cursor() as cur:
            applied = sorted(_pg_applied(cur))
        conn.commit()
    finally:
        conn.close()
    expected = [v for v, _ in PG_MIGRATIONS]
    print(json.dumps({"applied_versions": applied, "expected_versions": expected,
                      "up_to_date": applied == expected}))
    return 0 if applied == expected else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # store, reconciliation, SQLite, and PostgreSQL (psycopg) errors are reported as refusals
        print(
            json.dumps({"error": type(exc).__name__, "detail": str(exc)}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
