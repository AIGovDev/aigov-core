from __future__ import annotations

from typing import Any, Dict

from aigov_py.psycopg_database_url import resolve_psycopg_database_url


def upsert_run_row_postgres(row: Dict[str, Any]) -> None:
    """Upsert one run row into ``console.runs``, only if the existing row belongs to the same tenant.

    Requires the ``tenant_id`` column (``docs/operations/runs-tenant-migration.md``). A row owned by
    another tenant, or a legacy row with no owner, is not updated, and an error is raised.
    """
    from aigov_py.tenant_ledger import RunOwnershipError, validate_tenant_id

    tenant_id = validate_tenant_id(str(row.get("tenant_id") or ""))
    row = {**row, "tenant_id": tenant_id}
    try:
        import psycopg
    except ImportError as e:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "Install psycopg for postgres run persistence (e.g. pip install 'aigov-py[runs-postgres]')"
        ) from e

    sql = """
    insert into console.runs (
      id, tenant_id, created_at, mode, status, policy_version, bundle_sha256,
      evidence_sha256, report_sha256, evidence_source, closed_at, environment
    ) values (
      %(id)s, %(tenant_id)s, %(created_at)s::timestamptz, %(mode)s, %(status)s, %(policy_version)s,
      %(bundle_sha256)s, %(evidence_sha256)s, %(report_sha256)s, %(evidence_source)s,
      %(closed_at)s::timestamptz, coalesce(%(environment)s, 'dev')
    )
    on conflict (id) do update set
      created_at = excluded.created_at,
      mode = excluded.mode,
      status = excluded.status,
      policy_version = excluded.policy_version,
      bundle_sha256 = excluded.bundle_sha256,
      evidence_sha256 = excluded.evidence_sha256,
      report_sha256 = excluded.report_sha256,
      evidence_source = excluded.evidence_source,
      closed_at = excluded.closed_at,
      environment = excluded.environment
    where console.runs.tenant_id = excluded.tenant_id
    """

    with psycopg.connect(resolve_psycopg_database_url(), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, row)
            if cur.rowcount == 0:
                raise RunOwnershipError(
                    "run exists for a different tenant or without an owner; refusing to overwrite"
                )
