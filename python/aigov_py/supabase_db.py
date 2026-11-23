from __future__ import annotations

import os
from typing import Any, Dict


def create_supabase_client(strict: bool = True):
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

    if not url or not key:
        if strict:
            raise RuntimeError("Supabase env variables missing")
        return None

    from supabase import (
        create_client,  # optional dependency; imported only when a client is needed
    )

    return create_client(url, key)


def upsert_run_row_via_supabase(row: Dict[str, Any]) -> None:
    """Write one run row to Supabase ``runs`` with tenant ownership enforced in code.

    The service-role key bypasses row-level security, so this function is the only boundary:

    * refused in production (``AIGOV_ENVIRONMENT=prod``), with no override;
    * the row must carry a validated ``tenant_id``;
    * an existing row owned by another tenant (or by no tenant, i.e. a legacy row) is never
      overwritten.

    The check-then-write is not atomic. ``docs/operations/runs-tenant-migration.md`` describes the
    database constraint that makes the guarantee race-free.
    """
    from aigov_py.env_resolution import resolve_aigov_environment
    from aigov_py.tenant_ledger import RunOwnershipError, validate_tenant_id

    if resolve_aigov_environment() == "prod":
        raise RuntimeError(
            "Supabase service-role run writes are disabled in production (AIGOV_ENVIRONMENT=prod). "
            "Use the tenant-scoped GovAI Postgres path."
        )
    tenant_id = validate_tenant_id(str(row.get("tenant_id") or ""))
    run_id = str(row.get("id") or "")
    if not run_id:
        raise RuntimeError("run row has no id")

    client = create_supabase_client(strict=True)
    existing = client.table("runs").select("id,tenant_id").eq("id", run_id).execute()
    for found in existing.data or []:
        if found.get("tenant_id") != tenant_id:
            raise RunOwnershipError(
                f"run {run_id!r} already exists for a different tenant or without an owner; refusing to overwrite"
            )

    response = client.table("runs").upsert(row, on_conflict="id").execute()
    if hasattr(response, "error") and response.error:
        raise RuntimeError("Supabase run write failed")
