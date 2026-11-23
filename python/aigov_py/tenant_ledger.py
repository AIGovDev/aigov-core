"""Tenant ledger file mapping and run ownership (mirror of ``rust/src/project.rs``).

The Rust service stores each tenant's evidence in ``audit_log__<segment>.jsonl``. This module
computes the same file name so operator tooling can prove that a run belongs to a tenant from the
ledger itself, instead of trusting a caller-supplied tenant id.

Keep ``tenant_ledger_segment`` identical to the Rust implementation. Shared vectors are asserted on
both sides (``python/tests/test_tenant_ledger.py`` and ``rust/src/project.rs`` tests).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable
from pathlib import Path

LEDGER_BASE = "audit_log.jsonl"
LEGACY_TENANTS_ENV = "AIGOV_LEDGER_LEGACY_TENANTS"
LEDGER_DIR_ENV = "GOVAI_LEDGER_DIR"

_IDENTITY = re.compile(r"[A-Za-z0-9_-]{1,128}")
_MAX_HEX_BYTES = 100


class TenantLedgerError(ValueError):
    """Raised when a tenant id is invalid or ownership cannot be established."""


class RunOwnershipError(TenantLedgerError):
    """Raised when a run is owned by another tenant, or ownership is unknown (fail closed)."""


def validate_tenant_id(tenant_id: str) -> str:
    """Return the tenant id if it uses only ``[A-Za-z0-9_-]`` (1-128 characters); otherwise raise."""
    if not isinstance(tenant_id, str) or not _IDENTITY.fullmatch(tenant_id):
        raise TenantLedgerError(
            "tenant id must be 1-128 characters from [A-Za-z0-9_-]"
        )
    return tenant_id


def tenant_ledger_segment(tenant_id: str) -> str:
    """Injective segment for a tenant id (same rules as Rust ``tenant_ledger_segment``)."""
    if _IDENTITY.fullmatch(tenant_id):
        return tenant_id
    raw = tenant_id.encode("utf-8")
    if len(raw) <= _MAX_HEX_BYTES:
        return "~h" + raw.hex()
    return "~s" + hashlib.sha256(raw).hexdigest()


def tenant_ledger_segment_legacy(tenant_id: str) -> str:
    """Pre-v2 lossy segment (only for tenants explicitly listed as legacy)."""
    s = "".join(c if (c.isascii() and (c.isalnum() or c in "-_")) else "_" for c in tenant_id)[:128]
    return s if s else "_"


def legacy_tenant_ids(environ: dict | None = None) -> frozenset:
    env = os.environ if environ is None else environ
    raw = env.get(LEGACY_TENANTS_ENV, "")
    return frozenset(t.strip() for t in raw.split(",") if t.strip())


def segment_for_tenant(tenant_id: str, *, legacy: Iterable[str] | None = None) -> str:
    legacy_set = frozenset(legacy) if legacy is not None else legacy_tenant_ids()
    if tenant_id in legacy_set:
        return tenant_ledger_segment_legacy(tenant_id)
    return tenant_ledger_segment(tenant_id)


def ledger_path_for_tenant(
    tenant_id: str,
    *,
    ledger_dir: str | None = None,
    legacy: Iterable[str] | None = None,
) -> Path:
    """Path of the tenant's ledger file. Mirrors ``project::ledger_file_for_segment``."""
    name = f"audit_log__{segment_for_tenant(tenant_id, legacy=legacy)}.jsonl"
    base = ledger_dir if ledger_dir is not None else os.environ.get(LEDGER_DIR_ENV, "").strip()
    return Path(base) / name if base else Path(name)


def run_recorded_for_tenant(
    run_id: str,
    tenant_id: str,
    *,
    ledger_dir: str | None = None,
    legacy: Iterable[str] | None = None,
) -> bool:
    """True only if the tenant's own ledger file contains a record for ``run_id``.

    Fails closed: a missing ledger, an unreadable file, or a malformed line never proves ownership
    (a malformed line raises, so the caller cannot treat it as "not owned" by accident).
    """
    validate_tenant_id(tenant_id)
    path = ledger_path_for_tenant(tenant_id, ledger_dir=ledger_dir, legacy=legacy)
    if not path.is_file():
        return False
    found = False
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                event = json.loads(rec["event_json"])
            except (ValueError, KeyError, TypeError) as exc:
                raise TenantLedgerError(f"malformed ledger line {lineno} in tenant ledger") from exc
            if event.get("run_id") == run_id:
                found = True
    return found
