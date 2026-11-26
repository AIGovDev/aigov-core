"""Human approval store for consequential tool calls.

A request is bound to the exact call: tool name, action type, resource, tenant, and the
SHA-256 binding hash of the arguments. A human approver records a decision with
``approve`` or ``reject``. Approvals expire. The gate reads the record before any
execution and never trusts the agent's view of the approval.

SQLite is used here so that separate processes see the same decisions. A store that
cannot be read raises ``ApprovalStoreUnavailable``; the gate treats that as
INDETERMINATE and does not execute.
"""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum


class ApprovalStoreUnavailable(RuntimeError):
    """The approval store cannot be read or written. The gate fails closed on this."""


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    tenant_id: str
    tool_name: str
    action_type: str
    resource_id: str
    args_binding_hash: str
    status: ApprovalStatus
    approver: str
    requested_at: float
    decided_at: float | None
    expires_at: float | None


class ApprovalStore:
    """SQLite-backed approval records. One connection per call keeps this process-safe."""

    def __init__(self, path: str, ttl_seconds: float = 300.0) -> None:
        self._path = path
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._fail = False
        with self._session() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    args_binding_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approver TEXT NOT NULL,
                    requested_at REAL NOT NULL,
                    decided_at REAL,
                    expires_at REAL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        if self._fail:
            raise ApprovalStoreUnavailable(
                "approval store is unavailable (simulated outage)"
            )
        try:
            return sqlite3.connect(self._path, timeout=5.0)
        except sqlite3.Error as exc:
            raise ApprovalStoreUnavailable(
                f"approval store cannot be opened: {exc}"
            ) from exc

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def simulate_outage(self, down: bool) -> None:
        """Test hook: make every subsequent read and write fail, as if the service were down."""
        self._fail = down

    def create_request(
        self,
        *,
        tenant_id: str,
        tool_name: str,
        action_type: str,
        resource_id: str,
        args_binding_hash: str,
        now: float | None = None,
    ) -> str:
        approval_id = "apr_" + uuid.uuid4().hex
        requested = time.time() if now is None else now
        try:
            with self._lock, self._session() as conn:
                conn.execute(
                    "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        approval_id,
                        tenant_id,
                        tool_name,
                        action_type,
                        resource_id,
                        args_binding_hash,
                        ApprovalStatus.PENDING.value,
                        "",
                        requested,
                        None,
                        None,
                    ),
                )
        except sqlite3.Error as exc:
            raise ApprovalStoreUnavailable(str(exc)) from exc
        return approval_id

    def decide(
        self, approval_id: str, approver: str, approve: bool, now: float | None = None
    ) -> None:
        decided = time.time() if now is None else now
        status = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
        expires = decided + self._ttl if approve else None
        try:
            with self._lock, self._session() as conn:
                cur = conn.execute(
                    "UPDATE approvals SET status=?, approver=?, decided_at=?, expires_at=? "
                    "WHERE approval_id=? AND status=?",
                    (
                        status.value,
                        approver,
                        decided,
                        expires,
                        approval_id,
                        ApprovalStatus.PENDING.value,
                    ),
                )
                if cur.rowcount != 1:
                    raise ValueError(f"approval {approval_id} is not pending")
        except sqlite3.Error as exc:
            raise ApprovalStoreUnavailable(str(exc)) from exc

    def get(self, approval_id: str) -> ApprovalRecord | None:
        try:
            with self._session() as conn:
                row = conn.execute(
                    "SELECT approval_id, tenant_id, tool_name, action_type, resource_id, "
                    "args_binding_hash, status, approver, requested_at, decided_at, expires_at "
                    "FROM approvals WHERE approval_id=?",
                    (approval_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise ApprovalStoreUnavailable(str(exc)) from exc
        if row is None:
            return None
        return ApprovalRecord(
            approval_id=row[0],
            tenant_id=row[1],
            tool_name=row[2],
            action_type=row[3],
            resource_id=row[4],
            args_binding_hash=row[5],
            status=ApprovalStatus(row[6]),
            approver=row[7],
            requested_at=row[8],
            decided_at=row[9],
            expires_at=row[10],
        )
