"""
SQLite-backed document store for the AIGov OpenAI Agents SDK integration.

Provides real, observable side effects for integration testing.
Every write operation is durable to the SQLite file, so test assertions
can inspect actual persisted state including after process restart.

Design:
  - Three operations: read, update, delete
  - Each record has: doc_id, tenant_id, content, version, updated_at
  - Deleted documents are marked with deleted=1 (soft delete, audit-friendly)
  - Thread-safe via connection-per-call (SQLite WAL mode)
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DocumentRecord:
    doc_id: str
    tenant_id: str
    content: str
    version: int
    updated_at: float
    deleted: bool = False


class DocumentStore:
    """
    Persistent SQLite-backed document store.

    Thread-safe. Each call opens its own connection (WAL mode allows
    concurrent readers and one writer). The file path is the observable
    side-effect target in integration tests.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS documents (
                        doc_id      TEXT NOT NULL,
                        tenant_id   TEXT NOT NULL,
                        content     TEXT NOT NULL,
                        version     INTEGER NOT NULL DEFAULT 1,
                        updated_at  REAL NOT NULL,
                        deleted     INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (doc_id, tenant_id)
                    )
                """)
                conn.commit()
            finally:
                conn.close()

    def seed(self, doc_id: str, tenant_id: str, content: str) -> None:
        """Insert or replace a document (for test setup)."""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO documents "
                    "(doc_id, tenant_id, content, version, updated_at, deleted) "
                    "VALUES (?, ?, ?, 1, ?, 0)",
                    (doc_id, tenant_id, content, time.time()),
                )
                conn.commit()
            finally:
                conn.close()

    def read(self, doc_id: str, tenant_id: str) -> DocumentRecord | None:
        """Return document or None if not found / deleted."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM documents WHERE doc_id=? AND tenant_id=? AND deleted=0",
                (doc_id, tenant_id),
            ).fetchone()
            if row is None:
                return None
            return DocumentRecord(
                doc_id=row["doc_id"],
                tenant_id=row["tenant_id"],
                content=row["content"],
                version=row["version"],
                updated_at=row["updated_at"],
                deleted=bool(row["deleted"]),
            )
        finally:
            conn.close()

    def update(self, doc_id: str, tenant_id: str, content: str) -> DocumentRecord:
        """Update content, increment version. Creates if absent."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT version FROM documents "
                    "WHERE doc_id=? AND tenant_id=? AND deleted=0",
                    (doc_id, tenant_id),
                ).fetchone()
                new_version = (row["version"] + 1) if row else 1
                now = time.time()
                conn.execute(
                    "INSERT OR REPLACE INTO documents "
                    "(doc_id, tenant_id, content, version, updated_at, deleted) "
                    "VALUES (?, ?, ?, ?, ?, 0)",
                    (doc_id, tenant_id, content, new_version, now),
                )
                conn.commit()
                return DocumentRecord(
                    doc_id=doc_id,
                    tenant_id=tenant_id,
                    content=content,
                    version=new_version,
                    updated_at=now,
                )
            finally:
                conn.close()

    def delete(self, doc_id: str, tenant_id: str) -> bool:
        """Soft-delete. Returns True if document was present, False if already absent."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT version FROM documents "
                    "WHERE doc_id=? AND tenant_id=? AND deleted=0",
                    (doc_id, tenant_id),
                ).fetchone()
                if row is None:
                    return False
                conn.execute(
                    "UPDATE documents SET deleted=1, updated_at=? "
                    "WHERE doc_id=? AND tenant_id=?",
                    (time.time(), doc_id, tenant_id),
                )
                conn.commit()
                return True
            finally:
                conn.close()

    def all_records(self, tenant_id: str | None = None) -> list[DocumentRecord]:
        """Return all records including deleted ones (for audit assertions)."""
        conn = self._connect()
        try:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM documents WHERE tenant_id=? ORDER BY doc_id",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM documents ORDER BY tenant_id, doc_id"
                ).fetchall()
            return [
                DocumentRecord(
                    doc_id=r["doc_id"],
                    tenant_id=r["tenant_id"],
                    content=r["content"],
                    version=r["version"],
                    updated_at=r["updated_at"],
                    deleted=bool(r["deleted"]),
                )
                for r in rows
            ]
        finally:
            conn.close()

    def count_live(self, tenant_id: str | None = None) -> int:
        """Count non-deleted documents."""
        conn = self._connect()
        try:
            if tenant_id:
                return conn.execute(
                    "SELECT COUNT(*) FROM documents WHERE deleted=0 AND tenant_id=?",
                    (tenant_id,),
                ).fetchone()[0]
            return conn.execute(
                "SELECT COUNT(*) FROM documents WHERE deleted=0"
            ).fetchone()[0]
        finally:
            conn.close()
