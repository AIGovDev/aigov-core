"""Fail-closed guard for tests that run destructive SQL (DROP TABLE) against PostgreSQL.

A destructive test may only run when ALL of these hold:
  - AIGOV_PG_TEST_DESTRUCTIVE=1 is set explicitly (opt-in, never implied by DATABASE_URL alone);
  - the DSN uses a postgres scheme and a local host (localhost, 127.0.0.1, ::1);
  - the database name is a dedicated test database: ``aigov_integration`` or a name containing ``test``;
  - the database name is not a shared maintenance database (``postgres``, ``template0``, ``template1``).

If DATABASE_URL is unset, callers skip as before. If it is set but any condition fails, callers
must fail, not skip, so a misconfigured job cannot pass silently or touch the wrong database.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

OPT_IN_ENV = "AIGOV_PG_TEST_DESTRUCTIVE"
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
ALLOWED_DB_NAMES = frozenset({"aigov_integration"})
SHARED_DB_NAMES = frozenset({"postgres", "template0", "template1"})
_TEST_NAME = re.compile(r"[a-z0-9_]*test[a-z0-9_]*")


class UnsafeTestDatabase(RuntimeError):
    """Raised when a destructive test is pointed at a database it may not touch."""


def check_isolated_test_database(dsn: str, env: dict[str, str] | None = None) -> None:
    """Raise UnsafeTestDatabase unless ``dsn`` names an explicitly opted-in, isolated test database."""
    env = os.environ if env is None else env
    if env.get(OPT_IN_ENV) != "1":
        raise UnsafeTestDatabase(
            f"Destructive PostgreSQL tests need {OPT_IN_ENV}=1 set explicitly. Refusing to run."
        )

    parsed = urlparse(dsn)
    if parsed.scheme not in ("postgresql", "postgres"):
        raise UnsafeTestDatabase(f"Unsupported DATABASE_URL scheme {parsed.scheme!r}.")
    host = (parsed.hostname or "").lower()
    if host not in LOCAL_HOSTS:
        raise UnsafeTestDatabase(f"Destructive tests only run on a local host, got {host!r}.")

    db_name = parsed.path.lstrip("/")
    if not db_name or db_name in SHARED_DB_NAMES:
        raise UnsafeTestDatabase(f"Refusing shared or unnamed database {db_name!r}.")
    if db_name not in ALLOWED_DB_NAMES and not _TEST_NAME.fullmatch(db_name):
        raise UnsafeTestDatabase(
            f"Database {db_name!r} is not a dedicated test database (expected 'aigov_integration' "
            "or a name containing 'test')."
        )
