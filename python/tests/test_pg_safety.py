"""Unit tests for the destructive-PostgreSQL guard. These need no database and always run."""

import pytest

from _pg_safety import OPT_IN_ENV, UnsafeTestDatabase, check_isolated_test_database

OPTED_IN = {OPT_IN_ENV: "1"}
SAFE = "postgresql://aigov_test:pw@localhost:5432/aigov_integration"


def test_isolated_test_database_is_accepted():
    check_isolated_test_database(SAFE, env=OPTED_IN)


@pytest.mark.parametrize("dsn", [
    "postgresql://u:p@localhost:5432/aigov_unit_test",
    "postgresql://u:p@127.0.0.1:15432/test_gateway",
    "postgresql://u:p@[::1]:5432/pg_test_2",
])
def test_test_named_local_databases_are_accepted(dsn):
    check_isolated_test_database(dsn, env=OPTED_IN)


def test_refuses_without_explicit_opt_in_even_for_test_database():
    with pytest.raises(UnsafeTestDatabase, match=OPT_IN_ENV):
        check_isolated_test_database(SAFE, env={})


@pytest.mark.parametrize("value", ["0", "true", "yes", ""])
def test_opt_in_must_be_exactly_one(value):
    with pytest.raises(UnsafeTestDatabase):
        check_isolated_test_database(SAFE, env={OPT_IN_ENV: value})


@pytest.mark.parametrize("dsn", [
    "postgresql://postgres:postgres@127.0.0.1:5432/postgres",  # maintenance DB used by old CI jobs
    "postgresql://u:p@localhost:5432/template1",
    "postgresql://u:p@localhost:5432/template0",
])
def test_refuses_shared_maintenance_databases(dsn):
    with pytest.raises(UnsafeTestDatabase):
        check_isolated_test_database(dsn, env=OPTED_IN)


@pytest.mark.parametrize("dsn", [
    "postgresql://u:p@localhost:5432/aigov_prod",
    "postgresql://u:p@localhost:5432/customers",
    "postgresql://u:p@localhost:5432/govai",
    "postgresql://u:p@localhost:5432/",
    "postgresql://u:p@localhost:5432",
])
def test_refuses_non_test_or_unnamed_databases(dsn):
    with pytest.raises(UnsafeTestDatabase):
        check_isolated_test_database(dsn, env=OPTED_IN)


@pytest.mark.parametrize("dsn", [
    "postgresql://u:p@db.example.com:5432/aigov_integration",
    "postgresql://u:p@10.0.0.5:5432/aigov_integration",
    "postgresql://u:p@localhost.evil.example:5432/aigov_integration",
])
def test_refuses_non_local_hosts(dsn):
    with pytest.raises(UnsafeTestDatabase):
        check_isolated_test_database(dsn, env=OPTED_IN)


def test_refuses_unsupported_scheme():
    with pytest.raises(UnsafeTestDatabase):
        check_isolated_test_database("mysql://u:p@localhost:3306/aigov_integration", env=OPTED_IN)
