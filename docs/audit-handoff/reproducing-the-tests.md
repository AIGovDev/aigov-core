# Reproducing the tests

## Prerequisites

- macOS or Linux, Rust stable (the lockfile is `rust/Cargo.lock`; build with `--locked`), Python 3.12 (CI uses 3.11 for some jobs).
- PostgreSQL 16 or 18. Each test that needs it names a disposable database through an environment variable. Tests that drop tables refuse any database
  whose name lacks `test`, and require `AIGOV_PG_TEST_DESTRUCTIVE=1`.
- Docker, for the container tests.

## Commands

```
cd rust && cargo build --locked --release --bin aigov_audit          # release Core
cd rust && cargo test --locked                                         # no database; CI runs this
cd rust && AIGOV_TEST_PG_ADMIN_URL=... DATABASE_URL=... cargo test --locked -- --include-ignored --skip rollback_across_two_volumes
make crash-consistency-gate PY=python                                  # builds the fault-injection binary; 9 tests
make fault-absence-check PY=python                                     # the release binary has no crash-point names
AIGOV_TEST_PG_ADMIN_URL=... make two-volume-rollback                   # two disk images (macOS hdiutil); removes them afterwards
cd python && AIGOV_TEST_REGISTRY_PG_URL=... AIGOV_TEST_CORE_BIN=... PYTHONPATH=$PWD python -m pytest tests/test_issuance_cross_process.py
cd python && AIGOV_TEST_POLICY_PG_URL=... AIGOV_TEST_CORE_BIN=... PYTHONPATH=$PWD python -m pytest tests/test_policy_revision_across_processes.py
cd python && AIGOV_TEST_CORE_BIN=... PYTHONPATH=$PWD python -m pytest tests -q            # full Python suite (container file separate)
make gate ; make enterprise-readiness-check
python scripts/core_load_test.py --binary rust/target/release/aigov_audit --out-dir <dir>   # load (same host; minutes)
```

## Expected results on the release commit

Recorded in `docs/reports/pilot-readiness-closure-2026-11-26.md` (validation table) and the release acceptance report. Counts differ when the set of
tests changes; a failing test is a finding until it is explained.

## Known test environment traps

- A destructive PostgreSQL test refuses a database whose name lacks `test`. Use a name such as `govai_<purpose>_test_<id>`.
- The API-key map is set once per process. Tests that start several Core configurations use one process per configuration.
- Staging and production start require principals. A test that starts them without principals is wrong, not the server.
- Do not use `pkill` by pattern on a shared machine. Track the process ids that a test or script starts.
