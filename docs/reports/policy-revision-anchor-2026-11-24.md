# Durable PostgreSQL policy revision anchor — 2026-11-24

## Scope

Stores the accepted policy revision in PostgreSQL, independently of the filesystem watermark. Refs #500, #501, #502, #503.
Multi-instance runtime support is out of scope and stays in #501. No Railway, production, or external infrastructure was
changed. No credentials were created.

Protocol, crash-consistency analysis, bootstrap, recovery, and residual risks are in `docs/operations/policy-anchor-runbook.md`.

## What changed

- Migration `0003_policy_revision_anchor` (additive: one table). Expected migration count is now 3.
- `rust/src/policy_anchor.rs`: the decision (pure, unit-tested) and `reconcile_all_and_commit`, which commits every pending
  policy of one activation in one database transaction.
- `rust/src/policy_watermark.rs`: optional read, exclusive filesystem lock, writer used under the lock.
- `rust/src/policy_store.rs`: pending revisions are created only after the bundle set is accepted (after the directory-mode
  count check). Staging and production with a bundle require a database URL.
- `rust/src/lib.rs` (`run`): the activation commits after the listener is bound and before the service serves. A commit
  failure exits the process before serving.
- `rust/src/govai_api.rs`: `build_app_state` no longer commits the anchor.
- Container test default image is `aigov-core:test` (built from the repository). The previous default predated migration 0003.

## Protocol in one paragraph

Load and verify all bundles (nothing written). Bind the listener (a bind failure ends the process with nothing written).
Then, in `run`: take the per-host filesystem lock; open one database transaction; take an advisory lock per policy; decide
every policy; apply the database writes inside the transaction; write the filesystem record once, for all policies; commit
the transaction. The filesystem write comes after the database writes, so a database failure writes no record. There is no
atomicity across PostgreSQL and the filesystem. A failure at the commit itself leaves the record ahead of the anchor; the
next start rolls the anchor forward for a matching bundle, refuses an older one, and for a first start refuses until the
bootstrap procedure is run.

## Evidence

Results on commit `2bd70f4` (PR #503 head after this review), local only. Skipped and blocked items are not counted as passing.

| Suite | Result |
|-------|--------|
| Rust `cargo test --locked --no-fail-fast`, no database | 281 passed, 0 failed, 21 ignored (PostgreSQL-backed) |
| Rust ignored tests, PostgreSQL 18 (`--ignored`, fresh database per test) | 21 passed, 0 failed |
| Anchor integration tests, PostgreSQL 18 (`policy_anchor_pg`) | 17 passed (12 earlier cases, plus 5 activation-protocol cases) |
| Python `pytest` full suite, no database configured | 1026 passed, 0 failed, 87 skipped (database-gated) |
| Python `tests/test_postgres_integration.py`, PostgreSQL 18, destructive flag set on a scratch database | 33 passed, 0 failed |
| Python container tests, clean no-cache image `aigov-core:test` | 16 passed, 0 failed |
| Local harness, `--skip-live`, PostgreSQL 18 per ledger | 66 passed, 0 failed (includes 6 new checks in 3 scenarios: bind failure, insert failure, two bundles) |
| `ruff check`, `mypy` on the harness | pass |
| `make gate` | passes |
| Clippy on `policy_anchor`, `policy_watermark` | no findings |

Not run in this review: the full Python suite with a database configured (the 1109-passing figure in the earlier version
of this report was from a previous commit), live staging checks, and CI on the new head. CI on PR #503 must be checked
before any merge decision.

## Negative controls

- **Rollback by forged record (real binary).** On the previous commit `f5d1b89` (filesystem-only watermark): revision 3 is
  accepted; the attacker plants an older authentic revision-1 record with a recomputed tag; the signed revision-1 bundle is
  **accepted** (`started`). On this commit, the same replay is **refused**: `rollback refused: revision 1 is older than the
  anchored revision 3`.
- **Bind failure (real binary).** A listener already held the port. On the previous head (`b67a0c4`, anchor committed in
  `build_app_state`), the process failed with `Address already in use`, and the anchor row had already advanced to revision 5.
  On this commit the same start leaves no anchor row. Harness scenario `anchor.bind_failure_anchor_state` checks this.
- **First-start insert failure (real binary).** A bundle whose identifier violates the column constraint. On the previous
  head (`b67a0c4`), the filesystem record was written before the failure, and the next start refused with the bootstrap message. On
  this commit no record is written, and the next start fails on the same insert error. Scenario
  `anchor.insert_failure_writes_no_record` checks this.
- **Two bundles in the policy directory (real binary).** Refused with `multiple policy bundles matched (count=2)` before any
  anchor work; no anchor row is created. Scenarios `anchor.two_bundles_refused` and `anchor.two_bundles_no_anchor_rows`.
- **Concurrency test.** With the advisory lock and filesystem lock disabled, concurrent commits can move the record backwards
  (the earlier watermark negative control showed 6 of 8 runs failing).

## Defects found and fixed during this review

- **A failed listener bind advanced the anchor.** `build_app_state` committed before the listener was bound. Fixed: the
  commit runs in `run` after the bind succeeds.
- **A first-start insert failure left a filesystem record.** The record was written before the database insert. Fixed: the
  database writes run inside the transaction before the filesystem write.
- **Multiple pending revisions committed one after another, and were created before the count check.** A successful startup
  cannot reach a partial commit today, because two directory bundles are refused first. Fixed anyway: pending revisions are
  created only after the count check, and every policy commits in one transaction with one filesystem write.
- **Stale container test default image.** `python/tests/test_container_runtime.py` defaulted to `aigov-core:hardened`, which
  predates migration 0003. Fixed: the default is `aigov-core:test`, which must be built from the repository.

## Defects found and fixed during the earlier work

- The filesystem lock was a blocking `flock` taken inside an async task. Under contention, the worker threads deadlocked. It now
  runs on the blocking pool. Found by the concurrency test.
- A test used a closed connection pool; the test was corrected.
- Parallel test databases could collide on name; names are now unique per process and per call.

## Residual risks (declared; not claimed as protected)

- Simultaneous rollback of the database and the filesystem to the same older backup.
- A privileged database administrator who rewrites the anchor row.
- The anchor is not cryptographically authenticated (a keyed tag or an external signed anchor is an open decision in #501).
- A failure at the commit point of a **first start** leaves a filesystem record and no anchor row. The next start refuses until
  an operator runs the bootstrap procedure (runbook sections 4 and 6). This is tested, and it is an operator action, not an
  automatic recovery.
- There is no atomicity across PostgreSQL and the filesystem. The protocol fixes the order of writes; it does not make them one
  commit.
- Multi-instance and cross-host concurrency: out of scope (#501).
- Bootstrap of existing deployments is a manual, DBA-performed step (runbook section 6).

## Evaluation gate

Passes when the anchor decision and the protocol are tested against a real PostgreSQL 18 database, the concurrency and
failure-injection tests pass, the negative controls reproduce the defects on the previous commit and refuse or prevent them on
this one, the Rust, Python, container, and harness suites pass with skips and blocked items reported separately, and
`make gate` passes. The local results above satisfy these conditions. CI on the new head has not yet been checked in this
report.

## Human approval gate

Not approved for production by this report. Merging into `staging` is a separate decision, and it is not made here. Before
any production or multi-instance use, the open decisions in issue #501 must be made: authentication of the anchor, the
bootstrap procedure for each existing deployment, and the backup and restore policy for the database together with the
ledger volume.
