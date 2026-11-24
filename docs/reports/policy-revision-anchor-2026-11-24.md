# Durable PostgreSQL policy revision anchor — 2026-11-24

## Scope

Stores the accepted policy revision in PostgreSQL, independently of the filesystem watermark. Refs #500, #501, #502.
Multi-instance runtime support is out of scope and stays in #501. No Railway, production, or external infrastructure was
changed. No credentials were created.

Protocol, crash-consistency analysis, bootstrap, recovery, and residual risks are in `docs/operations/policy-anchor-runbook.md`.

## What changed

- Migration `0003_policy_revision_anchor` (additive: one table). Expected migration count is now 3.
- `rust/src/policy_anchor.rs`: the decision (pure, unit-tested) and the reconcile-and-commit step.
- `rust/src/policy_watermark.rs`: optional read, exclusive filesystem lock, writer used under the lock.
- `rust/src/policy_store.rs`, `rust/src/govai_api.rs`: the anchor is committed as the last startup step. Staging and production
  with a bundle require a database URL.
- Four positive startup tests are `#[ignore]` by default and run against a fresh database per test.

## Protocol in one paragraph

Filesystem lock; transaction with a per-policy advisory lock; decide; write the filesystem record first; commit the database
row last. A failed activation cannot move the anchor. The only window where the filesystem leads is between the two writes,
and it resolves deterministically: the same bundle rolls the anchor forward, and any older bundle is refused.

## Evidence

| Suite | Result |
|-------|--------|
| Rust `cargo test --locked --no-fail-fast`, no database | 281 passed, 0 failed, **16 ignored** (PostgreSQL-backed) |
| Rust ignored tests, PostgreSQL 18 (`--ignored`, fresh database per test) | 16 passed, 0 failed |
| Policy unit tests (`--lib policy_`) | 66 passed, 0 failed |
| Anchor integration tests, PostgreSQL 18 (12) | 12 passed (concurrency, failed write, recomputed tag, restored snapshot, deletion, bootstrap, restart, unreachable database, migration, key rotation) |
| Python `pytest python/tests`, no database (clean anchor image) | 1072 passed, 41 skipped (database-gated) |
| Python, PostgreSQL 18 | 1109 passed, 4 skipped (BLOCKED: live OAuth, live Supabase, Sigstore bundle, `mcnemar_F_vs_G`) |
| Container tests, clean no-cache image `aigov-core:anchor-1f1cb65`, PostgreSQL 18 | 16 passed |
| Local harness, full, PostgreSQL 18 per ledger (`--skip-live`) | 60 passed, 0 failed |
| Clippy on the anchor and watermark modules, library and tests | no findings |
| `make gate` | passes |

Skipped and blocked items are not counted as passing. Live remote checks were not run and are not reported.

## Negative controls

- **Rollback by forged record (real binary).** On the previous commit `f5d1b89` (filesystem-only watermark): revision 3 is
  accepted; the attacker plants an older authentic revision-1 record with a recomputed tag; the signed revision-1 bundle is
  **accepted** (`started`). On this commit, the same replay is **refused**: `rollback refused: revision 1 is older than the
  anchored revision 3`.
- **Harness on the previous commit.** The anchor scenarios cannot run there: the table does not exist, so the bootstrap step
  fails. This confirms the previous commit has no durable anchor. The harness run on the previous commit was not used as a
  pass/fail comparison.
- **Concurrency test.** With the advisory lock and filesystem lock disabled, concurrent commits can move the record backwards
  (the earlier watermark negative control showed 6 of 8 runs failing).

## Defects found and fixed during this work

- The filesystem lock was a blocking `flock` taken inside an async task. Under contention, the worker threads deadlocked. It now
  runs on the blocking pool. Found by the concurrency test.
- A test used a closed connection pool; the test was corrected.
- Parallel test databases could collide on name; names are now unique per process and per call.
- The Python container tests default to the image `aigov-core:hardened`, which predates migration 0003. Two Python runs failed on
  the migration count until `AIGOV_TEST_IMAGE` was set to the new image. CI sets the image explicitly. The local default should
  be updated; this is a known follow-up.

## Residual risks (declared; not claimed as protected)

- Simultaneous rollback of the database and the filesystem to the same older backup.
- A privileged database administrator who rewrites the anchor row.
- The anchor is not cryptographically authenticated (a keyed tag or an external signed anchor is an open decision in #501).
- Multi-instance and cross-host concurrency: out of scope (#501).
- Bootstrap of existing deployments is a manual, DBA-performed step (runbook section 6).

## Evaluation gate

Passes when the anchor decision and the protocol are tested against a real PostgreSQL 18 database, the concurrency and
failure-injection tests pass, the negative control reproduces the rollback on the previous commit and refuses it on this one,
the Rust, Python, container, and harness suites pass with skips and blocked items reported separately, and `make gate` passes.
All of these hold for the change set in this PR.

## Human approval gate

Not approved for production by this report. Merging into `staging` is a separate decision. Before any production or
multi-instance use, the open decisions in issue #501 must be made: authentication of the anchor, the bootstrap procedure for each
existing deployment, and the backup and restore policy for the database together with the ledger volume.
