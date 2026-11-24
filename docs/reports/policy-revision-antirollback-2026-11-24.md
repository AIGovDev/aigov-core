# Signed-policy revision model and anti-rollback — 2026-11-24

## Scope

Protects against replaying an older, validly signed policy bundle after a newer revision has been accepted. Builds on
the version record merged in #499 (`d76b069`). That version had three gaps this change closes: a failed activation
advanced the record, a missing record was accepted as a first start even when the ledger held data, and two processes
could interleave the check and the write.

No external infrastructure was changed. No Railway resource, credential, or deployment was created or modified.

## Revision model

- A policy's revision is its `version`, a plain non-negative integer. Other forms are refused.
- The accepted revision is recorded per `policy_id` in `<GOVAI_LEDGER_DIR>/policy_watermark.json`.
- Identity of content is the document digest. The `signatures` array is excluded, so re-signing the same content, rotating
  the signing key, or changing the trust store leaves the digest unchanged.
- Timestamps are not used for rollback decisions.

| Situation | Decision |
|-----------|----------|
| No record for the policy | accept and record |
| Revision lower than the record | refuse (`rollback refused`) |
| Same revision, same digest | accept, idempotent, no write |
| Same revision, different digest | refuse (`same-version content change refused`) |
| Higher revision | accept; record advances at commit |
| Invalid signature or failed contract | refuse before any check; nothing recorded |
| Verified, but startup fails later | nothing recorded (commit happens last) |
| Record corrupt, unreadable, or with unknown fields | refuse (fail closed) |
| Record missing, ledger holds data | refuse (refuses to assume a first start) |
| Record missing, ledger empty | first start: accept |
| Ledger directory missing | refuse; the directory is never created |

## Activation semantics

Two phases:

1. **Check** (`policy_watermark::check`) runs while the bundle loads. It verifies the revision against the current record,
   and writes nothing.
2. **Commit** (`PolicyStore::commit_revisions`) runs as the last step of `build_app_state`, after migrations, the ledger,
   the database pool, and the API key setup have succeeded. Commit takes an exclusive `flock` on
   `policy_watermark.lock`, re-reads the record, re-applies the decision, and writes atomically (temporary file, fsync,
   rename, directory fsync).

A process that fails before commit leaves the record unchanged. Two processes committing at once are serialized by the
lock, so the later commit cannot move the record backwards.

## PostgreSQL decision

The record is not stored in PostgreSQL. The ledger volume is the service's existing durable store for evidence. A table
would add a migration and a second place where the trust boundary is enforced. For a single instance, the file and
`flock` give the required atomicity. A multi-host deployment would need a shared store with a row lock; that is not
implemented, and this report does not claim it.

## Threat model

| Threat | Control | Evidence |
|--------|---------|----------|
| Redeploy an older signed bundle | rollback refused | scenario `revision.*` and unit tests |
| Same revision, changed content | refused | unit test, scenario |
| Failed activation advances the record | commit after startup only | scenario `revision.failed_activation_no_advance` |
| Invalid signature advances the record | check after verification; refused before check | scenario `revision.invalid_signature_no_advance` |
| Concurrent activations regress the record | exclusive flock around re-check and write | unit test; with the lock disabled, 6 of 8 runs failed |
| Lost or deleted record on a non-empty ledger | refused, not recreated | scenario `revision.missing_state_*` |
| Corrupt record | refused | unit test, scenario |
| Signing-key rotation resets protection | not reset: keyed by policy id and content digest | scenario `revision.key_rotation_same_revision` |
| Removed key | bundles from it refused | scenario `revision.old_key_removed` |

**Residual risks (not closed):**

- Whoever can write the ledger volume can rewrite the record to a lower revision, and the service cannot detect it. The
  record is not signed or MAC'd. Closing this needs a key outside the volume, which is a separate design.
- A missing record on an empty ledger is a first start, and the service cannot tell that apart from a deliberate reset of
  an empty deployment.
- The lock is local to one filesystem. Replicas on separate volumes each keep their own record.
- No multi-host shared store is implemented.

## Evidence

| Check | Result |
|-------|--------|
| Watermark unit tests (16), including the concurrency test | 16 passed |
| Concurrency test with the lock disabled (negative control) | 6 of 8 runs failed |
| Revision scenarios on the current code (`revision.*`, real binary) | 14 of 14 passed |
| Same scenarios on the previous commit `d76b069` (negative control) | 5 failed: failed activation advanced the record; missing state with ledger data was accepted; the invalid-signature, key-rotation, and missing-state checks then failed on the advanced record |
| Rollback scenarios (`rollback.*`, real binary) | 6 of 6 passed |
| Local simulation, full (`--skip-live`) | 47 passed, 0 failed |
| Rust `cargo test --locked` | 258 passed, 0 failed, 0 ignored |
| Clippy on the changed Rust | no findings |

Note on the control: the invalid-signature, key-rotation, and missing-state failures on the previous commit follow from the
first defect. The record had already advanced to 3, so the later checks ran against that state. The concurrency scenario
passed in the control because the ordering happened to work out in that run; the lock is shown by its unit test.

## Evaluation gate

Passes when the watermark unit tests (including concurrency), the revision and rollback scenarios against the real binary,
the local simulation, and the Rust suite pass, and the previous commit shows the defects these scenarios catch. All of these
hold for the change set in this PR. PostgreSQL 18 container and Python tests are reported in the pull request.

## Human approval gate

Not approved for production by this report. Merging into `staging` is a separate decision.

Operator decisions required before any multi-instance deployment:

- Whether the ledger volume backup includes the record, and who may reset it.
- Whether to move the record to a shared store with a row lock before running more than one instance.
