# Policy watermark integrity hardening — 2026-11-24

## Scope

Strengthens the persistent policy revision record (`policy_watermark.json`) merged in #500 (`c5697cf`). Multi-instance
deployment is out of scope and remains in issue #501. This change adds no external infrastructure, does not modify Railway,
and does not deploy anything.

The threat model, the architecture assessment with alternatives, and the operator recovery procedure are in
`docs/operations/policy-watermark-threat-model.md`.

## What changed

- **Integrity tag.** The record carries `record_sha256`, the SHA-256 of the canonical JSON of its schema and policies. An edit
  that does not recompute the tag is refused. The tag is **not** authentication: anyone who can write the file can recompute
  it. Authenticity needs a keyed tag, which is an architecture decision (see the threat model).
- **Symlink refusal.** The record and the lock are opened with `O_NOFOLLOW`. A symlink in place of the record is refused. The
  temporary file is created exclusively under a unique name, and a symlink at the record path is never replaced.
- **Explicit migration.** A legacy v1 record (no tag) is read and migrated to v2 on the next commit, with a log line. v1 is never
  written again, and unknown schemas are refused. There is no silent fallback to the legacy format.
- **Defensive schema check.** The v1 schema value is checked after parsing, not left unused.

## Evidence

| Check | Result |
|-------|--------|
| Watermark unit tests (28, including integrity, symlink, torn write, legacy migration, concurrency, residual) | 28 passed |
| Negative control, unit tests: the new integrity and symlink tests run against the previous module (`c5697cf`) | 8 of the new tests fail there |
| Negative control, real binary: integrity scenarios against `c5697cf` | 3 of 5 fail: the record carries no tag; a symlinked record is followed and accepted; an edited record is refused only by an unrelated rule |
| Integrity scenarios on the current code, real binary (`integrity.*`) | 5 of 5 pass |
| Local simulation, full (`--skip-live`) | 52 passed, 0 failed |
| Clippy on the watermark module | no findings |

The negative controls show that the tests detect the original weaknesses.

## Threat model summary

| Property | Status |
|----------|--------|
| Integrity against naive edits, torn writes, and random corruption | provided (tag) |
| Authenticity | **not provided** (unkeyed tag) |
| Freshness | **not provided** (no independent anchor) |
| Rollback resistance against edits, failed activation, concurrency, and missing state | provided |
| Rollback resistance against restoring an older authentic snapshot of the record | **not provided** (residual; test `restored_older_checksummed_snapshot_is_a_documented_residual`) |
| Empty-ledger reset | **not provided** (residual) |

## Residual risks

- An attacker with write access to the ledger volume can restore an older authentic record, and the service accepts it.
- A restored older ledger snapshot with a newer record is not detected by the watermark.
- An empty ledger with a reset record is a first start.
- Legacy v1 records are trusted once, at migration.
- Stray temporary files from a crash accumulate until an operator removes them.

These need an independent anchor (PostgreSQL, option C in the threat model) and, for authenticity, a keyed tag (option A). Neither
is implemented here, pending the decisions in the threat model and issue #501.

## Evaluation gate

Passes when the watermark unit tests pass, the integrity and revision scenarios pass against the real binary, the previous
commit fails the new scenarios, the Rust suite passes, clippy is clean on the module, and `make gate` passes. All of these hold
for the change set in this PR. PostgreSQL 18 and container results are reported in the pull request.

## Human approval gate

Not approved for production by this report. Merging into `staging` is a separate decision. The threat model's decisions 1 to 4
require a human decision before production, and before any multi-instance use, which remains tracked in issue #501.
