# Policy watermark: threat model, architecture, and recovery

Status: 2026-11-24. Applies to the record `<GOVAI_LEDGER_DIR>/policy_watermark.json` in staging and production.
Tracked in issue #501 (design review before multi-instance or production use).

## 1. Definitions

These four properties are different, and the implementation provides only some of them:

| Property | Meaning | Provided now? |
|----------|---------|---------------|
| **Integrity** | Detects changes to the record that the service did not make, provided the attacker does not recompute the tag | Yes, against naive edits, torn writes, and random corruption (SHA-256 `record_sha256`) |
| **Authenticity** | Proves the record was written by a holder of a secret | **No.** The tag is unkeyed. Anyone who can write the file can recompute it. |
| **Freshness** | Proves the record is the latest one ever written | **No.** Needs an independent anchor. |
| **Rollback resistance** | Refuses to accept a policy revision older than one already accepted | Partly. Holds when the record is intact and the service is the only writer on that volume. Fails if an older snapshot of the record is restored. |

## 2. Threats

| # | Threat | Control | Status |
|---|--------|---------|--------|
| T1 | Edit the record to a lower revision, then redeploy an older signed bundle | integrity tag; monotonic check | **Prevented against edits** (tested, real binary) |
| T2 | Edit the digest, policy identifier, or revision without recomputing the tag | tag mismatch refused | **Prevented** |
| T3 | Recompute the tag after an edit | none (unkeyed) | **Not prevented.** This is the authenticity gap. |
| T4 | Restore an older, authentic record (whole file or a volume snapshot) | none | **Not prevented.** Residual. Test `restored_older_checksummed_snapshot_is_a_documented_residual`. |
| T5 | Delete the record while ledger data remains | refused: the service does not assume a first start | **Prevented** |
| T6 | Delete the record on an empty ledger | accepted as a first start | **Not prevented.** Residual: a reset of an empty deployment looks like a first start. |
| T7 | Restore an older ledger snapshot while the record stays newer | the record stays monotonic; the watermark does not check the ledger | **Not detected** by the watermark. The ledger's own hash chain is a separate control. |
| T8 | Replace policy identifiers | tag covers the identifiers; whole-record replacement is T4 | **Prevented** for edits; residual for replacement |
| T9 | Symlink at the record path, the lock path, or the temporary name | `O_NOFOLLOW` reads and lock; unique temporary name created exclusively; refuse to replace a symlink | **Prevented** (tested, real binary). Residual: a race on directory components that an operator changes during a write. |
| T10 | Concurrent activations regress the record | exclusive `flock` around re-check and write | **Prevented** on one host (tested; 6 of 8 runs fail with the lock disabled) |
| T11 | Crash during write | temporary file, fsync, atomic rename, directory fsync | Either the old or the new record survives; both are monotonic. Stray temporary files are ignored and accumulate until removed by an operator. |
| T12 | Failed activation advances the record | commit is the last startup step | **Prevented** (tested) |
| T13 | Signing-key rotation resets protection | the record is keyed by policy identifier and content digest, not by key | **Not reset** (tested by idempotent re-signing) |
| T14 | Legacy (v1) record accepted without a tag | read once, migrated on commit with a log line; v1 is never written again | Accepted once, by design. An attacker who can write a v1 record can substitute it before migration (residual). |
| T15 | Silent fallback to an insecure format | unknown schemas refused; v1 is migrated, not kept | **Prevented** |

## 3. Architecture assessment

Properties each option adds, and what it costs:

**A. HMAC-authenticated record (keyed tag).** Adds **authenticity** against a writer who lacks the key. Does **not** prevent
replay of an older authentic record (T4) by itself: the old record still carries a valid tag. Costs: a secret that must be
provisioned, stored outside the ledger volume, rotated, and never logged. Key rotation needs a design: which keys verify,
which sign, and when old tags stop being accepted.

**B. Domain-separated integrity keys.** A key derived for the watermark, separate from any key used for the ledger, so a
compromise of one does not forge the other. Same costs as A, plus derivation rules. Worth doing only if A is adopted.

**C. PostgreSQL as an independent anchor.** Store `(policy_id, version, digest)` in a table, updated in the same
transaction that commits the record. Startup compares the file with the table and refuses when they disagree: a restored
older file is detected because the table is ahead. This addresses T4 and T6 when only the volume is restored. It does not
help if the database is restored from the same backup as the volume. It uses the existing PostgreSQL that staging and
production already require, so no new service is introduced. It needs a migration (a new table), so the migration count
and the migration tests change. It also gives row locking, which serves multi-instance use.

**D. Bind the record to the ledger's own hash chain.** Include the ledger head hash at commit. Detects a restored ledger
snapshot that is older than the record (T7). Does not help when the ledger and the record are restored together. Cheap, and
uses an existing mechanism, but it is a consistency check, not an anchor.

**Recommendation (not implemented; needs your decision):** C first, because it is the only option here that gives freshness
against a volume-only restore and uses existing infrastructure. Add A if the record is to be authenticated. D is a cheap
addition on top. C also covers the multi-instance case that issue #501 describes.

## 4. Decisions needed (not implemented in this change)

1. Adopt C (PostgreSQL anchor)? If yes: migration, failure behavior when the database is unreachable (fail closed), and
   backup procedure for the database alongside the volume.
2. Adopt A (keyed tag)? If yes: where the key lives, who holds it, how it rotates, and what happens when a key leaks.
3. Accept T6 (empty-ledger reset) for production? If not, first start must be an explicit, logged, operator action.
4. Accept T4 for staging only, pending C? (Current recommendation: yes for staging, no for production.)

## 5. Operator recovery and backup

**Backup.** Back up the ledger volume with `policy_watermark.json` in the same snapshot. Taking the snapshot with the service
stopped avoids a torn copy. Keep the record and the ledger together: a restored ledger without its record is refused
(T5); a restored record without its ledger is accepted and does not reset the revision.

**Restore.**

1. Restore the ledger volume, including the record, from the same backup.
2. Start the service. A valid record is accepted and the revision is retained.
3. If the service refuses with `integrity check failed`, the record was modified or corrupted. Do not edit it by hand: an
   edit fails the tag. Restore the record from a backup taken at the same time as the ledger.
4. If the service refuses with `refusing to assume a first start`, the record is missing but the ledger has data. Restore the
   record. Do not delete the ledger to get past the refusal, and do not create an empty record.

**Legacy migration.** Deployments that ran before this change have a v1 record. The first commit after the upgrade rewrites it
as v2 and logs `policy watermark: migrating a legacy v1 record`. Check for that line once. After migration the v1 format is
refused by design, and no operator action is needed.

**Rollback of content.** Never lower a revision. To return to older content, publish it under a higher revision number
(`docs/operations/policy-signing.md`, "Rollback").

**Stray temporary files.** A crash can leave `policy_watermark.json.tmp.*`. They are ignored. Remove them when the service
is stopped, after confirming that `policy_watermark.json` is present and valid.

**Never** delete, edit, or replace the record to bypass a refusal. Each of those is either detected or is a recorded
decision, and must be logged in the change ticket.

## 6. Keys and logs

The current tag is unkeyed, so there is no integrity key to expose. If option A is adopted, its key must never appear in
logs, evidence exports, or API responses; the implementation must be tested for that before adoption. The refusal messages
name the file path and the reason. They do not include digests or any secret.
