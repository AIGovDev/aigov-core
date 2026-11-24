# Policy revision anchor: protocol, crash consistency, bootstrap, and recovery

Status: 2026-11-24. Staging and production. Tracked in issue #501. Multi-instance runtime support is out of scope.

## 1. What the anchor is

The accepted policy revision is stored in PostgreSQL, in table `policy_revision_anchor` (migration
`0003_policy_revision_anchor`): one row per `policy_id` with `revision`, `digest_sha256`, and `updated_at`. The
filesystem record (`policy_watermark.json` on the ledger volume) is a **cache** of the same information. When the two
disagree, the database row is the authority, and the filesystem record is brought into line with it.

## 2. What it protects, and what it does not

| Property | Status |
|----------|--------|
| A filesystem record older than the anchor is refused, or restored from the anchor | **Protected** (for example, a restored older ledger volume) |
| Deleting the filesystem record does not reset the accepted revision | **Protected** (restored from the anchor) |
| A recomputed integrity tag does not help an attacker who only writes the filesystem | **Protected**: the anchor is the authority |
| A different digest at the anchored revision is refused | **Protected** |
| A failed activation does not advance the anchor | **Protected** (the anchor is written last; see section 4) |
| Concurrent activations cannot move the anchor backwards | **Protected** (advisory lock per policy, plus the per-host filesystem lock) |
| Database unavailable | **Fail closed**: startup refuses; nothing is written |
| Staging or production started without a database URL | **Refused**: there is no path that silently drops the anchor |
| Restored **database and filesystem together** from the same older backup | **Not protected.** Declared residual. |
| Simultaneous rollback of both stores by an attacker | **Not protected.** Declared residual. |
| A privileged database administrator rewriting the row | **Not protected.** Declared residual. |
| Multi-instance activation across hosts | **Out of scope** for this change. The advisory lock serializes the database; the filesystem lock is per host. |

## 3. Decision rules

For a verified bundle with revision `C` and digest `D`, against anchor `A` (if present) and filesystem record `F`
(if present), the service applies these rules in order. The code is `decide` in `rust/src/policy_anchor.rs`.

| Anchor | Filesystem | Outcome |
|--------|-----------|---------|
| absent | present | refuse: bootstrap required |
| absent | absent, ledger holds data | refuse: refusing to assume a first start |
| absent | absent, ledger empty | first start: insert `(C, D)` |
| present | `F` ahead of `A` and `C < F` | refuse: possible database restore |
| present | `F` at `A` with a different digest | refuse: filesystem conflicts with anchor |
| present | `F` ahead of `A`, same revision, different digest | refuse: conflicting pending content |
| present | any | `C < A`: refuse (rollback) |
| present | any | `C == A`, digest differs: refuse (conflicting content) |
| present | any | `C == A`, same digest: idempotent; restore `F` from `A` if behind or missing |
| present | `F` ahead of `A` and `C == F` (same digest) | roll forward: advance `A` to `C` |
| present | any | `C > A`: advance `A` to `C`, and write `F = C` |

Idempotent re-activation writes nothing. Re-signing the same content with a new key or a new expiry keeps the digest,
so it is idempotent (signing-key rotation does not reset the anchor).

## 4. Activation protocol and crash consistency

PostgreSQL and the filesystem cannot be committed together, so the order is fixed and every failure point has a defined
outcome:

1. Take the per-host filesystem lock (`flock` on `policy_watermark.lock`). Read `F`.
2. Open a database transaction and take `pg_advisory_xact_lock(hashtextextended(policy_id))`. Read `A`.
3. Decide (table above). A refusal ends the transaction with nothing written.
4. **Write `F` first**, atomically under the lock.
5. **Commit the database change** (`A` advances, or the row is inserted).

| Crash or failure point | State afterwards | Next start |
|------------------------|------------------|------------|
| before step 4 | nothing changed | normal |
| step 4 fails (filesystem write) | transaction rolled back; anchor unchanged | normal: the activation did not happen |
| after step 4, before step 5 (crash or commit failure) | `F` ahead of `A` | the same bundle rolls the anchor forward; any older bundle is refused |
| after step 5 | both at `C` | normal |

The window "after step 4, before step 5" is the only state where the filesystem leads the anchor. It is resolved
deterministically, and no silent acceptance is possible: an older bundle is refused. The anchor never advances unless
the filesystem write has succeeded first.

Startup is not complete until `commit_revisions` succeeds, and it runs after migrations, the database pool, and the
ledger check. A failure anywhere before it leaves the anchor where it was.

## 5. Migration

- Migration `0003_policy_revision_anchor` creates one table and touches no existing table. It is additive.
- The expected migration count is 3. A database that has not applied it refuses startup with
  `apply migrations (0003_policy_revision_anchor)`.
- Apply it with the normal migration step (`GOVAI_AUTO_MIGRATE=true`, or your existing migration procedure), before
  starting the new version.

## 6. Bootstrap (existing deployment with a filesystem record and no anchor row)

An existing deployment has a `policy_watermark.json` but no anchor row. The service refuses until an operator bootstraps it.
The service never bootstraps from the filesystem on its own: a tampered record would become the anchor.

1. Stop the service. Back up the database and the ledger volume.
2. Read the accepted record and check its integrity tag. The service does this on its next start; inspect the policy entry
   `(V, D)` in `policy_watermark.json`.
3. Confirm `D` is the digest of the bundle that is actually deployed. The digest is the document digest, excluding the
   `signatures` array. Verify it with the same function the service uses (`policy_payload_digest_sha256`, or the
   verification harness `prepare` output). Do not bootstrap from a digest you have not checked against the deployed bundle.
4. As the database administrator, insert the row, once:

   ```sql
   insert into policy_revision_anchor (policy_id, revision, digest_sha256)
   values ('<policy_id>', <V>, '<D>');
   ```

5. Start the service. The same bundle is accepted, and the anchor and the filesystem record agree.
6. Record who performed the bootstrap, the values, and the time in the change ticket.

## 7. Recovery

Never delete, edit, or replace the anchor to get past a refusal. Each refusal is a decision for a human.

| Message | Meaning | Action |
|---------|---------|--------|
| `rollback refused` | The bundle is older than the anchor | Publish the older content under a higher revision (see `policy-signing.md`) |
| `same-revision content change refused` | Same revision, different content | Publish the changed content under a new revision |
| `filesystem record is ahead of the anchor ... possible database restore` | Filesystem newer than anchor and the bundle older than it | Find out whether the database was restored from an older backup. If yes, restore the database from a backup that includes the revision; if no, investigate the filesystem record. |
| `filesystem record conflicts with the anchor` | Same revision, different digest between stores | Investigate which store is right; do not force either |
| `anchor is missing while the filesystem record exists` | Bootstrap needed | Section 6 |
| `refusing to assume a first start` | Ledger data with no record and no anchor | Restore the database and the ledger from the same backup; do not create an empty anchor |
| `apply migrations` | Table missing | Apply migration 0003 |
| `policy revision anchor unavailable` | Database unreachable | Restore connectivity. Startup stays refused until it is back. |

**Restore from backup.** Restore the database and the ledger volume from backups taken at the same time. If only one of them
is restored, the protocol still refuses unsafe combinations (section 3), but it cannot detect a consistent rollback of both.
That is the residual risk.

## 8. Residual risks (declared)

1. Simultaneous rollback of the database and the filesystem to the same older backup is not detected.
2. A privileged database administrator can rewrite the anchor row. The anchor is protected from the filesystem writer,
   not from the database owner.
3. There is no cryptographic authentication of the anchor. A keyed tag or an external signed anchor is an open decision
   (see `policy-watermark-threat-model.md`).
4. Multi-instance deployment is out of scope. Two hosts with separate filesystems each keep their own cache, but the shared
   anchor still applies. Concurrency across hosts is serialized by the database lock, not by the filesystem lock.
5. Development is unchanged. The anchor is not used in development, which keeps no watermark.
