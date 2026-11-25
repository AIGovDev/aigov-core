# Executor store: operations runbook

Scope: the executor's durable store (`executor.sqlite`), its schema, the lifecycle of each execution, recovery after a
crash, reconciliation of an unknown outcome, and receipt delivery. For a customer's executor on one host.

This runbook does not cover Core's own database (PostgreSQL), which is operated under `docs/operations/` for the Rust
service, nor the policy anchor (`docs/operations/policy-anchor-runbook.md`).

## 1. Schema ownership (resolves Decision 1 from the #511 audit)

- **Owner.** The AIGov SDK maintainers own the executor-store schema. Its migrations live in the SDK package, under
  `aigov_py/trusted/migrations/`, numbered and versioned: `0001_executor_store.sql` (schema v1, as shipped in #511), and
  `0002_executor_lifecycle.sql` (schema v2).
- **Writer.** Only the operator tool writes the schema: `python -m aigov_py.trusted.store_admin migrate`. The executor
  never creates or upgrades a table. A process that opens an unmigrated, legacy, or newer store refuses to start.
- **Why this placement.** The repository's rule for shipped packages is that they do not own schema at runtime
  (`docs/operations/runtime-schema-ownership.md`). The schema here is applied out of band, by an operator, before
  first use, so the package ships the migration text as data and never executes it on its own. The Rust service's
  migrations stay in `rust/migrations/`, because that database belongs to Core. This store is customer-operated local
  state, so it is versioned with the SDK.
- **Review.** Owners should confirm this placement. If they prefer a different location, the migration files move with
  no change to the schema.
- **Rules for future migrations.** A migration is a new numbered file. An applied file is never edited. A migration
  adds columns or tables, or relabels rows; it never drops or rewrites a record. A destructive change needs its own
  reviewed decision and is not made by this procedure.

## 2. Installation

```bash
pip install aigov-py                              # or the wheel built from the release
python -m aigov_py.trusted.store_admin migrate --db /var/lib/aigov/executor.sqlite \
    --backup-dir /var/backups/aigov
python -m aigov_py.trusted.store_admin status --db /var/lib/aigov/executor.sqlite
```

`status` must report `"current": true` and `"schema_version": 2` before the executor starts. The executor checks the
same thing when it opens the store and refuses otherwise.

For a new store, `migrate` creates the file. No backup is taken, because there is nothing to back up.

## 3. Upgrades

1. Stop the executor process. Recovery does not need to run first; a stopped executor cannot act.
2. Take a backup, even though `migrate` takes one itself, so that the copy is one you chose:

   ```bash
   cp /var/lib/aigov/executor.sqlite /var/backups/aigov/manual-$(date -u +%Y%m%dT%H%M%SZ).sqlite
   ```

3. Run `migrate` with `--backup-dir`. The tool takes a backup (`<name>-v<from>-<timestamp>.sqlite`), applies the pending
   migrations inside one transaction, checks the final version, and verifies the history chain. A failure rolls back and
   leaves the file as it was. The tool's output records the backup path and the chain check.
4. Check `status` and `verify-history`. Both must pass.
5. Start the executor, and let it run `recover` (section 6) at startup.

A v1 store is upgraded in place. Every v1 record is preserved. The upgrade relabels states as follows, and the history
records the origin of each row:

| v1 state | v2 state | Why |
|---|---|---|
| `reserved` (never finished) | `reconciliation_required` | the side effect may have run; never retried |
| `executed` with a receipt | `succeeded`, receipt `recorded` | the receipt reached Core |
| `executed` without a receipt | `succeeded`, receipt `none` | reported by `missing-receipts` |
| `failed` | `failed`, receipt `none` | reported by `missing-receipts` |

## 4. Backup and restore

- **What to back up.** The executor store file, and the backup directory's copies are themselves backups. Back up the
  file while the executor is stopped, or with `sqlite3 <file> ".backup <dest>"` while it runs. A plain file copy of a
  running store can be inconsistent.
- **Restore.** Stop the executor. Copy the backup into place. Run `status` and `verify-history`. Then start the
  executor and run recovery. A restored store may be behind Core: executions that Core has recorded after the backup
  was taken will appear unresolved or with a receipt missing, and recovery settles them from Core's export. It never
  repeats an action with an unknown outcome, so a restore cannot make an action run twice.
- **Never** restore a store over a live executor's file, or run two executors against one file. The store serialises
  writers on one host. It is not a shared store across hosts (see Limitations in the SDK reference).

## 5. The lifecycle

Each execution has one row and one history. The states, and the only transitions between them:

```
reserved -> started -> succeeded | failed | outcome_unknown -> reconciliation_required -> reconciled
reserved -> failed        (refused before any side effect: revoked, expired, not authorized, arguments unavailable)
```

Terminal states: `succeeded`, `failed`, `reconciled`. A receipt has its own state: `none`, `pending`, `recorded`.

What each state means for an operator:

| State | Meaning | Automatic action |
|---|---|---|
| `reserved` | Authorized and reserved. The side effect has not started. | Recovery resumes it once, after re-checking Core |
| `started` | The side effect is about to begin, or has begun, under a lease. | Recovery waits for the lease to expire, then records `outcome_unknown` |
| `outcome_unknown` | No definite outcome. Transitional: it moves to `reconciliation_required` in the same transaction. | None |
| `reconciliation_required` | Waiting for signed evidence about the external system. | **None. Never retried.** |
| `succeeded` / `failed` | A definite outcome was recorded. | Receipt delivery is retried |
| `reconciled` | Signed evidence was applied. The reconciled outcome is in `reconciled_outcome`. | Receipt delivery is retried |

## 6. Recovery after a restart

Run this at executor startup, in the process that owns the performer:

```python
from aigov_py.trusted import Executor
actions = executor.recover()        # safe to call any number of times
```

`recover` returns one action per unresolved execution. The actions:

| Action | Meaning | Operator follow-up |
|---|---|---|
| `resumed_once` | A reservation that had not started was performed once | none |
| `closed_without_action` | Refused before any side effect, with the reason | none, unless the reason is `stored_arguments_unavailable` (see below) |
| `deferred` | Core could not be asked. Nothing was performed. | none; it resumes when Core is back |
| `skipped` | A live worker holds the execution | none |
| `outcome_unknown` | A started execution whose lease expired. Now awaiting reconciliation. | **Reconcile (section 7)** |
| `awaiting_reconciliation` | Already unknown | **Reconcile** |
| `receipt_recorded` | A receipt was delivered, or settled from Core's export | none |
| `receipt_still_pending` | Core could not be reached; the receipt will be retried | none |

`stored_arguments_unavailable` means the reservation's stored arguments are missing or do not match the authorization's
digest. The executor will not guess the arguments, so it closes the execution without action. Investigate how the
arguments were lost, using `inspect`.

## 7. Reconciliation (unknown outcomes)

An execution in `reconciliation_required` is never run again by the executor. Someone must establish what happened in
the external system, and record it with signed evidence.

1. Find the execution: `python -m aigov_py.trusted.store_admin pending --db <file>`, or `report`.
2. Inspect it: `inspect --authorization-id <id>`. The history shows the start, the lease, and the outcome-unknown entry.
3. Check the external system by your own means. Keep the evidence (a statement, a confirmation, a log extract).
4. Sign the finding with the reconciler's key, which the operator holds (`sign-evidence`):

   ```bash
   python -m aigov_py.trusted.store_admin sign-evidence --db <file> --seed-file reconciler.json \
       --authorization-id <id> --outcome succeeded --external-reference "<system reference>" \
       --evidence-file proof.pdf > signed.json
   ```

   `outcome` is `succeeded`, `failed`, or `not_executed`. `not_executed` means the external system shows the action did
   not happen. The authorization is then closed. Running the action again needs a **new** authorization, which needs a
   new human approval. There is no command that re-runs an execution.

5. Apply it: `reconcile --db <file> --registry registry.json --evidence-file signed.json`.
   The tool verifies the signature against the pinned registry, checks every binding field against the stored
   execution, checks that the execution is awaiting reconciliation and the observation time is plausible, and then
   appends the evidence to the history. It prints the receipt's pending state.
6. Deliver the receipt: `resubmit-receipts --db <file> --core-url <url> --executor-key-env GOVAI_EXECUTOR_KEY`.

Refusals are reported with a reason and change nothing:

| Reason | What it means |
|---|---|
| `reconciliation_signature_invalid` | The signature does not verify under the registered key, or the payload was altered |
| `reconciler_not_authorized` | The signer is not in the registry, even if the key is valid |
| `reconciliation_binding_mismatch` | The evidence names a different execution, tool, arguments, or executor |
| `reconciliation_not_required` | The execution is not awaiting reconciliation, or this evidence was already applied |
| `reconciliation_timestamp_invalid` | Observed before the reservation, or in the future |
| `reconciliation_outcome_invalid` | Not `succeeded`, `failed`, or `not_executed` |
| `reconciliation_schema_mismatch` | The envelope is not reconciliation evidence |

**Escalation.** If the external system cannot settle the question, record it for manual investigation. This changes no
state and is kept in the history: `sign-escalation`, then `escalate`.

**The registry.** `registry.json` is `{"reconcilers": {"<identity>": "<public key, base64>"}}`. The operator maintains
it. Adding a reconciler is a reviewed change. Removing one takes effect immediately for every future evidence
envelope. Keep reconciler seeds out of the executor's environment; the executor never signs evidence.

## 8. Receipts

A receipt is evidence that an execution was recorded. Its delivery is retried. Its content is derived from the stored
row, so a resent receipt is the same evidence. It never runs the action.

- `pending`: written locally with the outcome. Delivery has not been acknowledged.
- `recorded`: Core acknowledged it, or its export shows it.
- `none` on a finished execution: a legacy row, or one whose receipt was never written. `missing-receipts` lists them.
  `recover` attaches a receipt to each one from its stored outcome.

Core rejects a duplicate event id. The executor settles a duplicate, or an unclear timeout, by looking the receipt up in
the run's export, and resubmits only if the export does not contain it.

## 9. Visibility

`report --db <file>` prints one JSON document:

- `by_state`, `pending_executions`, `unknown_outcomes`, `reconciliation_backlog`, `reconciliation_backlog_ids`
- `missing_receipts`, `pending_receipts`, `recovery_failures` (refusals caused by local state)
- `unresolved`: each unresolved execution with its state and lease
- `latency_ms`: `reserve_to_start`, `execution`, `receipt_delivery`, each with count, p50, p95, and max, computed from the
  history's timestamps
- `history.chain_verified`

Alert on any of these: `unknown_outcomes` above zero for longer than your reconciliation SLA; `reconciliation_backlog`
growing; `missing_receipts` or `pending_receipts` not falling after a restart; `recovery_failures` above zero;
`history.chain_verified` false. The executor also emits one structured log line per transition through the
`aigov_py.trusted.executor` and `aigov_py.trusted.receipts` loggers, which your log pipeline can collect.

## 10. Integrity

- `verify-history` recomputes the hash chain over every event. It detects a changed, reordered, or removed event.
- The history table refuses updates and deletes by trigger, so a normal database client cannot edit it.
- `report` includes the chain check. A store that fails it must not be trusted without investigation.
- The executions table is not part of the chain. Its rows must agree with the history: the state of each row must equal
  the last transition recorded for it. The check for this is `ExecutionStore.verify_projection()`; `verify-history` does
  not run it. Run it as part of any audit.

## 11. Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `SchemaMissing ... does not exist` | No file at the path | Run `migrate` to create it |
| `SchemaVersionMismatch ... version 1` | A v1 store | Run `migrate --backup-dir` |
| `SchemaVersionMismatch ... newer SDK` | The file was written by a newer SDK | Use that SDK |
| Executor refuses with `core_unavailable` | Core is down or unreachable | Restore Core. Nothing ran, nothing was recorded |
| `authorization_receipt_recorded` on a retry | Core already holds the receipt | Expected. The action ran once |
| `authorization_replayed` | This host already reserved the authorization | Expected for a second worker |
| `authorization_already_started` | Another worker started it | Expected for a second worker |
| `skipped` in recovery, for a long time | A worker is alive, or crashed with a lease that has not expired | Wait for the lease (`lease_seconds`), then recover again |
| `missing_receipts` growing | Core is refusing receipts | Check the receipt refusal in the log; `resubmit-receipts` after the cause is fixed |
| `history.chain_verified: false` | The history was altered outside the store | Stop, preserve the file, and investigate; do not continue on it |

## 12. Limitations

- One host per store. The store serialises writers on that host. For executors on several hosts, a shared store with the
  same atomic guarantees is required; it is not provided by this release.
- The lease must exceed the longest external call. A worker that runs longer than its lease can be treated as dead
  while still acting. Set `lease_seconds` above your longest call.
- Recovery cannot see the external system. It settles only what Core and the store record. An outcome that only the
  external system knows is settled by reconciliation, not by the executor.
- Reconciliation depends on the reconciler's diligence. The signature proves who signed, not that the finding is true.
