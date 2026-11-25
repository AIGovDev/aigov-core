# Executor lifecycle, crash recovery, and reconciliation — 2026-11-25

## Scope

Makes the trusted executor operationally recoverable after crashes, network failures, and ambiguous external outcomes.
Starts from `origin/staging` at `877d11f`, which includes PR #511 (merged; verified before any work). Refs #501, which stays
open: #501 is the policy-revision anti-rollback review, a different problem, and nothing here meets its acceptance
criteria. No Railway change, no deployment, no external infrastructure beyond local Docker, no paid API, no merge.

## Decision 1 from the #511 audit: schema ownership (resolved)

- **Owner.** The SDK maintainers own the executor-store schema, as versioned migrations in the package:
  `0001_executor_store.sql` (schema v1, as shipped in #511) and `0002_executor_lifecycle.sql` (schema v2).
- **Writer.** Only the operator tool applies them: `python -m aigov_py.trusted.store_admin migrate`. The executor never
  creates or upgrades a table. A store at a missing, legacy, or newer version is refused at open time.
- **Why in the package.** The schema belongs to the executor, which ships with the SDK. It is applied out of band, so the
  package never executes it, which keeps the repository's rule (`docs/operations/runtime-schema-ownership.md`) intact.
- **Review requested.** The owners should confirm this placement. The migrations are data, and they can move without
  change to the schema.
- **Procedure.** Backup before every upgrade (taken by the tool, with a documented manual copy), one transaction per
  migration, rollback on failure, and a verified history after. Documented in `docs/operations/executor-store-runbook.md`.

## Lifecycle

States: `reserved`, `started`, `succeeded`, `failed`, `outcome_unknown`, `reconciliation_required`, `reconciled`. Receipt
states: `none`, `pending`, `recorded`.

```
reserved -> started -> succeeded | failed | outcome_unknown -> reconciliation_required -> reconciled
reserved -> failed        (refused before any side effect)
```

Each transition is checked against a fixed table inside the transaction that records it. Each row carries the
authorization id, the executor identity, the tool, the argument digest, and the policy revision. Existing states were
reused where they existed (`reserved`, `executed` relabelled as `succeeded`, `failed`), and `outcome_unknown` and
`reconciliation_required` were added. An unknown outcome is never retried.

Concurrency: reservation is atomic (`BEGIN IMMEDIATE`). Core refuses an authorization once it has a receipt. Eight
processes racing for one authorization produce exactly one execution, against a real Core.

## History

`execution_events` is append-only (triggers refuse updates and deletes), and each entry is hash-chained to the previous
one. `verify_history()` detects altered, reordered, or removed entries. `verify_projection()` checks that every
`executions` row agrees with its last recorded transition. It was added after the first design left the projection
outside the chain, which the negative controls show as a real gap.

## Crash recovery: results at every boundary

Each boundary is a real process termination (`os._exit`) in a child process. The live run used the Core under test and
PostgreSQL. The side effect is a local log; its line count is the number of times the action ran.

| Boundary | Result after restart |
|---|---|
| Before reservation | nothing persisted; retry runs once |
| After reservation, before execution | resumed once; receipt reached Core once |
| Immediately before the side effect | outcome unknown after the lease expires; **not retried** (count stays 0) |
| During the side effect | outcome unknown; **not retried** (count stays 1) |
| After the side effect, before the outcome | outcome unknown; **not retried** |
| After the outcome, before the receipt | receipt delivered on restart; action not repeated |
| After Core stored the receipt, before the acknowledgement | settled from Core's export; **no duplicate receipt** |
| During recovery itself | next restart resumes once |
| Core unavailable during recovery | deferred; nothing performed; resumed once Core returned |

Measured: the live run recorded 53 of 53 checks in Docker mode and 53 of 53 in binary mode (release `aigov_audit`,
PostgreSQL 18). Resuming a reservation took 323 ms end to end, including starting the child process (Docker run).

## Reconciliation

Signed evidence only: Ed25519, domain-separated, from a reconciler in a pinned registry. The evidence is applied only if
the signer is registered, the signature verifies, every binding field matches the execution, the execution awaits
reconciliation, the outcome is one of `succeeded`, `failed`, `not_executed`, and the observation time is plausible. The
evidence is appended; earlier history is kept. Live results:

- forged signature by an unregistered key: refused (`reconciliation_signature_invalid`), state unchanged;
- unlisted reconciler identity: refused (`reconciler_not_authorized`);
- evidence bound to another tool: refused (`reconciliation_binding_mismatch`);
- authorized evidence: applied; the outcome receipt reached Core as `reconciled:succeeded`; the history keeps
  `outcome_unknown` and `reconciled`, and verifies;
- a reconciliation interrupted inside its transaction: nothing applied; retry applies it once (lifecycle suite).

There is no force-execute and no force-success. `not_executed` closes the authorization; running it again needs a new
authorization and a new human approval.

## Receipts and idempotency: what each mechanism guarantees

| Mechanism | Guarantee in this release |
|---|---|
| Authorization single use (Core) | one authorization per approval; a second use is refused (live) |
| Executor reservation (store) | one reservation per authorization per host (live, eight processes) |
| Receipt delivery retry | re-sent without repeating the action; duplicates settled by Core's export (live) |
| Downstream idempotency | the performer receives `execution_key(authorization_id)`, stable across retries and resumes. Whether the external system honours it is **not verified** here |
| Exactly-once external execution | **not claimed**. Unknown outcomes are held for reconciliation |

A bug found in live testing: Core requires a non-empty result digest on every receipt, but failed, refused, and reconciled
executions have no result data, so the receipt was rejected. Every receipt now carries a deterministic digest of its
recorded outcome.

## Visibility

`report()` and `store_admin report` give state counts, pending executions, unknown outcomes, the reconciliation backlog,
missing and pending receipts, recovery failures (local-state refusals), the unresolved list, both integrity checks, and
latency from the history's timestamps. Final measured values across the live run's stores:

- execution (started to finished): 7 samples, p50 2.8 ms, max 2.8 ms (the performer is a local file write);
- receipt delivery (finished to recorded): 7 samples, p50 206 ms (one HTTP round trip to Core, per receipt), max 206 ms;
- reserve to start: 11 samples, maximum about 21 s. That is the Core-outage scenario, in which a reservation waited
  through the outage and then resumed. The figure is the outage, not executor overhead.

Structured logs are emitted per transition through `aigov_py.trusted.executor` and `aigov_py.trusted.receipts`, which the
existing logging of the host collects. No external monitoring was added.

## Negative controls against the staging implementation

The same six controls were run against `origin/staging` (877d11f) and against this change, with the same harness
(`scripts/executor_negative_controls.py`, evidence in `docs/evidence/executor-lifecycle/`). The first attempt was invalid: child processes
started in the repository root and imported the root-level `aigov_py` shim instead of the package under test. The fix
starts every child in a scratch directory; the results below are from the corrected runs.

| Control | Staging | This change |
|---|---|---|
| C1 crash in the middle of the side effect | row `reserved`, indistinguishable from never-started; restart refused as replay; **cannot tell the action ran** | row `started` under a lease; recovery waits for the lease, then records `outcome_unknown`; the operator can see it ran |
| C2 receipt lost after Core stored it | store has no receipt; Core has one; **never reconciled** | receipt re-sent from the export; store and Core agree |
| C3 two workers race | one execution; refusals `authorization_receipt_recorded` | one execution; refusals `authorization_receipt_recorded` and `authorization_replayed` |
| C4 external system fails mid-call | exception escapes; row `reserved`; **not recorded as unknown** | `outcome_unknown`, then `reconciliation_required`; not retried |
| C5 recorded outcome edited | **accepted, undetected** | accepted by the database, **detected** by `verify_projection` |
| C6 capabilities | no versioned migrations, no reconciliation, no recovery, no report, no append-only history; schema version 0 | all present; schema version 2 |

C3 is the one control both implementations pass. The difference in refusal reasons is the order of the checks, not a
behavioural difference.

## Bugs found and fixed during the work

1. A v1 `reserved` row was mapped to `outcome_unknown`, which can never be reconciled. Mapped to `reconciliation_required`.
2. Reserved executions did not store their arguments, so a crashed reservation could not be resumed. Arguments are now
   stored with the reservation, and their digest is checked before any resume.
3. Receipts carried an empty result digest, which Core refuses (found by the live run). Fixed.
4. A module named `operator` shadowed Python's standard library when a script ran from its directory. Renamed to
   `store_admin`.
5. The projection (the `executions` table) was outside the hash chain. A projection check was added.
6. The performer's idempotency key changed on every attempt. It is now stable per authorization.
7. The first negative-control run was invalid (see above). Discarded and rerun.
8. Two live-driver errors (a run-id mismatch in the driver, and a receipt query on an empty run) were driver bugs, not
   executor bugs; corrected in the driver.

## Validation

All on the final tree (the last code change was the stable idempotency key; every run below is after it).

| Check | Result |
|---|---|
| Lifecycle, crash-recovery, reconciliation, migration, and operator suite (`test_executor_lifecycle.py`) | 43 passed |
| Full Python suite (`pytest python/tests`) | 1185 passed, 61 skipped (the skips are database-gated), exit 0 |
| Live recovery validation, Docker Core and PostgreSQL | 53 of 53 checks passed |
| Live recovery validation, release Core and PostgreSQL 18, binary mode | 53 of 53 checks passed |
| Reference, live Core (27 service-backed tests) | 27 passed |
| Acme Finance validation, Docker Core | 8 of 8 cases, 38 of 38 checks |
| Customer pilot end to end | 45 pass rows, 0 failing |
| Quickstart (Docker) | evidence checks pass |
| Downstream check from the installed wheel, offline | passed |
| Downstream check from the installed wheel, live (Docker Core) | refund executed once; 10 evidence checks pass |
| Staging policy harness, `--skip-live`, throwaway PostgreSQL 18 | 66 passed, 0 failed |
| Negative controls (staging and change) | recorded in `docs/evidence/executor-lifecycle/` |
| `make gate` | passed |
| Lint of changed Python (ruff) | clean for changed code |

Concurrent runs: the quickstart and the Acme validation were run at the same time on separate Cores and databases during
the #510 work, before this change, and each cleaned up only its own prefixed resources. The live recovery run stops only its
own Core, by name. It was not re-run concurrently on the final tree.

## Remaining limitations

- One host per store. Several executors on several hosts need a shared store with the same atomic reservation, which this
  release does not provide.
- The lease must exceed the longest external call. A longer call can be mistaken for dead while still acting.
- Recovery cannot observe the external system. Only reconciliation, by a person with signed evidence, resolves an
  unknown outcome.
- Downstream idempotency is not verified for any external system. The performer receives a stable key; whether the
  system honours it must be tested by the customer.
- Exactly-once across an external system is not claimed.
- The reconciler's signature proves who signed, not that the finding is true.
- The reconciler registry is maintained by the operator and is not rotated automatically.
- Timings are from one machine and single runs.
- The package version is unchanged. A bump is a release decision.

## Evaluation gate

Passes when: the executor's lifecycle is explicit, persistent, and enforced in the store; each boundary in the crash list
is tested with real process termination and recovers to the state its evidence supports, with no repeated action after an
unknown outcome; reconciliation accepts only authorized, correctly bound, signed evidence and keeps the history; schema
upgrades preserve every v1 record and are tested from the supported schema; the store refuses unmigrated and incompatible
files; the operator tool exposes reconciliation, escalation, and receipt resubmission without any force command; the
negative controls show the staging gaps and that this change closes them; and the affected suites, the live validations,
the harness, and `make gate` pass on the final tree. These hold for the tree recorded above, subject to CI on the final
HEAD.

## Human approval gate

Not approved for production by this report. Before production use, the owners must review Decision 1's placement; a
decision on the shared-store question for multi-host executors is needed; the reconciler registry needs an operating
procedure with rotation; the lease length must be set for each customer's longest call; and downstream idempotency must
be verified per external system. Issue #501 remains open and is not addressed. Merging into `staging` is a separate
decision, and this report does not make it.
