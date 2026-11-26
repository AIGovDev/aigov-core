# Distributed execution: architecture

Status: implemented on branch `feat/distributed-execution`. Verified locally only. No production deployment is claimed. Read
this with the runbook (`docs/operations/distributed-execution-runbook.md`) and the audit report
(`docs/reports/distributed-execution-2026-11-26.md`).

## Components and where their state lives

| Component | State | Shared across processes by | Authority for |
|---|---|---|---|
| Core ledger (`GOVAI_LEDGER_DIR`) | hash-chained JSONL per tenant, sidecar state and run index | a cross-process `flock` on `<ledger>.lock` (one host) | evidence order, duplicate event ids, approval consumption |
| Core policy revision | `policy_watermark.json` (per host), `policy_revision_anchor` (PostgreSQL) | PostgreSQL row lock and advisory lock | accepted policy revision (anti-rollback) |
| Trusted key registry | signed event log (per registry), `key_registry_anchor` (PostgreSQL) | PostgreSQL row lock; file lock on the log | which keys may sign, and when |
| Executor store | `executions` and `execution_events` (PostgreSQL, shared) or SQLite (one host) | PostgreSQL transactions, or `BEGIN IMMEDIATE` | at most one execution per authorization; outcomes; receipts |
| Downstream system | whatever it is | its own idempotency handling (see "What is not guaranteed") | the external effect |

Core's ledger is host-local. Several Core instances on one host share a ledger volume and serialize through the file lock.
Instances on different hosts must not share a ledger volume (see "Supported topologies").

## Executor store (PostgreSQL)

`python/aigov_py/trusted/store_pg.py`, schema `migrations/pg/0001_executor_pg.sql`, applied by `store_admin migrate-pg`.

Guarantees, and where each one is enforced:

- **One execution per authorization, across tenants.** `executions.authorization_id` is the primary key. A reservation is
  `INSERT ... ON CONFLICT DO NOTHING`. A second reservation returns false, in any process and for any tenant.
- **Atomic claim with a fence.** `start` is `UPDATE ... WHERE state = 'reserved'`, and it increments `fence`. The fence value
  is the claim's token. Only a token equal to the current `fence` on a `started` row can finish or mark that row. Anything else
  raises `StaleWorker` and writes nothing.
- **Leases on database time.** `lease_until = now() + interval` is computed by PostgreSQL. Expiry (`expire_lease`) compares it
  with `now()` in the database. Worker clocks never enter the decision.
- **Append-only history.** `execution_events` refuses UPDATE, DELETE, and TRUNCATE (triggers). Each row chains to the previous
  one by hash. `verify_history` recomputes the chain. An administrator who disables a trigger and edits a row is detected by
  the chain (tested).
- **Tenant isolation.** Every query is scoped by the store's tenant. Another tenant's execution looks like no execution.
- **Receipt recording is idempotent.** Recording the same receipt id again is a no-op. A different id is refused.
- **Schema versioning.** `executor_schema_migrations` records each applied version. The store refuses a database whose version
  is not the one it requires. Migrations are applied only by `store_admin migrate-pg`, under an advisory lock.

### Lock order and transaction boundaries

Every store transaction takes the execution's row lock first (an insert, an `UPDATE ... WHERE state = ...`, or
`SELECT ... FOR UPDATE`), and only then the chain lock (`pg_advisory_xact_lock(CHAIN_LOCK_KEY)`), which serializes appends to
the global hash chain. No transaction takes the chain lock and then a row lock, so two transactions cannot wait on each other
in a cycle. PostgreSQL's deadlock detector remains the backstop; a deadlock abort is a `TransactionRollbackError`, which the
store reports as `StoreUnavailable`, and nothing is committed.

Isolation: the default `READ COMMITTED`. Correctness does not depend on snapshot reads. Every decision that changes state is
taken under a row lock and re-checked on the locked row (`state`, `fence`, `receipt_state`). The chain lock makes the
`prev_hash` read and the insert one step.

Connections: one connection per store operation (short transactions). This keeps the store free of connection state, at the
cost of one round trip to open. A connection-limited role makes operations fail with `StoreUnavailable`, and the executor
refuses those calls before any side effect (tested).

## Executor coordination

The executor's order of operations is unchanged from the SDK (verify, status, reserve, start, side effect, finish, receipt).
What changed is which state the executor trusts:

1. **Reserve** (`reserve`): on `StoreUnavailable` the call is refused (`store_unavailable`). Nothing has started.
2. **Start** (`start`): returns the fence. The side effect is called only after this commit.
3. **Side effect**: the performer receives a stable idempotency key, `execution_key(authorization_id)`, which is the same on
   every retry and every resume. A downstream system that deduplicates on it makes its own retries safe.
4. **Finish** (`finish`, with the fence): refused with `StaleWorker` if the claim was taken over. The executor then reports
   `stale_worker` and sends no receipt for an outcome it could not record. If the database fails here (`StoreUnavailable`), the
   executor reports `outcome_not_recorded`. The row stays `started` under its lease.
5. **Receipt** (`receipts.deliver`): sent to Core, then recorded idempotently. A store failure leaves the receipt pending. A
   later recovery delivers it again. The action is never repeated for a receipt.

### Recovery

`recover()` decides from the store:

- `reserved`, never started: performed once, after the stored arguments are checked against their digest.
- `started`, lease expired (database clock): `expire_lease` moves it to `outcome_unknown`, then to
  `reconciliation_required`. It is never retried automatically. An expired lease is the only way recovery touches a started row.
- `started`, lease not expired: skipped. A live worker holds it.
- `finished` with a pending or missing receipt: the receipt is delivered again. The action is not repeated.

## Core under concurrency

Audited paths, and what each one relies on:

| Path | Serialization | Verified by |
|---|---|---|
| Ledger append, duplicate detection, approval consumption check | in-process mutex (per path) and cross-process `flock` on `<ledger>.lock`, held before the state read | two Core processes, 200 concurrent appends, and duplicate event ids sent to both (`test_distributed_core_ledger.py`) |
| Checkpoint append, tail repair | the same `flock` (`append_checkpoint`, `repair_trailing_partial_record`) | by construction; no nested call (a second `flock` on the same process would deadlock, so the append path does not call these) |
| Policy revision activation | PostgreSQL advisory transaction lock per policy, plus the host's `flock` on the watermark | `policy_anchor_pg` tests: concurrent activations, restored snapshot, deleted record, missing anchor |
| Key registry rotation and revocation | the anchor's row lock (PostgreSQL) and the log's file lock | `test_registry_postgres.py`: six processes revoke one key, exactly one applies |
| Authorization issuance during key or policy change | issuance re-reads the registry under the anchor before it signs, and re-checks the key before signing | `execution_authorization` tests (rotation and revocation between prepare and sign) |

## Time-of-check to time-of-use gaps (audit)

These gaps are real and are not closed by the database:

- **Core status to side effect.** The executor asks Core for the authorization's status, then reserves, starts, and performs the
  side effect. A revocation recorded in Core after the status check and before the side effect is not seen by this call. The
  window is the time between the status request and the performer's first effect. It is measured in milliseconds and is not
  zero. Only a revocation that Core makes effective before the executor's status check is honoured.
- **Expiry.** The executor checks `expires_at_utc` before reserving. An authorization can expire during the side effect.
  The side effect is not interrupted.
- **Downstream effect.** The database cannot make an external system apply an action once. See the next section.

## What is guaranteed, and what needs the downstream system

Guaranteed by the database, for the store's own state:

- At most one reservation per authorization, and at most one claim holder at a time.
- A finish or an unknown-outcome mark only from the current claim holder.
- No automatic retry of an execution whose outcome is unknown.
- A tamper-evident history, and an append-only history at the database level.

Not guaranteed by the database, and requiring the downstream system to cooperate:

- **Exactly-once external side effects.** A crash after the side effect and before the outcome is recorded leaves the row
  `reconciliation_required`. The executor does not know whether the external system applied the action. Only signed
  reconciliation evidence from that system resolves it.
- **Deduplication at the downstream system.** The stable key `execution_key(authorization_id)` lets a downstream system refuse a
  second application of the same authorization. The executor cannot enforce that. A downstream system without a deduplication
  key can apply the action twice if it is retried by hand.
- **Visibility.** An external system's state is not in the store. Reconciliation brings it in as signed evidence.

## Supported and unsupported topologies

Supported (verified locally):

- Several executor processes on any number of hosts, sharing one PostgreSQL executor store (one tenant per store object).
- Several Core instances on one host sharing one ledger volume, with a working `flock` (Linux and macOS local file systems, and
  a Docker named volume on one Docker host, verified with the example in `examples/distributed-execution/`).
- PostgreSQL as the shared store for the policy anchor and the key registry anchor (verified with PostgreSQL 18).

Not supported (not verified, and known to be unsafe):

- Several Core instances on **different hosts** sharing one ledger directory. The ledger's serialization is a host-local `flock`.
  Over NFS or another network file system, `flock` is not a reliable cross-host lock. Use one ledger host per tenant, or move the
  ledger into the database (not in this change).
- The SQLite executor store across hosts. It is a one-host store.
- A PostgreSQL deployment with a database administrator who can edit the anchors and the history together. See the runbook's
  residual-threat section.

## Failure behaviour

The rule: fail closed when the authoritative state cannot be established.

| Failure | Behaviour | Evidence |
|---|---|---|
| Store unreachable before reservation | refused `store_unavailable`; no side effect | `test_an_executor_that_cannot_reach_the_store...`; connection-exhaustion test |
| Store lost after the side effect | `outcome_not_recorded`; no receipt; row left `started` under its lease; recovery marks it unknown | network-cut test (proxy) |
| Process killed after the side effect | row `started`; after the lease, `outcome_unknown`; never re-run | crash test |
| Process killed after reserving | after recovery, performed once | crash test |
| Worker stalled past its lease | recovery marks unknown; the stalled worker's finish is refused (`stale_worker`); no receipt | stalled-worker test |
| Lease clock skew on the recovery host | no effect: expiry is on database time | skew control (this change) and its regression test |
| Duplicate request | refused `authorization_replayed` (or refused by Core's receipt status) | contention test |
| Duplicate receipt delivery | recorded once | concurrent receipt test |
| Core unavailable | refused `core_unavailable`; no side effect | Acme validation case `core_unavailable` |
| Core instance killed during issuance | not verified (no hook to interrupt issuance at a precise point) | see the audit report |
| Database connection exhaustion | refused before side effect; no duplicate | connection-exhaustion test |
