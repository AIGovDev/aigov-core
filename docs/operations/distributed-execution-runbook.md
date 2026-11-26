# Distributed execution runbook

Scope: running several executor processes and Core instances against shared PostgreSQL. Read
`docs/architecture/distributed-execution.md` first. It says what each guarantee depends on.

This runbook covers local and self-hosted operation. It does not describe any remote infrastructure. Nothing here changes a
Railway service, a remote database, or a deployment.

## 1. Choose a supported topology

| Topology | Status | Notes |
|---|---|---|
| Executors on many hosts, one PostgreSQL executor store | Supported (verified locally with PostgreSQL 18) | one tenant per store object |
| Core instances on one host sharing one ledger volume, plus PostgreSQL for policy and registry anchors | Supported (verified locally, including a two-container Docker example) | the ledger file lock is host-local |
| Core instances on different hosts sharing one ledger directory | **Not supported** | `flock` is not a cross-host lock; use one ledger host per tenant |
| SQLite executor store on more than one host | **Not supported** | the SQLite store is a one-host store |
| Executors with a downstream system that has no deduplication key | Supported with the stated limit | a retried side effect can be applied twice; see the architecture document |

## 2. Migrations

Migrations are applied by an operator, never by the executor.

Executor store (PostgreSQL), versioned:

```
python -m aigov_py.trusted.store_admin status-pg --url "$EXECUTOR_DB_URL"      # exit 0 if up to date
python -m aigov_py.trusted.store_admin migrate-pg --url "$EXECUTOR_DB_URL"     # applies pending versions, in order
```

- `migrate-pg` runs each migration in one transaction, under an advisory lock, so two operators cannot apply migrations
  at once. Re-running it is safe: applied versions are skipped.
- The store refuses to open a database whose version is not the one the SDK requires (`SchemaMissing` or
  `SchemaVersionMismatch`). It does not create or upgrade anything.
- Upgrade order: stop executors, run `migrate-pg`, check `status-pg`, start executors.

Core and the anchors: migrations are the Core's sqlx migrations (`rust/migrations/`). Core applies them when
`GOVAI_AUTO_MIGRATE=true`, or they are applied out of band. Readiness reports `migrations_complete: false` until they are.
The registry anchor table is migration `0004_key_registry_anchor`. The policy anchor is migration `0003`.

## 3. Health and readiness

Core:

- `GET /health`: the process is up.
- `GET /ready`: returns 200 only when all of these hold: the database answers a ping, the expected migrations are recorded in
  `_sqlx_migrations`, the ledger directory is writable, and the tenant's ledger is readable. Otherwise 503, with each check in
  the body. Use `/ready` for load-balancer routing, not `/health`.
- `GET /metrics`: Prometheus metrics for the HTTP layer and the runtime (existing).

Executors (a library, not a service): there is no health endpoint. Check the store with:

```
python -m aigov_py.trusted.store_admin status-pg --url "$EXECUTOR_DB_URL"
python -m aigov_py.trusted.store_admin report --db <sqlite path>      # one-host SQLite only
```

An executor that cannot open its store exits at start, and refuses every call while the store is unreachable. Both are
intended. Neither produces a side effect.

## 4. Structured events and what to watch

Executors emit one JSON line per event through the `aigov_py.trusted.executor` logger. Fields include `event`, `worker`,
`authorization_id`, and, where relevant, `outcome`, `reason`, and `lease_until_utc`. The events:

| Event | Meaning | Action |
|---|---|---|
| `reserved`, `started`, `finished` | the normal path | none |
| `stale_worker` | a worker's claim was taken over; its outcome was not recorded; no receipt was sent | check the execution is `reconciliation_required` |
| `outcome_not_recorded` | the side effect ran but the store was lost before the outcome was written | run recovery after the lease; then reconcile with evidence |
| `outcome_unknown` | recovery marked an execution whose lease expired | reconcile with signed evidence from the downstream system |
| `receipt_pending` | the store or Core did not take the receipt | recovery delivers it again |

Watch: the count of `outcome_unknown` and `reconciliation_required` rows, the count of `store_unavailable` refusals (a database
or connection problem), and the age of the oldest `started` lease. The operator CLI lists these for the SQLite store
(`store_admin pending`). For the PostgreSQL store, there is no CLI in this change; query `executions` by `state` and
`lease_until` (read-only).

## 5. Recovery procedures

### 5.1 An executor died

1. Start an executor (any host, same store and tenant) and run recovery:

   ```
   executor.recover()          # from the SDK; returns one action per unresolved execution
   ```

2. Read the actions. `resumed_once`: performed once after the store check. `outcome_unknown`: its lease passed, and it is now
   `reconciliation_required`. It is not retried. `skipped`: a live worker holds it; do nothing. `receipt_recorded`: delivered.
3. Do not force an execution. The store has no force command, by design.

### 5.2 An execution is `reconciliation_required`

The downstream system must say what happened. Its reconciler signs evidence; the store applies it once.

For the SQLite store, the operator CLI does this:

```
python -m aigov_py.trusted.store_admin inspect --db <db> --authorization-id <id>
python -m aigov_py.trusted.store_admin reconcile --db <db> --registry <reconcilers.json> --evidence-file <signed.json>
```

For the PostgreSQL store, this change provides the SDK functions (`reconcile.verify_reconciliation` then
`PostgresExecutionStore.reconcile`), not a CLI. A CLI for it is not verified in this change.

Evidence that has already been applied is refused, in any tenant. If no evidence can be obtained, escalate: `escalate` records a
flag and changes no state.

### 5.3 Receipts are pending

For the SQLite store, `store_admin resubmit-receipts --db <db>`. For the PostgreSQL store, the executor's own recovery
(`recover()`) delivers pending receipts. Delivery never repeats the action.

### 5.4 Core instance killed

Restart it. Readiness returns to 200 when the database and the ledger are back. The ledger's tail repair handles a partial last
line. An authorization whose request was killed before the response has no authorization in hand, so the executor refuses it.
A client retry gets a duplicate-event refusal (409). That path is not verified by an automated test in this change (see the
audit report).

## 6. PostgreSQL interruption and recovery

- **Executor loses the store before the side effect.** The call is refused with `store_unavailable`. Retry the call later. No
  side effect has run.
- **Executor loses the store after the side effect.** The call reports `outcome_not_recorded`. The row stays `started` under its
  lease. When the store is back and the lease has passed, run recovery (5.1). The execution becomes `reconciliation_required`.
  Reconcile it with evidence (5.2).
- **Core loses the database.** `/ready` reports 503. Core refuses consequential calls whose authorization needs the anchors
  (`AUTHORIZATION_KEY_UNAVAILABLE`), and the policy anchor refuses activation. Nothing is accepted on a guess.

Do not restart PostgreSQL to "clear" a state. Restarting does not change any row. Recovery is the procedure above.

## 7. Connection exhaustion

Symptoms: `store_unavailable` refusals, `StoreUnavailable` at start, `too many connections` in the database log.

1. Check the number of client sessions per database and role (`pg_stat_activity`).
2. Reduce executor concurrency, or raise the role's connection limit. The executor opens one short-lived connection per operation,
   so the steady-state count is roughly the number of executors in a store call.
3. Refusals are safe: each refused call happened before its side effect, or after it with `outcome_not_recorded`. Check the
   `outcome_not_recorded` count before assuming nothing ran.

## 8. Backup and restore

- The executor store and the anchors must be restored **together**, from the same point in time. A restore of the executor store
  alone, behind the anchors, is refused by the registry and policy anchors. A restore of the store alone, behind the executor's own
  history, is detected by the history chain (`verify_history`) only if the chain is intact.
- Back up the ledger directory with its sidecars (`.state.json`, `.run.*.events`, `.lock` may be omitted).
- Record the head hash of the executor history (`store_admin verify-history`) and of each ledger in an off-host location. A
  restore that does not match the recorded head is an investigation, not a normal restore.
- The registry trust file and the root key are not part of the database backup. They are kept under change control.

## 9. The Docker Compose example (local only)

`examples/distributed-execution/docker-compose.yml` starts PostgreSQL 18 and two Core containers that share one named ledger
volume on this Docker host. It is for local verification only. The Core image is built from `rust/Dockerfile`. The example runs
Core in `dev` mode, which the image overrides from its default `prod`. Do not reuse its credentials or its mode.

```
docker build -t aigov-core:test .
docker compose -f examples/distributed-execution/docker-compose.yml up -d
docker compose -f examples/distributed-execution/docker-compose.yml down -v      # removes only this example's volumes
```

## 10. Residual threats for operators

- A database administrator who can edit the executor history, the anchors, and the trust file together can rewrite history. The
  registry and the history chain can detect some of this, not all. Keep off-host head hashes (section 8).
- A compromised downstream system can report a false outcome in its evidence.
- Lease length must exceed the longest side effect. A shorter lease causes `outcome_unknown` for a slow but successful call.
  Choose it per tool.
