# Distributed execution and multi-instance consistency: audit report (2026-11-26)

Branch: `feat/distributed-execution`, from `origin/staging` at `652714f` (PR #514 merged). Commits: `16b0191` (this change) and
the documentation and evidence commit that follows it. The PR is against `staging`. Issue #501 stays open. Its requirement-by-
requirement review is in `docs/reports/issue-501-traceability-2026-11-26.md`.

Companion documents: `docs/architecture/distributed-execution.md` (guarantees, lock order, gaps),
`docs/operations/distributed-execution-runbook.md` (topologies, migrations, recovery), `docs/threat-model.md`,
`docs/trusted-execution-sdk.md` (section "The shared executor store (PostgreSQL)").

## Status, in one paragraph

Implemented and verified locally: a PostgreSQL executor store with atomic claims, fencing, database-clock leases, append-only
history, tenant isolation, and idempotent receipts; a cross-process ledger lock that fixes a confirmed corruption of the Core
ledger under two instances; process-level tests of the executor and of Core. Not verified: any deployment, any cross-host Core
ledger (unsupported), a real downstream system, a real Core under a kill during issuance, and the production behaviour of the
hardware the benchmark ran on, which was shared with unrelated load. Exactly-once external effects are not claimed.

## Audit: what was checked, and what was found

Checked: the executor (`executor.py`, `store.py`, `lifecycle.py`, `receipts.py`), the authorization issuance path (`execution_authorization.rs`, `govai_api.rs`),
the policy anchor (`policy_anchor.rs`, `policy_watermark.rs`), the key registry anchor (`key_registry.rs`, `keys.py`), the ledger
(`audit_store.rs`), and issue #501.

| # | Finding | Evidence | Status |
|---|---|---|---|
| A1 | **The ledger's critical section is protected only by an in-process mutex.** Two Core processes on one ledger interleave appends. | Two Core processes on one ledger, 200 concurrent requests: 181 returned HTTP 500 (`LEDGER_READ_ERROR: ledger corruption before EOF`); the chain was broken; the ledger was unreadable afterwards. Control: `origin/staging` binary, `scratchpad/mc/` runs. | **Fixed**: cross-process `flock` on `<ledger>.lock`, taken before the state read. Now 200 of 200, valid chain. |
| A2 | **Duplicate event-id detection and approval consumption are only as good as A1.** | Same runs; A1's fix makes both read under the lock. | Fixed with A1. Approval consumption across processes has no direct test (see verification). |
| A3 | **Executor leases use the worker's clock and recovery compares them with its own clock.** A recovery host two hours ahead declared a live, successful execution `outcome_unknown`. The live worker then raised `InvalidTransition`, sent no receipt, and the record stayed `reconciliation_required`. | `docs/evidence/distributed-execution/negative-control-clock-skew-staging.json` (the `origin/staging` tree, SQLite store). | **Fixed** on the PostgreSQL store: expiry is `now()` in the database. The SQLite store keeps worker clocks (one host). Regression test `test_a_recovery_host_whose_clock_is_two_hours_ahead_does_not_expire_a_live_lease`. |
| A4 | **No fencing.** A stale worker's finish was refused only because the state had moved on, not because its claim was checked. | Code reading of `finish` and `mark_outcome_unknown` on `origin/staging`. | **Fixed** on the PostgreSQL store: fence token required; stale tokens are refused and write nothing. |
| A5 | **A store failure after the side effect escaped as an exception.** | Code reading: `finish` and `receipts.deliver` did not catch store errors. | **Fixed**: `outcome_not_recorded`; receipt delivery returns "pending" on store errors. |
| A6 | **Receipt recording was not idempotent.** A second delivery raised. | `record_receipt_recorded` on `origin/staging` raised `InvalidTransition` on a repeat. | **Fixed** on the PostgreSQL store (no-op for the same id). The SQLite store still raises on a repeat; this is a known difference. |
| A7 | **Core status is checked before the side effect, not at it.** A revocation between the two is not seen. | Code reading of `Executor.execute`. | **Not fixed.** Residual; documented in the architecture document and the threat model. |
| A8 | **The policy and registry anchors already use PostgreSQL row and advisory locks.** | `policy_anchor.rs` (advisory transaction lock per policy); `key_registry_anchor` (row lock, compare-and-swap). | Confirmed; no change needed. Tested. |
| A9 | **Checkpoint append and tail repair took no lock.** | `audit_store.rs`. | **Fixed** (same `flock`; no nested call, to avoid self-deadlock). |
| A10 | **The ledger is host-local.** `flock` is not a cross-host lock. | Design. | **Documented as unsupported** for several Core instances on different hosts sharing one ledger. Not fixed; it needs a product decision (a database-backed ledger). |
| A11 | **Connections are per operation.** Each store call opens and closes its own connection: no session state, and a setup cost on every call. | Code (`store_pg._txn`). | Accepted; the setup cost is part of the measured latency. |

## Negative controls

Each control reproduces a finding against the current staging code and records the result.

| Control | Against | Result | Evidence |
|---|---|---|---|
| N1. Two Core processes on one ledger, 200 concurrent requests | `origin/staging` binary (`652714f`) | 181 of 200 HTTP 500; chain broken; ledger unreadable afterwards | `docs/evidence/distributed-execution/ledger-two-instance/RESULTS.md` (before and after) |
| N1'. The same load after the fix | this branch, release binary | 200 of 200; chain valid; 0 duplicates | `test_distributed_core_ledger.py` (2 tests, passing) |
| N2. Clock-skew lease expiry | `origin/staging` tree, SQLite store | recovery `outcome_unknown` on a live success; live worker raised; receipt `none`; final state `reconciliation_required`; side effects 1 | `docs/evidence/distributed-execution/negative-control-clock-skew-staging.json` |
| N2'. The same scenario | this branch, PostgreSQL store | recovery `skipped`; live worker `executed: true`; receipt `recorded`; final state `succeeded`; side effects 1 | `docs/evidence/distributed-execution/clock-skew-branch.json`; regression test |
| N3. Concurrency benchmark, SQLite store | `origin/staging` vs this branch, same load window | equivalent: 0 unauthorized, 0 duplicates, 0 false denials at 1, 2, 4, 8 workers; throughput within noise | `docs/evidence/distributed-execution/benchmark-sqlite-*.json` |

Honest note on N3: the staging SQLite store was already correct under concurrent processes on one host (`BEGIN IMMEDIATE`). Its
defects are the clock and fencing ones (N2, A4), which the benchmark does not exercise. The benchmark measures correctness under
contention and cost; the failure tests and N2 measure the defects.

## Implemented

1. **Cross-process ledger lock** (A1, A2, A9). `rust/src/audit_store.rs`.
2. **PostgreSQL executor store** (`python/aigov_py/trusted/store_pg.py`): one execution per authorization across tenants (primary
   key); atomic claim with fence; database-clock leases; append-only history (update, delete, truncate refused); hash chain
   covering every tenant; tenant scoping; idempotent receipts; `expire_lease` for recovery; typed `StaleWorker` and
   `StoreUnavailable`.
3. **Versioned migration** `migrations/pg/0001_executor_pg.sql`, applied by `store_admin migrate-pg` (advisory-locked, one
   transaction, skips applied versions) and checked by `status-pg`. Packaged in the wheel (checked).
4. **Executor changes** (`executor.py`): fence threaded through `finish` and `mark_outcome_unknown`; `store_unavailable` before a
   side effect; `outcome_not_recorded` and `stale_worker` after one; expiry on the store's clock when the store offers it;
   receipt delivery tolerant of store errors. The SQLite store accepts the same optional arguments.
5. **Benchmark** `scripts/distributed_benchmark.py`: reproducible; reports unauthorized executions, duplicate executions,
   unauthorized side effects, false denials, evidence verification, throughput, latency percentiles (all attempts and executed
   attempts), lock-wait samples, and recovery latency measured from the stored lease's expiry.
6. **Local multi-instance example**: `examples/distributed-execution/docker-compose.yml` (PostgreSQL 18 and two Core containers
   sharing one named volume). Local only.
7. **Documentation**: architecture, operations runbook, issue #501 traceability matrix, threat model rows, SDK section.

## Verification

Counts are from the runs on this tree (commit `16b0191` plus the test and evidence commit that follows it).

| Suite | Result |
|---|---|
| Rust, `cargo test --locked -- --include-ignored`, PostgreSQL 18 | 413 passed, 0 failed |
| Python, full suite with PostgreSQL, release Core, container tests | 1335 passed, 0 failed, 24 skipped |
| Store on PostgreSQL (`test_store_pg.py`) | 12 passed |
| Distributed executor processes (`test_distributed_executor_pg.py`) | 10 passed (run four times for stability) |
| Two Core processes on one ledger (`test_distributed_core_ledger.py`) | 2 passed |
| Container runtime (`test_container_runtime.py`, image built from `rust/Dockerfile`) | 16 passed |
| Executor lifecycle, SQLite (`test_executor_lifecycle.py`) | 43 passed |
| Registry and policy PostgreSQL suites | passing (in the Rust and Python totals above) |
| Security harness, local simulation, PostgreSQL 18 (`scripts/staging_policy_verify.py --skip-live`) | 66 passed, 0 failed, 0 blocked |
| Acme Finance validation (`examples/customer-integration/acme/validate.py`, binary mode, PostgreSQL) | 8 of 8 cases, 38 of 38 checks |
| Reference suites against a release Core on PostgreSQL: service-backed (`test_agent_reference_core.py`, 27), in-process (`test_agent_reference_integration.py`, 20), and the customer-pilot tests | 53 passed across the three files |
| Customer pilot (`examples/customer-pilot/pilot.py run`, synthetic data) | all checks passed; 45 pass rows, 0 failing |
| SDK wheel: built from a copy of `python/`, clean-venv install, offline downstream check | passed; the wheel contains the PostgreSQL migration |
| `make gate` and CI make targets (core runtime examples, reference integrations, governance, reconstructible demo, packaging, observability, lineage) | passed |
| Downstream Python consumption smoke, portable-evidence tests | passed |
| Docker Compose example: two Core containers, shared volume | 200 of 200 accepted; valid chain; 0 duplicates |
| Clock-skew control and the ledger control (above) | as stated |

Process-level coverage in `test_distributed_executor_pg.py`: four executors racing on the same authorizations (exactly one
execution each); a forged authorization (never executed); a process killed after the side effect (never re-run; `outcome_unknown`
after its lease); a process killed after reserving (performed once by recovery); a stalled worker past its lease (`stale_worker`,
no receipt); a network cut between the executor and PostgreSQL after the side effect (`outcome_not_recorded`; recovery after
restore); a clock two hours ahead on recovery (no expiry of a live lease); concurrent receipt recording (recorded once); an
unreachable store (no start); a connection-limited role under four processes (refused before any side effect, no duplicate).

Not covered by an automated test (named so they can be found): a Core instance killed during authorization issuance; a
simultaneous policy activation and key revocation across processes; a direct two-process approval-consumption test; a
PostgreSQL restart (as opposed to a network cut) under load.

## Benchmark

Method: `scripts/distributed_benchmark.py`. Each level runs `c` executor processes. Each process attempts every authorization in
its own order, so claims race. There are 120 valid authorizations and 20 forged ones. The side effect and Core are the test
stand-ins (a file-backed Core and a side-effect log). The numbers measure the store and the executor, not an external system or
a real Core. Latency is the executor's own end-to-end time for each call.

**Machine load was high and was not controlled.** Other processes on this machine (from an unrelated project) held a 1-minute load
average of about 30 to 47 during these runs, on 12 CPUs. The saved PostgreSQL run ends at a 1-minute load of 47.5
(`benchmark-postgres.json`). An earlier run of the same code, at a 1-minute load of 10 to 14, had about three times the
throughput and about a third of the recovery latency (`benchmark-postgres-earlier-lower-load.json`). Treat absolute numbers as specific
to this machine and its load. The correctness columns do not depend on load.

PostgreSQL 18, one shared executor store, this branch (`benchmark-postgres.json`):

| Workers | Valid executed | Unauthorized executions | Duplicate executions | False denials | Throughput (executed/s) | Executed p50 / p95 / p99 (ms) | Lock-wait samples / peak sessions |
|---|---|---|---|---|---|---|---|
| 1 | 120 / 120 | 0 | 0 | 0 | 20.3 | 40.0 / 81.7 / 91.2 | 0 / 1 |
| 2 | 120 / 120 | 0 | 0 | 0 | 47.9 | 31.7 / 71.1 / 111.6 | 1 / 2 |
| 4 | 120 / 120 | 0 | 0 | 0 | 84.2 | 29.7 / 77.5 / 129.8 | 10 / 4 |
| 8 | 120 / 120 | 0 | 0 | 0 | 97.0 | 53.5 / 60.4 / 64.3 | 9 / 5 |

Executed-attempt latency is the meaningful one at 1 worker (every attempt executes). At 2 to 8 workers most attempts are refused
at the status or reservation step, so the executed latency at those levels includes the waits of the executed attempts under
contention. Lock-wait samples are small, and the sampler saw only a few sessions at a time, so contention is observed, not
quantified. The executed latency at 2 to 8 workers is higher than at 1 worker in this run, which is the load, not a lock.

Recovery latency on the PostgreSQL store (lease 1 s, 5 runs, under the same load): the time from the lease's expiry to the recovery
that records the killed execution as `outcome_unknown`, measured against the stored `lease_until`: 72 to 410 ms (p50 321 ms). At
the lower load of the earlier run it was 79 to 119 ms (p50 107 ms). The recovery loop polls every 50 ms, and each poll starts a new
process, which dominates the latency under load.

SQLite store (one host), this branch and `origin/staging`, same load window (the staging control file predates the load-average field) (`benchmark-sqlite-branch.json`,
`benchmark-sqlite-staging-control.json`): 0 unauthorized, 0 duplicates, 0 false denials at 1, 2, 4, 8 workers. Throughput
112 to 145 per second on both, within noise.

Limits of the benchmark: one host; the Core is a stand-in; the side effect is a local file; the store connection is per operation,
so per-call latency includes connection setup; the load was uncontrolled; no multi-host run was made.

## Failure handling (summary; detail in the architecture document)

| Failure | Result | Verified |
|---|---|---|
| Executor terminated before the side effect | nothing ran; recovery performs it once after reservation | yes |
| Executor terminated after the side effect | not re-run; `outcome_unknown` after the lease | yes |
| Executor stalled past its lease | `stale_worker`; no receipt; recovery marked unknown | yes |
| PostgreSQL unreachable before a side effect | `store_unavailable`; nothing ran | yes (unreachable store; exhaustion) |
| PostgreSQL unreachable after a side effect | `outcome_not_recorded`; row under its lease; recovery later | yes (network cut through a test proxy) |
| PostgreSQL restarted | not separately verified; the network cut covers the executor's behaviour | partly |
| Network between executor and PostgreSQL interrupted | as above | yes |
| Expired leases and stale workers | database-clock decisions; fences | yes |
| Duplicate requests and receipts | refused or recorded once | yes |
| Concurrent policy activation and key revocation | each serialized; combined run not verified | partly |
| Connection exhaustion | refused before any side effect; no duplicate | yes |
| Partial transactions | every transaction either commits both the state and its history row or neither; a crash between append and anchor commit is reconciled | yes (reconcile tests; rollback tests) |
| Core instance killed during authorization issuance | not verified | no |

## Supported and unsupported topologies

See the runbook, section 1. In short: several executors on many hosts sharing one PostgreSQL store is supported; several Core
instances sharing one ledger volume is supported on one host; several Core instances on different hosts sharing a ledger directory
is **not** supported, and the SQLite executor store across hosts is not supported.

## Residual risks

- A revocation between the executor's status check and the side effect is not seen by that call (A7).
- A downstream system that cannot deduplicate by the stable key can apply a retried action twice.
- A slow side effect longer than its lease is recorded as unknown; the lease must exceed the longest side effect.
- Simultaneous compromise of database write access and of the trust files, or a database administrator who rewrites the history and
  its anchors together, is not detected by this code (the runbook's residual-threat section).
- Several Core instances on different hosts cannot share a ledger safely (A10).
- The SQLite executor store uses worker clocks; it is a one-host store.
- `policy` replay of a valid, unexpired bundle at its own revision (issue #501, R5) is unchanged.

## Unverified production assumptions

- That production PostgreSQL has the isolation, connection limits, and backup behaviour assumed here.
- That the downstream system provides a deduplication key and reconciliation evidence.
- That operators run `migrate-pg` and the anchor bootstrap in the documented order.
- That the lease length exceeds the longest real side effect.
- That the ledger volume's `flock` is reliable on the production file system (true on local and Docker named volumes on one host;
  not tested on any network file system).
- Performance on production hardware: not measured. The benchmark ran on a loaded local machine.

## Delivery

- Branch `feat/distributed-execution`, pushed. One PR against `staging`, opened from this branch (number and checks recorded at
  the end of this report, after the final push).
- Hosted checks are verified on the exact final HEAD in the PR's check list, not here.
- No Railway change, no remote service, database, volume, credential, or paid API was created. The local PostgreSQL cluster and
  the Docker containers were created on this machine for testing, and were removed or stopped at the end.
- Issue #501 remains open.

## Evaluation gate

Passes when, on the exact final HEAD: the cross-process ledger lock holds under two Core processes (two-instance test passes and the
chain verifies); the PostgreSQL executor store enforces one execution per authorization across tenants, fenced finishes, database-clock
expiry, append-only history, and tenant isolation (store and distributed suites pass); the clock-skew control is refused on this branch
and reproduces on the staging tree; the local security harness, Acme Finance validation, reference suites, customer pilot, container
tests, SDK wheel downstream check, and `make gate` pass; and the benchmark shows zero unauthorized executions, zero duplicate executions,
and zero false denials at 1, 2, 4, and 8 workers. Status: the local evaluation passes on this tree. The hosted checks on the PR's head are
the separate gate and are recorded on the PR, not here.

## Human approval gate

Not approved for production by this report. The owners must decide, before any production use: the ledger topology (one host per
tenant, or a database-backed ledger; several Core instances across hosts are not supported today); whether the downstream systems provide
a deduplication key and reconciliation evidence; the lease length per tool; who runs `migrate-pg` and in what order; and the residual
threats in the runbook. Issue #501 remains open. Merging into `staging` is a separate decision, and this report does not make it.

