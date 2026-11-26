# Customer pilot readiness: AIGov Core release candidate

Status: **controlled pilot, conditional GO. Not approved for unrestricted production.** The evidence is in
`docs/reports/release-candidate-2026-11-26.md`. The conditions below are part of the decision.

## Decision

| Scope | Decision | Basis |
|---|---|---|
| Controlled pilot: one tenant, one ledger host, production mode, with the conditions below | **GO, conditional** | No open Critical or High finding. Every High finding is fixed and tested. Local validation passes on `302c6dc` and `bb03393`. |
| Unrestricted production, several tenants on one host, or several hosts | **NO-GO** | Multi-host ledgers are unsupported (R-4). Issue #501 owner decisions D1–D4 are open. No load test was run (R-3). |

The GO becomes a NO-GO if the hosted CI run on the final head is not green, or if any condition below is not met.

### Conditions

1. **Principals in every pilot environment.** Run the pilot in production mode, or configure `GOVAI_PRINCIPALS_JSON` in staging too. Without
   principals, any key can post approvals (R-1).
2. **One ledger host per tenant.** Do not run several Core instances on different hosts that share a ledger directory.
3. **Owners record the #501 decisions D1–D4** (`docs/reports/release-candidate-2026-11-26.md`, appendix). The pilot may run before they are
   resolved, but the risk acceptance must be written down.
4. **The crash-consistency tests are run as a manual gate** before the pilot starts, because they are not in CI (R-5). Command below.
5. **The hosted CI run on the final commit is green** for every required check.

## Supported deployment topology

| Component | Supported for the pilot | Not supported |
|---|---|---|
| Core | One release binary per host, behind a load balancer that routes on `GET /ready` | Several Core instances across hosts sharing one ledger directory |
| Ledger | Local volume on the Core host | Network file systems shared by several hosts |
| PostgreSQL | One database for the policy anchor, key registry, and executor store; migrations applied by an operator | SQLite executor store on more than one host |
| Executors | Library in the customer's workers, one PostgreSQL executor store per tenant | Executors that cannot reach the store, and a downstream without a deduplication key for consequential actions |
| Container | `rust/Dockerfile`, non-root (UID 1000), production by default | Fault-injection builds |

## Installation and configuration

1. Build or pull the Core image from `rust/Dockerfile` (no `fault-injection` feature).
2. Set `AIGOV_ENVIRONMENT=prod` (the image default), `GOVAI_DATABASE_URL`, the signed policy bundle (`AIGOV_POLICY_BUNDLE_FILE`), the trust file
   (`AIGOV_POLICY_TRUST_ED25519_JSON`), `GOVAI_PRINCIPALS_JSON` (agent, approver, and executor keys), and the execution-authorization signing
   key (registry or environment seed; see `docs/operations/distributed-execution-runbook.md` section 2 and `docs/operations/key-management-runbook.md`).
3. Apply migrations: `GOVAI_AUTO_MIGRATE=true` on the first start, or out of band. `/ready` reports `migrations_complete: false` until they are applied.
4. Install the SDK wheel in each executor environment. The wheel includes the PostgreSQL executor schema. Apply it with
   `python -m aigov_py.trusted.store_admin migrate-pg --url "$EXECUTOR_DB_URL"`, then check with `status-pg`.
5. Start executors after the store check passes.

Production refuses to start without principals, without a signed bundle, and without a database URL. These refusals are intended.

## Customer integration requirements

- Each agent holds its own key. Approvers hold approver keys. Executors hold executor keys. A key posts only the event types its role owns.
- Consequential calls need an approval event first. The approval is single use.
- The executor records an `execution_receipt` only for an authorization it received. Core refuses receipts for authorizations it did not issue.
- A downstream system must accept a deduplication key derived from the authorization id, or accept that a retried side effect can apply twice
  (`docs/architecture/distributed-execution.md`). The pilot must choose which.
- Reconciliation evidence from the downstream system is required for any `reconciliation_required` execution (distributed runbook section 5.2).

## Security guarantees and limitations

Guaranteed in the tested configurations:

- No authorization is delivered without a committed evidence record (crash tests at three boundaries).
- An approval authorizes at most one consequential call, across processes and restarts.
- A receipt is accepted only from an authenticated executor and only for an authorization Core issued in the same run.
- Production does not start without authenticated principals, a signed bundle, or a database for the policy anchor.
- The ledger chain verifies after crashes, restarts, and concurrent appends on one host.

Not guaranteed, or not verified:

- External effects are not exactly once. The database guarantees one execution per authorization, not what the downstream system does (R-9).
- Multi-host ledgers and two-volume rollback (R-4, #501 A2).
- Behaviour under load and against slow clients. No timeout or concurrency limit is configured in Core (R-3).
- Signed or authenticated policy-anchor state beyond the database row (R-2, #501 D2).
- Exact HTTP status for oversized bodies (F-6).

## Operational responsibilities

| Party | Responsibility |
|---|---|
| AIGov operator | Core image, migrations, backups (`docs/operations/distributed-execution-runbook.md` section 8), the crash-test gate before the pilot, monitoring `/ready` and `/metrics` |
| Customer platform team | Principals and key custody, executor deployment, the downstream deduplication key, reconciliation of `reconciliation_required` rows |
| Customer compliance owner | Approver allowlist, approval decisions, acceptance of residual risks R-1 to R-11 |
| Both | Joint review of the first ten executions and the first incident drill |

## Acceptance criteria for the pilot

1. Every condition in the GO section is met and written down.
2. `make gate`, `make enterprise-readiness-check`, and the customer pilot (`examples/customer-pilot/pilot.py run`) pass on the deployed release.
3. The chain verifies on the pilot ledger after a day of traffic, and the head hash is recorded off host (distributed runbook section 8, `store_admin verify-history`).
4. `/ready` returns 200 through a restart of the Core process and a PostgreSQL restart.
5. Zero unauthorized executions, zero duplicate executions, and zero refusals that were not expected during the pilot, as shown by the ledger
   and the executor logs.
6. The receipts for every executed call are present, and every `reconciliation_required` row is resolved or accepted by the customer.

## Incident response and recovery

- **Core killed.** Restart it. Readiness returns when the database and ledger are back. A call killed before its response has no authorization
  in hand, so the executor refuses it. A client retry is refused as a duplicate (409). `docs/operations/distributed-execution-runbook.md` section 5.4.
- **PostgreSQL unavailable.** Core refuses consequential calls it cannot authorize (`AUTHORIZATION_KEY_UNAVAILABLE`), and `/ready` reports 503. Executors
  refuse before any side effect (`store_unavailable`). Runbook section 6 (same file).
- **Executor died during a side effect.** Run `executor.recover()` after the lease. A lease that expired leads to `reconciliation_required`. Reconcile
  with the downstream system's signed evidence (distributed runbook 5.1 and 5.2). Do not force an execution.
- **Suspected key compromise.** Revoke the key through the registry (`docs/operations/key-management-runbook.md`). Review every receipt and approval
  signed by it, from the ledger.
- **Suspected ledger tampering.** Stop Core. Compare the ledger head with the off-host head recorded at the last backup (`docs/operations/distributed-execution-runbook.md` section 8). Do not
  restore over evidence without investigation.

Crash-consistency gate (run before the pilot, from a checkout of the release commit):

```
cd rust && cargo build --release --features fault-injection --bin aigov_audit --target-dir ../target-fault
cd ../python && AIGOV_TEST_FAULT_CORE_BIN=$PWD/../target-fault/release/aigov_audit PYTHONPATH=$PWD \
  python -m pytest tests/test_crash_consistency_core.py tests/test_receipt_provenance_core.py tests/test_approval_single_use_two_instances.py -q
```

## Known risks

See the residual risks R-1 to R-11 in `docs/reports/release-candidate-2026-11-26.md`. The three most relevant for a pilot are R-1 (principals), R-3
(no timeout or concurrency limit), and R-5 (crash gate not in CI).

## What "controlled" means here

The pilot is controlled when: one tenant, one ledger host, production mode, the conditions above, named owners for each responsibility, and a
written decision to accept the residual risks. Anything beyond that is a new decision, not an extension of this one.
