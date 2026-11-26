# Paid enterprise pilot package: AIGov Core

Scope: one tenant, one ledger host, production mode, with principals. The decision and its conditions are in
`docs/release/pilot-readiness.md`. The evidence is in `docs/reports/pilot-readiness-closure-2026-11-26.md`.

Each guarantee below is marked **Verified** (a test or a measurement in this repository), **Assumed** (a condition the customer or operator must
meet), or **External** (depends on a system outside this repository).

## 1. Supported deployment topology

| Component | Pilot topology | Not supported in the pilot |
|---|---|---|
| Core | One release image per tenant, on one host, behind a load balancer that routes on `GET /ready` | Several Core instances on different hosts sharing one ledger directory |
| Ledger | Local volume on that host, backed up with the database | Network file systems shared between hosts |
| PostgreSQL | One database for the policy anchor, key registry, and executor store; PostgreSQL 16 or 18 | SQLite executor store on more than one host |
| Executors | Customer workers linked to the SDK, one executor store per tenant | Executors that cannot reach the store |
| Container | `rust/Dockerfile` image, non-root (UID 1000), `AIGOV_ENVIRONMENT=prod` by default | Fault-injection builds; a published port without TLS in front (see section 4) |
| Staging | Optional. If used, it must also have principals (R-1) | Staging without principals |

## 2. Onboarding checklist

1. Agree the pilot scope: tenant identifier, one or more agent systems, the executor's downstream system, and the event types in use.
2. Name the owners in section 6, with an escalation contact for each.
3. Provision the host, the volume for the ledger, and the PostgreSQL database. Record the versions.
4. Create the principals: one agent key per agent system, one approver key per named approver, one executor key per executor. Keys are not shared.
   The agent role posts pipeline and agent events; the approver role posts approvals, revocations, and risk reviews; the executor role posts receipts.
5. Install the signed policy bundle and the trust file. Confirm that a bundle with a different revision is refused (`docs/operations/policy-anchor-runbook.md`).
6. Start Core. Confirm `GET /ready` returns 200, and that `migrations_complete` is true.
7. Install the SDK wheel in each executor environment and run `store_admin migrate-pg`, then `status-pg` (exit 0).
8. Run the customer pilot against the deployed release: `examples/customer-pilot/pilot.py run` with a fresh output directory. It must report no failing checks.
9. Run the crash-consistency gate on the release commit (`make crash-consistency-gate`).
10. Record the head hash of the ledger and of the executor history off host (`store_admin verify-history`, distributed runbook section 8).
11. Sign off the acceptance criteria in section 5.

## 3. Integration requirements

- **Keys by role.** A key posts only the event types its role owns (see `role_may_post` in `rust/src/principals.rs`). Protected types, approvals and
  revocations and risk reviews and receipts, belong to one role each. Every other type is posted by the agent role.
- **Approval before execution.** A consequential call names an approval that a human approver recorded. The approval is single use. A repeated or
  unknown approval is refused (`approval_already_consumed`, `approval_not_found`).
- **Receipts.** The executor records an `execution_receipt` only for an authorization it received. Core refuses receipts for authorizations it did not issue
  in the same run.
- **Deduplication key.** The downstream system must accept the authorization id as an idempotency key, or the customer accepts in writing that a retried
  side effect can apply twice (R-9). This is external to AIGov.
- **Reconciliation.** Any execution in `reconciliation_required` is resolved by the downstream system's signed evidence (distributed runbook 5.2). No one forces an execution.
- **Limits.** Requests have a time limit of 30 s, a concurrency limit of 256, and a body limit of 2 MiB by default. Tune them with
  `AIGOV_REQUEST_TIMEOUT_SECS`, `AIGOV_MAX_CONCURRENT_REQUESTS`, and `AIGOV_MAX_BODY_BYTES` before the pilot starts. Invalid values stop startup.

## 4. Security guarantees and limitations

Verified (tests or measurements in this repository, on the final code):

- No authorization is delivered without a committed evidence record, at three crash boundaries of issuance (crash-consistency gate).
- One approval authorizes at most one consequential call across two processes and across restarts (two-instance test, five rounds).
- A receipt is accepted only from an authenticated executor, and only for an authorization Core issued in the same run (receipt provenance tests).
- Production and staging refuse to start without principals, a signed bundle, or the policy-anchor database (refusal tests and the staging simulation).
- An agent key cannot post an approval, a risk review, or a receipt when principals are configured (role tests and the staging simulation).
- A policy revision cannot roll back, on two real filesystems, against the database anchor (two-volume test).
- Request time, concurrency, and body size are bounded; health answers while the limit is reached (socket test; the negative control fails without the limit).
- The executor store never runs one authorization twice, at 1, 2, 4, and 8 workers, with zero false denials (benchmark on the final code).
- The ledger chain verifies after crashes, restarts, and concurrent appends on one host.
- No known vulnerabilities in the Rust crates (`cargo audit`, with one unmaintained-crate warning) or the Python closure (`pip-audit`).

Assumed (the customer or the operator must meet these):

- The host, the volume, and the database are protected from access by anyone outside the operators. A person with write access to the database can change the policy
  anchor row (R-2, #501 D1 and D2).
- Keys are kept by their holders and revoked when a holder leaves.
- The approver allowlist and the policy bundle are reviewed by the compliance owner.
- The downstream system deduplicates by the authorization id, or the duplicate risk is accepted.
- TLS and access control in front of the port are provided by the customer's load balancer or gateway. The container publishes plain HTTP.

External (outside this repository, not verified here):

- The downstream system's behaviour, and its evidence signatures.
- The load balancer's routing on `/ready`, and its TLS.
- The customer's identity provider, if OIDC is used.
- Hardware, disk, and network reliability of the host.

Not claimed:

- Exactly-once external effects (R-9).
- Multi-host ledgers (R-4).
- Behaviour under production load. The limits are defaults; the pilot measures it (section 5).
- Protection against a privileged database administrator who rewrites the anchor and the record together (R-2).
- Signed release artifacts. The provenance record and SBOMs are not signed.

## 5. Acceptance criteria and success metrics

Acceptance (all must hold before the pilot's first production call):

1. Every item in section 2 is done and signed off by the named owners.
2. The customer pilot, the crash-consistency gate, and the two-volume test pass on the release commit.
3. `GET /ready` is 200 through a Core restart and through a PostgreSQL restart (rehearsed).
4. One backup and one restore have been rehearsed, and the restored ledger verifies.

Success metrics, measured during the pilot. The targets are the pilot's, not results. None of them has been measured in production yet.

| Metric | Target | Source |
|---|---|---|
| Unauthorized executions | 0 | executor logs and the side-effect log, reconciled against the ledger |
| Duplicate executions | 0 | the same, per authorization id |
| False denials (valid approvals refused without a documented reason) | 0 | ledger refusal records |
| Ledger chain verification | passes every day | `verify` and `verify-history` |
| `/ready` availability | at least 99.5% over the pilot | load balancer |
| Evidence ingest latency, p95 | to be set after the first week's measurement | Core metrics (`/metrics`) |
| `reconciliation_required` rows resolved | within 2 working days | store report |
| Restore drill | passed once during the pilot | the drill record |

Ingest latency has no target in this document, because it has not been measured on a pilot-sized deployment. The first week sets it.

## 6. Operational responsibilities

| Party | Responsibilities |
|---|---|
| AIGov operator | The release image and its digest; migrations; backups with the database; the crash-consistency gate before each release; monitoring `/ready` and `/metrics`; incident response on the AIGov side |
| Customer platform team | Hosts, volumes, the database, principals and key custody, executor deployment, the deduplication key, reconciliation of rows, TLS and access control in front of Core |
| Customer compliance owner | The approver allowlist and approval decisions; the risk acceptances (R-1, R-2, R-6, R-9); the acceptance criteria; the exit review |
| Both | A joint review of the first ten production executions, and a joint incident drill before the first production call |

## 7. Incident response and rollback

**Incident classes.** (a) Core unavailable or refusing; (b) a suspected unauthorized execution; (c) a suspected ledger or anchor change; (d) a key or
principal compromise; (e) a database outage.

**Core unavailable or refusing.** Check `/ready` and the Core log. A refused start names the cause (for example, a missing principal or an out-of-range
limit). Fix the configuration and restart; nothing is written by a refused start. Consequential calls are refused while the anchors are unavailable, so no
execution happens on a guess.

**Suspected unauthorized execution.** Stop the executor for that tenant. Export the ledger and the executor history. Compare the side-effect log with the
authorizations and receipts. Report to the compliance owner within the same working day.

**Suspected ledger or anchor change.** Stop Core. Compare the ledger head and the executor history head with the off-host heads recorded at the last backup
(distributed runbook section 8). Do not restore over evidence until the comparison is written down.

**Key or principal compromise.** Revoke the key through the registry (`docs/operations/key-management-runbook.md`). Review every approval and receipt the key
posted since the last known good state.

**Database outage.** Core returns 503 on `/ready` and refuses consequential calls. Executors refuse before any side effect (`store_unavailable`). Recovery is the
runbook procedure; restarting the database does not change any row.

**Rollback.**

- *Core image.* Roll back to the previous image digest only if that image accepts the current schema. Migrations `0001` to `0004` have no down step. The
  previous image is recorded in the release record, and rollback is tested in the pilot's staging copy before production.
- *Policy revision.* A rollback to an older revision is refused by the anchor (the two-volume test). Do not try to force it. A new, higher revision is the fix.
- *Executor SDK.* Roll back by pinning the previous wheel only if the executor schema is unchanged. Otherwise stop the executors, restore the database from the
  backup taken before the upgrade, and redeploy.
- *Data.* The ledger and the executor history are append-only. Corrections are new events, not edits.

## 8. Pilot exit criteria

The pilot ends in one of three ways.

- **Extend to production.** All success metrics at target for the full pilot period; no open High or Critical finding; the residual risks accepted in writing
  by the owners; D1 to D4 decided; multi-host ledgers either not needed or designed separately.
- **Stop.** Any unauthorized or duplicate execution that is not explained within two working days; any unresolved chain or anchor discrepancy; a
  compliance owner's decision to stop.
- **Pause.** A failed acceptance criterion, a missing owner, or an open High finding. The pilot restarts after the cause is fixed and re-verified.

## 9. Commercial and external dependencies

- The pilot is paid. The price, terms, and support levels are not defined in this repository and are outside this package.
- The downstream systems, the customer's identity provider, and the customer's load balancer are external dependencies (section 4).
- No external infrastructure is provisioned by this package. Any service a pilot needs beyond the customer's own is a separate decision.
