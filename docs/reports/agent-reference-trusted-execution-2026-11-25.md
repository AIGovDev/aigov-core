# Trusted execution and authenticated human oversight for the agent reference — 2026-11-25

## Scope

Completes the trust boundary between the agent, the human approver, AIGov Core, and the tool executor, for the agent
reference (`examples/agent-reference`). Starts from `origin/staging` at `f7495e7` (PR #506 merged). Refs #501 (stays
open). No Railway, production, or external infrastructure was changed. No paid model API was used. No model-based
experiment was run. Credentials are generated per run and kept outside the repository.

This report supersedes the previous single-credential reference for the trust-boundary questions. The earlier report,
`docs/reports/agent-reference-integration-2026-11-25.md`, remains as the record of that state.

## What the trust boundary is now

| Party | Credential | Can | Cannot |
|---|---|---|---|
| Agent | its own API key, role `agent` | request approvals; submit reads and writes; record blocked calls | approve, revoke, record receipts |
| Approver | its own key, role `approver`, bound to one identity | approve or reject in that identity; revoke its own approvals | approve in another identity; approve its own request; submit calls |
| Executor | its own key, role `executor`, and the pinned authorization public key | record receipts for issued authorizations; check status | approve; submit calls |
| Core | the policy-bundle key and the authorization key, neither given to an actor | decide, record, and sign authorizations | (not an actor) |

## Requirements and where they are met

### P0 — Authenticated human approval

- **Separate credentials and permissions.** Core maps each API key to one principal and one role (`rust/src/principals.rs`).
  Each event type is allowed for one role only. Refusals are `role_not_permitted` (403).
- **Approver identity from authenticated credentials.** Core stamps `authenticated_principal`, `authenticated_identity`,
  and `authenticated_role` into every event, overwriting whatever the client sent. The `approver` field must equal the
  authenticated identity (`requires_field_matches_field`).
- **Self-approval and impersonation rejected.** The agent cannot post approvals (role). An approver cannot approve its own
  request (`requires_principal_relation`, distinct). An approver cannot name another approver (identity mismatch). An
  unlisted approver is refused by the allowlist.
- **Binding.** An approval is bound to the run (same run is required), the tool, the canonical argument digest, the policy
  revision (stamped by Core on the request and the call), and the authenticated principal.
- **Persisted identity.** The stamped fields are in the ledger record, so they are in Core's evidence and its export.
- **Expiry and single use preserved.** The approval gate's expiry and consumption checks are unchanged.

### P0 — Core-issued execution authorization

- **Issued after successful policy evaluation.** Core signs an authorization only for an accepted `tool_call` or
  `consequential_tool_call` (`rust/src/govai_api.rs`, `rust/src/execution_authorization.rs`).
- **Ed25519, domain-separated, dedicated key.** The signed message is `b"govai.execution_authorization.v1\0"` followed by
  the canonical JSON of the payload. The key is `GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX`, held only by Core. A signature
  over the bare payload, without the domain, does not verify (tested in Rust and in Python).
- **Binds** the run, tool, argument digest, policy revision, approval, the ledger record hash of the accepted call, the
  executor audience, the expiry, and a unique authorization id (`auth_<uuid>`).
- **The executor verifies independently** (`aigov_agent_reference/core_trusted.py`): signature with the pinned key,
  audience, run, tool, the digest it computes from its own arguments, and expiry with five seconds of skew. Then it asks
  Core for the status. It reserves in its own store and then acts.
- **The agent cannot mint authorization.** It holds no authorization key, and the signature covers every field.
- **Forged, expired, replayed, and modified authorizations are refused** (scenarios and tests below).
- **Single use at the executor.** The reservation is atomic (`BEGIN IMMEDIATE`; tested with eight concurrent threads).
- **Exactly-once across external systems is not claimed.** See the trusted-executor boundary below.

### P1 — Approval revocation

- **Authenticated.** Only the approver who gave an approval may revoke it (`requires_principal_relation`, same). A
  different approver's revocation is refused (`revocation_not_by_approver`).
- **Commit points defined.** The authorization commit point is the accepted call under the ledger lock, which consumes the
  approval. The revocation commit point is its own accepted event under the same lock. The executor's status check is a
  third point, and its reservation is a fourth. These serialize because revocation and consumption share the lock.
- **Revocation after issuance but before execution** has this exact semantics: a revocation recorded before the executor's
  status check stops the execution (`authorization_revoked`, tested). A revocation recorded after that check and before the
  side effect does not stop it. That window is real and is documented in `INTEGRATION.md`, section 4.
- **Revocation does not undo completed external actions.** This is stated in the same place.

### P1 — Execution receipts

- **Separate evidence.** An `execution_receipt` is its own ledger event, posted by the executor's key. It is accepted only
  for an issued authorization for the same tool and argument digest, and only once per authorization
  (`requires_issued_authorization`, tested).
- **Recorded fields:** the authorization id; the authenticated executor identity (stamped by Core); the tool and argument
  digest; the outcome; the result digest; and the timestamp (Core's record time).
- **Authorization alone is not proof of execution.** The status endpoint moves from `authorized` to `receipt_recorded`, and
  the export has no receipt until the executor records one (scenario `authorization_without_execution_is_distinguishable`).

## Regression tests (against a real local Core)

All run against a live trusted Core, with the separate identities, except where noted.

| Requirement | Test (scenario or test) | Result |
|---|---|---|
| Agent self-approval refused | `agent_self_approval_refused` | passed |
| Forged approver identity refused | `forged_approver_identity_refused` | passed |
| Unlisted approver refused | `unlisted_approver_refused` | passed |
| Valid authenticated approval succeeds | `human_approved_write` | passed |
| Revoked approval refused | `revoked_approval` (includes another approver's revocation refused) | passed |
| Revocation after issuance, before execution | `revocation_after_issue_before_execution` | passed |
| Expired approval refused | `expired_approval` | passed |
| Forged execution authorization refused | `forged_authorization_refused` (tampered, re-signed with another key, wrong audience, expired) | passed |
| Modified arguments refused | `modified_arguments_refused` (executor digest check; Core linkage check in `post_approval_mutation`) | passed |
| Authorization replay refused | `replayed_approval` (executor refuses a second use; Core refuses a second authorization) | passed |
| Concurrent consumption cannot authorize duplicate execution | `concurrent_consumption_cannot_duplicate` (8 Core submissions: one authorization; 8 executors: one execution) | passed |
| Core unavailability fails closed | `core_unavailable_fails_closed` (agent gets no authorization; executor refuses; same authorization runs after recovery) | passed |
| Authorization without execution is distinguishable | `authorization_without_execution_is_distinguishable` | passed |
| Evidence independently verifiable | `evidence_independently_verifiable` (offline signature; record-hash binding; receipt present) | passed |
| Prompt injection refused | `prompt_injection` | passed |
| Human rejection refused | `human_rejected` | passed |
| Read through the executor | `allowed_read_only` | passed |

Totals: 18 of 18 scenarios passed; 27 service-backed tests passed (18 scenarios, 7 needing no Core, the benchmark invariants,
and a live tampering check).

Rust tests: 18 gate tests in `rust/tests/tool_approval_gate.rs` (7 new), including the 8-way race test; 13 unit tests for
principals and authorization signing.

## Negative controls

Two sets, both from `examples/agent-reference/negative_controls.py`, using the same seven attacks.

**Trusted Core, separate keys** (`results/negative_controls_trusted.json`): 7 protected, 0 gaps.

**Current staging, one key for every role** (`results/negative_controls_staging.json`): 1 protected, 6 gaps.

- Agent self-approval: accepted on staging (gap). Refused by role on the trusted Core.
- Forged approver identity: accepted on staging (gap). Refused by identity on the trusted Core.
- Approval revocation: no mechanism on staging (gap). Revocation works and the attack is refused on the trusted Core.
- Core-issued authorization: none on staging (gap). Issued on the trusted Core.
- Execution receipts: no mechanism on staging (gap). Accepted only from the executor on the trusted Core.
- Concurrent consumption: exactly one accepted on both (protected). Staging already had this.
- One credential requests, approves, and writes: the write is accepted on staging (gap). Refused on the trusted Core.

## Benchmark (service-backed, trusted execution)

Deterministic and scripted. 10 categories, 10 cases each: 100 cases, 190 calls, 520 Core HTTP requests.

| Measure | Result |
|---|---|
| Unauthorized executions | 0 of 150 calls that must not run (executor-reported and sandbox history) |
| Authorized completions | 40 of 40 |
| False denials | 0 |
| Consequential calls executed without approval | 0 of 150 |
| Evidence verification | 100 of 100 cases |
| Authorization latency (Core accepts and signs; accepted calls) | p50 22.3 ms, p95 33.2 ms, p99 36.9 ms (n=50) |
| Executor verification latency (local checks and status call) | p50 2.0 ms, p95 5.0 ms, p99 8.5 ms (n=50) |
| End-to-end latency (agent submission to executor receipt; executed calls) | p50 50.1 ms, p95 69.6 ms, p99 71.1 ms (n=40) |

Model-based experiments: not run. They are kept separate from this deterministic benchmark, and no benchmark result here
is a model result. Latency is from one machine and one run.

The in-process benchmark is a separate architecture and is not combined with these figures.

## Trusted-executor boundary and bypass paths

**Inside the boundary:** Core's authorization key; Core's policy key (kept separate); the executor's pinned public key,
its store, and its key; the ledger lock.

**Outside the boundary, not stopped by this design:**

- any process that performs a side effect without going through the executor. The external system must accept calls only
  from the executor, with its own credentials;
- any process that can reach the executor's store or key. The executor must run where the agent cannot reach it;
- a Core other than the one the executor trusts (the pinned key and the status URL must point at the right Core);
- clock manipulation beyond the five-second skew allowance.

**Not claimed:**

- exactly-once execution across external systems. A crash between the side effect and the receipt leaves a reservation
  with no receipt, which an operator must reconcile against the external system;
- that revocation stops an execution that has begun, or undoes a completed one;
- resistance to prompt injection in general.

## Gaps remaining (declared)

1. **Identities are static.** Principals and approver identities are configuration. No identity provider, no key rotation
   procedure, no hardware binding. API keys are bearer secrets.
2. **Core's authorization key is an environment secret** in this reference. It must move to a managed key store and be
   rotated by publishing a new pinned key to executors.
3. **Single host.** One Core process per ledger. The executor's store is a local SQLite file, so executors on different
   hosts need a shared store with the same atomic reservation.
4. **The revocation window** between the executor's status check and its side effect (documented above).
5. **Reconciliation** of reservations without receipts is manual.
6. **Approval TTL** in the reference policy is five seconds (a demonstration value).

## Evaluation gate

Passes when every trust-boundary requirement has a regression test that runs against a live Core and passes; the
negative controls show the attacks refused on the trusted Core and succeeding or missing on the baseline; the benchmark
shows zero unauthorized executions and zero false denials on the deterministic workload; the Rust, Python, PostgreSQL,
container, and security-harness suites pass; the agent-reference tests run in CI with none skipped; and `make gate`
passes. These hold for this change set on the committed tree.

## Human approval gate

Not approved for production by this report. Merging into `staging` is a separate decision. Before any production use:
an identity provider and key-management design for approvers and the executor, a managed authorization key with rotation,
a shared executor store with the same atomic reservation, reconciliation of reservations without receipts, and a reviewed
approval TTL. The open decisions in issue #501 still apply.
