# Integrating AIGov Core with your agent

This guide is for connecting your own tools and approval process to AIGov Core, using the trusted-execution design.
Four parties hold separate credentials, and each can do only its own part:

- **Agent**: requests approvals and submits calls. It holds only its own key. It cannot approve, revoke, sign, or write
  receipts.
- **Approver**: a human decision, recorded under the approver's own key. Core checks that the approver named in the
  record is the authenticated identity, and that the approver is not the requester.
- **Core**: decides every call by policy. It records the decision in the ledger. For each accepted call it issues a
  signed execution authorization, with a key that no agent holds.
- **Executor**: performs the side effect. It verifies the authorization itself before it acts, and records a receipt
  afterwards. It holds its own key and the pinned public authorization key.

Read the README first for the decision table, the policy, and the results. Read sections 1 to 3 before you wire
anything. Read section 5 before you deploy.

The reference code is in `aigov_agent_reference/core_trusted.py`, `core_gate.py`, `core_policy.py`, and
`trusted_scenarios.py`. The launcher that generates identities is `service/trust_setup.py`.

## 1. Decide what needs a human

List the consequential actions: writes, admin changes, deployments, payments, anything hard to undo. Their tools go on
the write allowlist in your policy. They need an approval. Reads need no approval, but they still go through the executor
with an authorization, so every side effect has the same path.

## 2. Write the policy and register the identities

Start from `policies/core_policy.unsigned.json`. It is the reviewed policy. Changes are reviewed like code, and a test
checks that the signed bundle is the code's output.

The policy decides, per event type:

- `tool_call` (reads) and `consequential_tool_call` (writes): the tool allowlists (`requires_decision_enum`), and for
  writes the approval gate (`requires_unconsumed_approval`) with its freshness window (`max_age_seconds`) and linkage
  keys (tool, call id, argument digest, policy revision).
- `human_approved`: the approver allowlist, the identity match (`requires_field_matches_field`), self-approval refusal
  (`requires_principal_relation`, distinct), and the timestamp freshness check.
- `human_approval_revoked`: only the approver who gave the approval may revoke it (`requires_principal_relation`, same).
- `execution_receipt`: only for an issued authorization, for the same tool and argument digest, and only once
  (`requires_issued_authorization`).

Identities are configured in `GOVAI_PRINCIPALS_JSON`: one entry per API key, with a principal id, a human identity, a
role (`agent`, `approver`, or `executor`), and a tenant. Core refuses startup if a key is not also in `GOVAI_API_KEYS`,
if two principals share an id, or if an approver's identity is also the agent's.

Core needs two more settings for authorizations: `GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX` (the 32-byte Ed25519 seed,
held only by Core) and `GOVAI_EXECUTOR_AUDIENCE`. Issuance requires principals to be configured.

## 3. Route each actor through its own credential

**Agent.** For each tool call, the agent submits an evidence event with its own key:

- a read: `tool_call`, with the argument digest;
- a write without an approval yet: `tool_approval_requested`, then `consequential_tool_call` naming that request. Core
  answers `REQUIRE_APPROVAL`. Show the request to the approver along with the exact arguments.
- a write with an approval: `consequential_tool_call`, naming the approval. Core answers `ALLOW` with a signed
  `execution_authorization`, or refuses with a reason.

The agent passes the authorization to the executor. It cannot change it: the signature covers every field.

**Approver.** A reviewer's interface posts `human_approved` (approve or reject) with the approver's own key, and
`human_approval_revoked` to withdraw an approval. The approver's key is not given to the agent. In the reference, the
approver's identity comes from the approver's principal, and Core refuses a record that names someone else.

**Executor.** The executor, with its own key:

1. verifies the authorization signature with the pinned public key, under the domain
   `govai.execution_authorization.v1`;
2. checks the audience, the run, the tool, the expiry (with five seconds of clock skew), and that the argument digest
   it computes from its own arguments equals the authorization's;
3. asks Core for the status (`GET /execution-authorizations/{run}/{id}/status`). It proceeds only if the state is
   `authorized`. If Core cannot be reached, it refuses;
4. reserves the authorization in its local store, atomically. A second reservation is a replay, and is refused;
5. performs the side effect;
6. posts an `execution_receipt` with the outcome and a result digest.

The reservation comes before the side effect and the receipt comes after it, so the two records are separate evidence.
An authorization with no receipt means it was issued and not confirmed. A receipt means the executor recorded an outcome.

## 4. Commit points, and what revocation can and cannot do

- **Authorization** is decided when Core records the accepted call under the ledger lock. The approval is consumed at
  that point, so one approval produces at most one authorization. Revocation and consumption share that lock, so they
  serialize: a revocation recorded first stops the call, and a call recorded first is not undone by a later revocation
  of the approval.
- **Revocation after issuance, before execution.** The executor checks status before it reserves. A revocation recorded
  before that check stops the execution. A revocation recorded after the check, and before the side effect, does not
  stop it. This window is small and it is real. Do not describe revocation as stopping an execution that has begun.
- **Revocation does not undo completed external actions.** Once the side effect has happened, nothing in this design can
  reverse it. Revocation is for authorizations that have not yet been used.
- **Exactly-once across external systems is not claimed.** The executor's store prevents a second local execution of the
  same authorization. If the executor crashes after the side effect and before the receipt, the store shows a reservation
  with no receipt. An operator must reconcile that against the external system. Core cannot see the external action.

## 5. Keys, the trust boundary, and the bypass paths

The trust boundary is the set of places where a credential can do something that matters:

- Core's **authorization key** signs authorizations. It must never be given to an agent, an approver, or an executor.
  Keep it in a secret store, and rotate it by publishing a new pinned key to executors.
- Core's **policy key** signs the policy bundle. Keep it separate from the authorization key.
- The **executor's pinned public key** is the only thing an executor needs to verify an authorization offline. Pin it from
  configuration, not from the authorization itself.
- The **agent's key** can submit calls and read. A stolen agent key can request approvals and submit calls that the
  policy then refuses or holds for approval. It cannot approve.
- An **approver's key** can approve or reject, but only as the identity it is bound to. A stolen approver key can approve
  requests in that identity. Protect approver keys as human credentials, and rotate them.
- The **executor's key** can record receipts for authorizations that exist. A stolen executor key can record false
  receipts; it cannot create authorizations.

Uncontrolled bypass paths, which this design does not stop:

- Any process that can perform the side effect without asking the executor. The sandbox and the external systems must
  accept calls only from the executor, with their own credentials.
- Any process holding the executor's private state (its local store and key). The executor must run in a process the
  agent cannot reach.
- A Core that is not the one the executor trusts. The executor's pinned key and its status URL must point at your Core.
- Clock manipulation beyond the five-second skew allowance, on the executor or on Core.

## 6. Operate on the evidence

- Verify each run with `GET /verify/{run_id}` (Core's chain check). For each executed call, check that the authorization's
  `consequential_record_hash` matches the record Core stored for the consequential event, and that a receipt exists.
  The reference's benchmark and scenarios do this, and the scenario `evidence_independently_verifiable` shows the offline
  check.
- Alert on `INDETERMINATE` and on `core_unavailable` refusals. Fix the dependency first; do not retry blindly.
- Watch refusal reasons. A spike in `role_not_permitted`, `approver_identity_mismatch`, or `self_approval_refused` means
  a credential is being misused.
- Reconcile reservations that have no receipt (section 4).

## 7. Limits to plan around

- **Identities are static.** Principals come from configuration, and approver identities are names written in that
  configuration. There is no identity provider in this design. Connecting one is the next step, and it changes who can
  hold an approver key.
- **API keys are bearer secrets.** They are not bound to hardware or to a device. Rotate them, and store them as secrets.
- **Single host.** The ledger lock serializes writes within one Core process. Do not run two Core processes on one
  ledger. The executor's store is local SQLite: one store per executor, and executors on different hosts need a shared
  store with the same atomic reservation.
- **Expiry is server-clock based** for approvals, and executor-clock based for authorizations (five seconds of skew).
- **Not prompt-injection immunity.** Core limits what an injected instruction can do. It does not stop a model from being
  manipulated.

## 8. Reproduce it locally

For an end-to-end run on synthetic enterprise tools, with a report, see `docs/customer-pilot.md` and
`examples/customer-pilot/pilot.py run`. The steps below reproduce the reference itself.


1. `pip install -e "python[agent-reference]"`
2. `python examples/agent-reference/service/start_local_core.py start` (Docker), or
   `service/start_core_binary.py` with a release binary and a PostgreSQL database.
3. `export GOVAI_TRUST_STATE=~/.cache/aigov-agent-reference/state.json` (or the path the binary launcher printed).
4. `python examples/agent-reference/run_core_demo.py --cases 10`: the 18 scenarios and the benchmark.
5. `python -m pytest python/tests/test_agent_reference_core.py -q`: the service-backed tests.
6. `python examples/agent-reference/negative_controls.py --core-url ... --agent-key ... --approver-key ... --executor-key ...`:
   the seven attacks, with the agent, approver, and executor keys from the state file.
7. `python examples/agent-reference/service/start_local_core.py stop`.

Copy the scenarios into your own test suite and point them at your tools and policy. At minimum, keep these:
self-approval refused; forged approver identity refused; valid approval accepted; revoked and expired approvals refused;
tampered, wrong-audience, and expired authorizations refused; changed arguments refused; a replayed authorization refused;
concurrent use of one approval producing one authorization; Core unreachable failing closed; authorization without a
receipt distinguishable from a completed execution; evidence verifiable offline.
