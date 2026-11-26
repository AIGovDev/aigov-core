# AIGov Core: reference integration for tool-using agents

This example runs a real [smolagents](https://github.com/huggingface/smolagents) agent against AIGov Core with
**trusted execution**. Four parties hold separate credentials and can do only their own part:

- the **agent** requests approvals and submits calls;
- the **approver** (a human) decides approvals, under its own key, in its own identity;
- **Core** decides every call by policy, records it in the ledger, and issues a signed execution authorization;
- the **executor** verifies that authorization itself before any side effect, and records a receipt afterwards.

Everything runs locally against synthetic tools. No model API, no network service, no credential beyond the keys this
example generates.

There are two architectures. Their results are reported separately and never combined:

| | Trusted execution (the integration) | In-process prototype |
|---|---|---|
| Where the decision is made | AIGov Core, over HTTP | The gate, inside the agent's process |
| Who performs the side effect | A separate executor, after verifying Core's authorization | The same process |
| Evidence | The Core ledger, plus the executor's receipts | A local hash-chained log |
| Needs | Docker (or a release binary) and PostgreSQL | Python only |

## Run it

Requires Python 3.10 or newer (tested on 3.12), Docker, and this repository.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e "python[agent-reference]"

# 1. Start a local Core container with PostgreSQL. It generates the identities and keys for this run.
python examples/agent-reference/service/start_local_core.py start

# 2. Run the 18 trusted-execution scenarios and the benchmark.
export GOVAI_TRUST_STATE=~/.cache/aigov-agent-reference/state.json
python examples/agent-reference/run_core_demo.py --cases 10

# 3. The seven trust-boundary attacks, with the three separate keys.
python examples/agent-reference/negative_controls.py --core-url http://127.0.0.1:18088 \
  --agent-key ... --approver-key ... --executor-key ...   # keys are in the state file

# 4. Stop the containers, network, ledger volume, and state file.
python examples/agent-reference/service/start_local_core.py stop
```

No Docker? `service/start_core_binary.py --binary <release aigov_audit> --database-url <postgres url>` starts Core
without a container. CI uses this path.

Tests, with a Core running and `GOVAI_TRUST_STATE` set: `python -m pytest python/tests/test_agent_reference_core.py -q`.
Without the state file, the service tests skip, unless `AIGOV_REF_REQUIRE_CORE=1`, which makes a missing Core a failure.
Seven tests need no Core at all: the fail-closed check, the policy match, signature and domain checks, and the atomic
single-use reservation.

## How a call is authorized and run

```
 agent (its key)                Core (policy, ledger, signing key)            executor (its key)
 ───────────────                ───────────────────────────────────            ──────────────────
 tool_approval_requested  ───▶  record the request, stamp the requester
                                                      ◀─── human_approved (approver's key)
                                 check identity, self-approval, freshness
 consequential_tool_call  ───▶  check approval: approved, in scope, not
                                revoked, not used, in date, same call
                                ── record the call, consume the approval
                                ── sign an authorization ─────────────▶  verify the signature (pinned key, domain)
                                                                         check audience, run, tool, digest, expiry
                                ◀──── status check ───────────────────── GET status (must be "authorized")
                                                                         reserve (single use), then act
                                ◀──── execution_receipt ────────────────  record the outcome and a result digest
```

Core answers each submission with a decision: `ALLOW` (accepted, with a record hash, and for a call, a signed
authorization), `REQUIRE_APPROVAL` (no approval recorded yet), `DENY` (refused, with Core's reason), or
`INDETERMINATE` (Core unreachable: fail closed). The reason comes from Core, not from the reference.

## What each credential can and cannot do

| Credential | Can | Cannot (refused by Core, by role) |
|---|---|---|
| Agent | request approvals, submit reads and writes, record blocked calls | approve, revoke, record receipts |
| Approver (identity `maintainer@…`) | approve or reject its own identity's requests, revoke its own approvals | approve in another identity, approve its own request, submit calls, record receipts |
| Executor | record receipts for issued authorizations, check status | approve, submit calls |
| Core's authorization key | sign authorizations | (held only by Core; never given to an actor) |

## Results (last run, `results/trusted_*.json`)

Scenarios: 18 of 18 passed. Each checks Core's decisions and refusal reasons, the sandbox state, the executor's
receipts, Core's chain verification, and that every executed call is backed by an authorization whose record hash
matches Core's ledger.

- Allowed read-only call, run through the executor.
- Agent self-approval refused (`role_not_permitted`). Forged approver identity refused (`approver_identity_mismatch`).
  Unlisted approver refused (`approver_not_allowlisted`).
- Human-approved write: refused before approval, then authorized and executed once, with a receipt.
- Human-rejected write refused. Prompt injection asking for a deployment refused (`tool_not_permitted`).
- Expired approval refused. Replayed approval refused twice: by Core (`approval_already_consumed`) and by the executor
  (`authorization_receipt_recorded`).
- Core unreachable: the agent gets `INDETERMINATE`, and the executor refuses (`core_unavailable`). The same authorization
  runs once Core returns.
- Changed arguments after approval refused by Core (`approval_linkage_mismatch`).
- Revoked approval refused. Another approver's revocation refused (`revocation_not_by_approver`). Revocation after
  issuance and before the executor's check stops execution (`authorization_revoked`).
- Tampered, re-signed, wrong-audience, and expired authorizations refused by the executor.
- Changed arguments under a valid authorization refused by the executor (`authorization_arguments_mismatch`).
- Eight concurrent submissions on one approval: one authorization. Eight concurrent executors on one authorization: one
  execution.
- An authorization with no receipt is distinguishable from a completed execution (`status` moves from `authorized` to
  `receipt_recorded`).
- Evidence verifies offline: the authorization's signature with the pinned key, and its record hash against Core's ledger.

Benchmark (deterministic, scripted agent; 10 categories, 10 cases each, 100 cases, 190 calls, 520 Core HTTP requests):

| Measure | Result |
|---|---|
| Unauthorized executions | 0 of 150 calls that must not run |
| Authorized completions | 40 of 40 |
| False denials | 0 |
| Consequential calls executed without approval | 0 of 150 |
| Evidence verified (Core chain, record hashes, receipts, refusals recorded) | 100 of 100 cases |
| Authorization latency (Core accepts and signs) | p50 22.3 ms, p95 33.2 ms, p99 36.9 ms (n=50) |
| Executor verification latency (local checks and status call) | p50 2.0 ms, p95 5.0 ms, p99 8.5 ms (n=50) |
| End-to-end latency (agent submission to executor receipt) | p50 50.1 ms, p95 69.6 ms, p99 71.1 ms (n=40) |

These are one machine and one run. Latency varies between runs.

## Negative controls: the same attacks against two systems

`negative_controls.py` runs seven attacks against a Core. Each control separates the attack from the mechanism the
design needs.

| Control | Trusted Core (separate keys) | Current staging (one key for every role) |
|---|---|---|
| Agent self-approval | protected: `role_not_permitted` | **gap**: accepted |
| Forged approver identity | protected: `approver_identity_mismatch` | **gap**: accepted |
| Approval revocation | protected: agent refused, approver's own revocation accepted | **gap**: no revocation event exists |
| Core-issued authorization | protected: signed authorization present | **gap**: none issued |
| Execution receipts | protected: agent refused, executor's receipt accepted | **gap**: no receipt event exists |
| Concurrent consumption of one approval | protected: exactly one accepted | protected: exactly one accepted |
| One credential requests, approves, and writes | protected: approval refused | **gap**: the write is accepted |

Staging already has the consumption lock. Everything else in the table is missing there.

## What Core needed

Core had no pre-execution authorization for tool calls, and no way to tie an approval to an authenticated person. This
change adds:

- **Principals with roles** (`rust/src/principals.rs`). `GOVAI_PRINCIPALS_JSON` maps each key to one principal, a human
  identity, a role, and a tenant. Core stamps the authenticated fields into every event itself, and checks the event type
  against the role.
- **Approval gates** (`rust/src/policy_engine.rs`): `requires_field_matches_field` (approver identity),
  `requires_principal_relation` (distinct requester for approvals, same approver for revocation), revocation checked
  inside the approval gate, and `requires_issued_authorization` for receipts.
- **Signed execution authorizations** (`rust/src/execution_authorization.rs`). Ed25519 with a domain prefix
  (`govai.execution_authorization.v1`) and a dedicated key. The signed payload binds the run, tool, argument digest,
  policy revision, approval, the ledger record, the executor audience, the expiry, and a unique id.
- **Ledger ordering** (`rust/src/govai_api.rs`, `rust/src/audit_store.rs`): with principals configured, every ingest is
  checked under the ledger lock, so revocation and consumption serialize.
- **Status endpoint**: `GET /execution-authorizations/{run}/{id}/status`, for the executor only.

Tests: 18 Rust gate tests (7 new, for identity, self-approval, revocation, and receipts), the race test, and the
authorization signature tests.

## Trust boundary and what is not claimed

The full statement is in `INTEGRATION.md` (sections 4 and 5), and in the report. In summary:

- **Exactly-once across external systems is not claimed.** The executor reserves before it acts. A crash between the
  side effect and the receipt leaves a reservation with no receipt, which an operator must reconcile.
- **Revocation** stops an authorization that has not yet been checked by the executor. It does not stop a side effect
  that has begun, and it does not undo a completed one.
- **Identities are static.** Approver identities are names in configuration, not from an identity provider.
- **Single host.** One Core process per ledger. The executor's store is a local SQLite file.
- **Bypass paths** the design does not stop: a process that performs the side effect without the executor, a process
  that holds the executor's store and key, and a Core other than the one the executor trusts.

## The in-process prototype

`run_demo.py` runs similar scenarios against an in-process gate, for quick regression of the integration logic. It is not
evidence about Core. Its benchmark uses a deterministic scripted agent under three enforcement conditions. Without
enforcement, 1,600 unauthorized calls executed; with it, none did. Those figures measure the gate, not Core.

## Files

The customer pilot, which reuses this trusted-execution code with its own tools and identities, is in
`examples/customer-pilot/` (see `docs/customer-pilot.md`).

```
examples/agent-reference/
  README.md                          this file
  INTEGRATION.md                     guide: identities, commit points, revocation window, bypass paths
  run_core_demo.py                   trusted scenarios and benchmark (needs a running Core)
  negative_controls.py               the seven trust-boundary attacks, against any Core
  run_demo.py                        in-process prototype scenarios and benchmark
  policies/
    core_policy.unsigned.json        reviewed Core policy (the signed bundle is generated at start)
    example_policy.json              in-process prototype policy
  service/
    trust_setup.py                   identities, API keys, principals, signing keys for one Core run
    start_local_core.py              Docker: Core and PostgreSQL 18
    start_core_binary.py             no Docker: release binary, used by CI
  aigov_agent_reference/
    core_policy.py                   the Core policy and its signing
    core_gate.py                     HTTP client, one principal per client; decisions from Core's answers
    core_trusted.py                  agent, approver, and executor actors; authorization verification; executor store
    trusted_scenarios.py             18 scenarios
    trusted_benchmark.py             benchmark with authorization, verification, and end-to-end latency
    gate.py, approvals.py, decision_log.py, policy.py, environment.py, agent.py, scenarios.py, benchmark.py
                                     in-process prototype
  results/                           machine-readable results from the last runs
python/tests/test_agent_reference_core.py          27 service-backed and no-Core tests
python/tests/test_agent_reference_integration.py   20 in-process tests
rust/tests/tool_approval_gate.rs                   18 Rust gate tests
```
