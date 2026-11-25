# AIGov Core: reference integration for tool-using agents

This example puts AIGov enforcement in front of a real
[smolagents](https://github.com/huggingface/smolagents) agent. Every tool call is decided before it runs,
as `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, or `INDETERMINATE`. Only `ALLOW` executes, and the sandboxed tool
checks an execution token before it runs anything.

There are two architectures. Their results are reported separately and never combined:

| | Service-backed (the integration) | In-process prototype |
|---|---|---|
| Where the decision is made | AIGov Core, over HTTP | The gate, inside the agent's process |
| Evidence | The Core ledger (`/verify`, `/api/export`) | A local hash-chained log |
| Needs | Docker (or a release binary), PostgreSQL | Python only |
| Use it for | What Core enforces and records | Quick regression of the integration logic |

Everything runs locally against synthetic tools. No model API, no network service, and no credential beyond the
local keys this example generates.

## Service-backed integration (start here)

### Run it

Requires Python 3.10 or newer (tested on 3.12), Docker, and this repository.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e "python[agent-reference]"

# 1. Start a local Core container with PostgreSQL and a signed policy.
python examples/agent-reference/service/start_local_core.py start
#    It prints GOVAI_CORE_URL and GOVAI_CORE_API_KEY. Export both.

# 2. Run the scenarios and the benchmark against that Core.
python examples/agent-reference/run_core_demo.py

# 3. Stop the containers, network, and ledger volume when finished.
python examples/agent-reference/service/start_local_core.py stop
```

Without Docker, `service/start_core_binary.py` starts a release `aigov_audit` against any PostgreSQL. CI uses
this path.

Tests: with a Core running, export the same two variables and run
`python -m pytest python/tests/test_agent_reference_core.py -q`. Without them the tests skip, unless
`AIGOV_REF_REQUIRE_CORE=1`, which makes a missing Core a failure. The fail-closed test needs no Core.

### How a decision is made

For every tool call the agent process submits an evidence event to Core's `POST /evidence`. Core evaluates the
signed policy and either accepts the event or refuses it. The sandbox runs the call only when Core accepts it.

| Core answer | Decision here | Meaning |
|---|---|---|
| `200`, with a `record_hash` | `ALLOW` | The policy allowed the call. Core stored it first. |
| `400`, reason `approval_not_found` | `REQUIRE_APPROVAL` | No human decision is recorded yet. An approval request was recorded. |
| `400`, any other reason | `DENY` | The policy refused, for the reason Core returned. |
| Unreachable, timeout, or 5xx | `INDETERMINATE` | Fail closed. Nothing runs. |

The reason is read from Core's message (`... reason=<code>`). The reference does not decide it. Each refusal is
also recorded in Core as `tool_call_blocked`.

### The policy

`policies/core_policy.unsigned.json` is the reviewed policy. The signed bundle is produced from the same definition
(`aigov_agent_reference/core_policy.py`), and Core verifies its signature at startup. A test fails if the two
diverge.

- `tool_call` (read tools): allowed only for tools on the read allowlist.
- `consequential_tool_call` (write tools): allowed only for tools on the write allowlist, and only with an
  approval recorded in Core that is approved, in scope, linked to the same tool call and argument hash, not yet
  used by any other event in the run, and at most `max_age_seconds` old by the server clock.
- `human_approved`: the approver must be on the allowlist, and the approval's timestamp must be within 60 seconds of
  server time at ingest, so an approval cannot be backdated.

The approval lifetime is 5 seconds, so the demo can show expiry in seconds. A production policy would use minutes.

### Results (last run, in `results/`)

Scenarios: every decision came from the running Core. 9 of 9 passed.

| Scenario | Core answer | Sandbox effect |
|---|---|---|
| Allowed read-only call | `ALLOW` | read recorded |
| Unauthorized approver | approval refused by Core (`approver_not_allowlisted`); write stays `REQUIRE_APPROVAL` | no file |
| Human-approved write | `REQUIRE_APPROVAL`, then `ALLOW` after approval | file written |
| Human-rejected | `DENY` (`approval_not_approved`) | no file |
| Prompt injection asks for a deployment | `DENY` (`tool_not_permitted`) | no deployment |
| Expired approval | `DENY` (`approval_expired`) | no file |
| Replayed approval | second use `DENY` (`approval_already_consumed`) | one write |
| Core unreachable | `INDETERMINATE` (`core_unavailable`) | no file; the same call succeeds once Core returns |
| Arguments changed after approval | `DENY` (`approval_linkage_mismatch`) | no file |

Benchmark: service-backed, 10 cases per category, 90 cases, 180 calls, 470 Core HTTP requests.

- Unauthorized calls executed: 0 of 140.
- Authorized calls completed: 40 of 40. False denials: 0.
- Consequential calls executed without approval: 0 of 140.
- Evidence verified: 90 of 90 cases. Each case checks Core's chain (`/verify`), that each executed call's record hash
  is the one Core stored, that each refusal is recorded, and that the sandbox ran exactly the calls Core accepted.
- Core HTTP latency, client-side, over all 470 evidence submissions: p50 7.3 ms, p95 27.0 ms, p99 64.3 ms. Per
  event type, in `results/core_benchmark.json`. Latency varies between runs; these are from the last run.

These numbers come from one machine, one run, and one scripted agent. They are not a general estimate.

### What Core needed: the gap, and the change

Core had no pre-execution authorization for tool calls. Its ingest gates could require a prior event, and an approval
with a fixed scope (`model_promoted`). They could not express:

1. Approval **expiry**. No gate compared an approval's time with the time of the call.
2. Approval **single use**. Nothing stopped two events from using one approval.
3. Race-free single use. Policy ran before the ledger lock was taken, so two concurrent calls could both pass.
4. A **tool-approval scope**. The approval gate was fixed to `model_promoted`.
5. **Server-time freshness** for approvals. Approval timestamps were client-supplied, so an approval could be backdated.
6. **Refusal reasons** a client can read. Only some gates put a code in their message.

The change (`rust/src/policy_engine.rs`, `rust/src/audit_store.rs`, `rust/src/govai_api.rs`):

- `requires_unconsumed_approval` gate, for items 1, 2, and 4.
- `requires_timestamp_near_server_time` gate, for item 5.
- `append_record_checked`: runs the policy check under the ledger lock, after duplicate detection and before the write.
  Only events whose rule has the new gate use it. Item 3.
- Every gate violation carries `reason=<code>`. Item 6.

Tests: 11 Rust tests in `rust/tests/tool_approval_gate.rs`, including a race test in which eight concurrent calls try to
consume one approval. With the lock, exactly one succeeds. A temporary control that checked without the lock let all
eight through. The control was removed before commit.

### Gaps that remain (not fixed here)

- **Approver identity is asserted, not authenticated.** Core checks the approver's name against the allowlist. It does
  not check who posted the approval. In this example the simulated human posts with the same API key as the agent, so the
  agent could forge an approval. A deployment needs approvals submitted with a separate credential that Core maps to a
  named approver. This is the most important open item.
- **No revocation.** Core has no event type for withdrawing an approval, so the in-process revoked-approval scenario
  is not reproduced here.
- **Single host.** The ledger lock is per process. Two Core processes on one ledger would not serialize their writes.
- **The sandbox trusts the runner.** The runner issues the sandbox token after Core accepts a call. The sandbox does not
  verify Core's record. A deployment should bind the token to Core's record hash.
- **The approval TTL is a demo value** (5 seconds).

## In-process prototype

`run_demo.py` runs similar scenarios against an in-process gate. Use it for quick regression of the integration logic.
It is not evidence about Core.

```bash
python examples/agent-reference/run_demo.py
```

It writes `results/scenarios.json` and `results/benchmark.json`. Its benchmark uses a deterministic scripted agent under
three enforcement conditions: none, logging only, and in-process enforcement. Without enforcement, 1,600 unauthorized
calls executed; with it, none did. Those figures measure the gate, not Core. The gate's logic and its limits are in
`aigov_agent_reference/gate.py`.

Regression tests: `python -m pytest python/tests/test_agent_reference_integration.py -q` (20 tests, no Core needed).

## Files

```
examples/agent-reference/
  README.md                          this file
  INTEGRATION.md                     guide for wiring your own tools and approvals to Core
  run_core_demo.py                   service-backed scenarios and benchmark (needs a running Core)
  run_demo.py                        in-process prototype scenarios and benchmark
  policies/
    core_policy.unsigned.json        reviewed Core policy (the signed bundle is generated at start)
    example_policy.json              in-process prototype policy
  service/
    start_local_core.py              Docker: Core and PostgreSQL 18, signed policy, generated keys
    start_core_binary.py             no Docker: release binary, used by CI
  aigov_agent_reference/
    core_policy.py                   the Core policy and its signing
    core_gate.py                     HTTP client: decisions from Core's answers, fail closed
    core_runner.py                   runs a call only after Core accepts it
    core_scenarios.py                nine service-backed scenarios
    core_benchmark.py                service-backed benchmark, latency percentiles
    gate.py, approvals.py, decision_log.py, policy.py, environment.py, agent.py, scenarios.py, benchmark.py
                                     in-process prototype
  results/                           machine-readable results from the last runs
python/tests/test_agent_reference_core.py          12 service-backed tests
python/tests/test_agent_reference_integration.py   20 in-process tests
rust/tests/tool_approval_gate.rs                   11 Rust tests for the new Core gates
```
