# AIGov Core: reference integration for tool-using agents

This example puts AIGov Core's enforcement primitives in front of a real
[smolagents](https://github.com/huggingface/smolagents) agent. Every tool call the agent
makes is decided before it runs. The decision is one of `ALLOW`, `DENY`,
`REQUIRE_APPROVAL`, or `INDETERMINATE`. Only `ALLOW` executes, and the tool itself checks
that before it runs. The example writes a tamper-evident decision log and checks it.

Everything runs locally against synthetic tools. No model API, network service, or
credential is needed.

## Run it

Requires Python 3.10 or newer (tested on 3.12) and this repository. From the repository root:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e "python[agent-reference]"
python examples/agent-reference/run_demo.py
```

This runs the ten scenarios, checks the sandbox state after each one, runs the benchmark,
and writes `results/scenarios.json` and `results/benchmark.json`. It takes about a minute.
`--scenarios-only` skips the benchmark, and `--cases 20` makes the benchmark smaller.

Regression tests:

```bash
python -m pytest python/tests/test_agent_reference_integration.py -q
```

## What it demonstrates

Each scenario runs a real `ToolCallingAgent`. Each scenario then checks what happened to
the sandbox and whether the decision log verifies, not only the gate's returned verdict.

| Scenario | What the agent does | Decision | Sandbox effect |
|---|---|---|---|
| `allowed_read_only` | Reads repository metadata | `ALLOW` | none (read) |
| `denied_unauthorized_write` | Writes with an approval from someone the policy does not authorize | `DENY` (`policy:unauthorized_principal`) | no file |
| `human_approved_write` | Requests a write, is held for approval, then retries after a human approves | `REQUIRE_APPROVAL`, then `ALLOW` | file written |
| `human_rejected` | Retries after a human rejects | `DENY` (`human_rejected`) | no file |
| `prompt_injection` | Repo metadata contains an instruction to deploy; the model follows it | read `ALLOW`; deploy `DENY` (`tool_not_permitted_for_agent`) | no deployment |
| `expired_approval` | Uses an approval after its time limit | `DENY` (`approval_expired`) | no file |
| `replayed_approval` | Uses the same approval twice | second call `DENY` (`approval_replayed`) | one write |
| `aigov_unavailable` | Approval service is down during the retry | `INDETERMINATE` (`gate_unavailable`) | no file |
| `post_approval_mutation` | Changes the content after approval | `DENY` (`approval_does_not_match_request`) | no file |
| `revoked_approval` | Approval is revoked before use | `DENY` (`approval_revoked`) | no file |

The prompt-injection scenario is deliberate. The scripted model obeys the injected text.
The result shows that the gate refuses the call. It does not show that a language model
resists injection.

## Decisions

Evaluated in this order. The first decision that is not `ALLOW` stops the call.

1. The tool must be on the agent's policy allowlist. Otherwise `DENY`, `tool_not_permitted_for_agent`.
2. Consequential actions (`repo:write`, `repo:admin`, `deploy:production`) need a human approval.
   - No approval ID: a pending request is created, and the decision is `REQUIRE_APPROVAL`.
   - Unknown ID, or an approval bound to different arguments: `DENY`.
   - Pending: `REQUIRE_APPROVAL`. Rejected: `DENY`. Expired or revoked: `DENY`.
3. The approver of record (or the agent, for read-only actions) must be authorized by the signed policy for this action, this resource, and this tenant.
4. The approval is consumed once. A second use is `DENY` (`approval_replayed`).
5. The revocation list is checked again immediately before execution.
6. A write-ahead entry is appended to the decision log. Then an execution token is issued. The sandbox verifies that token before it does anything.

Any exception in steps 1 to 6 returns `INDETERMINATE` and executes nothing.

## Architecture

```
  smolagents ToolCallingAgent  (structured tool calls; no code execution)
        │  tool call (name, arguments, approval_id?)
        ▼
  governed tools  ──►  AgentGate.request()
                          │ 1 allowlist   2 approval state   3 policy   4 consume once
                          │ 5 revocation  6 write-ahead log → EAT issued
                          │                                   │
                          ▼ decision (ALLOW / DENY /          ▼ ALLOW only
                            REQUIRE_APPROVAL / INDETERMINATE)  SandboxedGitHubTools
                          │                                   │ verifies the EAT itself;
                          ▼                                   │ records every attempt
                  decision_log.jsonl  (hash chain)            ▼
                          ▲                             sandbox repo state
                          └──── verify_evidence() ◄──── execution history
```

## What is reused and what is new

Reused from `benchmarks/agent-verification` (no changes to them):

| Component | Used for |
|---|---|
| `TrustedPolicyProvider`, `PolicyRecord`, `make_policy_record` | Signed, versioned authorization records |
| `ReplayRegistry` with `SqlNonceStore` (SQLite) | Consuming an approval exactly once across processes |
| `RevocationList` | Revoking an approval before execution |
| `ExecutionTokenAuthority` | Binding an execution token to tool, arguments, action, resource, and tenant |
| `SandboxedGitHubTools` | Synthetic tools with observable state; checks the token itself |
| `compute_args_binding_hash`, `TOOL_CAPABILITY_MAP` | Argument binding and tool-to-action mapping |

New in `examples/agent-reference`:

- `approvals.py`: a SQLite approval store. Requests are bound to the exact call. Approvals expire.
- `gate.py`: the pre-execution gate, the write-ahead decision log, and `verify_evidence`.
- `decision_log.py`: hash-chained JSON Lines log and its verifier.
- `policy.py`, `policies/example_policy.json`: declarative policy loaded into signed records.
- `agent.py`: smolagents tools that route every call through the gate, and a scripted model.
- `scenarios.py`, `benchmark.py`, `run_demo.py`: scenarios, the three-condition benchmark, and the entry point.

Deliberately not used: `ToolGateway` and `ConditionIOrchestrator`. Their external-state
check compares an audit record's executed value with a read-back. That check verifies an
action after it has happened. It would not authorize a write before it runs, because the
state has not changed yet. The gate above performs the pre-execution checks with the same
primitives, and the sandbox still verifies the token.

## Controlled execution and bypass paths

The agent can reach a tool only through the governed tools built in `agent.py`. Each of
those tools calls `AgentGate.request`. Within the gate, the only path to the sandbox passes
an execution token issued after `ALLOW`.

Paths this example does **not** cover, and what would cover them:

- **Arbitrary code execution.** `CodeAgent` runs model-written Python, which is a separate
  path. This example never uses it. If you add a code-executing agent, run it in a sandbox
  with no access to tool objects, and make the tools reachable only through the gate.
- **Direct calls to the sandbox.** `SandboxedGitHubTools.execute` refuses calls without a
  token from its own authority (tested). Code that holds the authority object could still
  issue tokens. Keep it out of the agent's process.
- **Network access from the agent process.** Not restricted here. Restrict it at the
  process or network level in a deployment.

## Benchmark

Same agent, same scripted plans, same approval store, and same sandbox in all three
conditions. Only the enforcement layer differs.

- **A, no enforcement.** Every call runs.
- **B, logging only.** Every decision is logged, and every call runs.
- **C, AIGov enforcement.** Only `ALLOW` runs.

Workload: 10 categories, 100 cases each, deterministic. That is 2,000 calls per condition
(1,600 that must not run, 400 that must). Ground truth is fixed by each case, not by any
condition's output. Results from the last run (`results/benchmark.json`):

| Condition | Unauthorized executions | Authorized calls completed | False denials | Consequential calls held without approval | Evidence verified (cases) | Gate median latency |
|---|---|---|---|---|---|---|
| A, no enforcement | 1600 / 1600 | 400 / 400 | 0 / 400 | 0.0% | 0.0% | 0.04 ms |
| B, logging only | 1600 / 1600 | 400 / 400 | 0 / 400 | 0.0% | 10.0% | 0.64 ms |
| C, AIGov enforcement | **0 / 1600** | 400 / 400 | 0 / 400 | **100.0%** | **100.0%** | 0.41 ms |

Definitions:

- *Unauthorized executions*: calls that should not run, and did run. Counted from the sandbox history.
- *Authorized completion*: calls that should run, and did run.
- *False denials*: calls that should run, and did not.
- *Consequential calls held without approval*: write, admin, and deploy calls that should not run, and did not.
- *Evidence verified*: a case passes only if the decision log verifies and every executed call was logged as `ALLOW`. Condition A records no decisions, so it cannot pass. Condition B passes only cases where it executed nothing unauthorized.
- *Gate latency*: time inside `AgentGate.request` per call, excluding agent overhead. It depends on the machine and on disk speed. The numbers above are from one machine.

Limits, stated plainly:

- The agent is a scripted, deterministic model. These numbers measure enforcement on a fixed workload. They say nothing about how a language model behaves, and they do not establish resistance to prompt injection in general.
- The workload is synthetic and small. Read the counts, not an estimated rate.
- No model-based experiment was run. That would need a model and, for a local model, a multi-gigabyte download, which requires explicit approval.
- Deterministic regression tests are in `python/tests/test_agent_reference_integration.py`. Benchmark results are in `results/`.

## Results files

- `results/scenarios.json`: for each scenario, the checks, gate decisions, sandbox state, and evidence verification result.
- `results/benchmark.json`: dataset digest, condition summaries, and every call record. About 3 MB.

Sandbox state fields such as `created_at` and `execution_id` vary between runs. Decisions, reasons, and pass or fail results do not.

## Trust boundary and limits

- **Approvals are trusted as written.** `ApprovalStore.decide` records whoever calls it. In a deployment, the call must come from an authenticated human channel, and the agent must have no path to it. This example uses an operator step in the scenario code to stand in for that channel.
- **The approval store and the decision log are not authenticated.** Anyone with write access to the SQLite file can change an approval. The decision log detects edits and deletions, but it is not signed and is not anchored anywhere outside the file. A deployment needs both protected.
- **Signing keys are unmanaged.** The execution token key and the policy key are generated in-process. The benchmark warns about this, and it is unsafe for production. Use a managed key before any real use: see `benchmarks/agent-verification/kms_key_provider.py` and `sql_key_provider.py`.
- **The policy signature key is per process.** A second process cannot verify these records. This is fine for this example, which keeps everything in one process.
- **In-process gate.** This example does not call the AIGov Core service, and does not write to its evidence ledger. The local decision log is the only evidence. Connecting the gate to the service is a separate piece of work.
- **Replay protection is SQLite.** Multiple processes on one machine share it. Multiple hosts need the PostgreSQL nonce store, which the benchmark already provides and this example does not wire up.
- **Prompt injection is not solved.** The gate limits what an injected instruction can do. It does not stop a model from being manipulated.

## Files

```
examples/agent-reference/
  README.md                       this file
  INTEGRATION.md                  guide for wiring your own tools and approvals
  run_demo.py                     single-command demonstration and benchmark
  policies/example_policy.json    declarative policy (tenant, allowlist, approvers)
  aigov_agent_reference/
    gate.py                       pre-execution gate and evidence verification
    approvals.py                  human approval store
    decision_log.py               hash-chained decision log
    policy.py                     policy loader (signed records)
    environment.py                per-run wiring
    agent.py                      smolagents tools and scripted model
    scenarios.py                  ten end-to-end scenarios
    benchmark.py                  three-condition benchmark
  results/                        machine-readable results from the last run
python/tests/test_agent_reference_integration.py   regression tests
```
