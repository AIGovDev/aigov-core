# Reference agent integration with pre-execution enforcement — 2026-11-25

## Scope

Adds `examples/agent-reference`: a runnable reference integration that puts AIGov enforcement primitives in front of a real
smolagents `ToolCallingAgent`. Refs #501 (stays open). No Railway, production, or external infrastructure was changed, no
paid model API was used, and no credentials were created.

The integration is described in `examples/agent-reference/README.md`. The customer guide is
`examples/agent-reference/INTEGRATION.md`.

## What changed

- `examples/agent-reference/aigov_agent_reference/`: the pre-execution gate (`gate.py`), the human approval store
  (`approvals.py`), the hash-chained decision log (`decision_log.py`), the policy loader (`policy.py`), the per-run wiring
  (`environment.py`), the smolagents tools and scripted model (`agent.py`), the ten scenarios (`scenarios.py`), and the
  three-condition benchmark (`benchmark.py`).
- `examples/agent-reference/run_demo.py`: one command runs the scenarios and the benchmark and writes `results/`.
- `examples/agent-reference/results/`: `scenarios.json` and `benchmark.json`, generated from the committed code.
- `python/tests/test_agent_reference_integration.py`: 20 regression tests. They need the `agent-reference` extra, which pins
  `smolagents==1.26.0`.
- `python/pyproject.toml`: adds the `agent-reference` optional dependency group.
- No change to `benchmarks/agent-verification`, `rust/`, or any CI workflow.

## Design decisions

- **Composition, not reuse of `ToolGateway`.** `ToolGateway` and `ConditionIOrchestrator` check an audit record's executed
  value against a read-back of external state. That verifies an action after it has happened. It cannot authorize a write
  before it runs, because the state has not changed yet. The gate composes the same primitives (policy records, replay
  protection, revocation, execution tokens, sandboxed tools) with pre-execution checks.
- **Write-ahead decision log.** The gate appends the authorization entry before it issues an execution token. Evidence
  verification checks that every authorized sandbox execution has such an entry. A log that cannot be written stops
  execution.
- **`ToolCallingAgent`, not `CodeAgent`.** Model-written Python is a separate execution path that the gate does not control.
  A test checks the module's code (not its prose) for any use of `CodeAgent`.
- **Scripted model.** The agent's model is deterministic. It emits tool calls from a fixed plan, so the benchmark measures
  enforcement and not model behaviour.

## Evidence

Results from the committed code on this branch, local only.

| Suite | Result |
|-------|--------|
| Reference scenarios (`run_demo.py`) | 10 of 10 passed |
| Reference regression tests (`test_agent_reference_integration.py`) | 20 passed |
| Full Python suite, with the release binary | 1092 passed, 41 skipped (database-gated) |
| Python integration, PostgreSQL 18 scratch database (`test_postgres_integration.py`) | 33 passed |
| Rust default suite (`cargo test --locked --no-fail-fast`) | 281 passed, 22 ignored; no Rust code changed |
| Container tests on a clean no-cache image built from this tree (`test_container_runtime.py`) | 16 passed |
| Local security harness, PostgreSQL 18, `--skip-live` | 66 passed, 0 failed, 0 blocked |
| `make gate` | passes |
| Ruff on the new files | clean |

Not run: live staging checks (skipped by design), and any model-based experiment.

## Benchmark

Same agent, same scripted plans, same approval store, and same synthetic sandbox in all three conditions. Ground truth is
fixed by each case. Workload: 10 categories, 100 cases each, 2,000 calls per condition (1,600 that must not run, 400 that
must).

| Condition | Unauthorized executed | Authorized completed | False denials | Consequential calls held without approval | Evidence verified (cases) |
|---|---|---|---|---|---|
| A, no enforcement | 1600 / 1600 | 400 / 400 | 0 / 400 | 0.0% | 0.0% |
| B, logging only | 1600 / 1600 | 400 / 400 | 0 / 400 | 0.0% | 10.0% |
| C, AIGov enforcement | 0 / 1600 | 400 / 400 | 0 / 400 | 100.0% | 100.0% |

Gate latency is machine-dependent. The committed run shows a median of 0.04 ms (A), 0.64 ms (B), and 0.41 ms (C).

## Scenario coverage

Allowed read-only action; denied unauthorized write; human-approved consequential write; human-rejected action;
prompt injection that asks for a deployment (the gate denies the deployment); expired approval; replayed approval;
approval service unavailable (fails closed); argument change after approval; revoked approval. Each scenario checks the
sandbox state and the decision log, not only the verdict.

## Negative controls

- Condition A executes every unauthorized call. Its evidence is absent by definition, so it cannot pass evidence
  verification.
- Condition B executes the same unauthorized calls and records them as blocked. Its evidence therefore fails in every case
  where it ran an unauthorized call.

## Limitations (declared; not claimed as protected)

- No claim of resistance to prompt injection in general. The gate limits what an injected instruction can do.
- The agent in these results is a deterministic scripted model. The results say nothing about how any language model behaves.
- The approval store is not authenticated. Whoever calls `ApprovalStore.decide` is recorded as the approver. A deployment
  must restrict that call to an authenticated human channel.
- The approval store (SQLite) and the decision log are not signed or anchored. Edits and deletions in the log are detected,
  but the log itself is not authenticated.
- The execution-token and policy signing keys are generated per process and are unmanaged. They are not suitable for
  production.
- The gate runs in-process. It does not call the AIGov Core service and does not write to its ledger. Evidence is the local
  hash-chained log only.
- Replay protection in this example is SQLite, shared only between processes on one machine. Multi-host operation needs the
  PostgreSQL nonce store, which is not wired here.
- Continuous integration does not install the `agent-reference` extra. The regression tests skip there unless the extra is
  installed. The local run is the evidence for them.

## Evaluation gate

Passes when the reference scenarios and regression tests pass, the benchmark shows the enforcement condition with zero
unauthorized executions and zero false denials on this workload, the negative controls behave as described, the existing
suites are unaffected, and `make gate` passes. All of these hold for this change set on the committed tree.

## Human approval gate

Not approved for production by this report. Merging into `staging` is a separate decision. Before any production use the
following are needed: an authenticated approver channel, managed signing keys, authentication or signing of the approval
store and decision log, and a connection to the AIGov Core evidence ledger. The open decisions in issue #501 still apply.
