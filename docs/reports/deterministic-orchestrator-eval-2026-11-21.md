# Deterministic Verification Orchestrator (Condition G) — 2026-11-21

## 1. Original failure mode (Condition F)

PR #445 introduced a mandatory verification gate (Condition F): any call to
`report_verdict` is intercepted; the gate rejects it and returns a structured
`{"blocked": true, "missing_tools": [...]}` response if any of
`check_audit_record`, `verify_approval`, or `read_external_state` have not
been called yet. If `max_steps=6` is reached without all tools called, the
verdict defaults to `False` (fail_closed).

**Observed failure**: Qwen2.5-3B does not respond to gate feedback. When
blocked, it retries `report_verdict` on the next step instead of calling
the named missing tool. Of 59 scenarios where the gate blocked at least once,
49 (83%) ended in `fail_closed=False`. Result: FRR=0.929 (13/14 positive
scenarios rejected). The gate correctly blocked 13 unsafe actions (FAR
0.393→0.196) but introduced an equal number of false rejections (1:1 tradeoff).

**Root cause**: the gate design relies on the model's ability to interpret
structured feedback and adapt its next tool call. Qwen2.5-3B lacks this
capability at the 3B-parameter scale.

## 2. Implemented architecture

### Deterministic Verification Orchestrator (DVO)

`benchmarks/agent-verification/deterministic_verification_orchestrator.py`

The DVO independently executes all 3 required evidence checks using canonical
scenario identifiers, before the model runs. Tool results are pre-injected into
the model's conversation context. The model only needs to reason from
pre-existing evidence and call `report_verdict`.

**Data flow:**

```
Benchmark runner
  → canonical_params (from Scenario definition — NEVER model-generated)
  → DeterministicVerificationOrchestrator.orchestrate(proposal_id, approval_id, record_id)
      → SandboxToolExecutor.execute("check_audit_record", {proposal_id})
      → SandboxToolExecutor.execute("verify_approval", {proposal_id, approval_id})
      → SandboxToolExecutor.execute("read_external_state", {record_id, field})
      → _compute_authorization(audit, approval, external) → dvo_authorized: bool
      → returns VerificationEvidence
  → evidence.as_injected_messages() pre-pended to model context
  → QwenAgent.run() with pre-injected context
      → model reasons from evidence (3 steps already done)
      → model calls report_verdict → model_verdict
  → Final verdict = dvo_authorized AND model_verdict
      (DVO-NO overrides any model-YES — security invariant)
```

**Authorization logic** (mirrors `condition_d`):
```python
authorized = (
    audit.found is True
    AND audit.hash_verified is True
    AND approval.valid is True
    AND external.value is not None
    AND external.value == audit.executed_value  # consistency check
)
```

**Security invariants:**
1. Canonical IDs from Scenario definition — never from model output
2. DVO-NO always overrides model-YES (enforced in `mlx_qwen_adapter.py`)
3. All 3 tools always called regardless of intermediate results
4. Tool errors, missing results, and mismatched values fail closed
5. `report_verdict` never called by DVO (model's exclusive responsibility)
6. Each scenario runs in an independent DVO instance (no state leakage)
7. DVO tool calls recorded with `origin="dvo"` for auditability

**Trust boundary:**
- TRUSTED: `SandboxToolExecutor` results, canonical scenario parameters,
  DVO's `dvo_authorized` decision
- UNTRUSTED: model output, model-generated tool arguments, model reasoning
  (model can only make the final verdict more conservative, never less)

**Verdict sources for Condition G:**
- `dvo_orchestrated`: DVO=YES AND model=YES → accept
- `dvo_rejected`: DVO=NO → reject (overrides model)
- `model_rejected_dvo_ok`: DVO=YES, model=NO → reject (model conservative)
- `dvo_fallback`: DVO=YES, model no verdict → reject (fail safe)

### Condition G_scripted oracle (theoretical upper bound)

`condition_g_scripted(s) = condition_d(s) AND s.ground_truth`

Represents a perfect model that reasons correctly from pre-injected evidence:
- Accepts all DVO-authorized positives (TP=14, FN=0)
- Rejects all DVO false positives (the 16 D FPs become TNs)
- Result: F1=1.0, FP=0, FN=0 (oracle upper bound)

The gap between G_scripted and G_actual quantifies Qwen2.5-3B's reasoning
deficit on DVO-authorized scenarios.

## 3. Security invariants

| Invariant | Mechanism | Test |
|---|---|---|
| Canonical IDs only | `canonical_params` passed separately from scenario_summary | `test_model_cannot_bypass_dvo_via_fabricated_tool_call` |
| DVO-NO overrides model-YES | `if not evidence.dvo_authorized: verdict=False` in adapter | `test_dvo_rejection_overrides_model_positive` |
| All 3 tools always run | `orchestrate()` calls all 3 regardless | `test_all_three_tools_called` |
| Fail closed on errors | Errors → `found=False`/`valid=False` → reject | `test_tool_exception_fails_closed` |
| Consistency check | `ext.value == audit.executed_value` | `test_replay_attack_external_state_mismatch` |
| No prompt injection | Authorization uses structured bool fields, not strings | `test_prompt_injection_in_audit_value_does_not_bypass` |
| No state leakage | Independent DVO per scenario | `test_multiple_scenarios_independent` |
| Multi-failure recording | All failures listed, no short-circuit | `test_one_failure_reason_does_not_hide_another` |
| Cross-tenant rejection | Approval.proposal_id mismatch → reject | `test_cross_tenant_approval_rejected` |
| DVO never calls report_verdict | Checked in test | `test_dvo_does_not_call_report_verdict` |

## 4. Experimental methodology

**Dataset**: `build_full_dataset(seed_base=42, seed_expanded=7)`, 70 scenarios,
14 positive / 56 negative. Hash: `b9624d8710dfe45f` (same frozen dataset as
Conditions D, E, F).

**Hardware**: Apple M-series (arm64), Darwin 25.2.0.

**Model**: Qwen2.5-3B-Instruct-4bit via MLX (mlx-lm, local weights at
`~/models/Qwen2.5-3B-Instruct-4bit`), temperature=0.0 (greedy), `max_steps=6`.

**Condition G protocol**:
1. DVO calls all 3 tools with canonical IDs → `VerificationEvidence`
2. Evidence pre-injected into model context as 6 messages (3 assistant+tool pairs)
3. Model runs (max_steps=6 remaining), only needs to call `report_verdict`
4. Final verdict = `dvo_authorized AND model_verdict`

**Oracle independence**: Ground truth set by scenario parameters, never derived
from the verifier, the DVO, or the model.

**No synthetic substitution**: Real Qwen2.5-3B local inference on all 70 scenarios.

## 5. Results and statistical analysis

### Confusion matrices — all conditions

| Condition | TP | FP | TN | FN | F1 | Acc | 95% CI | FAR | FRR |
|---|---|---|---|---|---|---|---|---|---|
| A — self-report | 14 | 55 | 1 | 0 | 0.337 | 0.214 | [0.118, 0.310] | 0.982 | 0.000 |
| B — tool response | 14 | 51 | 5 | 0 | 0.354 | 0.271 | [0.167, 0.376] | 0.911 | 0.000 |
| C — external state | 14 | 34 | 22 | 0 | 0.452 | 0.607 | [0.397, 0.631] | 0.607 | 0.000 |
| D — AIGov verifier | 14 | 16 | 40 | 0 | 0.636 | 0.771 | [0.673, 0.870] | 0.286 | 0.000 |
| E — Qwen (ungated) | 14 | 22 | 34 | 0 | 0.560 | 0.686 | [0.577, 0.794] | 0.393 | 0.000 |
| F — Qwen (gated) | 1 | 11 | 45 | 13 | 0.077 | 0.657 | [0.546, 0.768] | 0.196 | 0.929 |
| F_scripted (oracle) | 14 | 16 | 40 | 0 | 0.636 | 0.771 | [0.673, 0.870] | 0.286 | 0.000 |
| G_scripted (oracle) | 14 | 0 | 56 | 0 | 1.000 | 1.000 | [1.000, 1.000] | 0.000 | 0.000 |
| **G — Qwen (DVO)** | — | — | — | — | — | — | — | — | — |

*Condition G metrics pending benchmark completion.*

### McNemar D/E/F/G (pending)

| Pairing | b | c | n_discordant | χ² | p | Significant? |
|---|---|---|---|---|---|---|
| D vs E | 11 | 5 | 16 | 1.563 | 0.213 | No |
| D vs F | 18 | 10 | 28 | 1.750 | 0.187 | No |
| E vs F | 15 | 13 | 28 | 0.036 | 0.860 | No |
| D vs G | — | — | — | — | — | Pending |
| E vs G | — | — | — | — | — | Pending |
| F vs G | — | — | — | — | — | Pending |

### DVO statistics (pending)

| Metric | Value |
|---|---|
| Total scenarios | 70 |
| DVO authorized | — |
| DVO rejected | — |
| Model rejected (DVO ok) | — |
| Final accepted | — |
| Final rejected by DVO | — |
| Final rejected by model | — |
| Avg DVO orchestration overhead | — ms |
| Latency overhead vs E | — % |

## 6. Remaining limitations

1. **Model reasoning on DVO-authorized FPs**: The 16 D FPs (scenarios where
   all evidence looks valid but action is unauthorized) are passed to the model
   as "authorized-looking" evidence. If the model cannot detect the semantic
   violation from the evidence, those remain FPs in G. This is the residual
   gap between G_actual and G_scripted.

2. **Evidence model completeness**: The DVO checks the same 4 evidence signals
   as `condition_d`. If the actual authorization requires additional signals
   (e.g., multi-party approval, rate-limiting), those are not checked.

3. **Canonical ID trust**: Canonical IDs are correct iff the benchmark runner
   correctly reads them from the Scenario definition. In production, the
   canonical identity of the action must come from an audited source, not from
   user-supplied input.

4. **Latency**: DVO adds 3 synchronous tool calls per scenario. For high-throughput
   deployments, these should be parallelized or cached.

5. **Qwen2.5-3B**: The model still provides the final reasoning step. A larger
   model would better identify semantic violations in DVO-authorized FP scenarios.

## 7. Production-readiness implications

**Production-ready aspects:**
- DVO is fully deterministic — same inputs always produce same authorization
- No LLM dependency for mandatory evidence collection
- Fail-closed design: errors default to rejection
- Canonical ID enforcement at the trust boundary
- Independent evidence provenance (DVO tool calls logged separately)

**Not production-ready (requires additional work):**
- Evidence model must be extended to cover all authorization requirements
- Canonical ID source must be audited in production (not benchmark runner)
- DVO tool calls should be parallelized
- Full E2E integration test with the actual AIGov production API

## Human approval gate

- Human code-review and merge authorization: **PENDING**
- No production data was changed during this evaluation
- Raw results at `benchmarks/agent-verification/results_qwen_full_70_condG.json`
- DVO implementation at `benchmarks/agent-verification/deterministic_verification_orchestrator.py`
- Tests: `python/tests/test_deterministic_orchestrator.py` (34 model-independent + regression)
