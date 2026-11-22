# Agent-Tool Integration: Real Authorization Enforcement

**Date:** 2026-11-22  
**Branch:** `feat/agent-tool-integration`  
**Depends on:** PR #452 (Condition I hardening, merged 2026-11-22)  
**Dataset hash (integration scenarios):** `109def7478261bf9745d0d4caabe836748dba92ebda754cbfc03b2476acb6259`

---

## 1. Architecture and trust boundaries

```
     AI AGENT
         │  ToolRequest(tool_name, arguments, approval_id, action_type, ...)
         ▼
┌────────────────────────────────────────────────────────────────┐
│  ToolGateway                                                   │
│                                                                │
│  Step 1: deepcopy(arguments) → frozen_args  ← TOCTOU fix      │
│  Step 2: capability map check (tool → required action_type)   │
│  Step 3: build SandboxedDVOExecutor from dvo_state            │
│  Step 4: ConditionIOrchestrator                               │
│            └─ audit integrity                                  │
│            └─ approval validity                                │
│            └─ ReplayRegistry.try_consume()                     │
│            └─ RevocationList.is_revoked()                      │
│            └─ TrustedPolicyProvider.lookup_authorization()     │
│            └─ external state consistency                       │
│  Step 5: compute_policy_i_decision(evidence, model_verdict)   │
│  Step 6: execute IFF decision == ALLOW (uses frozen_args)      │
│  Step 7: SandboxedGitHubTools.execute() records all attempts  │
└────────────────────────────────────────────────────────────────┘
         │  ALLOW → executes tool, returns ToolExecutionResult
         │  DENY / INDETERMINATE / REQUIRES_REVIEW → blocked
         ▼
┌──────────────────────────────────┐
│  SandboxedGitHubTools            │
│  (in-memory, no real API calls)  │
│  - read_repo_metadata            │
│  - create_file                   │
│  - open_pull_request             │
│  - modify_repo_settings          │
│  - request_deployment            │
└──────────────────────────────────┘
```

**Trust boundary:**

| Layer | Trusted | Rationale |
|---|---|---|
| frozen_args | YES | Deepcopied before authorization; execution uses the same copy |
| ConditionIOrchestrator | YES | Deterministic DVO + policy checks |
| TrustedPolicyProvider | YES | HMAC-verified records |
| ReplayRegistry | YES | Atomic lock-based try_consume |
| RevocationList | YES | Thread-safe with Lock |
| SandboxedDVOExecutor | YES (scenario-driven) | Provides test evidence to orchestrator |
| model_verdict | ADVISORY | Can flag REQUIRES_REVIEW; cannot grant ALLOW |
| tool_name, arguments | UNTRUSTED | Validated before any execution |
| model_reasoning | UNTRUSTED | Recorded for audit only; never parsed |

---

## 2. Agent-tool execution lifecycle

1. **Agent submits ToolRequest** with tool_name, arguments, authorization context, and model_verdict.
2. **Gateway freezes arguments** (deepcopy) — this copy is used for both HMAC binding and execution.
3. **Capability map check**: gateway verifies `tool_name → required action_type` matches `req.action_type`. Mismatch → DENY without further checks.
4. **DVO executor built** from `req.dvo_state` (audit record, approval, external state).
5. **ConditionI orchestration**: 5-step deterministic chain (audit → approval → replay → revocation → policy lookup → external state).
6. **Policy decision computed**: INDETERMINATE if tool/orchestration error; DENY if any deterministic check fails; REQUIRES_REVIEW if model absent or concerned; ALLOW only if all checks pass and model approves.
7. **Execution gate**: `SandboxedGitHubTools.execute()` runs only if `decision == ALLOW`, using frozen_args. All attempts (authorized and blocked) are recorded with execution_id, args_binding_hash, and decision.

---

## 3. Threat model

| Attack vector | Gateway defence | Evidence |
|---|---|---|
| Prompt injection in tool output | Model verdict advisory only; DVO checks run independently | J-PI01–04: all 4 blocked despite model_verdict=True |
| Tool output injection (fake audit/external state) | DVO checks run on sandbox state independent of model | J-TO01–03: blocked by hash/approval failures |
| Privilege escalation (read → write) | Policy lookup enforces action_type scope | J-PE01–03: policy denied |
| Wrong tool/action_type claim | Capability map (Step 2) rejects before policy lookup | J-PE04–05: capability mismatch |
| Cross-tenant substitution | Policy lookup is tenant-scoped | J-CT01–02, J-CT04: denied |
| Approval replay | ReplayRegistry.try_consume() atomically consumes nonce | J-AR02, J-CE02: replay_detected |
| Policy revocation (fixture) | TrustedPolicyProvider checks `revoked=True` | J-PR01, J-PR03: policy_revoked/expired |
| Runtime approval revocation | RevocationList checked before policy lookup | J-PR02: approval_revoked_at_runtime |
| Confused deputy | Nonce covers (approval_id, tenant_id, action_type, resource_id, proposal_id); policy scope enforced | J-CD01–03: denied |
| TOCTOU: mutate arguments between auth and exec | deepcopy at hash time; execution uses frozen copy | regression test: verified |
| Policy service outage | try/except → INDETERMINATE → no execution | regression test: verified |
| Concurrent execution (same approval) | ReplayRegistry with Lock; 10 concurrent threads → 1 executes | J-CE01/02, concurrent unit test |

---

## 4. Red-team methodology

Phase 4 performed an adversarial review of the implementation immediately after Phase 1–2. The review searched for:

- Authorization bypasses
- Race conditions
- Policy-source contamination
- Replay vulnerabilities
- Incorrect trust assumptions

### Confirmed findings and fixes

**Finding 1 — TOCTOU: mutable arguments dict** (Severity: Medium)

*Description*: `ToolRequest.arguments` is a plain `dict`. If the caller (or a concurrent thread) mutated it after `gateway.request()` was called but before execution, the executed arguments could differ from the args_binding_hash. The hash would no longer match what actually ran.

*Fix*: At the start of `gateway.request()`, before any check, the gateway calls `copy.deepcopy(req.arguments)` to produce `frozen_args`. All subsequent operations (hashing, execution) use `frozen_args`. Caller mutations to `req.arguments` after this point are silently ignored.

*Regression test*: `TestSecurityRegressions::test_regression_toctou_mutation_uses_frozen_args`

**Finding 2 — Uncaught policy-service exception** (Severity: Medium)

*Description*: If `ConditionIOrchestrator` or `TrustedPolicyProvider` raised an exception (e.g., due to a faulty or simulated-outage policy backend), the exception propagated through `gateway.request()` uncaught. This could crash the agent loop — a denial-of-service risk — and might leave execution state undefined.

*Fix*: `gateway.request()` wraps the entire orchestration + decision block in `try/except Exception`. Any exception returns `PolicyDecisionRecord.indeterminate(...)` with a `"policy_service_exception:..."` reason. The tool is never executed (fail-closed). The gateway always returns a `ToolExecutionResult` without raising.

*Regression test*: `TestSecurityRegressions::test_regression_policy_outage_fails_closed`

### Findings not confirmed

**Check: model reasoning injection** — model_reasoning string is stored in the `PolicyDecisionRecord` for audit purposes only. It is never parsed by `compute_policy_i_decision()`. Injecting authorization commands into the reasoning string has no effect on the decision outcome. ✓

**Check: DVOScenarioState re-entrancy** — DVOScenarioState is read-only after construction. Multiple SandboxedDVOExecutors sharing the same state read it concurrently without race conditions. ✓

**Check: ReplayRegistry thread safety** — 10 concurrent goroutines calling `try_consume()` on the same nonce result in exactly 1 True and 9 False, with no errors. The Lock in ReplayRegistry is effective. ✓

---

## 5. Evaluation protocol (frozen)

**Reference time:** `_NOW = 1763913600.0` (2026-11-21 00:00:00 UTC)  
**Construction order:**
1. Policy fixture (POLICY_FIXTURE) defined with HMAC-signed records
2. `should_execute` derived from `_FIXTURE_PROVIDER.lookup_authorization()` for policy-dependent scenarios — never manually labelled
3. Scenarios frozen; `agent_integration_scenarios.py` not modified after evaluation
4. Evaluation run; results written to `results_agent_integration.json`

**Model verdict design:** All scenarios set `model_verdict=True` to simulate a model that approves. This directly tests that deterministic Condition I checks block unauthorized execution even when the model verdict would grant access.

---

## 6. Actual execution results

**Dataset:** 39 scenarios, 10 attack categories  
**Dataset hash:** `109def7478261bf9...`  
**Results file:** `benchmarks/agent-verification/results_agent_integration.json`

| Metric | Value |
|---|---|
| **Unauthorized operations executed** | **0** |
| Authorized operations executed | 13 |
| Authorized operations blocked | 0 |
| **FAR (false authorization rate)** | **0.000** |
| **FRR (false rejection rate)** | **0.000** |
| F1 | 1.000 |
| Avg enforcement latency | 0.1 ms |

**Category breakdown:**

| Category | Total | Unauthorized executed | Authorized blocked |
|---|---|---|---|
| `legitimate_authorized` | 5 | 0 | 0 |
| `prompt_injection` | 4 | 0 | 0 |
| `tool_output_injection` | 3 | 0 | 0 |
| `privilege_escalation` | 5 | 0 | 0 |
| `cross_tenant_operation` | 4 | 0 | 0 |
| `approval_replay` | 4 | 0 | 0 |
| `policy_revocation` | 3 | 0 | 0 |
| `tool_argument_substitution` | 4 | 0 | 0 |
| `confused_deputy` | 4 | 0 | 0 |
| `concurrent_execution` | 3 | 0 | 0 |

**Decision distribution:** ALLOW=13, DENY=26, INDETERMINATE=0, REQUIRES_REVIEW=0

**Security verdict: PASS — zero unauthorized tool executions across all 39 scenarios including all 10 attack categories.**

---

## 7. Statistical uncertainty

The evaluation comprises 39 scenarios, 26 of which test attack vectors (n_negative=26). With 0 bypasses observed in 26 adversarial attempts, the 95% Clopper-Pearson upper bound on the true bypass rate is `1 - 0.05^(1/26) ≈ 0.109` (10.9%). This bound is wide because the scenario count is small.

The evaluation is not a randomised test — it is a structured red-team evaluation covering 10 qualitatively distinct attack categories. Its value is in breadth of attack coverage, not statistical power. The two security vulnerabilities found and fixed in Phase 4 were not represented in the original scenario set.

Limitations on statistical claims:
- 39 scenarios is small; a real adversary would probe more attack paths
- Scenarios are scripted, not generated by a real adversary model
- Latency (0.1 ms avg) reflects in-process sandboxed execution; real policy-service calls would be orders of magnitude slower

---

## 8. Security-versus-availability tradeoffs

**FRR = 0.000**: No legitimate authorized operations were blocked.

This is consistent with the Condition I adversarial holdout (FRR=0.000, 170 scenarios). The enforcement overhead — in this integration — is negligible (0.1 ms/operation average in-process). Real deployments with network-bound policy-service calls would see higher latency.

**REQUIRES_REVIEW** does not appear in this evaluation because all scenarios set `model_verdict=True`. In production, `model_verdict=None` (no inference) → REQUIRES_REVIEW → human review queue → availability cost depending on queue throughput. This cost is not measured here.

**Capability map enforcement** (Step 2) adds one additional blocking layer for mismatched tool/action_type requests. This prevents an agent from claiming a weaker capability to get authorization for a tool that requires a stronger one — at zero availability cost to legitimate requests (legitimate requests always provide the correct action_type).

---

## 9. Remaining production-readiness blockers

| Item | Severity | Description |
|---|---|---|
| In-process DVO executor | HIGH | Real deployment requires network calls to audit service, approval service, and state store |
| In-memory ReplayRegistry | HIGH | Nonce store is per-process; restarting the gateway loses all consumed nonces (replay window re-opens) |
| In-memory RevocationList | HIGH | Revocations lost on restart; must be persisted |
| Static POLICY_FIXTURE | MEDIUM | Real policy store needs append-only signed log with version history |
| No persistent execution log | MEDIUM | `SandboxedGitHubTools` history is in-memory; real audit requires durable immutable log |
| Model advisory wired but not tested end-to-end | LOW | Scenarios use scripted `model_verdict`; real Qwen inference path tested in prior PR #452 |
| Path traversal in create_file | LOW | Sandboxed tool is in-memory only; real integration needs server-side path sanitization |
| HSM key management | LOW | PolicyKeyProvider uses symmetric benchmark key; production needs KMS-backed signing |
| No rate limiting | LOW | Gateway has no per-approval-id rate limit; DoS via many invalid requests possible |

**Production readiness: NOT READY.** The enforcement mechanism is structurally sound and all security invariants hold in this evaluation. The blockers above are infrastructure gaps, not design flaws.

---

## 10. Files

| File | Description |
|---|---|
| `benchmarks/agent-verification/sandboxed_tools.py` | DVOScenarioState, SandboxedDVOExecutor, SandboxedGitHubTools |
| `benchmarks/agent-verification/tool_gateway.py` | ToolGateway, ToolRequest, ToolExecutionResult, TOOL_CAPABILITY_MAP |
| `benchmarks/agent-verification/agent_integration_scenarios.py` | 39 frozen adversarial scenarios |
| `benchmarks/agent-verification/run_agent_integration.py` | Evaluation CLI runner |
| `benchmarks/agent-verification/results_agent_integration.json` | Full execution trace |
| `python/tests/test_agent_integration.py` | 36 security-invariant unit tests |

---

## Reproduction

```bash
git checkout feat/agent-tool-integration
cd benchmarks/agent-verification

# Full evaluation
uv run python3 run_agent_integration.py \
  --out results_agent_integration.json

# Smoke test (first 5 scenarios)
uv run python3 run_agent_integration.py --smoke

# Unit tests
cd ../../
uv run --with pytest python -m pytest python/tests/test_agent_integration.py -v
```

---

## Evaluation gate

- [x] 39 scenarios across 10 attack categories; dataset hash `109def7478261bf9...` (frozen)
- [x] Policy fixture defined before scenarios; `should_execute` derived from policy, not labels
- [x] **Unauthorized operations executed: 0** (FAR=0.000)
- [x] Authorized operations blocked: 0 (FRR=0.000)
- [x] 36 unit tests pass: capability map, legitimate ops, deny enforcement, replay, concurrency, security regressions
- [x] Two red-team vulnerabilities found (TOCTOU mutation, policy outage escape) and fixed
- [x] Regression tests added for both fixes
- [x] Concurrent 10-thread test: exactly 1 execution per approval_id, 0 races
- [x] No real GitHub API calls or production deployments made
- [x] No production data modified

**Evaluation verdict: PASS.**  
AIGov prevents unauthorized real tool execution without blocking legitimate operations in this evaluation. Zero unauthorized executions across all 10 attack categories including prompt injection, privilege escalation, cross-tenant, replay, revocation, confused-deputy, and concurrency.

---

## Human approval gate

- Human code review and merge authorization: **PENDING**
- Do not merge without authorization
- Do not deploy without authorization
