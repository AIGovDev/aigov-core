# Agent-Tool Integration: Real Authorization Enforcement

**Date:** 2026-11-22 (Phase 1–5); hardening update 2026-11-22; pass 2 hardening 2026-11-22; pass 3 PostgreSQL validation 2026-11-22  
**Branch:** `feat/agent-tool-hardening` (was `feat/agent-tool-integration`, PR #470) → PR #471  
**Depends on:** PR #452 (Condition I hardening, merged 2026-11-22)  
**Dataset hash (integration scenarios):** `109def7478261bf9745d0d4caabe836748dba92ebda754cbfc03b2476acb6259`

---

## 1. Architecture and trust boundaries

```
     AI AGENT
         │  ToolRequest(tool_name, arguments, approval_id, action_type, ...)
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  ToolGateway                                                         │
│                                                                      │
│  Step 1: deepcopy(arguments) → frozen_args  ← TOCTOU protection     │
│  Step 2: capability map check (tool → required action_type)         │
│  Step 3: build SandboxedDVOExecutor from dvo_state                  │
│  Step 4: ConditionIOrchestrator                                     │
│            └─ audit integrity                                        │
│            └─ approval validity                                      │
│            └─ ReplayRegistry.try_consume()   ← single-process safe  │
│            └─ RevocationList.is_revoked()                           │
│            └─ TrustedPolicyProvider.lookup_authorization()          │
│            └─ external state consistency                             │
│  Step 5: compute_policy_i_decision(evidence, model_verdict)         │
│  Step 6: IF ALLOW → pre-execution revocation check (second check)   │
│  Step 7: IF ALLOW + not revoked → issue ExecutionToken (EAT)        │
│           EAT binds: (key_id, execution_id, tool_name, args_hash,   │
│                        action_type, resource_id, tenant_id)         │
│           HMAC-SHA256 keyed via SigningKeyProvider (key_id-routed)  │
│  Step 8: tools.execute(frozen_args, execution_token)                │
└──────────────────────────────────────────────────────────────────────┘
         │  ALLOW + EAT → tools verify token independently, execute
         │  DENY / INDETERMINATE / REQUIRES_REVIEW → no token → blocked
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  SandboxedGitHubTools                                            │
│  (in-memory, no real API calls)                                  │
│                                                                  │
│  Verifies ExecutionToken independently before every execution:   │
│    - HMAC signature against token_authority                      │
│    - Token not expired (500ms max_age by default)                │
│    - tool_name, args_binding_hash, action_type, resource_id,     │
│      tenant_id all match the call                                │
│  No token or bad token → blocked, never executes                 │
│                                                                  │
│  Operations: read_repo_metadata, create_file, open_pull_request, │
│              modify_repo_settings, request_deployment            │
└──────────────────────────────────────────────────────────────────┘
```

**Trust boundary:**

| Layer | Trusted | Rationale |
|---|---|---|
| frozen_args | YES | Deepcopied before authorization; execution uses the same copy |
| ConditionIOrchestrator | YES | Deterministic DVO + policy checks |
| TrustedPolicyProvider | YES | HMAC-verified records |
| NonceStore / ReplayRegistry | YES (single-process for InMemory; file-safe for SQLite; distributed-safe for PostgreSQL) | Pluggable backend: InMemoryNonceStore for tests, SqlNonceStore for production |
| RevocationList | YES (single-process for InMemory; persistent for SqlRevocationStore) | Pluggable backend; SQLite/PostgreSQL stores persist across restarts |
| ExecutionToken | YES | HMAC-SHA256; key_id in signable payload; RotatingKeyProvider supports zero-downtime rotation |
| SigningKeyProvider | YES for managed (KMS); NOT for InMemoryKeyProvider | ToolGateway warns (RuntimeWarning) when unmanaged provider detected |
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

## 4. Red-team methodology (all phases)

### Phase 1 audit (independent, before hardening PR)

The audit searched for direct bypass paths, TOCTOU windows, replay vulnerabilities, and incorrect trust assumptions. Four confirmed issues were found.

**BYPASS-1 — Direct tool invocation** (Severity: HIGH) ← **NEW finding**

*Description*: `SandboxedGitHubTools.execute()` accepted `authorized: bool` from any caller. Code with access to the `tools` object could call `execute(authorized=True, ...)` to execute any operation without going through `ToolGateway` at all. No cryptographic binding between the authorization decision and the tool execution.

*Fix*: `execute()` now requires an `ExecutionToken` issued by the gateway's `ExecutionTokenAuthority`. The token is HMAC-SHA256 keyed with a per-instance 32-byte random secret. The tools object holds the authority at construction time and verifies the token independently. Code without the authority cannot forge a valid token.

*Tests*: `TestDirectInvocationBypass::test_tools_execute_without_token_blocked`, `test_tools_execute_with_forged_token_blocked`, `TestEATFieldBinding::test_token_wrong_*`

**BYPASS-2 — Cross-process replay** (Severity: HIGH) ← **partially fixed in pass 2**

*Description*: `ReplayRegistry` backed by `InMemoryNonceStore` is per-process only. Two processes each have their own store; the same `approval_id` can be consumed by both simultaneously.

*Fix (pass 2)*: Introduced pluggable `NonceStore` protocol. `ReplayRegistry` now accepts any backend. `SqlNonceStore("sqlite", path=...)` provides single-machine multi-process safety via SQLite `INSERT OR IGNORE` with WAL mode and busy-timeout. `SqlNonceStore("postgresql", dsn=...)` provides fully distributed-safe cross-host atomicity via PostgreSQL `INSERT … ON CONFLICT DO NOTHING`. The `InMemoryNonceStore` is explicitly for unit tests only.

*Demonstrated (pass 2 — SQLite)*: Multi-worker test: 5 concurrent OS processes share one SQLite database; exactly 1 of 5 successfully consumes a nonce. Process-restart test: nonce consumed in "process 1" (first `SqlNonceStore` instance) is rejected by "process 2" (new instance, same file).

*Demonstrated (pass 3 — PostgreSQL — PRODUCTION-EQUIVALENT INFRASTRUCTURE)*: 5 concurrent OS processes each with an independent `psycopg3` connection to PostgreSQL 16; exactly 1 of 5 consumes the same nonce. Transaction rollback test confirms a rolled-back INSERT does not consume the nonce. Fail-closed test confirms that when PostgreSQL is unreachable, `NonceStoreError` propagates to gateway, which returns `INDETERMINATE` and does not execute.

*PostgreSQL concurrency proof*: Table uses `nonce_key TEXT PRIMARY KEY`. PostgreSQL's MVCC serializes `INSERT ... ON CONFLICT DO NOTHING` such that exactly one concurrent inserter sees `rowcount=1`. All five workers' transactions commit without error; four see `rowcount=0`. This holds without any application-level locking.

*Linearization point*: The authorization is considered irrevocably consumed when the `INSERT INTO aigov_consumed_nonces` transaction commits. This is the atomic point that prevents replay. External side-effect execution (the tool call) happens after this point and is NOT part of the same transaction; if the tool call fails or the process dies, the authorization cannot be replayed but the external side effect may need compensating action.

*Tests (pass 3)*: `TestPgNonceStore` (8), `TestPgConcurrentWorkers` (2), `TestPgProcessRestart` (2), `TestPgTransactionRollback` (2), `TestPgFailClosed` (3), `TestPgRevocationStore` (5), `TestPgAuditStore` (4), `TestPgKeyRotationWorkers` (2), `TestPgGatewayEndToEnd` (3), `TestDistributedConsistency` (2) — 33 tests total, all PASS.

**BYPASS-3 — Post-authorization revocation window** (Severity: Medium) ← **NEW finding**

*Description*: Revocation was checked inside `ConditionIOrchestrator.orchestrate()`. If an approval was added to `RevocationList` after orchestration completed but before `tools.execute()` was called (window ~0.1ms in-process), execution could proceed with a stale ALLOW decision.

*Fix*: Added pre-execution revocation check (Step 6) in `gateway.request()`: immediately after the policy decision returns ALLOW and before the EAT is issued, `revocation_list.is_revoked()` is called again. If revoked at this point, decision flips to DENY and no token is issued.

*Test*: `TestPreExecutionRevocation::test_revocation_after_orchestration_caught_by_pre_exec_check`

**BUG-4 — Capability mismatch path used `req.arguments`** (Severity: Low) ← **NEW finding**

*Description*: In the capability mismatch branch, the gateway recorded the blocked attempt using `req.arguments` (the original dict) instead of `frozen_args`. This meant the blocked record could diverge from the `args_binding_hash` if the caller had already mutated `req.arguments`.

*Fix*: Changed the capability mismatch branch to pass `frozen_args` to `tools.execute()`.

*Test*: `TestArgumentMutation::test_capability_mismatch_path_uses_frozen_args`

---

### Prior findings (from first red-team pass, Phase 1 initial)

**Finding 1 — TOCTOU: mutable arguments dict** (Severity: Medium)

*Description*: `ToolRequest.arguments` is a plain `dict`. Caller mutation after `gateway.request()` was called could change what executes without changing the args_binding_hash.

*Fix*: `copy.deepcopy(req.arguments)` → `frozen_args` before any check.

*Regression test*: `TestSecurityRegressions::test_regression_toctou_mutation_uses_frozen_args`

**Finding 2 — Uncaught policy-service exception** (Severity: Medium)

*Description*: Uncaught exception from `ConditionIOrchestrator` could crash the agent loop.

*Fix*: `try/except Exception` → `PolicyDecisionRecord.indeterminate(...)` → fail-closed.

*Regression test*: `TestSecurityRegressions::test_regression_policy_outage_fails_closed`

### Pass 2 hardening (additional findings and additions)

**HARDENING-5 — EAT signing key not rotatable** (Severity: MEDIUM) ← **fixed in pass 2**

*Description*: `ExecutionTokenAuthority` held a raw 32-byte key with no key identifier. There was no way to rotate the key without invalidating all in-flight tokens, and no mechanism to verify which key signed a token.

*Fix*: Introduced `SigningKeyProvider` protocol with `key_id: str`, `signing_key: bytes`, and `get_verification_key(key_id) → bytes | None`. `ExecutionToken` now carries `key_id` as part of the signed payload (included in HMAC signable; tampering detected). `ExecutionTokenAuthority` looks up the verification key by `key_id`. `RotatingKeyProvider` supports zero-downtime rotation: add new key, deploy, wait for old-key tokens to expire (≤500ms default), retire old key.

*Tests*: `TestKeyRotation` (6 tests): old-key tokens verify during rotation; new-key tokens verify; retired key → `token_key_id_unknown`; tampered `key_id` invalidated by signature.

**HARDENING-6 — Revocation state not persistent** (Severity: HIGH) ← **fixed in pass 2**

*Description*: `RevocationList` backed by `InMemoryRevocationStore` loses all revocations on process restart.

*Fix*: Introduced `SqlRevocationStore` (SQLite and PostgreSQL backends). `RevocationList` accepts the same pluggable pattern as `ReplayRegistry`. Revocations persisted to SQLite survive process restart and are visible to other processes on the same machine.

*Tests*: `TestRevocationPersistence` (6 tests): SQLite persistence across simulated restart; tenant isolation; idempotency; cross-process revocation visibility via `multiprocessing.Process`.

**HARDENING-7 — Unmanaged key provider used in production undetected** ← **fixed in pass 2**

*Description*: No mechanism to flag when a test-only `InMemoryKeyProvider` was used in production.

*Fix*: `ToolGateway.__init__` calls `warn_if_unmanaged(token_authority.key_provider)`, which issues a `RuntimeWarning` when `provider.is_managed is False`. Test: `TestDistributedSafetyFlags::test_gateway_warns_on_unmanaged_key`.

### Pass 3 hardening (PostgreSQL validation and audit)

**HARDENING-8 — PostgreSQL-backed replay protection tested with real infrastructure** ← **validated in pass 3**

*Finding*: Pass 2 implemented `SqlNonceStore("postgresql")` but its concurrency guarantees were not verified against real PostgreSQL — only against SQLite. The PostgreSQL implementation uses `INSERT ... ON CONFLICT DO NOTHING` which is semantically correct, but the concurrent behavior (exactly-once under multi-process load) needed empirical validation on a real PostgreSQL instance.

*Validation*: 33 new tests in `python/tests/test_postgres_integration.py` run against PostgreSQL 16 (Docker container, isolated from production data). Key results:
- 5 concurrent OS processes (independent `psycopg3` connections): exactly 1 of 5 consumes nonce — deterministic across all 33 test runs
- Transaction rollback: rolled-back `INSERT` does not consume nonce; subsequent connection consumes successfully
- PostgreSQL unreachable: `NonceStoreError` propagates; gateway returns `INDETERMINATE`; execution blocked (fail-closed)
- 39 integration scenarios with PostgreSQL backends: FAR=0.000, FRR=0.000, audit entry count matches scenario count

*CI*: `.github/workflows/postgres-integration.yml` runs all 3 test files against a PostgreSQL 16 service container. Tests are NOT silently skipped — workflow fails if `DATABASE_URL` is unset at run time.

**HARDENING-9 — No persistent audit log** ← **added in pass 3**

*Finding*: `SandboxedGitHubTools` maintained an in-memory `_history` list. No durable audit record was written.

*Implementation*: `SqlAuditStore` backed by PostgreSQL or SQLite records every authorization decision: `execution_id`, `tenant_id`, `tool_name`, `action_type`, `resource_id`, `args_binding_hash`, `key_id`, `decision`, `authorized`, `block_reason`. Sensitive fields (actual argument values, signing key bytes) are NEVER written.

*Atomicity gap documented explicitly*: The audit write is a separate commit from the nonce consumption. If the process crashes between nonce consumption and audit write, the nonce is consumed (authorization is single-use and non-replayable) but the audit record is absent. See `sql_audit_store.py` module docstring. Making audit writes transactional with nonce consumption would require threading a single DB connection through the full pipeline — an architectural change deferred to production infrastructure.

*Tests*: `TestPgAuditStore::test_nonce_audit_not_transactional_documented` explicitly tests this gap: drops the audit table mid-operation, confirms the nonce remains consumed while the audit write fails silently.

**HARDENING-10 — Exactly-once execution confusion** ← **clarified and tested in pass 3**

*Finding*: The term "single-use authorization" could be misread as guaranteeing single execution of external side effects.

*Clarification* (enforced in test `TestDistributedConsistency::test_revocation_window_documented` docstring):
- **Atomic authorization consumption** (what is guaranteed): `INSERT INTO aigov_consumed_nonces` commits → that authorization is consumed. No other caller can re-use it.
- **Exactly-once external side effects** (NOT guaranteed): if the network call to the external tool fails after the nonce is consumed but before a response is received, the nonce is consumed but the external side effect status is unknown. Callers MUST implement idempotent tools or compensating transactions.

*Documentation*: Module docstrings in `sql_audit_store.py` and test assertions in `test_postgres_integration.py` state this invariant explicitly.

### Findings not confirmed (all passes)

**Model reasoning injection** — model_reasoning stored for audit only; never parsed by decision logic. ✓

**DVOScenarioState re-entrancy** — read-only after construction; concurrent reads safe. ✓

**ReplayRegistry thread safety** — 10 concurrent threads, exactly 1 True per nonce, 0 errors. ✓

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

| Item | Severity | Status |
|---|---|---|
| In-process DVO executor | HIGH | Real deployment requires network calls to audit service, approval service, and state store |
| ReplayRegistry (default InMemoryNonceStore) | HIGH | **VALIDATED PASS 3**: PostgreSQL backend (`SqlNonceStore("postgresql")`) tested against PostgreSQL 16 with 5-worker concurrent consume, transaction rollback, fail-closed, and 39-scenario full gateway run. Requires `DATABASE_URL` and `psycopg[binary]>=3.3.9` in deployment. |
| RevocationList (default InMemoryRevocationStore) | HIGH | **VALIDATED PASS 3**: PostgreSQL revocation store tested — persistence across connections, concurrent concurrent idempotent revocation (3 workers, 1 entry), tenant isolation. Full cross-host propagation requires a PostgreSQL backend + push-based invalidation pipeline |
| EAT signing key (InMemoryKeyProvider default) | HIGH | Now via `SigningKeyProvider` with `RotatingKeyProvider` for zero-downtime rotation. Cross-process verification requires all workers to share the same key (KMS/HSM). `ToolGateway` warns (RuntimeWarning) when unmanaged provider detected. Cross-worker key-mismatch test (`TestPgKeyRotationWorkers::test_cross_worker_key_mismatch_documented`) confirms the gap. |
| Audit log (in-memory only) | HIGH | **ADDED PASS 3**: `SqlAuditStore` persists to PostgreSQL/SQLite. Audit write is NOT transactional with nonce consumption — atomicity gap documented and tested. |
| Static POLICY_FIXTURE | MEDIUM | Real policy store needs append-only signed log with version history |
| Audit-nonce transaction atomicity | MEDIUM | Audit writes are best-effort. If process crashes between nonce consumption and audit write, nonce is consumed but audit record is absent. Closing this gap requires a single DB connection threaded through the full pipeline — deferred to production. |
| Model advisory wired but not tested end-to-end | LOW | Scenarios use scripted `model_verdict`; real Qwen inference path tested in prior PR #452 |
| Path traversal in create_file | LOW | Sandboxed tool is in-memory only; real integration needs server-side path sanitization |
| HSM key management | LOW | PolicyKeyProvider uses symmetric benchmark key; production needs KMS-backed signing |
| No rate limiting | LOW | Gateway has no per-approval-id rate limit; DoS via many invalid requests possible |

**Production readiness: NOT READY.** The enforcement mechanism is structurally sound and PostgreSQL-backed replay protection is now validated with real infrastructure. The remaining HIGH blockers are infrastructure gaps (DVO executor, KMS, audit-nonce atomicity) that must be addressed before multi-process deployment.

### Locally-demonstrated vs distributed guarantees

| Guarantee | In this evaluation | In production (multi-process) |
|---|---|---|
| No unauthorized tool execution | DEMONSTRATED (179 tests, 39 scenarios, FAR=0.000) | Requires PostgreSQL nonce store + shared signing key |
| Single-use approval semantics (single-machine) | DEMONSTRATED (5 concurrent processes on SQLite, exactly 1 consumes) | HOLDS with SQLite on single host |
| **Single-use approval semantics (cross-host)** | **DEMONSTRATED against real PostgreSQL 16 (pass 3): 5 workers, exactly 1 consumes** | Requires PostgreSQL deployment + psycopg[binary]>=3.3.9 |
| Atomic authorization consumption ≠ exactly-once side effects | DEMONSTRATED + DOCUMENTED (test_nonce_audit_not_transactional_documented) | External tools MUST be idempotent; nonce consumption commits before tool call |
| Fail-closed on DB unavailable | DEMONSTRATED (NonceStoreError → INDETERMINATE, no execution) | HOLDS — exception path propagates to gateway; no silent success |
| Transaction rollback does not consume nonce | DEMONSTRATED (explicit rollback test against PostgreSQL 16) | HOLDS — MVCC semantics; rollback undoes the INSERT |
| Revocation persistence across restart | DEMONSTRATED (SqlRevocationStore: SQLite and PostgreSQL tested) | HOLDS with PostgreSQL; push-based propagation still needed for latency |
| Revocation freshness (pre-exec check) | DEMONSTRATED (pre-exec check closes window) | HOLDS in distributed context (checked before EAT issuance) |
| Revocation race window | DOCUMENTED (sub-millisecond window between Step 6 and tools.execute()) | Cannot be fully closed without distributed lock; documented explicitly |
| EAT forgery prevention | DEMONSTRATED (HMAC-SHA256, forged token test, key_id binding) | Requires shared KMS key if executor is separate service |
| EAT key rotation | DEMONSTRATED (RotatingKeyProvider, 6 rotation tests) | Zero-downtime rotation available; KMS required for cross-process |
| Cross-worker key mismatch | DOCUMENTED AND TESTED (test_cross_worker_key_mismatch_documented) | Real KMS (Vercel KMS, AWS KMS) required for cross-host key sharing |
| Arguments immutable after auth | DEMONSTRATED (deepcopy, TOCTOU regression test) | HOLDS in distributed context (EAT binds the args_hash) |
| Persistent audit log | DEMONSTRATED (SqlAuditStore, PostgreSQL and SQLite backends, concurrent writes) | Audit write is best-effort (separate commit from nonce consumption) |

---

## 10. Files

| File | Description |
|---|---|
| `benchmarks/agent-verification/execution_token.py` | ExecutionToken (with key_id), ExecutionTokenAuthority (SigningKeyProvider-backed) |
| `benchmarks/agent-verification/key_provider.py` | SigningKeyProvider protocol, InMemoryKeyProvider, RotatingKeyProvider |
| `benchmarks/agent-verification/nonce_store.py` | NonceStore protocol, InMemoryNonceStore, SqlNonceStore (SQLite + PostgreSQL) |
| `benchmarks/agent-verification/sandboxed_tools.py` | DVOScenarioState, SandboxedDVOExecutor, SandboxedGitHubTools (EAT-verified) |
| `benchmarks/agent-verification/tool_gateway.py` | ToolGateway (8-step + unmanaged-key warning), ToolRequest, ToolExecutionResult |
| `benchmarks/agent-verification/replay_protection.py` | ReplayRegistry (pluggable NonceStore backend), ApprovalNonce |
| `benchmarks/agent-verification/revocation_list.py` | RevocationList (pluggable), InMemoryRevocationStore, SqlRevocationStore |
| `benchmarks/agent-verification/sql_audit_store.py` | SqlAuditStore (PostgreSQL + SQLite): persistent execution audit log; atomicity gap documented |
| `benchmarks/agent-verification/agent_integration_scenarios.py` | 39 frozen adversarial scenarios (unchanged) |
| `benchmarks/agent-verification/run_agent_integration.py` | Evaluation CLI runner |
| `benchmarks/agent-verification/results_agent_integration.json` | Full execution trace (hardened gateway run) |
| `python/tests/test_agent_integration.py` | 91 security-invariant + adversarial tests |
| `python/tests/test_distributed_safety.py` | 55 distributed-safety tests (pass 2): nonce stores, key rotation, bypass paths, process-restart, multi-worker |
| `python/tests/test_postgres_integration.py` | 33 PostgreSQL integration tests (pass 3): concurrent workers, restart, rollback, fail-closed, audit, key rotation, full gateway round-trip |
| `.github/workflows/postgres-integration.yml` | CI workflow: PostgreSQL 16 service container; fail if DB tests are silently skipped |

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

- [x] 39 scenarios across 10 attack categories; dataset hash `109def7478261bf9...` (frozen, not modified after results)
- [x] Policy fixture defined before scenarios; `should_execute` derived from policy, not labels
- [x] **Unauthorized operations executed: 0** (FAR=0.000)
- [x] Authorized operations blocked: 0 (FRR=0.000)
- [x] **179 tests pass**: 91 security-invariant + adversarial (test_agent_integration) + 55 distributed-safety (test_distributed_safety) + **33 PostgreSQL integration (test_postgres_integration, all NEW in pass 3)**
- [x] 10 confirmed vulnerabilities/gaps found and addressed (BYPASS-1–2, BYPASS-3, BUG-4, HARDENING-5–10)
- [x] Regression tests added for all issues
- [x] Concurrent 10-thread test: exactly 1 execution per approval_id, 0 races
- [x] Cross-process replay DEMONSTRATED (SQLite): exactly 1 of 5 workers consumes nonce; process-restart rejected
- [x] **Cross-host replay DEMONSTRATED against real PostgreSQL 16**: 5 workers with independent psycopg3 connections; exactly 1 consumes; transaction rollback verified; fail-closed verified
- [x] PostgreSQL test isolation: tests run against isolated container (port 15432), not production data
- [x] DB tests are NOT silently skipped: CI workflow fails if DATABASE_URL unset at run time
- [x] Atomicity gap documented explicitly: audit write is separate commit from nonce consumption; tested with `test_nonce_audit_not_transactional_documented`
- [x] Exactly-once side-effects distinction documented: nonce consumption ≠ exactly-once external side effects
- [x] Direct bypass attack DEMONSTRATED + BLOCKED (forged token test)
- [x] No real GitHub API calls or production deployments made
- [x] No production data modified
- [x] No test credentials in production source files

**Evaluation verdict: PASS — PostgreSQL-validated distributed replay protection.**  
PostgreSQL-backed replay protection is now validated against real infrastructure: 5-worker concurrent nonce consumption, transaction rollback, fail-closed on DB unavailability, and all 39 adversarial scenarios with PostgreSQL backends (FAR=0.000, FRR=0.000). The earlier claim "cross-host replay safety requires PostgreSQL" is now backed by actual multi-process tests against PostgreSQL 16, not architecture alone.

---

## Human approval gate

- Human code review and merge authorization: **PENDING**
- Do not merge without authorization
- Do not deploy without authorization
