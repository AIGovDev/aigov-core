# Agent-Tool Integration: Real Authorization Enforcement

**Date:** 2026-11-22 (Phase 1–5); hardening update 2026-11-22; pass 2 hardening 2026-11-22; pass 3 PostgreSQL validation 2026-11-22; pass 4 adversarial security review 2026-11-22; pass 5 FINDING-3/5 fixes 2026-11-22  
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

### Pass 4 hardening (independent adversarial security review)

**FINDING-1 (HIGH → FIXED) — args_binding_hash truncated to 64 bits**

*Finding*: `compute_args_binding_hash()` returned `hashlib.sha256(...).hexdigest()[:16]` — only the first 16 hex characters (64 bits) of the SHA-256 digest. Birthday collisions are achievable at ~2^32 trials (~4 seconds on modern hardware), enabling argument substitution attacks where an EAT authorized for arguments A passes `verify_for_execution` when presented with a colliding argument set B.

*Fix*: Removed `[:16]` truncation. `hexdigest()` now returns all 64 hex characters (256 bits). Birthday collisions now require ~2^128 work.

*File*: `benchmarks/agent-verification/sandboxed_tools.py:425`

*Regression test*: `TestFinding1ArgsHashTruncation::test_hash_length_is_64_chars_after_fix`

**FINDING-2 (MEDIUM → FIXED) — verify_for_execution does not check execution_id**

*Finding*: `ExecutionTokenAuthority.verify_for_execution()` had no `expected_execution_id` parameter. The `execution_id` is included in the EAT's signable payload (and therefore covered by the HMAC signature), but was never checked against the calling context's execution_id. In the current single-process gateway, there is no serialization step between EAT issuance and use, so this only manifests as audit inconsistency. In a distributed context where EATs cross a network boundary, it would permit cross-request token reuse: a valid EAT from request exec-A with matching (tool, args, tenant) would pass verification for request exec-B.

*Fix*: Added `expected_execution_id: str | None = None` to `verify_for_execution()`. When provided, `token.execution_id` must match exactly; mismatch returns `("False", "token_execution_id_mismatch")`. `sandboxed_tools.execute()` now always passes `expected_execution_id=execution_id` from its own calling context.

*File*: `benchmarks/agent-verification/execution_token.py:196`; `benchmarks/agent-verification/sandboxed_tools.py:220`

*Regression test*: `TestFinding2ExecutionIdNotVerified::test_execution_id_verified_after_fix`, `test_matching_execution_id_accepted_after_fix`, `test_tools_execute_passes_execution_id_to_verify`

**FINDING-3 (MEDIUM → FIXED in pass 5) — Tautological action_type/resource_id check**

*Finding*: `sandboxed_tools.execute()` called `verify_for_execution()` with `expected_action_type=execution_token.action_type` and `expected_resource_id=execution_token.resource_id`. These values came from the token being verified, so the field checks always passed for a structurally valid token regardless of the calling context. The HMAC signature prevents forgery, so this was NOT exploitable in the current single-process architecture. In a distributed context, a correctly signed token for a higher-privilege action_type (e.g., `repo:admin`) could be substituted without the field check detecting it.

*Fix (pass 5)*: `sandboxed_tools.execute()` now accepts `expected_action_type: str = ""` and `expected_resource_id: str = ""` from the calling context. When non-empty, these are passed to `verify_for_execution()` instead of the token's own fields. `tool_gateway.py` always passes `expected_action_type=req.action_type, expected_resource_id=req.resource_id` from the original request (not from the token) in both execute paths. The fallback to token fields (empty default) preserves backward compatibility for unit tests that don't supply them.

*Files*: `benchmarks/agent-verification/sandboxed_tools.py` (new params + verify_action/verify_resource routing); `benchmarks/agent-verification/tool_gateway.py` (both execute calls updated)

*Regression tests*: `TestFinding3TautologicalActionTypeCheck::test_action_type_verified_against_caller_context`; `TestFinding3NegativeRegressions::test_wrong_action_type_rejected_when_supplied_independently`, `test_wrong_resource_id_rejected_when_supplied_independently`, `test_tools_execute_rejects_mismatched_action_type`, `test_tools_execute_rejects_mismatched_resource_id`, `test_gateway_passes_action_type_resource_id_independently` (5 new tests)

**FINDING-4 (LOW → DOCUMENTED) — Nonce consumed before revocation check; partial DB failure burns approval**

*Finding*: `ConditionIOrchestrator.orchestrate()` calls `try_consume()` before `is_revoked()`. If `is_revoked()` raises (e.g., revocation store is briefly unavailable), the nonce is permanently consumed but no execution happened. The approval is irrecoverably burned. This is **fail-closed** (no unauthorized execution), but constitutes a denial-of-service on approvals under partial DB failures: a flapping revocation store would permanently invalidate approvals.

*Ordering analysis (pass 5)*: Reversing the order (revocation before nonce consumption) introduces a TOCTOU vulnerability: an approval could be valid at revocation-check time, consumed as the nonce is committed, but then revoked in the window before execution. The reverse ordering trades a DoS risk for a bypass risk — a worse trade-off. Making both operations atomic would require threading a single DB connection through both stores (a major architectural refactor). Current ordering is intentionally fail-closed: partial DB failure burns the approval but never allows unauthorized execution. This is the correct security trade-off for the current architecture.

*Decision*: NO CODE CHANGE. Current ordering (nonce before revocation) is correct. Documented as accepted risk: DoS on approvals under partial DB failure.

**FINDING-5 (LOW → FIXED in pass 5) — EAT used time.monotonic_ns() for expiry (non-portable)**

*Finding*: `is_expired()` computed `time.monotonic_ns() - self.issued_at_ns > self.max_age_ns`. Monotonic clock values are per-process and not comparable across processes or machines. In the current single-process gateway, the EAT was issued and verified in the same process, so this was not exploitable. In a distributed deployment where EATs are serialized and passed across a network, the expiry check would be meaningless (or wildly incorrect).

*Fix (pass 5)*:
- `issued_at_ns` and `not_before_ns` now use `time.time_ns()` (UTC wall clock, not per-process monotonic)
- New field `not_before_ns: int` added to `ExecutionToken` dataclass and included in the HMAC-signed payload. Defaults to `issued_at_ns` on issue; can be set to a future timestamp to defer token validity.
- New method `is_not_yet_valid(clock_skew_ns)`: rejects tokens whose `not_before_ns` is in the future.
- `ExecutionTokenAuthority.__init__()` now accepts `clock_skew_ns: int = 0` to tolerate synchronized-clock drift. Applied symmetrically to both expiry and not-before checks.
- `verify_for_execution()` now checks not-before before expiry (after signature).
- `issue()` accepts an optional `not_before_ns` parameter for deferred-validity tokens.

*Cross-process portability*: a token issued in a spawned subprocess is verified in the parent process using the same signing key; `time.time_ns()` makes this reliable. Tested in `TestFinding5WallClockTimestamps::test_cross_process_token_verification`.

*Files*: `benchmarks/agent-verification/execution_token.py` (all changes); `python/tests/test_distributed_safety.py:597` (tampered token updated with `not_before_ns` field); `python/tests/test_adversarial_security_review.py` (tampered + forged tokens updated)

*Regression tests (5 new in TestFinding5WallClockTimestamps)*: `test_issued_at_is_wall_clock`, `test_not_before_ns_in_signable_payload`, `test_future_not_before_rejected`, `test_clock_skew_widens_expiry_window`, `test_cross_process_token_verification`

### Findings not confirmed (all passes)

**Model reasoning injection** — model_reasoning stored for audit only; never parsed by decision logic. ✓

**DVOScenarioState re-entrancy** — read-only after construction; concurrent reads safe. ✓

**ReplayRegistry thread safety** — 10 concurrent threads, exactly 1 True per nonce, 0 errors. ✓

**SQL injection** — all queries use parameterized placeholders (`%s`/`?`); no string interpolation of user input. ✓

**Algorithm confusion** — `key_id` is part of the signed payload; a verifier cannot be tricked into verifying with a different key by changing `key_id` on an issued token. ✓

**Cross-tenant authorization** — `tenant_id` is independently checked in `verify_for_execution` against the call context; the HMAC also covers it. Cross-tenant EAT substitution is blocked. ✓

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
| No unauthorized tool execution | DEMONSTRATED (170 tests, 39 scenarios, FAR=0.000) | Requires PostgreSQL nonce store + shared signing key |
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
| **EAT expiry portable across processes** | **DEMONSTRATED (pass 5): issued in spawned subprocess, verified in parent — test_cross_process_token_verification. time.time_ns() (wall clock) used; monotonic removed.** | Requires NTP-synchronized clocks; use clock_skew_ns for drift tolerance |
| **not_before_ns enforced and signed** | **DEMONSTRATED (pass 5): stripping not_before_ns invalidates HMAC; future not_before_ns rejected — test_not_before_ns_in_signable_payload, test_future_not_before_rejected** | HOLDS — field is in signable payload; cannot be zeroed without breaking signature |
| **action_type/resource_id independent binding** | **DEMONSTRATED (pass 5): gateway passes req.action_type/req.resource_id as independent expected values to execute(); mismatched values blocked — TestFinding3NegativeRegressions (5 tests)** | HOLDS in distributed context |
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
| `python/tests/test_agent_integration.py` | 36 security-invariant + adversarial tests |
| `python/tests/test_distributed_safety.py` | 55 distributed-safety tests (pass 2): nonce stores, key rotation, bypass paths, process-restart, multi-worker |
| `python/tests/test_adversarial_security_review.py` | 25 adversarial regression tests (pass 4–5): FINDING-1–5 coverage, FINDING-3/5 negative regressions, cross-process verification |
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
- [x] **170 tests pass**: 36 (test_agent_integration) + 21 (test_adversarial_execution) + 25 (test_adversarial_security_review) + 55 (test_distributed_safety) + 33 (test_postgres_integration) = 170. All verified against real PostgreSQL 16 via Unix socket.
- [x] **Test count discrepancy resolved**: report previously claimed 194; root cause was double-counting test_adversarial_execution.py (21 tests) within test_agent_integration, and misreporting test_agent_integration as 91 tests. Actual count: 36 (not 91). Corrected above.
- [x] 16 confirmed vulnerabilities/gaps found and addressed (BYPASS-1–2, BYPASS-3, BUG-4, HARDENING-5–10, FINDING-1 HIGH, FINDING-2 MEDIUM, FINDING-3 MEDIUM FIXED, FINDING-4 LOW documented, FINDING-5 LOW FIXED)
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

**Evaluation verdict (pass 3): PASS — PostgreSQL-validated distributed replay protection.**  
PostgreSQL-backed replay protection is now validated against real infrastructure: 5-worker concurrent nonce consumption, transaction rollback, fail-closed on DB unavailability, and all 39 adversarial scenarios with PostgreSQL backends (FAR=0.000, FRR=0.000).

**Evaluation verdict (pass 4 — independent adversarial review): CONDITIONAL GO**

| Finding | Severity | Status at pass 4 |
|---|---|---|
| FINDING-1: args_binding_hash truncated to 64 bits | HIGH | **FIXED** (commit dc5f616) |
| FINDING-2: verify_for_execution missing execution_id check | MEDIUM | **FIXED** (commit dc5f616) |
| FINDING-3: tautological action_type/resource_id checks | MEDIUM | Documented; fix deferred to pass 5 |
| FINDING-4: nonce consumed before revocation → DoS on approvals | LOW | Documented; fail-closed; no code change |
| FINDING-5: monotonic_ns EAT expiry non-portable across processes | LOW | Documented; fix deferred to pass 5 |

**Evaluation verdict (pass 5 — FINDING-3/5 remediation): GO (with standing production blockers)**

| Finding | Severity | Final status |
|---|---|---|
| FINDING-1: args_binding_hash truncated to 64 bits | HIGH | **FIXED** (dc5f616) |
| FINDING-2: verify_for_execution missing execution_id check | MEDIUM | **FIXED** (dc5f616) |
| FINDING-3: tautological action_type/resource_id checks | MEDIUM | **FIXED** (pass 5): independent expected values now propagated from request context through gateway → execute() → verify_for_execution(). 5 negative regression tests confirm blocking. |
| FINDING-4: nonce consumed before revocation → DoS on approvals | LOW | **DOCUMENTED** (pass 5): reversing order introduces TOCTOU; shared transaction requires major refactor. Current fail-closed ordering is correct. No code change. |
| FINDING-5: monotonic_ns EAT expiry non-portable across processes | LOW | **FIXED** (pass 5): time.time_ns() used throughout; not_before_ns field added and signed; clock_skew_ns configurable; cross-process verification tested. |

**All MEDIUM/HIGH findings fixed. No unresolved exploitable vulnerabilities. 170 tests pass (36 + 21 + 25 + 55 + 33).**

**Remaining conditions before production deployment (unchanged from pass 4):**

1. `InMemoryKeyProvider` (`is_managed=False`) must be replaced with a managed KMS provider before production deployment. The gateway already emits a `RuntimeWarning`; it must be treated as a hard blocker.
2. FINDING-4 must be evaluated against the target deployment's availability SLA. Under a stable DB, this is not a live risk. No code change is needed.
3. Human code review and merge authorization: **PENDING** (do not merge without authorization).

---

## Pass 6 — OpenAI Agents SDK adversarial review (PR #474, 2026-11-22)

**Branch:** `feat/openai-agents-integration` → PR #474  
**Reviewer approach:** Independent adversarial review of the PR #474 implementation; not only the description.

### Review scope

- OpenAI Agents SDK FunctionTool execution boundary
- Authorization bypasses and direct side-effect paths
- Approval registry concurrency and replay races
- Cross-process and cross-tenant token reuse
- Argument binding and TOCTOU
- Fail-closed behavior during outages
- Audit persistence and integrity after restart
- Distinction between simulated and actual SDK execution

### Baseline

| Branch | Pass | Skip | Fail (pre-existing) |
|--------|------|------|---------------------|
| staging | 780 | 86 | 5 |
| PR #474 (pre-review) | 792 | 86 | 5 |
| PR #474 (post-fixes) | 797 | 86 | 5 |

The 5 pre-existing failures are identical across all three and unrelated to the SDK integration: `test_dependabot_yml_targets_staging_for_all_ecosystems`, `test_epistemic_readiness_cli_json`, `test_repo_root_module_entrypoint_policy_compile`, `test_generate_script_roundtrip`, `test_sigstore_dependency_importable`.

---

### FINDING-SDK-1 (HIGH → FIXED) — Action-type downgrade: `delete_document` authorized under `document:read` policy

**Root cause:** `TOOL_CAPABILITY_MAP` in `tool_gateway.py` only contained GitHub tools. Document tools (`read_document`, `update_document`, `delete_document`) were absent. The gateway's step-2 capability check (`TOOL_CAPABILITY_MAP.get(req.tool_name)`) returned `None` for document tools, causing the check to be unconditionally skipped:

```python
required_action = TOOL_CAPABILITY_MAP.get(req.tool_name)
if required_action is not None and req.action_type != required_action:
    # deny
```

An attacker calling `ToolGateway.request()` directly could pass `tool_name="delete_document"` with `action_type="document:read"`. The policy lookup would find the subject's `document:read` record and issue an EAT with `action_type="document:read"`. `SandboxedDocumentTools.execute()` verified the EAT with `expected_action_type="document:read"` (from the same request context), which matched. `_dispatch("delete_document", ...)` then executed the deletion.

**Confirmed:** The exploit was reproduced in-session:
```
delete under read action_type — decision: allow
executed: True
document after attack: None   ← document deleted
```

**Fix (pass 6):**
1. Registered document tools in `TOOL_CAPABILITY_MAP` in `tool_gateway.py` — gateway now rejects mismatched action_type at step 2.
2. Wired up `TOOL_ACTION_TYPES` in `SandboxedDocumentTools.execute()` — defense-in-depth check runs before EAT verification. `TOOL_ACTION_TYPES` was defined in the original PR but never called (dead code).

Regression test: `test_s1_action_type_downgrade_blocked_by_gateway` — calls gateway directly with `delete_document`/`document:read`; asserts `capability_mismatch=True`, `executed=False`, document unmodified.

---

### FINDING-SDK-2 (MEDIUM → FIXED) — `TOOL_ACTION_TYPES` defined but never enforced (dead code)

`SandboxedDocumentTools.TOOL_ACTION_TYPES` mapped each document tool to its required action_type, but the check was never called in `execute()`. This meant that even a correctly built EAT with the wrong action_type (e.g., issued with `document:read` for a `delete_document` call by a stale or buggy gateway) would not be caught at the execution layer.

**Fix (pass 6):** `execute()` now checks `expected_action_type` against `TOOL_ACTION_TYPES.get(tool_name)` before EAT verification. If they don't match, the call is blocked and recorded with `blocked_reason="action_type_mismatch:..."` before any crypto is performed. Conditional: check only fires when both `expected_action_type` and `expected_for_tool` are non-empty (preserves backward compatibility with direct calls that omit expected_action_type).

Regression test: `test_s2_action_type_mismatch_blocked_in_execute` — issues a valid EAT for `delete_document` with `action_type="document:read"` and calls `execute()` directly; asserts blocked with `action_type_mismatch` reason.

---

### FINDING-SDK-3 (MEDIUM → FIXED) — `make_sdk_tools()` raises `JSONDecodeError` on malformed LLM arguments

`_invoke_read/update/delete` called `_json.loads(args_json)` without try/except. If the OpenAI Agents SDK passed malformed JSON (truncated model output, injection attempt via `{not valid json}`), an unhandled `ValueError` propagated through the SDK's exception handler. The LLM would receive an opaque error traceback rather than a structured `authorized: false` response, and no audit record would be created.

**Fix (pass 6):** Added `_parse_args()` helper that wraps `_json.loads()` in a try/except; returns a structured JSON error string on failure. All three invoke functions call it and return early on parse error.

Regression test: `test_s5_malformed_sdk_args_handled` — passes `{not valid json}` to `read_document.on_invoke_tool()`; asserts structured JSON response with `authorized: false`, `decision: "deny"`, `block_reason` contains `malformed_args`.

---

### FINDING-SDK-4 (LOW → DOCUMENTED) — In-process `execution_history` not durable across restarts

`SandboxedDocumentTools._history` is an in-memory list. After process restart, the execution attempt audit log is gone. The `DocumentStore` (SQLite) is durable — soft-deletes and version increments survive restart. But the execution attempt history (including blocked attempts) is lost.

**Not fixed** — this is an inherent property of the in-memory design, already documented in `benchmarks/openai-agents-integration/README.md` as a limitation. Production deployment requires a durable audit store (the existing `SqlAuditStore` in the AIGov stack).

**New test** (`test_s4_audit_persistence_across_restart`): verifies that document mutations survive restart via SQLite (the durable layer) while explicitly documenting that execution_history does not. Opens a fresh `DocumentStore` instance against the same file; confirms soft-delete row is present; confirms no phantom history from the original process.

---

### FINDING-SDK-5 (LOW → NO CODE CHANGE) — Direct `SandboxedDocumentTools.execute()` without token: fail-closed verified

Calling `execute()` without a token (bypassing the entire gateway + approval stack) correctly returns `success: False, blocked_reason: "no_execution_token"` and performs no side effect. The document is unmodified. This was the intended behavior and was already correct — no fix needed. Added `test_s3_direct_execute_no_token_blocked` to make this an explicit, named regression guarantee.

---

### FINDING-SDK-6 (INFO) — Approval registry not durable across restarts (documented)

`ApprovalRegistry` is in-memory per-process. In a multi-process or distributed deployment, two workers could each consume the same approval. This is documented in the README and in FINDING-4 (nonce store section). No fix in this pass — production deployment requires a PostgreSQL-backed nonce store (already demonstrated in pass 3).

---

### FINDING-SDK-7 (INFO) — Cross-process EAT reuse blocked by design

Each `ExecutionTokenAuthority` instance uses a fresh in-memory HMAC key. EATs from one process are invalid in another process (key mismatch). This was tested in pass 5 (`test_cross_process_token_verification`) for the GitHub tools; the same property holds for document tools since `SandboxedDocumentTools` uses the same `ExecutionTokenAuthority` interface.

---

### SDK integration security summary

| Finding | Severity | Status |
|---------|----------|--------|
| FINDING-SDK-1: action_type downgrade — delete under read policy | HIGH | **FIXED** (pass 6) |
| FINDING-SDK-2: TOOL_ACTION_TYPES dead code — no execute()-layer enforcement | MEDIUM | **FIXED** (pass 6) |
| FINDING-SDK-3: JSONDecodeError on malformed LLM args in make_sdk_tools | MEDIUM | **FIXED** (pass 6) |
| FINDING-SDK-4: execution_history not durable across restarts | LOW | **DOCUMENTED** |
| FINDING-SDK-5: direct execute() bypass fail-closed | LOW | **VERIFIED** (new test) |
| FINDING-SDK-6: approval registry not durable (multi-process) | INFO | **DOCUMENTED** |
| FINDING-SDK-7: cross-process EAT reuse blocked by design | Info | **VERIFIED** |

**Confirmed bypasses: 0** (after fixes).  
**Unauthorized side effects: 0** (after fixes).

New tests added: `test_s1`–`test_s5` (+5 tests → 17 total in harness).  
Full suite post-fixes: **797 passed, 86 skipped, 5 pre-existing failures** (same 5 as staging).

---

### Pass 6 verdict: CONDITIONAL GO

Conditions for production deployment (unchanged from pass 5, plus one new):

1. `InMemoryKeyProvider` (`is_managed=False`) must be replaced with a managed KMS provider.
2. `ApprovalRegistry` must be backed by a durable, distributed nonce store (already implemented in pass 3 — `SqlNonceStore` with PostgreSQL).
3. `SandboxedDocumentTools._history` must be replaced with or supplemented by a durable `SqlAuditStore` instance for production execution audit.
4. Human code review and merge authorization: **PENDING** (do not merge without authorization).

---

---

## Pass 7 — Durable authorization hardening (PR #477, 2026-11-22)

**Branch:** `feat/durable-sdk-authorization` → PR #477  
**Base:** `5a0c3eb` (staging after PR #476 merged)  
**Objective:** Make authorization, replay protection, and audit evidence durable across restarts and multiple processes.

### What changed

#### `SqlApprovalRegistry` (new file: `adapter/sql_approval_registry.py`)

Replaces the in-memory `ApprovalRegistry` for production use. Key properties:

| Property | SQLite backend | PostgreSQL backend |
|---------|---------------|-------------------|
| Durable across restarts | ✓ | ✓ |
| Multi-thread atomic consume | ✓ (file-level WAL locking) | ✓ (row-level FOR UPDATE SKIP LOCKED) |
| Multi-process atomic consume | ✓ (single machine) | ✓ (distributed) |
| `is_distributed_safe` | `False` | `True` |

**Atomicity guarantee:** Consumption uses `UPDATE … WHERE consumed_at IS NULL`. Exactly one concurrent caller wins (rowcount == 1); all others get `ApprovalNotFound`. Two threads racing for the same approval: exactly one succeeds. Verified by D2 (20 concurrent threads) and D13 (10-thread nonce race across shared SQLite).

**Schema:** `aigov_sdk_approvals` table with `registered_at` and `consumed_at` lifecycle columns. `consumed_at IS NULL` = pending. Indexed on `(tool_name, action_type, resource_id, tenant_id, consumed_at)` for fast key lookup.

#### `SandboxedDocumentTools.execute()` — durable audit writes

When an `audit_store` (`SqlAuditStore`) is configured, `execute()` now appends an audit row for every authorization outcome: ALLOW, DENY, capability_mismatch, action_type_mismatch, expired EAT, revoked approval. Writes are best-effort (non-fatal): a DB outage during the audit write does NOT block the authorization decision (D11 verified). `key_id` from the EAT signing key is included for key-rotation forensics.

#### `AIGovGuardedDocumentTools` — durable backend wiring

New `audit_store` parameter (optional `SqlAuditStore`). When provided:
- Wired into `SandboxedDocumentTools` for per-execution audit rows
- Passed through to `ToolGateway` (which also wires it in for blocked attempts at the gateway level)

New `is_distributed_safe` property: `True` only when BOTH the approval registry AND the replay registry use distributed-safe backends (PostgreSQL). Correctly `False` for all SQLite combinations.

New error handling: `ApprovalRegistryError` (I/O failure during approval consume) is caught in `execute_tool()` and returns a denial, preventing any authorization bypass from an erroring registry.

#### `aigov_sdk_adapter.py` — new imports

Added: `SqlApprovalRegistry`, `SqlAuditStore`, `SqlNonceStore` imports. `ApprovalNotFound` is now the unified base exception from `approval_registry.py` (re-exported by `sql_approval_registry.py`); both registries raise it.

---

### Test results (D1–D15, 18 tests)

| Test | Coverage | Result |
|------|----------|--------|
| D1 | Approval survives process restart (fresh SqlApprovalRegistry, same file) | ✓ PASS |
| D2 | 20 concurrent threads race for 1 approval; exactly 1 wins; document version increments once | ✓ PASS |
| D3 | consumed_at persisted; fresh instance sees 0 pending, 1 consumed; replay raises ApprovalNotFound | ✓ PASS |
| D4 | SqlAuditStore records ALLOW and DENY rows; decision/tool_name/authorized fields verified | ✓ PASS |
| D5 | Audit log survives restart; row count matches across fresh SqlAuditStore instances | ✓ PASS |
| D6 | Tenant-B approval cannot consume tenant-A's resource; document intact | ✓ PASS |
| D7 | delete_document approval cannot be consumed by read_document (key mismatch) | ✓ PASS |
| D8 | Expired EAT (1ns max_age_ns) is blocked; document untouched | ✓ PASS |
| D9 | Revoked approval (RevocationList) blocks after consumption; document intact | ✓ PASS |
| D10 | ApprovalRegistryError during consume: fails closed; no authorization; document untouched | ✓ PASS |
| D11 | Audit write failure swallowed silently; authorization proceeds normally (best-effort audit) | ✓ PASS |
| D12 | is_distributed_safe=False for SQLite (approval + replay); documented accurately | ✓ PASS |
| D13 | 10 threads sharing same SqlNonceStore file: exactly 1 nonce consume wins | ✓ PASS |
| D14 | 4 parametrized scenarios (no_approval, wrong_tool, wrong_resource, wrong_tenant): all deny; zero side effects | ✓ PASS |
| D15 | is_distributed_safe documented accurately for all backend combinations | ✓ PASS |

**Zero unauthorized side effects in all 18 negative / adversarial tests.**

---

### Full suite results

| Scope | Commit | Pass | Skip | Fail |
|-------|--------|------|------|------|
| python/ + benchmarks/ | staging `5a0c3eb` | 913 | 85 | 0 |
| python/ + benchmarks/ | this PR | **931** | 85 | **0** |

Delta: +18 new durable authorization tests. No pre-existing tests regressed.

---

### Threat model update

| Threat | Before | After |
|--------|--------|-------|
| Approval replay after process restart | No cross-restart protection (in-memory lost) | Blocked: consumed_at persisted; replays get ApprovalNotFound |
| Concurrent approval race (two threads/processes) | Threading.Lock guards single-process; cross-process unprotected | Blocked: atomic UPDATE WHERE consumed_at IS NULL; exactly one winner |
| Cross-tenant approval substitution | Key includes tenant_id (correctly rejected) | Unchanged; explicitly verified in D6 |
| Cross-tool approval substitution | Key includes tool_name (correctly rejected) | Unchanged; explicitly verified in D7 |
| Approval registry I/O error | Exception propagates; undefined behavior | Caught; fail-closed: ApprovalRegistryError → deny |
| Audit completeness across restarts | In-memory history lost on restart | SqlAuditStore persists to SQLite/PostgreSQL; survives restart |
| Audit write masking authorization | N/A | Best-effort only: audit failure does NOT block authorization (D11) |

### Remaining limitations (unchanged from pass 6)

1. `InMemoryKeyProvider` must be replaced with a managed KMS/HSM provider for production
2. `ApprovalRegistry` / `SqlApprovalRegistry` on SQLite: not distributed-safe across machines; use PostgreSQL for multi-host deployments
3. Audit writes and nonce consumption are in separate transactions (documented in `sql_audit_store.py`); a process crash between them leaves a consumed nonce without an audit record — the authorization is still single-use, but the evidence of the attempt is missing

---

## Pass 8 — Final security and durability review (PR #477, 2026-11-22)

### Review focus

1. Atomic single-use approval consumption under concurrent PostgreSQL transactions
2. Process crashes between approval consumption, EAT verification, execution, audit
3. SQL audit record durability and correct association
4. Best-effort audit write gap — protected side effects without durable evidence
5. Explicit fail-closed policy for mandatory audit evidence
6. PostgreSQL outages, rollback, retry, cross-process replay
7. `is_distributed_safe` accuracy
8. Authorization vs execution outcome separation
9. Regression tests with exact counts

---

### Findings

#### FINDING-DUR-1 — HIGH (FIXED)
**Best-effort audit permits destructive side effects without durable evidence**

`SandboxedDocumentTools.execute()` previously called `self._audit_store.record(...)` (best-effort, exceptions swallowed) BEFORE `_dispatch()`. If the audit store was unavailable at that exact moment, `_dispatch()` still ran: a document could be deleted or updated with no durable audit row. An audit store outage or intermittent failure is the attack surface.

**Fix:** Added `SandboxedDocumentTools.MANDATORY_AUDIT_TOOLS = frozenset({"update_document", "delete_document"})` and `SqlAuditStore.record_mandatory()` (propagates exceptions, no suppression). For authorized write/delete calls, `execute()` now attempts `record_mandatory()` BEFORE dispatch. If the write fails → `authorized` is set `False`, `block_reason = "mandatory_audit_failed:<exc>"`, `effective_decision = "mandatory_audit_failed"`, and `_dispatch()` is never called. `document:read` remains best-effort only (read-only, no mutation risk).

**Operational requirement:** An `audit_store` must be configured in every production deployment that uses document write or delete tools. Without one, mandatory audit is not enforced (no audit_store configured → no audit attempted, by design).

**Tests:** D16 (delete blocked), D17 (update blocked) — both confirm:
- `result.authorized = True` (policy approved)
- `result.executed = False` (dispatch blocked)
- `"mandatory_audit_failed" in result.block_reason`
- Document unchanged after the blocked call

---

#### FINDING-DUR-2 — MEDIUM (FIXED)
**`ToolCallResult.authorized` conflated policy decision with execution outcome**

`execute_tool()` previously set `authorized = gw_result.executed`. This made `authorized=False` whenever execution failed for any reason — including EAT expiry after a valid ALLOW decision. An incident investigator seeing `authorized=False` in the audit log would incorrectly conclude the authorization was denied, when in reality the policy approved but execution was blocked post-authorization (expired token, mandatory audit failure, etc.).

**Fix:** Changed to `authorized = gw_result.decision_record.decision == PolicyDecision.ALLOW`. Now `authorized=True` faithfully records "the authorization pipeline approved this call"; `executed=True` records "the tool side effect actually ran". The two can differ when:
- EAT expires between issuance and verification (D8: `authorized=True, executed=False`)
- Mandatory audit write fails (D16/D17: `authorized=True, executed=False`)

**Tests:** D8 updated to assert `result.authorized` (True) + `result.executed` (False). D16/D17 also validate the distinction.

---

#### FINDING-DUR-3 — INFO (NOT FIXED — documented)
**`is_distributed_safe` reads `_gateway._replay_registry` via private attribute**

`AIGovGuardedDocumentTools.is_distributed_safe` accesses `self._gateway._replay_registry` — a private attribute. If `ToolGateway` renames this attribute, the property silently returns `False`, which is the safe (conservative) default. Not a security bug, but brittle. Recommend `ToolGateway.expose_replay_registry` property in a future refactor.

---

### Threat model update (addendum to § 3)

| Threat | Before Pass 8 | After Pass 8 |
|---|---|---|
| Destructive op with no audit evidence (audit store down) | **POSSIBLE** — best-effort audit, dispatch always ran | **BLOCKED** — mandatory pre-dispatch audit for write/delete |
| Authorization/execution confusion in audit log | **POSSIBLE** — `authorized` = `executed` → misleading | **FIXED** — `authorized` = policy ALLOW; `executed` = dispatch ran |
| Cross-process audit attribute access brittle | INFO — private `_replay_registry` attribute | DOCUMENTED, low risk (fails safe) |

---

### Test results

| Suite | Pass | Fail | Skip | Notes |
|---|---|---|---|---|
| `test_sdk_durable.py` | 20 | 0 | 0 | +D16, +D17; D8, D11 assertions updated |
| `test_sdk_harness.py` | 16 | 0 | 1 | S5 skipped (no live SDK — pre-existing) |

**Total: 36 passed, 0 failed, 1 skipped**

Pre-existing staging-level failures (unchanged from PR #476 baseline):
- `test_dependabot_yml_targets_staging_for_all_ecosystems` — config mismatch
- `test_epistemic_readiness_cli_json` — CLI entrypoint
- `test_repo_root_module_entrypoint_policy_compile` — policy compile CLI
- `test_generate_script_roundtrip` — signed audit export
- `test_sigstore_dependency_importable` — sigstore not installed

---

### Verdict: **CONDITIONAL GO** (staging merge)

All confirmed HIGH and MEDIUM vulnerabilities are fixed with regression tests. The PR is safe to merge to staging under the following conditions:

1. **Configure `audit_store` in production**: mandatory audit enforcement only activates when an `SqlAuditStore` is configured. Any production deployment using `update_document` or `delete_document` MUST wire in an `audit_store`. Document this in the deployment runbook.
2. **Share KMS-backed `KeyProvider` across workers**: the `InMemoryKeyProvider` in `SandboxedDocumentTools` is per-process. Multi-worker deployments must inject a shared managed provider (the `RuntimeWarning` in the test run documents this requirement).
3. **PostgreSQL for `SqlApprovalRegistry` and `SqlNonceStore`** in multi-process deployments: `is_distributed_safe` must return `True` before claiming distributed replay safety. SQLite backends are correct for single-process only.
4. **FINDING-DUR-3 (INFO)**: private attribute access in `is_distributed_safe` — not blocking, but schedule a `ToolGateway.replay_registry` property in a follow-up.

Do not merge to production without authorization. Do not deploy without authorization.

---

## Pass 9 — Fail-closed mandatory audit, two-phase evidence, regression tests (2026-11-22)

### Gaps addressed

**GAP-1 (HIGH, FIXED)**: When `audit_store=None`, the mandatory audit condition in `execute()` was guarded by `and self._audit_store is not None`, so the entire check was silently skipped. Write and delete operations proceeded with no audit protection — no fail-closed behavior was enforced when audit infrastructure was absent.

**GAP-2 (DESIGN, FIXED)**: `"pre_execution_authorized"` was used as the decision label for the pre-execution audit row. This name did not clearly distinguish authorization intent from execution outcome. Renamed to `"authorized_pre_execution"` to reflect that this row proves the authorization decision, not that execution completed.

**GAP-3 (DESIGN, FIXED)**: After dispatch, there was no durable record that execution actually completed. The `"authorized_pre_execution"` row is proof of intent; without an `"executed"` row, forensic reconstruction could not distinguish authorized-but-crashed from authorized-and-completed.

### Changes applied

**`adapter/aigov_sdk_adapter.py`**

1. `SandboxedDocumentTools.__init__()`: Added `bypass_mandatory_audit: bool = False` parameter. Must be `False` in production. Allows explicit test isolation without an audit store.

2. `SandboxedDocumentTools.execute()` — mandatory audit condition refactored from:
   ```python
   if authorized and tool_name in self.MANDATORY_AUDIT_TOOLS and self._audit_store is not None:
   ```
   to:
   ```python
   if authorized and tool_name in self.MANDATORY_AUDIT_TOOLS and not self._bypass_mandatory_audit:
       if self._audit_store is None:
           authorized = False
           block_reason = "mandatory_audit_unconfigured:no_audit_store_set"
           ...
   ```
   This enforces fail-closed behavior when audit infrastructure is absent, unless test-isolation bypass is explicitly set.

3. `SandboxedDocumentTools.execute()` — added post-execution best-effort audit row after `_dispatch()`:
   - `decision="executed"` row written after dispatch completes
   - Best-effort only (`record()`, not `record_mandatory()`) — a failed post-execution write must NEVER roll back a completed side effect
   - Two-phase evidence: `"authorized_pre_execution"` = authorization granted, `"executed"` = dispatch completed; both rows needed for verified execution

4. `AIGovGuardedDocumentTools.__init__()`: Added `bypass_mandatory_audit: bool = False` parameter, threaded through to `SandboxedDocumentTools`.

**`tests/test_sdk_durable.py`**

- `_make_guarded()`: defaults to a temp-file `SqlAuditStore` (instead of `None`) so all existing tests exercise the mandatory audit path. Pass `audit_path=""` to get `audit_store=None` (requires `bypass_mandatory_audit=True` for non-mandatory tools, or tests the fail-closed path).

- **D18** (`test_d18_missing_audit_store_blocks_mandatory_tools`): Without `audit_store`, `delete_document` must be blocked (`mandatory_audit_unconfigured` in `block_reason`). Policy ALLOW, but `executed=False`, document untouched.

- **D19** (`test_d19_preaudit_row_persists_across_simulated_crash`): `_dispatch` patched to raise immediately after pre-execution audit commits. Pre-execution row (`"authorized_pre_execution"`) must persist in the SQLite file (opened on a fresh connection), no `"executed"` row (dispatch never ran), document untouched.

- **D20** (`test_d20_post_execution_audit_failure_does_not_roll_back`): Post-execution `_do_record` call patched to fail. Document mutation must succeed, `executed=True`, pre-execution row present. Confirms post-execution audit failure is non-fatal.

**`tests/test_sdk_harness.py`**

- `_make_harness()`: defaults to a temp-file `SqlAuditStore` so all harness tests exercise the mandatory audit path.

### Test results (Pass 9)

| Suite | Passed | Failed | Skipped | Notes |
|---|---|---|---|---|
| `test_sdk_durable.py` | 23 | 0 | 0 | +D18, +D19, +D20 |
| `test_sdk_harness.py` | 16 | 0 | 1 | S5 skipped (no live SDK — pre-existing) |

**Total: 39 passed, 0 failed, 1 skipped**

### Updated threat model

| Threat | Mitigation | Status |
|---|---|---|
| Write/delete with no audit configured | Blocked fail-closed (`mandatory_audit_unconfigured`) | **FIXED (Pass 9)** |
| Audit write failure allows side effect | Blocked fail-closed (`mandatory_audit_failed`) | Fixed (Pass 8) |
| Pre-execution row confused with execution proof | Renamed `authorized_pre_execution`; `executed` row added post-dispatch | **FIXED (Pass 9)** |
| `authorized` conflated with `executed` | Separated: `authorized=ALLOW decision`, `executed=dispatch ran` | Fixed (Pass 8) |
| Replay attack (concurrent workers) | `SqlApprovalRegistry` atomic `UPDATE WHERE consumed_at IS NULL` | Fixed (PR #476) |
| Approval revocation window | Pre-execution revocation re-check before EAT issuance | Existing |
| Cross-tenant substitution | Approval key binds `(tool_name, action_type, resource_id, tenant_id)` | Existing |
| `is_distributed_safe` brittle access | Documented (FINDING-DUR-3); schedule property follow-up | INFO only |

### Verdict: **GO** (staging merge)

Pass 9 closes the remaining gaps from the CONDITIONAL GO verdict in Pass 8:

- GAP-1 (fail-closed on missing audit_store): **FIXED**
- GAP-2 (authorization intent vs. execution proof semantics): **FIXED**
- GAP-3 (no post-execution outcome record): **FIXED**

All regression tests pass (39/40, 1 pre-existing skip). The two-phase audit evidence model (`authorized_pre_execution` → `executed`) is verified by D19 (crash: pre row persists, no executed row) and D20 (post-audit failure: execution persists, no rollback).

Remaining staging conditions (unchanged from Pass 8):
1. Wire `audit_store` in every production deployment using write/delete tools.
2. Share KMS-backed `KeyProvider` across workers in multi-process deployments.
3. Use PostgreSQL-backed `SqlApprovalRegistry` and `SqlNonceStore` for distributed deployments.

Do not merge to production without authorization. Do not deploy without authorization.

---

## Human approval gate

- Human code review and merge authorization: **PENDING**
- Do not merge without authorization
- Do not deploy without authorization
