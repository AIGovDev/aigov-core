# AIGov OpenAI Agents SDK Integration

Production-oriented security integration between [OpenAI Agents SDK v0.25.0](https://github.com/openai/openai-agents-python)
and the AIGov authorization gateway stack.

---

## Overview

Every document tool call made by an AI agent passes through the full AIGov
authorization pipeline before any side effect executes. The LLM cannot
authorize its own actions: authorization is determined solely by pre-registered
approvals consumed by the adapter, and enforced by HMAC-signed
ExecutionAuthorizationTokens (EAT).

```
LLM calls tool → FunctionTool.on_invoke_tool
                → ApprovalRegistry.consume()       [pre-approval gate]
                → ToolGateway.request()             [full pipeline]
                   → ConditionI orchestration       [audit + replay + revocation + policy]
                   → EAT issuance (HMAC-SHA256)     [binding auth to this exact call]
                   → SandboxedDocumentTools.execute [EAT verified independently]
                   → DocumentStore side effect       [SQLite write]
```

---

## Three Tools

| Tool name         | Action type       | Side effect           |
|-------------------|-------------------|-----------------------|
| `read_document`   | `document:read`   | None (read-only)      |
| `update_document` | `document:write`  | SQLite UPDATE / INSERT|
| `delete_document` | `document:delete` | SQLite soft-delete    |

---

## Reproduction

```bash
# From the aigov-core-j root
export PYTHONPATH=benchmarks/agent-verification

# Run the 12-scenario adversarial test harness (no live API key needed)
python -m pytest benchmarks/openai-agents-integration/tests/test_sdk_harness.py -v

# Run the 7-scenario demo (writes results/demo_results.json)
python benchmarks/openai-agents-integration/demo/run_demo.py
```

---

## Test Scenarios

### Adversarial harness (`test_sdk_harness.py`) — 12 tests

| ID   | Threat category               | Expected decision | SQLite asserted |
|------|-------------------------------|-------------------|-----------------|
| T1   | Authorized read               | allow             | content unchanged |
| T2   | Authorized update             | allow             | version incremented |
| T3   | Authorized delete             | allow             | soft-delete + audit row |
| T4   | No pre-approval (LLM unauthorized) | no_approval  | unmodified |
| T5   | Prompt-injection resource substitution | no_approval | unmodified |
| T6   | Approval replay (second call) | no_approval       | second write not persisted |
| T7   | Cross-tenant substitution     | no_approval       | tenant-A isolated |
| T8   | Wrong tool escalation         | no_approval       | unmodified |
| T9   | Revoked approval              | deny              | unmodified |
| T10  | Expired EAT (1 ns max_age)   | blocked           | unmodified |
| —    | Resource-ID derivation helper | (unit)            | — |
| —    | Unknown tool name             | deny              | no-op |

---

## Security Properties

### What AIGov enforces that the LLM cannot override

1. **Pre-approval required**: Every tool call consumes a single-use approval
   registered by the application before the agent runs. No approval → DENY.
   This models the real-world workflow where a human or policy system
   pre-authorizes specific actions before the agent runs.

2. **EAT binding**: The gateway issues an HMAC-SHA256 ExecutionAuthorizationToken
   that binds `(tool_name, args_binding_hash, action_type, resource_id,
   tenant_id, execution_id)`. The tools object verifies this token
   independently before any side effect.

3. **Tautology-free verification (FINDING-3)**: `action_type` and `resource_id`
   are passed to `verify_for_execution` from the original request context,
   not from the token's own fields. A token cannot self-authorize a different
   action type or resource.

4. **Replay protection**: Each `approval_id` may only be consumed once.
   The ConditionI orchestrator tracks nonces; replay → DENY.

5. **Revocation**: The revocation list is checked during ConditionI orchestration
   AND immediately before EAT issuance, closing the TOCTOU window.

6. **Fail-closed**: Any exception from the policy or orchestration layer →
   INDETERMINATE → no execution.

7. **Portable timestamps (FINDING-5)**: `time.time_ns()` (UTC wall clock) is
   used for all EAT timestamps. EATs are verifiable across process boundaries.

8. **Tenant isolation**: `tenant_id` is supplied by the execution context
   (the application), not by the LLM's arguments. Cross-tenant resource_id
   derivation makes approval reuse across tenants structurally impossible.

---

## Limitations (not addressed by this integration)

| Limitation | Detail |
|------------|--------|
| **No live inference** | Deterministic tests do not call the OpenAI API. Adversarial LLM behavior (jailbreaks, indirect prompt injection from document content) requires separate red-team evaluation. |
| **No distributed replay safety** | `ReplayRegistry` is in-memory per-process. Distributed deployment requires a shared, durable nonce store (Redis, PostgreSQL). This is not implemented or claimed. |
| **No production key management** | `ExecutionTokenAuthority` defaults to an in-memory key. Production requires a managed key provider (KMS, HSM). The implementation warns at construction time. |
| **In-memory approval registry** | `ApprovalRegistry` is per-process. Production requires a persistent, audited approval store with its own authorization controls. |
| **No encrypted storage** | SQLite `DocumentStore` stores content in plaintext. Production requires encryption at rest. |
| **No network isolation** | Tests run in-process. Production deployment requires network-level isolation between the AIGov gateway and the LLM inference endpoint. |

---

## Files

```
benchmarks/openai-agents-integration/
├── adapter/
│   ├── document_store.py        SQLite-backed document store (real side effects)
│   ├── approval_registry.py     Single-use pre-approval registry
│   └── aigov_sdk_adapter.py     AIGov gateway adapter + OpenAI Agents SDK FunctionTools
├── tests/
│   └── test_sdk_harness.py      12 adversarial test scenarios (no live API)
├── demo/
│   └── run_demo.py              7-scenario demo (writes results/demo_results.json)
├── results/
│   └── demo_results.json        Machine-readable demo run results
└── README.md                    This file
```
