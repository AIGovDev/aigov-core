# Security isolation and benchmark expansion — 2026-11-19

## Scope

PR `feat/security-and-benchmark-p2` → `staging` adds:

1. **Negative cross-tenant authorization tests** (`python/tests/test_security_isolation.py`):
   20 tests verifying that tenant A cannot read, modify, or retrieve audit evidence
   belonging to tenant B.

2. **HTTP 404 fix** (`rust/src/govai_api.rs`):
   Three read endpoints (`bundle_for_run`, `compliance_summary_for_run`, `verify_ledger`)
   returned HTTP 200 with `{ok: false}` for missing run IDs. Fixed to return 404.

3. **Benchmark expansion** (`benchmarks/agent-verification/independent_benchmark.py`):
   Added `build_expanded_dataset()` (50 stratified scenarios targeting 3 FP root-cause
   categories), `build_full_dataset()` (70 scenarios total), and `mcnemar_test()`
   paired comparison.

4. **FP root-cause analysis script**
   (`benchmarks/agent-verification/analyze_fp_scenarios.py`): classifies 8 Qwen FPs
   by root cause category.

5. **Benchmark regression tests** (`python/tests/test_benchmark_regression.py`):
   25 deterministic tests covering dataset integrity, condition correctness, FP categories,
   and McNemar infrastructure.

## Evaluation gate

### 1. Cross-tenant authorization tests (20 tests)

**Verified behavior:**
- Tenant A cannot read tenant B's bundle, bundle-hash, compliance-summary,
  verify-ledger, or api/export endpoints.
- Cross-tenant reads return HTTP 404 on the fixed binary (or HTTP 200 with
  `{ok: false, error: "run_not_found"}` on the pre-fix binary; both are acceptable
  to the test assertions to remain compatible with the binary on staging).
- Body `tenant_id` field does NOT override API-key-bound tenant assignment.
- Duplicate event IDs in the same tenant are rejected (409/422).
- Same event ID in different tenants is accepted (correct namespace isolation).
- `Basic` auth scheme and whitespace bearer tokens are rejected (401).

**Test run:** 20/20 pass with rebuilt binary (Rust HTTP status code fix applied).
**Combined with existing E2E suite:** 38/38 pass (18 staging E2E + 20 security).

### 2. HTTP 404 fix (rust/src/govai_api.rs)

Three run_not_found paths now return `(StatusCode::NOT_FOUND, Json(...)).into_response()`:
- `bundle_for_run`: was defaulting to 200 when events list was empty.
- `compliance_summary_for_run`: same.
- `verify_ledger`: same.

`bundle_hash_for_run` and `api/export` already returned 404 and are unchanged.

This is a semantic correctness fix, not a security fix — data isolation was
intact before this change.

**Rust test suite:** 1/1 pass.

### 3. Expanded benchmark dataset (70 scenarios)

Base dataset (seed=42): 20 scenarios (4 positive / 16 negative), unchanged.
Expanded dataset (seed=7): 50 scenarios (10 positive / 40 negative), stratified into:

| Category | Count | FP risk | Root cause |
|---|---|---|---|
| F1 — invalid approver identity | 12 | HIGH | `verify_approval` returns `valid: True` with `unknown@external.invalid` |
| F2 — only external state contradicts | 14 | HIGH | audit+approval pass; only `read_external_state` fails |
| F3 — missing audit record, approval valid | 14 | MEDIUM | no audit record; approval may be active |
| Positives | 10 | — | all checks pass |

Full 70-scenario dataset condition results (95% Wilson CI):

| Condition | F1 | Acc | 95% CI | FAR |
|---|---|---|---|---|
| A — self-report | 0.337 | 0.214 | [0.118, 0.310] | 0.982 |
| B — tool response | 0.354 | 0.271 | [0.167, 0.376] | 0.911 |
| C — external state | 0.452 | 0.514 | [0.397, 0.631] | 0.607 |
| D — AIGov verifier | 0.636 | 0.771 | [0.673, 0.870] | 0.286 |

McNemar's test (C vs D, 70 scenarios): χ²=5.78, p=0.016 (significant at α=0.05,
n_discordant=50). Condition D is statistically distinguishable from C.

**Benchmark regression tests:** 25/25 pass.

### Limitations

- Qwen (condition E) results require the MLX model and are not re-run here.
  The 8 FPs from the prior run are explained by root-cause analysis but are not
  re-verified against the model.
- The expanded dataset exercises the scripted oracle (condition D) only.
  Condition E (Qwen) must be re-run against the full 70-scenario dataset separately.
- McNemar p-value uses the Abramowitz & Stegun approximation (accurate for z in [0, 5]);
  exact p-values would require scipy.stats.
- `AIGOV_POLICY_STRICT=false` remains set in the security test fixture;
  policy parity with deployed staging is unverified.

## Human approval gate

- Human code-review and merge authorization: **PENDING**.
- No production data was changed during preparation of this change.
