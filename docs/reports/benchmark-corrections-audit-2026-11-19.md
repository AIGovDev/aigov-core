# Benchmark corrections audit — 2026-11-19

## Scope

PR #442 (`feat/benchmark-corrections` → `staging`) corrects three issues found in post-merge audit of PRs #440 and #441.

Source: https://github.com/AIGovDev/aigov-core/pull/442

## Evaluation gate

### 1. Staging E2E fixture — GOVAI_API_KEYS mismatch (python/tests/test_staging_e2e.py)

**Root cause:** The `api_base` fixture set `GOVAI_API_KEYS=key1` (single key) while
`GOVAI_API_KEYS_JSON={key1: tenant1, key2: tenant2}` (two keys). The binary requires
all keys present in `GOVAI_API_KEYS_JSON` to also appear in `GOVAI_API_KEYS`; keys
absent from `GOVAI_API_KEYS` receive HTTP 401. This caused `api_key_2` requests to
be rejected, so `test_tenant_isolation_separate_ledgers` was permanently skipped.

**Fix:** `GOVAI_API_KEYS=f"{api_key},{api_key_2}"`. Both keys now accepted.

**Result:** 18/18 staging E2E tests pass. `test_tenant_isolation_separate_ledgers`
exercises that two tenants can submit evidence concurrently without key-rejection.

### 2. Staging E2E fixture — _is_alive() uncaught URLError

**Root cause:** `_http()` only catches `urllib.error.HTTPError` (4xx/5xx responses)
but not `urllib.error.URLError` (connection refused, network error). During binary
startup the port is not yet open; `_is_alive()` would propagate the `URLError` up
through the fixture's readiness loop, causing ERROR-at-setup instead of a clean skip.

**Fix:** Wrap `_http()` call in `_is_alive()` with a broad `except Exception: return False`.

### 3. Qwen benchmark — verdict_source tracking (mlx_qwen_adapter.py, run_qwen_benchmark.py)

**Root cause:** `AgentTrace` had no field distinguishing model-generated verdicts from
fallback verdicts (default=False applied when the model never called `report_verdict`).
The earlier benchmark run reported TP=3, TN=7 and "5 positive / 15 negative" — all
wrong. The correct figures are TP=4, TN=8, 4 positive / 16 negative.

**Fix:** Add `verdict_source: str` field to `AgentTrace` with values `"model_tool"`,
`"prose_parse"`, `"fallback"`. Populate it in the agent loop. Report the breakdown
and separate accuracy metrics in the JSON output.

**Verified result (seed=42):**

| Field | Incorrect (PR #441) | Correct |
|-------|---------------------|---------|
| n_positive | 5 | **4** |
| n_negative | 15 | **16** |
| TP | 3 | **4** |
| TN | 7 | **8** |
| FP, FN | 8, 0 | 8, 0 (unchanged) |
| F1, FAR, Acc | 0.500, 0.500, 0.600 | 0.500, 0.500, 0.600 (unchanged) |

Verdict sources: model_tool=17, prose_parse=0, fallback=3.
All 3 fallback scenarios (S03, S09, S11) had gt=False; fallback=False was correct.

## Limitations not addressed

- Tenant isolation test verifies that two tenants can submit evidence with separate keys,
  not that one tenant cannot read the other's evidence. Negative authorization (cross-read
  denial) is not covered.
- `AIGOV_POLICY_STRICT=false` is still set in the fixture; policy parity with deployed
  staging remains unverified.
- Statistical significance: no paired analysis of Conditions D and E has been performed.
  The conditions use different oracle mechanisms. Comparisons are descriptive only.

## Human approval gate

- Human code-review and merge authorization: **PENDING**.
- No production data was changed during preparation of this correction.
