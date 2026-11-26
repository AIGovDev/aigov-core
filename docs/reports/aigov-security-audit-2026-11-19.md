# AIGov Security and Production-Readiness Audit

**Date:** 2026-11-19
**Scope:** python/aigov_py/, rust/src/, python/tests/, scripts/, deployments/

---

## Executive summary

One medium-severity defect was found and fixed in this PR (FINDING-01).
Four low-severity advisory items are documented for future hardening.
No hardcoded production credentials exist in the repository at this staging HEAD.

---

## Findings

### FINDING-01 — Medium — FIXED

**Location:** `python/aigov_py/agent_action_verification.py:310`
**Title:** `payload_intact` check always returned PASS (self-comparison tautology)

**Root cause:**

```python
# Before fix — tautology: compares property to itself
recomputed = pkg.proposal.payload_digest
checks["payload_intact"] = "PASS" if recomputed == pkg.proposal.payload_digest else "FAIL"
```

The variable `recomputed` was assigned the result of `pkg.proposal.payload_digest` and then immediately compared against `pkg.proposal.payload_digest`. This is always equal regardless of the actual payload content.

**Impact:** An `EvidencePackage` whose `proposal` body was substituted after approval (e.g. during deserialization from storage or over the wire) would pass this check. For in-memory frozen dataclasses the `chain_integrity` check would catch tampering; the vulnerability is in deserialization/database paths where the chain digest could be recomputed after substitution.

**Fix (this PR):**

```python
# After fix — re-derives from canonical_payload bytes, compares to what approver signed
recomputed = "sha256:" + hashlib.sha256(pkg.proposal.canonical_payload).hexdigest()
checks["payload_intact"] = "PASS" if recomputed == pkg.approval.approved_payload_digest else "FAIL"
```

**Regression test:** `tests/test_agent_action_verification.py::test_aav_15_payload_intact_detects_substituted_proposal`

---

### FINDING-02 — Low — Advisory

**Location:** `rust/src/audit_api_key.rs:116,125`
**Title:** API key lookup uses `HashMap::get` — not constant-time

`HashMap::get` and `contains_key` are not constant-time. An attacker with sub-millisecond network timing access could enumerate API key prefixes. The governor-based per-tenant rate limit (`rate_limit.rs`) mitigates brute-force. Acceptable for internal service mesh; recommend upgrading to `subtle` crate constant-time comparison before public SaaS exposure.

---

### FINDING-03 — Low — Advisory

**Location:** `rust/Cargo.lock` (transitive)
**Title:** Pre-allowlisted Rust advisory warnings

`cargo audit` reports 4 pre-allowlisted warnings (exit 0):
- `chrono` — unmaintained
- `event-listener` — unsound
- `rustix` — unsound
- `chacha20` — yanked

None are in the evidence verification hot path. Track in next dependency refresh cycle.

---

### FINDING-04 — Low — Advisory

**Location:** `python/pyproject.toml` (transitive)
**Title:** Transitive Python CVEs in test/dev dependencies

- `dnspython 2.8.0` — 2 CVEs; fix: `2.9.2`
- `filelock 4.1.0` — 15 CVEs; fix: `4.2.1`

Neither package is imported by core evidence verification or the Rust API. Update in next dependency maintenance pass.

---

### FINDING-05 — Low — Advisory

**Location:** `python/aigov_py/experiments/` (not reachable from production handlers)
**Title:** `skip_events_digest` ablation path bypasses chain verification

The experiments module contains a `skip_events_digest` flag for ablation studies. This code is not imported by any production handler or CLI entry point. Recommend adding a `# noqa` marker and a comment that it must not be promoted to production, or gating it behind `AIGOV_ENVIRONMENT=dev` at load time.

---

## Security controls confirmed

| Control | Status | Evidence |
|---------|--------|---------|
| Tenant isolation | PASS | `govai_api.rs:256` — per-API-key ledger isolation |
| Duplicate event rejection | PASS | `audit_store.rs:551` + concurrent tests |
| Rate limiting (staging/prod) | PASS | `rate_limit.rs:28` — enabled by default, keyed per tenant |
| `AIGOV_POLICY_STRICT` in CI | PASS | `aigov-ci.yml`, nightly, compliance, release-validation workflows |
| SQL injection prevention | PASS | Parameterized queries via psycopg only (`govai_postgres_runs.py`) |
| Hardcoded credential scan | PASS | `secrets.token_urlsafe(24)` used for all test API keys since `5b0aabc` |
| `cargo-audit` | PASS | 0 CVEs, 4 pre-allowlisted warnings |
| Replay detection | PASS | `replay_validation.rs` + duplicate `event_id` enforcement |

---

## Evaluation gate

| Item | Status |
|------|--------|
| FINDING-01 fixed with regression test | PASS |
| All 497 Python tests pass | PASS |
| `cargo-audit` exits 0 | PASS |
| No hardcoded credentials in test suite | PASS |

## Human approval gate

Merge requires:
1. `aigov-ci` required check passes (includes `aigov-core-portable` job and `cargo-audit`).
2. `CLA v2 / agreement` required check passes.
3. Human reviewer confirms FINDING-01 fix is correct before merging to staging.
