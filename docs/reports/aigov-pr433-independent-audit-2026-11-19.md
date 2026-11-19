# AIGov — Independent Audit of PR #433
## Audit date: 2026-11-19
## Audited commit: 31b8c70 (staging HEAD after merge)
## Auditor: Independent review (automated)

---

## Evaluation gate

**CONDITIONAL GO** — All items in this audit have been verified by executing the
relevant tests or by code inspection. The findings below do not block the
current staging merge but must be resolved before a production release.

## Human approval gate

**STATUS:** Awaiting maintainer sign-off.

---

## 1. Scope

This audit independently reviews the following files introduced by PR #433
(`feat/ws1-cla-audit-closure` → `staging`, merged 2026-11-19 at SHA 31b8c70):

| File | Type |
|------|------|
| `python/aigov_py/agent_action_verification.py` | New module |
| `python/tests/test_agent_action_verification.py` | New tests |
| `python/tests/test_agent_verification_benchmark.py` | New tests |
| `python/tests/test_f1_e2e_workflow.py` | New tests |
| `benchmarks/agent-verification/dataset_generator.py` | New benchmark |
| `benchmarks/agent-verification/run_benchmark.py` | New benchmark |
| `benchmarks/agent-verification/demo.py` | New demo |
| `docs/reports/cla-v2-security-audit-2026-11-18.md` | Updated report |

---

## 2. Finding matrix

| ID | File | Line | Severity | Category | Status |
|----|------|------|----------|----------|--------|
| AUDIT-01 | `benchmarks/agent-verification/dataset_generator.py` | 196–210 | **HIGH** | Circular validation | CONFIRMED |
| AUDIT-02 | `python/aigov_py/agent_action_verification.py` | 232 | **MEDIUM** | Mocked evidence posting | CONFIRMED |
| AUDIT-03 | `python/aigov_py/agent_action_verification.py` | 153–181 | **LOW** | No persistence layer | CONFIRMED |
| AUDIT-04 | `python/tests/test_f1_e2e_workflow.py` | 42–80 | **MEDIUM** | In-process state machine, no real IdP | CONFIRMED (documented) |
| AUDIT-05 | `python/aigov_py/agent_action_verification.py` | 270–310 | **LOW** | Verifier not wired to real API | CONFIRMED |

---

## 3. Detailed findings

### AUDIT-01 — Circular validation in Condition D benchmark (HIGH)

**File:** `benchmarks/agent-verification/dataset_generator.py` lines 196–210  
**File:** `benchmarks/agent-verification/run_benchmark.py` line 61

**Actual behavior:**
The `aigov_verdict` field for each benchmark case is **pre-computed inside the
dataset generator** using the same decision logic as the AIGov verifier.
The Condition D scorer (`condition_d_aigov`) then checks
`case["aigov_verdict"] == "VALID"` — it reads back the value it already wrote.

This means Condition D achieves F1=1.0 by construction, not by executing the
verifier against independently observed state. It is a tautology.

**Expected behavior:**
Condition D should invoke `verify_evidence()` on a genuinely independently
produced `EvidencePackage`, then compare the verifier's output against an
oracle that was derived independently of the verifier's decision logic.

**Reproduction:**
```python
# dataset_generator.py line 210: aigov_verdict is pre-labelled
# run_benchmark.py line 61:
def condition_d_aigov(case):
    return case.get("aigov_verdict") == "VALID"   # reads the pre-label
```

**Recommended correction:**
1. Remove `aigov_verdict` from `BenchmarkCase` and `cases.jsonl`.
2. Add an `EvidencePackage` serialized form to each case (or a factory function).
3. Condition D scorer must call `verify_evidence(reconstruct_package(case))`.
4. Ground-truth oracle must derive expected verdicts without referencing
   `verify_evidence()` internals.

**Verification test:**
See correction in `python/tests/test_agent_verification_benchmark.py` —
`test_condition_d_calls_verifier_not_precomputed_label`.

---

### AUDIT-02 — EvidenceRecorder defaults to mock POST (MEDIUM)

**File:** `python/aigov_py/agent_action_verification.py` line 232

**Actual behavior:**
```python
self._post = post_fn or (lambda d: {"ok": True, "record_hash": "mocked"})
```
When no `post_fn` is supplied (i.e., in all current tests and the demo),
the recorder never calls the real AIGov `POST /evidence` endpoint. The
string `"mocked"` is returned as the record hash.

**Expected behavior:**
Unit tests and the portable demo legitimately use an in-memory stub.  
However, the README and PR description imply that this module integrates with
the production AIGov evidence API. An integration-level `post_fn` wired to
`govai.evidence.submit_event` via a live `GovAIClient` does not exist in this
PR.

**Impact:**
The `chain_digest` stored in `EvidencePackage` is never persisted to the
AIGov append-only ledger (`audit_log.jsonl`). Tamper detection demonstrated
in `demo.py` is purely in-memory and cannot be verified by an independent
auditor reading the ledger.

**Recommended correction:**
Add an integration adapter in `python/aigov_py/agent_action_verification.py`:
```python
def make_aigov_post_fn(client: GovAIClient):
    from govai.evidence import submit_event
    return lambda event: submit_event(client, event)
```
Document that the portable module uses an in-memory stub for unit tests.
An integration test against a live binary (or the existing govai CI fixture)
should validate the real ledger path.

**Status:** DOCUMENTED. The module correctly identifies itself as a
"portable reference". The issue is that tests assert this constitutes
"production integration" in PR documentation. The code is accurate; the
claims in PR description are overstated.

---

### AUDIT-03 — SyntheticProcurementApp has no persistence (LOW)

**File:** `python/aigov_py/agent_action_verification.py` lines 153–181

**Actual behavior:**
`SyntheticProcurementApp` stores state in a Python dict (`self._records`).
Any process restart drops all state. There is no database, no file, no
API boundary.

**Expected behavior for a benchmark:**
The target application is explicitly labelled "synthetic" and "isolated".
This is acceptable for a unit-test harness. For the benchmark to claim
real-world applicability, at least one test layer should use a persistent
or external target system boundary.

**Impact:** LOW — this is by design for portable tests. The limitation is
already documented in `benchmarks/agent-verification/README.md`.

---

### AUDIT-04 — F1 tests use in-process simulation (MEDIUM)

**File:** `python/tests/test_f1_e2e_workflow.py` lines 42–80

**Actual behavior:**
The 22 passing F1 tests exercise an in-process `F1Workflow` class that
simulates the AIGov tenant onboarding state machine. No HTTP calls are made.
No Supabase queries are run. The two skipped tests document the actual
blockers (`SUPABASE_URL`, `DATABASE_URL`).

**Expected behavior:**
Acceptable as a unit/contract test layer. These tests do NOT validate that
the real AIGov HTTP API or Supabase schema implements the same state machine.

**Verification:**
Confirmed by grep — no `httpx`, `requests`, or `supabase` imports in the
test file. The `unittest.mock.patch` import is present but unused in passing
tests.

**Recommended correction:**
Add an integration test layer that calls the actual staging HTTP API
(e.g., `GET /compliance-summary`, `POST /evidence`) using the binary compiled
in govai-ci. Mark integration tests with `pytest.mark.integration` and skip
when the binary is unavailable.

---

### AUDIT-05 — Verifier not connected to real API (LOW)

**File:** `python/aigov_py/agent_action_verification.py` lines 270–310

**Actual behavior:**
`verify_evidence()` is a pure-Python in-memory function. It does not call
the AIGov Rust API (`GET /verify*`, `GET /bundle`). It recomputes the chain
digest locally and compares.

**Expected behavior:**
Acceptable for a portable reference implementation. Noted as a
limitation — the verifier is not a drop-in replacement for the Rust binary's
cryptographic verification, which uses NaCl signatures and sigstore attestation.

---

## 4. CLA v2 audit report review

**File:** `docs/reports/cla-v2-security-audit-2026-11-18.md`

The report correctly records:
- Final SHA `099e76487be99b74b4dcf724e83a518f07ffbcc8` on main.
- PR #431 (staging) and PR #432 (main→staging→main) with timestamps.
- Ruleset state for both branches.
- All 5 E2E test results.

**Verdict: PASS** — The audit closure section is accurate and evidence-based.

---

## 5. Test execution evidence

```
Platform: Darwin 25.2.0, Python 3.10.13
Run: 2026-11-19

python -m pytest python/tests/test_agent_action_verification.py -q
  23 passed in 0.07s

python -m pytest python/tests/test_f1_e2e_workflow.py -q
  22 passed, 2 skipped in 0.03s

python -m pytest python/tests/test_agent_verification_benchmark.py -q
  11 passed in 0.07s

python -m pytest python/tests/ -q --ignore=test_golden_path_e2e.py \
       --ignore=test_signed_audit_export_bundle_demo.py
  485 passed, 3 skipped in 6.33s
  (test_signed_audit_export_bundle_demo: pre-existing sigstore infra failure)
```

---

## 6. Summary

| Finding | Severity | Action required |
|---------|----------|----------------|
| AUDIT-01 Circular benchmark | HIGH | Fix before treating benchmark as independent evidence |
| AUDIT-02 Mocked evidence POST | MEDIUM | Add integration adapter; update PR docs |
| AUDIT-03 No target persistence | LOW | Document; add integration layer if claiming production coverage |
| AUDIT-04 F1 in-process simulation | MEDIUM | Add HTTP integration tests against binary |
| AUDIT-05 Verifier not API-connected | LOW | Document as portable reference |

**Overall PR #433 verdict: CONDITIONAL GO (staging)**  
The portable reference implementation is correct, well-tested, and useful as a
specification. It does not constitute production validation. The benchmark's
Condition D result (F1=1.0) must not be cited as independent evidence of
AIGov superiority until AUDIT-01 is corrected.


---

# Appendix A — F1 staging E2E evidence

# AIGov F1 Staging End-to-End Verification
## Date: 2026-11-19
## Environment: Local AIGov Rust binary (release build) on 127.0.0.1:18090
## Binary: rust/target/release/aigov_audit (compiled 2026-11-19)

---

## Evaluation gate

**CONDITIONAL GO** — All observable F1 workflow steps verified against the
real Rust binary. Full OAuth and Supabase-backed tenant provisioning remain
blocked by missing credentials (documented as SKIP).

## Human approval gate

**STATUS:** Awaiting maintainer sign-off.

---

## 1. Environment

| Item | Value |
|------|-------|
| Binary | `rust/target/release/aigov_audit` |
| Test API key | `f1-test-key` (isolated test instance) |
| Test tenant | `test-tenant-f1` |
| Run ID prefix | `f1-staging-real-*` |
| Database | In-memory ledger (no Postgres — `GOVAI_LEDGER_DIR` local) |
| Port | 18090 |
| `GET /ready` response | `{"ok":true,"ready":true}` |

---

## 2. Test results

| Test | Endpoint | Status | Evidence |
|------|----------|--------|----------|
| F1-REAL-01 `user_authenticated` event | `POST /evidence` | **PASS** | `record_hash=1bacfc6f650115913330…` |
| F1-REAL-02 `legal_accepted` ToS 2026-07-23.1 | `POST /evidence` | **PASS** | `record_hash=41c9015562670ae6dfcc…` |
| F1-REAL-03 `legal_accepted` Privacy Policy 2026-11-12 | `POST /evidence` | **PASS** | `record_hash=356192461e0c5aefb5be…` |
| F1-REAL-04 `legal_accepted` DPA 2026-07-23.1 | `POST /evidence` | **PASS** | `record_hash=1f38ecf6fd120cf502da…` |
| F1-REAL-05 `tenant_activated` | `POST /evidence` | **PASS** | `record_hash=8944b5618bbc9d5a63a0…` |
| F1-REAL-06 `resource_accessed` | `POST /evidence` | **PASS** | `record_hash=5be8862770230b2ec3c4…` |
| F1-REAL-07 Retrieve audit events | `GET /compliance-summary` | **PASS** | Returns event summary |
| F1-REAL-08 Hash chain integrity | `GET /verify` | **PASS** | `{"ok":true}` |
| Missing API key rejected | `POST /evidence` (no key) | **PASS** | HTTP 401 |

**Integration test suite:** `python/tests/test_f1_real_api_integration.py`  
**Result:** 8/8 PASS (auto-starts ephemeral binary on a random high port)

---

## 3. F1 workflow state machine (portable layer)

From `python/tests/test_f1_e2e_workflow.py`:

| Test | State Transition | Status |
|------|-----------------|--------|
| F1-01 OAuth callback | PENDING_AUTH → AUTHENTICATED | PASS (mocked IdP) |
| F1-02 Session validation | Valid/invalid/expired | PASS |
| F1-03 Legal gate | Blocked without acceptance | PASS |
| F1-04 Document version check | Outdated version rejected | PASS |
| F1-05 Acceptance | PENDING_LEGAL → LEGAL_ACCEPTED | PASS |
| F1-06 Persistence failure | Rolls back state | PASS |
| F1-07 Activation | LEGAL_ACCEPTED → ACTIVE | PASS |
| F1-08 Cross-tenant isolation | Access denied | PASS |
| F1-09 Idempotency | Duplicate acceptance no-op | PASS |
| F1-10 Audit events | Ordered events, unique IDs | PASS |
| Real OAuth callback | — | **SKIP** (Supabase/Google IdP required) |
| Real tenant provisioning | — | **SKIP** (`DATABASE_URL` required) |

---

## 4. Blockers

| Blocker | Requirement | Priority |
|---------|------------|----------|
| Full OAuth callback | Live `SUPABASE_URL`, Google/GitHub OAuth app credentials | P1 for production |
| Tenant Supabase provisioning | `DATABASE_URL` with enterprise schema (`teams`, `team_members`, `compliance_workflow`) | P1 for production |
| Browser E2E | Playwright + staging URL | P2 |

---

## 5. Limitations

- Tested against a local binary using an in-memory ledger, not the govbase.dev
  production or staging deployment. The behavior matches the production binary
  since it is the same build, but network routing, TLS, load balancers, and
  Supabase-backed persistence are not exercised.
- Real OAuth and IdP flows require live external credentials and are out of
  scope for local automated testing.
- The `compliance_workflow` table (enterprise schema) is not tested without
  Postgres; the portable test layer exercises the equivalent state machine.


---

# Appendix B — AIGov rebranding evidence

# AIGov Rebranding Audit
## Date: 2026-11-19

---

## Evaluation gate

**CONDITIONAL GO** — The highest-impact naming migrations are complete.
Remaining legacy identifiers are categorized below; none block staging.

## Human approval gate

**STATUS:** Awaiting maintainer sign-off.

---

## 1. Inventory summary

Before this workstream, the repository contained approximately **550 files** with
legacy GovAI identifiers. After migration:

| Category | Before | After | Method |
|----------|--------|-------|--------|
| Workflow files renamed | 3 (`govai-ci.yml`, `python-govai.yml`, `govai-smoke.yml`) | Renamed to `aigov-ci.yml`, `python-aigov.yml`, `aigov-smoke.yml` | `git mv` |
| Workflow `name:` fields | 3 (`govai-ci`, `python-govai`, `govai-smoke`) | Updated to `aigov-ci`, `python-aigov`, `aigov-smoke` | Edit |
| Test file references to old filenames | 2 | Updated | Edit |
| `python/pyproject.toml` description | "thin govai audit HTTP client (import govai)" | "audit HTTP client, evidence tooling, agent verification" | Edit |
| CLI entry point | `govai` only | `aigov` (canonical) + `govai` (compat alias) | Edit |
| `python/govai/__init__.py` docstring | GovAI-centric | Documents as backward-compatibility shim | Edit |
| `python/govai/client.py` | No AIGov aliases | Added `AIGovClient`, `AIGovError`, `AIGovHTTPError`, `AIGovAPIError` | Edit |
| Internal CI variable names | `govai-ci-portable-*`, `govai-ci-artifacts` | `aigov-ci-portable-*`, `aigov-ci-artifacts` | Edit |

---

## 2. Required status checks — safety verified

The branch rulesets require exactly these check names:

```
main:    aigov-core-portable, CLA v2 / agreement
staging: aigov-core-portable, cargo-audit, CLA v2 / agreement
```

These checks are generated by the **job ID** `aigov-core-portable` inside
`.github/workflows/aigov-ci.yml` (formerly `govai-ci.yml`). The job ID was
already `aigov-core-portable` before this rename. The workflow file rename
does **not** change the required check name.

**Risk: NONE** — Verified by inspecting the ruleset configuration before and after.

---

## 3. Remaining legacy identifiers — classified

### 3a. `python/govai/` package (backward-compatibility shim — INTENTIONALLY PRESERVED)

The `govai/` Python package provides `import govai` for downstream consumers.
Renaming it would constitute a **breaking change** to the public API.

**Decision:** Preserve `govai/` as the backward-compatibility import path.
Add `AIGovClient` and related aliases in `govai/client.py`.
Document in `govai/__init__.py` that new code should use `aigov_py`.

### 3b. `govai` CLI command (backward-compatible alias — INTENTIONALLY PRESERVED)

The `govai` command is used throughout CI scripts, the README, operator
documentation, and integration examples. It is also the command used in
the `aigov-ci.yml` CI workflow itself.

**Decision:** Keep `govai` as a working alias. Add `aigov` as the canonical
entry point. Update documentation to prefer `aigov` for new scripts.

### 3c. Environment variable names (`GOVAI_*`)

Variables like `GOVAI_AUDIT_BASE_URL`, `GOVAI_API_KEY`, `GOVAI_RUN_ID`
appear in workflows, documentation, and operator configuration.

**Decision:** These are **operator-visible external configuration** and
are NOT renamed in this workstream. A coordinated migration would require
updating operator documentation and providing a compatibility period with
dual-variable support. Ticket for future workstream.

### 3d. Rust source code (`rust/src/`)

Rust source does not contain user-facing GovAI branding in this audit.
Internal module names and struct names in Rust are not part of the
public Python API and are out of scope for this workstream.

### 3e. Historical documentation (`CHANGELOG.md`, `research/`)

Historical references to GovAI in CHANGELOG and research directories
represent accurate historical naming and must not be retroactively edited.

### 3f. Example integrations (`examples/`)

Example files (`examples/ci/govai-check.yml`, etc.) reference the product
by its historical name and serve as integration templates for external users.
Renaming them would break links in existing operator documentation.
Included in future documentation-refresh workstream.

### 3g. API specification (`api/govai-http-v1.openapi.yaml`)

The OpenAPI specification filename encodes the v1 HTTP API version contract.
Renaming it would break any tooling that references the spec by path.
Added to future workstream with API versioning review.

### 3h. MCP server files

`mcp/govai_mcp_server.py` — legacy MCP server filename. Safe to rename
but no behavioral change. Added to documentation-refresh workstream.

---

## 4. Python compatibility

| Import | Status |
|--------|--------|
| `import govai` | Preserved — backward-compatible shim |
| `from govai.client import GovAIClient` | Preserved |
| `from govai.client import AIGovClient` | New canonical alias added |
| `import aigov_py` | Canonical package — unchanged |
| CLI `govai` command | Preserved as alias |
| CLI `aigov` command | New canonical entry point added |

---

## 5. Test results after rebranding

```
python -m pytest python/tests/ -q (excluding golden_path_e2e and sigstore demo)
486 passed, 3 skipped in 5.00s

python scripts/gate_reports.py
Report gate passed.

python scripts/check_cla_workflow_security.py
PASS: CLA workflow security invariants
```

---

## 6. Remaining legacy identifier count

After this workstream, approximately **119 maintainable files** still contain
legacy identifiers. Of these:

- ~40 are test files referencing the `govai` import package (backward-compat)
- ~20 are workflow files using `govai` CLI command (compat alias)
- ~15 are Python modules with `GovAI*` class/variable references (compat aliases added)
- ~44 are examples, historical docs, and external configuration identifiers

None of these block staging or represent unintended legacy naming in
user-facing maintained interfaces.
