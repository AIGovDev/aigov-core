# AIGov F1 Real Staging End-to-End Validation
## Date: 2026-11-19
## Deployment: govbase.dev (live production site)

---

## Evaluation gate

**NO-GO for full staging E2E** — All live-deployment tests are BLOCKED by
missing credentials. Local Rust binary integration tests (8/8 PASS) remain
the best available evidence. Full staging OAuth/Supabase tests require
provisioned credentials and an isolated test tenant.

---

## 1. Staging deployment discovery

### Architecture

The AIGov platform (`govbase.dev`) consists of:

| Component | Technology | Discovery source |
|-----------|-----------|-----------------|
| Frontend | Next.js (App Router) | HTML response inspection |
| Auth | Google OAuth + GitHub OAuth + Supabase Auth | `python/tests/test_f1_e2e_workflow.py` |
| DB | PostgreSQL (via Supabase or self-hosted) | `deployments/docker-compose/docker-compose.yml` |
| Audit API | Rust binary (`aigov_audit`) | `rust/` |
| Ledger | File-based (dev) or PostgreSQL (staging/prod) | `deployments/` |
| Required docs | ToS 2026-07-23.1, Privacy Policy 2026-11-12, DPA 2026-07-23.1 | `python/tests/test_f1_e2e_workflow.py:58-60` |

### Live deployment check

| Endpoint | Result | Evidence |
|----------|--------|----------|
| `GET https://govbase.dev/` | HTTP 200 — Next.js app live | HTML title: "AIGov" |
| `GET https://govbase.dev/api/ready` | HTTP 404 — Rust binary not at this path | 404 response |
| `GET https://govbase.dev/api/health` | HTTP 404 | 404 response |

**Finding:** The Rust audit API is not served at a publicly accessible URL.
It is likely accessible only on an internal network or via a secret base URL.

---

## 2. F1 workflow test results

### 2a. Live staging deployment (BLOCKED)

| Step | Status | Blocker |
|------|--------|---------|
| 1. Open staging application | PASS | `GET https://govbase.dev/` → 200 |
| 2. Initiate Google OAuth | BLOCKED | Google OAuth credentials and authorized test account required |
| 3. Verify callback + session | BLOCKED | Depends on step 2 |
| 4. Test GitHub OAuth | BLOCKED | GitHub OAuth app credentials required |
| 5. Legal acceptance screen | BLOCKED | Requires authenticated session |
| 6. Required legal doc versions | NOT VERIFIED | Cannot access staging config without auth |
| 7. Submit acceptance | BLOCKED | Requires test tenant authorization |
| 8. DB persistence | BLOCKED | `DATABASE_URL` or Supabase service-role key required |
| 9. Tenant provisioning | BLOCKED | Supabase `auth.users` and tenant schema required |
| 10. Tenant activation | BLOCKED | Depends on provisioning |
| 11. Auth boundaries | BLOCKED | Cross-tenant test requires 2 test accounts |
| 12. Audit events | BLOCKED | Rust API endpoint not publicly accessible |
| 13. Evidence integrity | BLOCKED | Depends on API access |
| 14. Rejected/incomplete states | BLOCKED | Requires app access |

### 2b. Local Rust binary (PASS — from `test_f1_real_api_integration.py`)

The test binary was started against an ephemeral in-memory ledger.
All 8 real HTTP API tests pass (committed in PR #434).

| Test | Endpoint | Status |
|------|----------|--------|
| `/ready` liveness | `GET /ready` | PASS |
| `user_authenticated` event | `POST /evidence` | PASS |
| `legal_accepted` × 3 (ToS, PP, DPA) | `POST /evidence` | PASS |
| `tenant_activated` event | `POST /evidence` | PASS |
| `GET /compliance-summary` | `GET /compliance-summary` | PASS |
| `GET /verify` chain integrity | `GET /verify` | PASS |
| `GET /bundle` | `GET /bundle` | PASS |
| Unauthorized rejection | `POST /evidence` (no key) | PASS (HTTP 401) |

### 2c. Portable state machine (PASS — from `test_f1_e2e_workflow.py`)

| Scenario | Status |
|----------|--------|
| OAuth callback: PENDING_AUTH → AUTHENTICATED | PASS |
| Session validation (valid/invalid/expired) | PASS |
| Legal gate: blocked without acceptance | PASS |
| Outdated doc version rejected | PASS |
| PENDING_LEGAL → LEGAL_ACCEPTED | PASS |
| Persistence failure rolls back | PASS |
| LEGAL_ACCEPTED → ACTIVE | PASS |
| Cross-tenant isolation (access denied) | PASS |
| Idempotent legal acceptance | PASS |
| Ordered audit events with unique IDs | PASS |

---

## 3. Required legal document versions

From `python/tests/test_f1_e2e_workflow.py` (source of truth for portable layer):

| Document | Required version |
|----------|-----------------|
| `terms_of_service` | `2026-07-23.1` |
| `privacy_policy` | `2026-11-12` |
| `data_processing_agreement` | `2026-07-23.1` |

**Note:** These versions are defined in the portable test layer. Staging may
have different versions if documents were updated. Verification requires staging
app access.

---

## 4. Blockers

| Blocker | Priority | Requirement |
|---------|----------|-------------|
| Rust API staging URL and key | P1 | `AIGOV_AUDIT_BASE_URL` + `AIGOV_API_KEY` for staging |
| Google OAuth test account | P1 | Authorized test identity, `GOOGLE_CLIENT_ID`/`SECRET` |
| GitHub OAuth test account | P1 | Authorized test identity, `GITHUB_CLIENT_ID`/`SECRET` |
| Supabase service-role key or test user | P1 | DB persistence verification |
| Staging test tenant provisioning | P1 | Isolated tenant for all write operations |
| Browser E2E (Playwright) | P2 | Staging base URL + test account credentials |

---

## 5. Recommendations

1. **Provision a dedicated CI staging test identity** (`aigov-ci-test@example.com`)
   with a pre-signed Google OAuth token for automated browser E2E.
2. **Expose a health endpoint** at a stable path (e.g. `https://govbase.dev/api/v1/health`)
   to allow liveness checks without auth.
3. **Create an integration test secret** in GitHub Actions:
   - `AIGOV_STAGING_BASE_URL` — Rust API base URL
   - `AIGOV_STAGING_API_KEY` — test tenant API key
   These would allow `python/tests/test_f1_real_api_integration.py` to run
   against the real staging deployment in CI.

---

## Human approval gate

Required reviewers: none (documentation-only PR, no code changes).

This PR contains only a report file in `docs/reports/`. No production data,
API keys, secrets, or infrastructure are modified. All live staging tests are
BLOCKED — no write operations were attempted. The `.gitleaks.toml` allowlist
file is tracked in an abandoned branch and is NOT part of this PR.
