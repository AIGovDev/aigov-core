# Repository debt audit and cleanup

**Date:** 2026-09-30
**Scope:** Whole-repository audit for duplicate files, placeholders, dead references, and drift between documentation and implementation. Four independent review passes (code, docs, operational config/CI, and a stray untracked directory), followed by fixes for everything with a safe, mechanical resolution.
**Related:** the runtime-auth fixes on this same branch (`ai_discovery_completed.py`, `/verify-log` retirement, `make flow_full` completeness) are tracked separately in this branch's own commit history — this report covers the broader repo sweep that followed.

This file was itself one of the findings: it was cited as authoritative from `README.md`, `docs/roadmap.md`, and `docs/contributors/contributor-pathways.md`, but did not exist until this pass.

## Issues addressed

| ID | Finding | Resolution |
|----|---------|------------|
| RD-1 | `aigov-core-agpl/` — an untracked, ~15MB, three-week-stale manual snapshot from the AGPL relicensing work, missing dozens of files present in current `python/aigov_py/`, referenced nowhere | Deleted |
| RD-2 | `docker-compose.yml` set `GOVAI_API_KEYS` but not the required paired `GOVAI_API_KEYS_JSON` (`rust/src/audit_api_key.rs` documents both as required together) — the README's own copy-paste Docker demo (`docker compose up` → `examples/blocked_deployment.sh`) failed at the first `POST /evidence` with `400 TENANT_RESOLUTION_FAILED` instead of ever reaching the intended `BLOCKED` verdict | Added `GOVAI_API_KEYS_JSON` alongside `GOVAI_API_KEYS`; corrected the misleading "optional" comment |
| RD-3 | `ENTERPRISE_LAYER.md` — cited 5+ times (`ARCHITECTURE.md`, `DEMO_FLOW.md`, `docs/architecture/platform-vs-core-boundary.md`) as the reference for RBAC/teams/compliance-workflow semantics; did not exist | Written from the real implementation (`rust/src/rbac.rs` roles/permissions table, `rust/src/auth.rs` JWT flow, the `compliance_workflow` state machine, and the frozen-core boundary rule) |
| RD-4 | `rust/migrations/` does not contain the `teams`/`team_members`/`compliance_workflow` schema — `DEMO_FLOW.md`, `ARCHITECTURE.md`, and `docs/database-environments.md` all named specific migration files (`0001_govai_core.sql`, `0002_add_compliance_context_fields.sql`, `0003_compliance_workflow.sql`, `0004_console_runs.sql`) that do not exist; the repo only ships `0001_core_api_key_usage.sql` and `0002_core_issued_api_keys.sql` | Corrected all three docs to state the schema isn't shipped in Core and must come from an operator-provisioned database; documented as a real gap in `ENTERPRISE_LAYER.md`, not just a doc fix |
| RD-5 | `dashboard/` contains only a brand asset — no Next.js app, `package.json`, or `lib/` tree was ever committed — while `ARCHITECTURE.md`, `DEMO_FLOW.md`, and `docs/project/local_development.md` document `cd dashboard && npm install`/`npm run dev` as if it were live, working Core code | Added explicit "not shipped in AIGov Core" caveats to all three; these describe the hosted GovAI Platform dashboard, not this repository |
| RD-6 | `docs/project/local_development.md` documented `make fail-closed-demo` (`scripts/run_fail_closed_demo.py`) as the fail-closed demo entrypoint; neither the Makefile target nor the script exist | Replaced with the real entrypoint, `bash examples/blocked_deployment.sh`, which is exercised in CI |
| RD-7 | Duplicated HTTP-POST auth-header logic hand-copied across `ai_discovery_completed.py`, `approve.py`, `promote.py` — the exact drift risk that caused the auth bug fixed earlier on this branch | Extracted to `python/aigov_py/_evidence_http.py::post_evidence_json`; all three now share one implementation |
| RD-8 | `docs/index.md` — 89 broken links (`pricing/`, `buyer/`, `tenant-console/`, `../dashboard/app/layout.tsx`, ...) describing the closed GovAI Platform's doc tree, not this OSS repo; `examples/README.md` had 10 similar dead links (`commercial-demo/`, `marketplace/`, `partner-ecosystem/`, ...) | See "Platform-leak link cleanup" below |
| RD-9 | Scattered Platform-only dead links: `trust/README.md`, `docs/pricing/index.md`, `docs/architecture/epistemic-model.md` → `knowledge-preservation-layer.md`, `docs/multi-tenant/overview.md` → `hosted-platform/README.md`/`control-plane/README.md`, three `.cursor-plugin/*.md` → `docs/commercial/*.md` links, and a wrong relative path to `.cursor-plugin/mcp.json` | See "Platform-leak link cleanup" below |
| RD-10 | Six `docs/observability/*.md` files promise `scripts/operational_health_score.py` and four sibling scripts that were never committed; `docs/registry/*.md` cites a `marketplace/` tree (`manifest.json`, `policy-pack-format.md`, `security-and-trust.md`) that doesn't exist | Docs corrected to state these are not yet implemented rather than silently 404 for a reader; not fabricated as real scripts/content (see note below) |
| RD-11 | `legal/published/{privacy-policy,dpa}.md` are literal placeholder stubs ("Legal text pending counsel review") living under a `published/` path | **Not resolved in this pass** — flagged for a human decision, not auto-drafted; see note below |

## What was deliberately *not* "fixed"

Two categories of finding don't get a mechanical resolution, on purpose:

- **`legal/published/{privacy-policy,dpa}.md`** — these are real legal documents. Auto-generating replacement text for a privacy policy or DPA is not something to do without counsel review, regardless of how confidently a diff could be produced. Recorded here so the gap is visible, not silently fixed with fabricated legal language.
- **`scripts/operational_health_score.py` and the `marketplace/` tree (RD-10)** — building five unspecified scripts or a registry submission format from scratch, based only on what docs imply they should do, risks shipping code nobody asked for and nobody reviewed the design of. Docs were corrected to stop overclaiming; the underlying features remain unbuilt.

## Platform-leak link cleanup (RD-8, RD-9)

The dominant pattern across the docs audit wasn't random link rot — it's **GovAI Platform** (the closed, commercial product) content that leaked into this OSS repository's docs/examples during a monorepo split and was never pruned. `README.md`'s own "Core vs Non-Core" table already draws this line; these files didn't follow it. Each dead link was either removed or replaced with a short note pointing at the Core-scoped equivalent where one exists.

## Files changed

| Path | Change |
|------|--------|
| `aigov-core-agpl/` | **Deleted** (untracked, stale duplicate) |
| `docker-compose.yml` | Added `GOVAI_API_KEYS_JSON` |
| `ENTERPRISE_LAYER.md` | **Added** |
| `ARCHITECTURE.md` | Corrected enterprise-layer migration claim; added dashboard caveat |
| `DEMO_FLOW.md` | Corrected migration-file prerequisites; corrected dashboard section; fixed `fail-closed-demo` reference |
| `docs/database-environments.md` | Corrected migration-file listing |
| `docs/project/local_development.md` | Corrected dashboard + fail-closed-demo instructions |
| `python/aigov_py/_evidence_http.py` | **Added** — shared `post_evidence_json()` |
| `python/aigov_py/ai_discovery_completed.py`, `approve.py`, `promote.py` | Use shared helper instead of copy-pasted auth logic |
| `python/tests/test_ai_discovery_completed.py` | Updated mock patch targets for the moved `urlopen` call |
| `docs/index.md`, `examples/README.md`, and scattered `.md` files with Platform-only links | Dead links removed/corrected |
| `docs/observability/*.md`, `docs/registry/*.md` | Corrected to stop claiming unshipped scripts/tree as present |
| `docs/reports/repo-debt-audit-and-cleanup.md` | **Added** (this file) |

## Validation commands

```bash
cd python && source .venv/bin/activate && python -m pytest -q
docker compose up -d --build && bash examples/blocked_deployment.sh
```
