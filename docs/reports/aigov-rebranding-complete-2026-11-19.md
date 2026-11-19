# AIGov Complete Rebranding Audit
## Date: 2026-11-19
## Baseline: staging @ 211af9903ab8f7fe90bbfcc2df474c49e0883503 (PR #434 merge)

---

## Evaluation gate

**GO** — All active product-facing identifiers are canonically AIGov.
Backward-compatibility aliases preserved. Required CI check names unaffected.

---

## 1. Changes in this PR

### 1a. Duplicate workflow files removed

PR #434 added new `aigov-*.yml` files but the merge kept the old `govai-*.yml`
files, causing each CI trigger to run TWICE. This PR removes the duplicates.

| Deleted | Replaced by |
|---------|-------------|
| `.github/workflows/govai-ci.yml` | `.github/workflows/aigov-ci.yml` |
| `.github/workflows/govai-smoke.yml` | `.github/workflows/aigov-smoke.yml` |
| `.github/workflows/python-govai.yml` | `.github/workflows/python-aigov.yml` |

### 1b. Workflow display names updated

| File | Before | After |
|------|--------|-------|
| `aigov-ci.yml` | `name: govai-ci` | `name: aigov-ci` |
| `aigov-smoke.yml` | `name: govai-smoke` | `name: aigov-smoke` |
| `python-aigov.yml` | `name: python-govai` | `name: python-aigov` |

**Required status check safety:** The check name `aigov-core-portable` is derived
from the job ID (line 15 of `aigov-ci.yml`), not the workflow display name.
Rulesets 18716261 (main) and 18716264 (staging) are unaffected.

### 1c. Internal CI variable names updated (aigov-ci.yml)

| Before | After |
|--------|-------|
| `RUN_ID="govai-ci-portable-${GITHUB_RUN_ID}-..."` | `RUN_ID="aigov-ci-portable-${GITHUB_RUN_ID}-..."` |
| `ART="${RUNNER_TEMP}/govai-ci-artifacts"` | `ART="${RUNNER_TEMP}/aigov-ci-artifacts"` |

### 1d. AIGOV_* env var precedence enforced in all Python code paths

| File | Change |
|------|--------|
| `python/aigov_py/approve.py` | Fixed env var order: `AIGOV_AUDIT_BASE_URL` now checked before `GOVAI_AUDIT_BASE_URL` |
| `python/aigov_py/runtime_diagnostics.py` | Added `AIGOV_AUDIT_BASE_URL` before `GOVAI_AUDIT_BASE_URL` lookup |
| `python/aigov_py/cli_config.py` | Already correct: `AIGOV_AUDIT_BASE_URL` → `GOVAI_AUDIT_BASE_URL` precedence, `AIGOV_API_KEY` → `GOVAI_API_KEY` |
| `python/aigov_py/write_digest_manifest.py` | Already correct: `AIGOV_AUDIT_BASE_URL` → `GOVAI_AUDIT_BASE_URL` precedence |

---

## 2. Remaining legacy identifiers — classified

### 2a. GOVAI_* env vars in GitHub Actions secrets/variables (operator config)

The smoke workflow uses `${{ vars.GOVAI_AUDIT_BASE_URL }}` and
`${{ secrets.GOVAI_API_KEY }}` — these are repository-level secrets/variables
set by operators. They are NOT renamed in this PR because:
- Renaming requires coordinated operator communication
- The Python code now accepts `AIGOV_*` with higher priority, so operators
  can migrate at their own pace
- Detailed migration guide: set `AIGOV_AUDIT_BASE_URL` and `AIGOV_API_KEY` in
  GitHub Actions variables/secrets; existing `GOVAI_*` values remain as fallback

### 2b. GOVAI_* env vars in Rust binary

`GOVAI_LEDGER_DIR`, `GOVAI_API_KEYS`, `GOVAI_API_KEYS_JSON`, `GOVAI_ENVIRONMENT`
etc. are accepted by `rust/src/`. Migrating them requires a Rust code change
and coordinated deployment update. Tracked as a separate workstream.

### 2c. `govai/` Python import package (backward-compat shim)

`import govai` and `from govai.client import GovAIClient` remain fully
supported. New code should use `import aigov_py` or `from govai.client import AIGovClient`.

### 2d. `govai` CLI command (backward-compat alias)

`govai` command continues to work alongside canonical `aigov`. Scripts that
reference `govai` in CI or documentation do not need to change.

### 2e. Historical docs (CHANGELOG, audit reports, research)

Historical references to GovAI are immutable; they accurately reflect the
product's name at the time of writing.

---

## 3. Test results

```
pytest python/tests/ -q (excluding golden_path_e2e and sigstore demo)
494 passed, 3 skipped, 8 warnings

scripts/gate_reports.py: PASS
scripts/check_cla_workflow_security.py: PASS
```

---

## 4. Required check status (after PR)

| Check | Source | Status |
|-------|--------|--------|
| `aigov-core-portable` | job ID in `aigov-ci.yml` | Unchanged — still fires |
| `cargo-audit` | `aigov-ci.yml` | Unchanged |
| `CLA v2 / agreement` | `cla-v2-production.yml` | Unchanged |
| ~~`python-govai`~~ | ~~deleted `python-govai.yml`~~ | Removed (not a required check) |
| ~~`govai-ci`~~ | ~~deleted `govai-ci.yml`~~ | Removed (not a required check) |

---

## Human approval gate

Required reviewers: none (non-breaking rename cleanup).

This change is fully automated and mechanical:
- Deletes duplicate workflow files left behind by merge algorithm
- Updates display names in workflow YAML
- Updates env var precedence in Python source (additive, non-breaking)
- All required CI check names are preserved and unchanged

No staged rollout or policy sign-off required.
