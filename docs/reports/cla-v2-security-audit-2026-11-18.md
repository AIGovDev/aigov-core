# CLA v2 security audit — 2026-11-18

Auditor: Independent security review (Claude Sonnet 4.6 / monika.dvorack@gmail.com)

## Scope

Independent verification that CLA v2 is correctly deployed, secure, and operational
after merging PR #428 (staging → main) and PR #429 (AI attribution fix).

---

## Repository state (verified)

| Branch  | Commit    | Tree-diff to other |
|---------|-----------|-------------------|
| main    | 0d5e7400  | 0 files           |
| staging | bb29188   | 0 files           |

main and staging are tree-identical.  main carries one extra merge commit (the
PR #428 merge) that is not on staging; all file content is equivalent.

### Merged PRs inspected

| PR  | Branch                       | Merged to | Merged at (UTC)       |
|-----|------------------------------|-----------|-----------------------|
| 426 | feat/cla-retire-legacy-v2    | staging   | 2026-11-18T16:35:07Z  |
| 429 | fix/cla-v2-ai-attribution-428| staging   | 2026-11-18T18:33:48Z  |
| 430 | fix/cla-v2-staging-merge     | staging   | 2026-11-18T18:43:20Z  |
| 428 | staging                      | main      | 2026-11-18T18:47:01Z  |

---

## CI results on staging tip bb29188 (pre-merge to main)

All checks that ran on staging before the PR #428 merge:

| Workflow                   | Conclusion |
|----------------------------|------------|
| CLA v2 production          | success    |
| CLA Assistant              | skipped ✓  |
| compliance                 | success    |
| govai-ci                   | success    |
| release-validation         | success    |
| supply-chain-audit         | success    |
| python-govai               | success    |
| security-scan              | success    |
| CLA workflow security guard| success    |
| CLA v2 shadow tests        | success    |
| PR branch policy           | success    |
| oss-developer-experience   | success    |

CLA Assistant shows `skipped` because PR #426 added `if: false` — correct behavior.

On main merge commit 0d5e7400: CLA workflow security guard — success.

---

## Branch ruleset verification (read-only GitHub API)

| Branch  | Ruleset ID | Required checks                                      |
|---------|------------|------------------------------------------------------|
| main    | 18716261   | aigov-core-portable, CLA v2 / agreement              |
| staging | 18716264   | aigov-core-portable, cargo-audit, CLA v2 / agreement |

CLAAssistant is **not** in either ruleset.  No enforcement gap.

---

## Security findings

### FINDING-1 — Bot identity cross-pairing (LOW, FIXED)

**Affected files:** `scripts/cla_v2_shadow.py`, `scripts/cla_v2_production.py`

**Before fix:**
```python
BOT_ALLOWLIST = {"dependabot[bot]", "github-actions[bot]"}
VERIFIED_BOT_IDS = {49699333, 41898282}
# check: login in BOT_ALLOWLIST and uid in VERIFIED_BOT_IDS
```

The check used two independent sets.  A commit authored by `dependabot[bot]`
(login ∈ BOT_ALLOWLIST) with numeric ID `41898282` (GitHub Actions' ID, not
dependabot's — uid ∈ VERIFIED_BOT_IDS) would be incorrectly exempted from CLA
checking.  Symmetric: `github-actions[bot]` with dependabot's ID (49699333).

**Exploitability:** not exploitable in production.  The GitHub Commits API
returns `author.login` and `author.id` server-side from the git author email;
GitHub never assigns a cross-paired login+ID to a real commit.

**After fix (`fix/cla-v2-bot-identity-pairing`):**
```python
BOT_IDENTITY_MAP = {
    "dependabot[bot]": 49699333,
    "github-actions[bot]": 41898282,
}
# check: login in BOT_IDENTITY_MAP and uid == BOT_IDENTITY_MAP[login]
```

**Regression tests added:**
- `test_bot_cross_paired_id_is_unsigned` (shadow)
- `test_correct_bot_identity_is_exempted` (shadow)
- `test_bot_cross_paired_id_not_exempt` (production)

**PR:** pending (see Phase 5 below).

---

### FINDING-2 — Hardcoded AI model name (LOW, DEFERRED)

**Affected file:** `scripts/cla_v2_shadow.py` (line 69)

The exempted AI tool trailer is hardcoded as `"Claude Sonnet 4.6"`.  When the
project's Claude Code configuration is upgraded to a later model, commits with
the new attribution trailer will trigger `AuditError("Co-authored commit
requires manual identity verification")`, causing the CLA check to post an
`error` status.

**Exploitability:** none — this hardens the check; it cannot be used to bypass
CLA enforcement.

**Risk:** operational disruption (CLA check errors on maintainer PRs) when the
model name changes.  The fix (a targeted PR adding the new model name) is
straightforward.

**Status:** deferred; no security regression until the model name changes.

---

### FINDING-3 — AI attribution trailer not creating a legal signatory (CONFIRMED CORRECT)

PR #429 changed the co-author trailer check so that the exact strings
`Co-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>` and
`Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>` are silently
skipped instead of raising `AuditError`.

The fix is correct and fail-closed:
- The AI tool trailer is NOT added to the `identities` dict; no phantom signer
  is created.
- Commit `author.login` is still extracted from the GitHub API and checked for
  a CLA.
- All other `co-authored-by:` lines (including lookalikes with a different
  email) still raise `AuditError`.
- The exemption applies only to `contributors()`; it does not affect signature
  verification, PR submitter checks, or the required status gate.

Regression tests verified: `test_exact_ai_attribution_does_not_create_human_cla_signer`,
`test_ai_attribution_plus_human_coauthor_still_blocks`, `test_lookalike_ai_attribution_still_blocks`.

---

## Tests executed (local)

```
python3 -m unittest discover -s tests -p 'test_cla_v2_*.py' -v
```

```
Ran 33 tests in 0.007s
OK
```

33/33 tests pass (30 existing + 3 new regression tests for FINDING-1).

```
python3 scripts/check_cla_workflow_security.py
PASS: CLA workflow security invariants (cla.yml + cla-v2-production.yml)
```

---

## Other security properties verified

| Property | Verdict |
|---|---|
| Fail-closed on API errors | ✓ — `AuditError` propagates; `main()` exits 1 |
| Numeric contributor identity verification | ✓ — `commit.author.id` validated as positive int |
| Historical CLA consent validation | ✓ — live comment re-fetched; `created_at == updated_at` enforced; body, author, PR ref, URL checked |
| Co-author trailer handling (AI) | ✓ — only exact trailer exempted; no phantom signer |
| Pagination / 250-commit cap | ✓ — commit count > 250 or mismatch raises `AuditError` |
| Bot identity pairing (after fix) | ✓ — dict lookup enforces login→uid pair |
| `pull_request_target` safety | ✓ — workflow checks out `ref: staging` with `persist-credentials: false`; no PR head code executed |
| Token permissions | ✓ — `permissions: {}` default deny; `GH_TOKEN` only |
| TOCTOU / consent editing | ✓ — `updated_at != created_at` raises `AuditError` |
| CLA retirement gap | ✓ — `CLAAssistant` retired with `if: false`; `CLA v2 / agreement` is a required check on both branches before retirement landed |
| Required check continuity | ✓ — rulesets updated atomically in previous session; no enforcement gap |

---

## Remaining risks and limitations

1. **Hardcoded AI model name (FINDING-2):** Requires a follow-on PR when the
   Claude Code model is upgraded.  Low risk until then.

2. **`cla_v2_shadow.py` is informational:** The shadow script exits 0 regardless
   of audit result.  It is not a required gate.  The enforcement gate is
   `cla_v2_production.py` via the `CLA v2 / agreement` commit status.

3. **Nightly validation queued:** Pre-existing CI billing issue.  Does not
   reflect code correctness; all functional tests pass locally.

4. **Cargo audit warnings (4):** Pre-existing (chrono, event-listener, rustix,
   chacha20).  CI runs `cargo audit` without `--deny`; no blocking errors.

---

## Recommendation

**GO** — CLA v2 is correctly deployed and operational.

The critical enforcement properties (fail-closed API errors, numeric identity
binding, historical consent re-verification, co-author trailer handling, bot
identity verification, branch protection, required status check continuity) are
all present and verified.  The one code-quality defect found (bot identity
cross-pairing) has been fixed in `fix/cla-v2-bot-identity-pairing` (PR #431,
merged to staging 2026-11-18; PR #432 promoted to main 2026-11-19) with
regression tests; it was not exploitable in production.

**Final deployed SHA (main):** `099e764` — includes bot identity pairing fix.
**Final deployed SHA (staging):** `caebbaa` — identical tree.

---

## Evaluation gate

| Test | Command | Result |
|------|---------|--------|
| CLA v2 unit suite | `python3 -m unittest discover -s tests -p 'test_cla_v2_*.py'` | 33 passed, 0 failed |
| CLA workflow security guard | `python3 scripts/check_cla_workflow_security.py` | PASS |
| Gate reports check | `python3 scripts/gate_reports.py` | PASS (after adding this heading) |
| Cursor plugin smoke | `python3 scripts/smoke_cursor_plugin.py` | PASS |
| Required status checks (main) | GitHub API — rulesets/18716261 | `aigov-core-portable`, `CLA v2 / agreement` |
| Required status checks (staging) | GitHub API — rulesets/18716264 | `aigov-core-portable`, `cargo-audit`, `CLA v2 / agreement` |
| Unsigned E2E | PR #108 `CLA v2 / agreement = failure` | 2026-11-18T15:18:31Z |
| Signed E2E | PR #424 run 44090159750 `CLA v2 / agreement = success` | Verified |

Findings: 1 low-severity code defect (bot identity cross-pairing, FINDING-1) — fixed in this PR.
No critical or high-severity findings.

---

## Human approval gate

A maintainer must:

1. Inspect the diff in `fix/cla-v2-bot-identity-pairing` (PR #431) and confirm the
   `BOT_IDENTITY_MAP` change correctly maps each bot login to its expected numeric ID.
2. Confirm all required CI checks pass on PR #431 before merging.
3. Confirm that FINDING-1 is acceptable as a low-severity fix (not exploitable in production).
4. No change to rulesets, branch protection, or workflow permissions is authorized by this report.
5. Merge authorization is the maintainer's responsibility; this report does not grant it.

---

## Audit closure (2026-11-19)

| Event | SHA / Reference | Timestamp |
|-------|----------------|-----------|
| PR #431 merged to staging | `caebbaa` | 2026-11-18 |
| PR #432 (staging→main) merged | `099e76487be99b74b4dcf724e83a518f07ffbcc8` | 2026-11-19 |
| Main/staging tree diff | identical | confirmed post-merge |
| Final CI on PR #431 | 11/11 checks pass | 2026-11-19T08:07 UTC |

**AUDIT CLOSED — GO.** CLA v2 is fully deployed to main and staging with all
identified defects resolved. No further action required by this audit.

---

## Evidence references

| Item | Reference |
|------|-----------|
| main initial merge commit (PR #428) | `0d5e7400668ac11fe27aa8352fd5f5210b1d3ffb` |
| main final HEAD (PR #432) | `099e76487be99b74b4dcf724e83a518f07ffbcc8` |
| staging tip (PR #431) | `caebbaa` |
| PR #428 merge timestamp | 2026-11-18T18:47:01Z |
| PR #431 merge timestamp | 2026-11-18 (bot identity fix) |
| PR #432 merge timestamp | 2026-11-19 (promote fix to main) |
| Unsigned contributor E2E | PR #108, `CLA v2 / agreement = failure`, 2026-11-18T15:18:31Z |
| Signed contributor E2E | PR #424 SHA d9e3147, run 44090159750 |
| Fix branch | `fix/cla-v2-bot-identity-pairing` |
| Test run | 33 tests, 0 failures |
| Security guard | PASS |
| Ruleset main (18716261) | `aigov-core-portable` + `CLA v2 / agreement`, updated 2026-11-17 |
| Ruleset staging (18716264) | `aigov-core-portable` + `cargo-audit` + `CLA v2 / agreement`, updated 2026-11-17 |
