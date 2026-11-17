#!/usr/bin/env python3
"""Fail-closed static regression checks for privileged CLA workflow configuration.

Run: python3 scripts/check_cla_workflow_security.py
This is a configuration guard, not a substitute for action-code review.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
failures = []

def require(condition, message):
    if not condition:
        failures.append(message)

# ── Legacy CLA Assistant (cla.yml) ──────────────────────────────────────────
# cla.yml is retired; it must be present but have its job disabled with
# `if: false` so the action never fires. The historical content invariants
# (allowlist, consent phrase, etc.) still apply to prevent silent re-enablement.
legacy_path = ROOT / ".github/workflows/cla.yml"
source = legacy_path.read_text(encoding="utf-8")

require(re.search(r"(?m)^permissions:\s*\{\}\s*$", source), "cla.yml: Workflow must deny permissions by default")
require("pull_request_target:" in source and "issue_comment:" in source, "cla.yml: Preserve CLA PR and signing triggers")
require("synchronize" in source and "opened" in source, "cla.yml: Recheck new PRs and new commits")
require(re.search(r"uses:\s*contributor-assistant/github-action@[0-9a-f]{40}(?:\s|$)", source), "cla.yml: Pin CLA action to full immutable SHA")
require("path-to-signatures: signatures/version1/cla.json" in source, "cla.yml: Keep the existing signature store")
require("branch: cla-signatures" in source, "cla.yml: Keep dedicated signature branch")
require(re.search(r"(?m)^\s*group:\s*cla-signatures-global\s*$", source), "cla.yml: Serialize writes to shared CLA signature JSON across all PRs")
require("cancel-in-progress: false" in source, "cla.yml: Do not cancel in-flight signature writes")
require("statuses: write" in source and "contents: write" in source, "cla.yml: CLA needs status and signature writes")
require("allowlist: MonikaDvorackova,dependabot[bot],github-actions[bot]" in source, "cla.yml: Do not broaden CLA exemptions")
require("github.event.comment.body == 'I have read the CLA Document and I hereby sign the CLA'" in source, "cla.yml: Preserve exact signature consent")
require("github.event.comment.body == 'recheck'" in source, "cla.yml: Preserve recheck command")
require(re.search(r"(?m)^\s+custom-pr-sign-comment:\s*I have read the CLA Document and I hereby sign the CLA\s*$", source), "cla.yml: Require an active exact CLA acceptance input (not a comment)")
require(re.search(r"(?m)^\s+use-dco-flag:\s*false\s*$", source), "cla.yml: Keep DCO mode disabled")
require("github.event.issue.pull_request" in source, "cla.yml: Reject ordinary issue comments")
require("github.event_name == 'pull_request_target'" in source, "cla.yml: Preserve PR validation")
require("secrets.GITHUB_TOKEN" in source, "cla.yml: Use ephemeral GitHub token")
require(not re.search(r"(?im)^\s*(?:-|\s)*uses:\s*actions/checkout@", source), "cla.yml: Never checkout PR code in privileged CLA workflow")
require(not re.search(r"(?im)^\s*(?:-|\s)*run:\s*", source), "cla.yml: Never execute shell commands in privileged CLA workflow")
require("PERSONAL_ACCESS_TOKEN" not in re.sub(r"(?m)^\s*#.*$", "", source), "cla.yml: Never add a long-lived PAT")
require("github.event.pull_request.head" not in source, "cla.yml: Never interpolate untrusted PR head into privileged workflow")
# Legacy workflow must be retired (job disabled) to prevent silent re-enablement.
require(re.search(r"(?m)^\s+if:\s+false\s*(?:#.*)?$", source), "cla.yml: Retired workflow job must have 'if: false' to prevent re-enablement")

# ── First-party CLA v2 production (cla-v2-production.yml) ───────────────────
v2_path = ROOT / ".github/workflows/cla-v2-production.yml"
v2 = v2_path.read_text(encoding="utf-8")

require("pull_request_target:" in v2 and "issue_comment:" in v2, "cla-v2-production.yml: Must handle PR and comment events")
require(re.search(r"(?m)^\s*cancel-in-progress:\s*false\s*$", v2), "cla-v2-production.yml: Must not cancel in-flight signature writes")
require("PERSONAL_ACCESS_TOKEN" not in re.sub(r"(?m)^\s*#.*$", "", v2), "cla-v2-production.yml: Never add a long-lived PAT")
require("github.event.pull_request.head" not in v2, "cla-v2-production.yml: Never interpolate untrusted PR head")
# The checkout must be pinned to the protected branch, never the PR head.
require(re.search(r"ref:\s*(main|staging)", v2), "cla-v2-production.yml: Checkout must pin to a protected branch ref, never PR head")
require("persist-credentials: false" in v2, "cla-v2-production.yml: Must not persist credentials in checkout")
# GitHub token only; no PAT or long-lived credential.
require("${{ github.token }}" in v2 or "secrets.GITHUB_TOKEN" in v2, "cla-v2-production.yml: Must use ephemeral GitHub token")
require(re.search(r"(?m)^\s*group:\s*cla-v2-signatures-global\s*$", v2), "cla-v2-production.yml: Must serialize all CLA writes with global concurrency group")

if failures:
    for issue in failures:
        print("FAIL:", issue)
    raise SystemExit(1)
print("PASS: CLA workflow security invariants")
