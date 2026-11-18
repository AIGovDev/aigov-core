#!/usr/bin/env python3
"""Fail-closed static regression checks for privileged CLA workflow configuration.

Run: python3 scripts/check_cla_workflow_security.py
This is a configuration guard, not a substitute for action-code review.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
failures = []

def require(condition, label, message):
    if not condition:
        failures.append(f"{label}: {message}")


# ── CLA Assistant (legacy) ────────────────────────────────────────────────────
source = (ROOT / ".github/workflows/cla.yml").read_text(encoding="utf-8")

require(re.search(r"(?m)^permissions:\s*\{\}\s*$", source), "cla.yml", "Workflow must deny permissions by default")
require("pull_request_target:" in source and "issue_comment:" in source, "cla.yml", "Preserve CLA PR and signing triggers")
require("synchronize" in source and "opened" in source, "cla.yml", "Recheck new PRs and new commits")
require(re.search(r"uses:\s*contributor-assistant/github-action@[0-9a-f]{40}(?:\s|$)", source), "cla.yml", "Pin CLA action to full immutable SHA")
require("path-to-signatures: signatures/version1/cla.json" in source, "cla.yml", "Keep the existing signature store")
require("branch: cla-signatures" in source, "cla.yml", "Keep dedicated signature branch")
require(re.search(r"(?m)^\s*group:\s*cla-signatures-global\s*$", source), "cla.yml", "Serialize writes to shared CLA signature JSON across all PRs")
require("cancel-in-progress: false" in source, "cla.yml", "Do not cancel in-flight signature writes")
require("statuses: write" in source and "contents: write" in source, "cla.yml", "CLA needs status and signature writes")
require("allowlist: MonikaDvorackova,dependabot[bot],github-actions[bot]" in source, "cla.yml", "Do not broaden CLA exemptions")
require("github.event.comment.body == 'I have read the CLA Document and I hereby sign the CLA'" in source, "cla.yml", "Preserve exact signature consent")
require("github.event.comment.body == 'recheck'" in source, "cla.yml", "Preserve recheck command")
require(re.search(r"(?m)^\s+custom-pr-sign-comment:\s*I have read the CLA Document and I hereby sign the CLA\s*$", source), "cla.yml", "Require an active exact CLA acceptance input (not a comment)")
require(re.search(r"(?m)^\s+use-dco-flag:\s*false\s*$", source), "cla.yml", "Keep DCO mode disabled")
require("github.event.issue.pull_request" in source, "cla.yml", "Reject ordinary issue comments")
require("github.event_name == 'pull_request_target'" in source, "cla.yml", "Preserve PR validation")
require("secrets.GITHUB_TOKEN" in source, "cla.yml", "Use ephemeral GitHub token")
require(not re.search(r"(?im)^\s*(?:-|\s)*uses:\s*actions/checkout@", source), "cla.yml", "Never checkout PR code in privileged CLA workflow")
require(not re.search(r"(?im)^\s*(?:-|\s)*run:\s*", source), "cla.yml", "Never execute shell commands in privileged CLA workflow")
require("PERSONAL_ACCESS_TOKEN" not in re.sub(r"(?m)^\s*#.*$", "", source), "cla.yml", "Never add a long-lived PAT")
require("github.event.pull_request.head" not in source, "cla.yml", "Never interpolate untrusted PR head into privileged workflow")
require(re.search(r"(?m)^\s+if:\s+false\s*(?:#.*)?$", source), "cla.yml", "CLAAssistant job must be retired (if: false) — CLA v2 is the active enforcement")


# ── CLA v2 (first-party) ──────────────────────────────────────────────────────
v2 = (ROOT / ".github/workflows/cla-v2-production.yml").read_text(encoding="utf-8")
v2_no_comments = re.sub(r"(?m)^\s*#.*$", "", v2)

require(re.search(r"(?m)^permissions:\s*\{\}\s*$", v2), "cla-v2-production.yml", "Workflow must deny permissions by default")
require("pull_request_target:" in v2 and "issue_comment:" in v2, "cla-v2-production.yml", "Preserve CLA PR and signing triggers")
require(re.search(r"(?m)^\s*cancel-in-progress:\s*false\s*$", v2), "cla-v2-production.yml", "Do not cancel in-flight signature writes")
require("PERSONAL_ACCESS_TOKEN" not in v2_no_comments, "cla-v2-production.yml", "Never add a long-lived PAT")
require("github.event.pull_request.head" not in v2, "cla-v2-production.yml", "Never interpolate untrusted PR head")
require(re.search(r"(?m)^\s*ref:\s*(staging|main)\s*$", v2), "cla-v2-production.yml", "Must check out protected branch code (staging or main)")
require("persist-credentials: false" in v2, "cla-v2-production.yml", "Must not persist credentials after checkout")
require("${{ github.token }}" in v2 or "secrets.GITHUB_TOKEN" in v2, "cla-v2-production.yml", "Use ephemeral GitHub token only")
require(re.search(r"(?m)^\s*group:\s*cla-v2-signatures-global\s*$", v2), "cla-v2-production.yml", "Serialize writes with cla-v2-signatures-global concurrency group")


if failures:
    for issue in failures:
        print("FAIL:", issue)
    raise SystemExit(1)
print("PASS: CLA workflow security invariants (cla.yml + cla-v2-production.yml)")
