#!/usr/bin/env python3
"""Fail-closed static regression checks for privileged CLA workflow configuration.

Run: python3 scripts/check_cla_workflow_security.py
This is a configuration guard, not a substitute for action-code review.
"""
from pathlib import Path
import re

p = Path(__file__).resolve().parents[1] / ".github/workflows/cla.yml"
source = p.read_text(encoding="utf-8")
failures = []

def require(condition, message):
    if not condition:
        failures.append(message)

require(re.search(r"(?m)^permissions:\s*\{\}\s*$", source), "Workflow must deny permissions by default")
require("pull_request_target:" in source and "issue_comment:" in source, "Preserve CLA PR and signing triggers")
require("synchronize" in source and "opened" in source, "Recheck new PRs and new commits")
require(re.search(r"uses:\s*contributor-assistant/github-action@[0-9a-f]{40}(?:\s|$)", source), "Pin CLA action to full immutable SHA")
require("path-to-signatures: signatures/version1/cla.json" in source, "Keep the existing signature store")
require("branch: cla-signatures" in source, "Keep dedicated signature branch")
require(re.search(r"(?m)^\s*group:\s*cla-signatures-global\s*$", source), "Serialize writes to shared CLA signature JSON across all PRs")
require("cancel-in-progress: false" in source, "Do not cancel in-flight signature writes")
require("statuses: write" in source and "contents: write" in source, "CLA needs status and signature writes")
require("allowlist: MonikaDvorackova,dependabot[bot],github-actions[bot]" in source, "Do not broaden CLA exemptions")
require("github.event.comment.body == 'I have read the CLA Document and I hereby sign the CLA'" in source, "Preserve exact signature consent")
require("github.event.comment.body == 'recheck'" in source, "Preserve recheck command")
require("custom-pr-sign-comment: I have read the CLA Document and I hereby sign the CLA" in source, "Require exact CLA acceptance rather than permissive upstream regex")
require("github.event.issue.pull_request" in source, "Reject ordinary issue comments")
require("github.event_name == 'pull_request_target'" in source, "Preserve PR validation")
require("secrets.GITHUB_TOKEN" in source, "Use ephemeral GitHub token")
require(not re.search(r"(?im)^\s*(?:-|\s)*uses:\s*actions/checkout@", source), "Never checkout PR code in privileged CLA workflow")
require(not re.search(r"(?im)^\s*(?:-|\s)*run:\s*", source), "Never execute shell commands in privileged CLA workflow")
require("PERSONAL_ACCESS_TOKEN" not in re.sub(r"(?m)^\s*#.*$", "", source), "Never add a long-lived PAT")
require("github.event.pull_request.head" not in source, "Never interpolate untrusted PR head into privileged workflow")
if failures:
    for issue in failures:
        print("FAIL:", issue)
    raise SystemExit(1)
print("PASS: CLA workflow security invariants")
