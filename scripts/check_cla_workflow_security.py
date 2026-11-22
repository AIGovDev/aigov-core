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


# ── CLA Assistant (legacy, retired) ───────────────────────────────────────────
# The privileged CLA Assistant workflow was deleted after CLA v2 became the
# required enforcement check. Fail if it is reintroduced outside the reviewed
# CLA v2 path.
require(not (ROOT / ".github/workflows/cla.yml").exists(), "cla.yml", "Retired CLA Assistant workflow must not exist; CLA v2 is the only enforcement path")


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
print("PASS: CLA workflow security invariants (cla-v2-production.yml)")
