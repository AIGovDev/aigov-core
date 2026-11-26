"""Regression tests: one mandatory CLA agreement status, no legacy CLA Assistant path.

Configuration-only checks (no network, no tokens). Regex parsing matches
scripts/check_cla_workflow_security.py so the tests run on the bare CI Python.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PRODUCTION = "cla-v2-production.yml"
CLA_WORKFLOWS = {
    PRODUCTION,
    "cla-v2-shadow.yml",
    "cla-v2-trusted-shadow.yml",
    "cla-security-guard.yml",
}
# Only the commit status published by scripts/cla_v2_production.py is required.
REQUIRED_CONTEXT = "CLA v2 / agreement"
# Visible job names. Anything else on a CLA workflow is a new check and must be reviewed.
EXPECTED_JOB_NAMES = {
    "CLA enforcement engine (posts agreement status)",
    "CLA independent audit (not a required status)",
    "CLA unit tests (not a required status)",
    "CLA workflow security guard (not a required status)",
}


def read(name):
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def strip_comments(text):
    return re.sub(r"(?m)^\s*#.*$", "", text)


def job_names(text):
    # Job-level names sit at exactly four spaces; step names are deeper and do not match.
    return re.findall(r"(?m)^    name: (.+?)\s*$", strip_comments(text))


class LegacyCLAAbsenceTests(unittest.TestCase):
    def test_legacy_cla_assistant_workflow_file_is_absent(self):
        self.assertFalse((WORKFLOWS / "cla.yml").exists(), "CLA Assistant workflow must not be reintroduced")

    def test_no_workflow_uses_cla_assistant_action_or_name(self):
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = strip_comments(path.read_text(encoding="utf-8"))
            for legacy in ("contributor-assistant", "cla-assistant", "CLA Assistant", "CLAAssistant"):
                self.assertNotIn(legacy, text, f"{path.name} references legacy CLA Assistant ({legacy})")

    def test_no_alternative_cla_workflows(self):
        found = {path.name for path in WORKFLOWS.glob("*cla*.yml")}
        self.assertEqual(found, CLA_WORKFLOWS, "CLA workflows changed; a new CLA system needs review")


class SingleAgreementGateTests(unittest.TestCase):
    def test_only_enforcement_workflow_writes_statuses(self):
        writers = sorted(
            name for name in CLA_WORKFLOWS
            if re.search(r"(?m)^\s*statuses:\s*write\s*$", read(name))
        )
        self.assertEqual(writers, [PRODUCTION])

    def test_required_context_is_published_only_by_enforcement_script(self):
        script = (ROOT / "scripts" / "cla_v2_production.py").read_text(encoding="utf-8")
        self.assertIn(f'CONTEXT = "{REQUIRED_CONTEXT}"', script)
        for name in CLA_WORKFLOWS - {PRODUCTION}:
            self.assertNotIn("/statuses/", strip_comments(read(name)), f"{name} must not post commit statuses")

    def test_only_enforcement_workflow_handles_signing_comments(self):
        triggers = {
            name for name in CLA_WORKFLOWS
            if re.search(r"(?m)^  issue_comment:\s*$", read(name))
        }
        self.assertEqual(triggers, {PRODUCTION})

    def test_enforcement_still_gated_by_staging_code_and_no_credentials(self):
        text = read(PRODUCTION)
        self.assertRegex(text, r"(?m)^\s*ref:\s*staging\s*$")
        self.assertIn("persist-credentials: false", text)
        self.assertNotIn("github.event.pull_request.head", text)


class PresentationTests(unittest.TestCase):
    def test_visible_job_names_are_exactly_the_reviewed_set(self):
        names = []
        for name in sorted(CLA_WORKFLOWS):
            names.extend(job_names(read(name)))
        self.assertEqual(sorted(names), sorted(EXPECTED_JOB_NAMES))
        self.assertEqual(len(names), len(set(names)), "CLA job names must be unique")

    def test_no_visible_job_uses_the_required_context_name(self):
        # The gate is the commit status; a job with the same display name would look like a second gate.
        for name in CLA_WORKFLOWS:
            for job in job_names(read(name)):
                self.assertNotEqual(job, REQUIRED_CONTEXT)


class TrustedAuditTests(unittest.TestCase):
    def test_trusted_audit_runs_only_protected_code_without_write_scopes(self):
        text = read("cla-v2-trusted-shadow.yml")
        self.assertRegex(text, r"(?m)^\s*ref:\s*staging\s*$")
        self.assertNotIn("github.event.pull_request.head", text)
        self.assertNotIn("statuses: write", text)
        self.assertIn("contents: read", text)


if __name__ == "__main__":
    unittest.main()
