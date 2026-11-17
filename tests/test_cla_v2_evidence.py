"""Security regressions for CLA evidence builder."""
import importlib.util
import pathlib
import unittest

path = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "cla_v2_evidence.py"
spec = importlib.util.spec_from_file_location("cla_v2_evidence", path)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)

class EvidenceTests(unittest.TestCase):
    def event(self):
        return {"issue": {"number": 184, "pull_request": {"url": "x"}},
                "comment": {"id": 5253888750, "body": evidence.CONSENT,
                            "created_at": "2026-11-17T08:00:00Z",
                            "updated_at": "2026-11-17T08:00:00Z",
                            "html_url": "https://github.com/AIGovDev/aigov-core/pull/184#issuecomment-5253888750",
                            "user": {"login": "alice", "id": 42}}}
    def test_valid_deterministic_record(self):
        event = self.event()
        a = evidence.record(event, "AIGovDev/aigov-core", "a" * 64)
        self.assertEqual(a, evidence.record(event, "AIGovDev/aigov-core", "a" * 64))
        self.assertEqual(a["github_user_id"], 42)
    def test_wrong_consent_rejected(self):
        event = self.event()
        event["comment"]["body"] += " extra"
        with self.assertRaises(evidence.EvidenceError):
            evidence.record(event, "AIGovDev/aigov-core", "a" * 64)
    def test_edited_consent_rejected(self):
        event = self.event()
        event["comment"]["updated_at"] = "2026-11-17T09:00:00Z"
        with self.assertRaises(evidence.EvidenceError):
            evidence.record(event, "AIGovDev/aigov-core", "a" * 64)
    def test_non_pr_comment_rejected(self):
        event = self.event()
        del event["issue"]["pull_request"]
        with self.assertRaises(evidence.EvidenceError):
            evidence.record(event, "AIGovDev/aigov-core", "a" * 64)
    def test_spoofed_source_rejected(self):
        event = self.event()
        event["comment"]["html_url"] = "https://evil.example"
        with self.assertRaises(evidence.EvidenceError):
            evidence.record(event, "AIGovDev/aigov-core", "a" * 64)
