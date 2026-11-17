"""Unit tests for informational CLA v2 shadow verdicts."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "cla_v2_shadow.py"
spec = importlib.util.spec_from_file_location("cla_v2_shadow", SCRIPT)
cla = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cla)

class ShadowTests(unittest.TestCase):
    def test_signed_numeric_identity(self):
        with patch.object(cla, "get", return_value={"user": {"login": "contributor", "id": 42}, "commits": 1}), patch.object(cla, "contributors", return_value={"contributor": 42}), patch.object(cla, "signatures", return_value={("contributor", 42)}):
            self.assertTrue(cla.audit("owner/repo", 1)["approved"])

    def test_same_login_different_id_is_unsigned(self):
        with patch.object(cla, "get", return_value={"user": {"login": "contributor", "id": 99}, "commits": 1}), patch.object(cla, "contributors", return_value={"contributor": 99}), patch.object(cla, "signatures", return_value={("contributor", 42)}):
            self.assertEqual(cla.audit("owner/repo", 1)["unsigned"], ["contributor"])

    def test_multiple_authors_blocks_unsigned(self):
        with patch.object(cla, "get", return_value={"user": {"login": "signed", "id": 1}, "commits": 2}), patch.object(cla, "contributors", return_value={"signed": 1, "unsigned": 2}), patch.object(cla, "signatures", return_value={("signed", 1)}):
            self.assertFalse(cla.audit("owner/repo", 1)["approved"])

    def test_unsigned_pr_submitter_blocks(self):
        with patch.object(cla, "get", return_value={"user": {"login": "unsigned_submitter", "id": 99}, "commits": 1}), patch.object(cla, "contributors", return_value={"signed": 1}), patch.object(cla, "signatures", return_value={("signed", 1)}):
            self.assertEqual(cla.audit("owner/repo", 1)["unsigned"], ["unsigned_submitter"])

    def test_unmapped_submitter_fails_closed(self):
        with patch.object(cla, "get", return_value={"user": None, "commits": 1}), patch.object(cla, "contributors", return_value={"signed": 1}):
            with self.assertRaises(cla.AuditError):
                cla.audit("owner/repo", 1)

    def test_pagination_over_100(self):
        batch = [{"author": {"login": "a", "id": 1}}] * 100
        with patch.object(cla, "get", side_effect=[batch, [{"author": {"login": "b", "id": 2}}]]):
            self.assertEqual(cla.contributors("owner/repo", 3), {"a": 1, "b": 2})

    def test_commit_api_limit_fails_closed(self):
        with self.assertRaises(cla.AuditError):
            cla.contributors("owner/repo", 1, expected_count=251)

    def test_truncated_commit_list_fails_closed(self):
        with patch.object(cla, "pages", return_value=[{"author": {"login": "a", "id": 1}}]):
            with self.assertRaises(cla.AuditError):
                cla.contributors("owner/repo", 1, expected_count=2)

    def test_unmapped_author_fails_closed(self):
        with patch.object(cla, "pages", return_value=[{"author": None}]):
            with self.assertRaises(cla.AuditError):
                cla.contributors("owner/repo", 3)

    def test_signature_comment_mismatch_fails_closed(self):
        import base64
        import json
        record = {"name": "alice", "id": 42, "comment_id": 7, "created_at": "2026-01-01T00:00:00Z", "pullRequestNo": 2}
        payload = {"encoding": "base64", "content": base64.b64encode(json.dumps({"signedContributors": [record]}).encode()).decode()}
        wrong_comment = {"user": {"login": "alice", "id": 42}, "body": "not consent",
                         "created_at": record["created_at"], "updated_at": record["created_at"],
                         "html_url": "https://github.com/owner/repo/pull/2#issuecomment-7"}
        with patch.object(cla, "get", side_effect=[payload, wrong_comment]):
            with self.assertRaises(cla.AuditError):
                cla.signatures("owner/repo")

    def test_coauthor_trailer_requires_manual_review(self):
        commit = {"author": {"login": "alice", "id": 42},
                  "commit": {"message": "Change\n\nCo-authored-by: Bob <bob@example.com>"}}
        with patch.object(cla, "pages", return_value=[commit]):
            with self.assertRaises(cla.AuditError):
                cla.contributors("owner/repo", 1, expected_count=1)

    def test_maintainer_name_spoof_does_not_bypass(self):
        with patch.object(cla, "get", return_value={"user": {"login": "MonikaDvorackova", "id": 999}, "commits": 1}), patch.object(cla, "contributors", return_value={"MonikaDvorackova": 999}), patch.object(cla, "signatures", return_value=set()):
            self.assertEqual(cla.audit("owner/repo", 1)["unsigned"], ["MonikaDvorackova"])

    def test_indented_coauthor_trailer_fails_closed(self):
        commit = {"author": {"login": "alice", "id": 42},
                  "commit": {"message": "Change\\n  Co-authored-by: Bob <bob@example.com>"}}
        with patch.object(cla, "pages", return_value=[commit]):
            with self.assertRaises(cla.AuditError):
                cla.contributors("owner/repo", 1, expected_count=1)

    def test_bot_login_with_wrong_numeric_id_is_unsigned(self):
        with patch.object(cla, "get", return_value={"user": {"login": "dependabot[bot]", "id": 999}, "commits": 1}), patch.object(cla, "contributors", return_value={"dependabot[bot]": 999}), patch.object(cla, "signatures", return_value=set()):
            self.assertEqual(cla.audit("owner/repo", 1)["unsigned"], ["dependabot[bot]"])

    def test_api_error_fails_closed(self):
        with patch.object(cla, "get", return_value={"user": {"login": "alice", "id": 42}, "commits": 1}), patch.object(cla, "contributors", side_effect=cla.AuditError("API unavailable")):
            with self.assertRaises(cla.AuditError):
                cla.audit("owner/repo", 3)

if __name__ == "__main__":
    unittest.main()
