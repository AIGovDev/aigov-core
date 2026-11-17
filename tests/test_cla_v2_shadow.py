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
        with patch.object(cla, "get", return_value={"user": {"login": "maintainer", "id": 100}, "commits": 1}), patch.object(cla, "contributors", return_value={"contributor": 42}), patch.object(cla, "signatures", return_value={("contributor", 42)}):
            self.assertTrue(cla.audit("owner/repo", 1)["approved"])

    def test_same_login_different_id_is_unsigned(self):
        with patch.object(cla, "contributors", return_value={"contributor": 99}), patch.object(cla, "signatures", return_value={("contributor", 42)}):
            self.assertEqual(cla.audit("owner/repo", 1)["unsigned"], ["contributor"])

    def test_multiple_authors_blocks_unsigned(self):
        with patch.object(cla, "contributors", return_value={"signed": 1, "unsigned": 2}), patch.object(cla, "signatures", return_value={("signed", 1)}):
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

    def test_api_error_fails_closed(self):
        with patch.object(cla, "contributors", side_effect=cla.AuditError("API unavailable")):
            with self.assertRaises(cla.AuditError):
                cla.audit("owner/repo", 3)

if __name__ == "__main__":
    unittest.main()
