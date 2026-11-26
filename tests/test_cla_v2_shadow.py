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

    def test_exact_ai_attribution_does_not_create_human_cla_signer(self):
        commit = {"author": {"login": "MonikaDvorackova", "id": 95243292},
                  "commit": {"message": "Change\n\nCo-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>"}}
        with patch.object(cla, "pages", return_value=[commit]):
            self.assertEqual(cla.contributors("owner/repo", 1, expected_count=1),
                             {"MonikaDvorackova": 95243292})

    def test_ai_attribution_plus_human_coauthor_still_blocks(self):
        commit = {"author": {"login": "alice", "id": 42},
                  "commit": {"message": "Change\n\nCo-authored-by: Claude Sonnet 4.6 <noreply@anthropic.com>\nCo-authored-by: Bob <bob@example.com>"}}
        with patch.object(cla, "pages", return_value=[commit]):
            with self.assertRaises(cla.AuditError):
                cla.contributors("owner/repo", 1, expected_count=1)

    def test_lookalike_ai_attribution_still_blocks(self):
        commit = {"author": {"login": "alice", "id": 42},
                  "commit": {"message": "Change\n\nCo-authored-by: Claude Sonnet 4.6 <attacker@example.com>"}}
        with patch.object(cla, "pages", return_value=[commit]):
            with self.assertRaises(cla.AuditError):
                cla.contributors("owner/repo", 1, expected_count=1)

    def test_maintainer_name_spoof_does_not_bypass(self):
        with patch.object(cla, "get", return_value={"user": {"login": "MonikaDvorackova", "id": 999}, "commits": 1}), patch.object(cla, "contributors", return_value={"MonikaDvorackova": 999}), patch.object(cla, "signatures", return_value=set()):
            self.assertEqual(cla.audit("owner/repo", 1)["unsigned"], ["MonikaDvorackova"])

    def test_indented_coauthor_trailer_fails_closed(self):
        commit = {"author": {"login": "alice", "id": 42},
                  "commit": {"message": "Change\n  Co-authored-by: Bob <bob@example.com>"}}
        with patch.object(cla, "pages", return_value=[commit]):
            with self.assertRaises(cla.AuditError):
                cla.contributors("owner/repo", 1, expected_count=1)

    def test_bot_login_with_wrong_numeric_id_is_unsigned(self):
        with patch.object(cla, "get", return_value={"user": {"login": "dependabot[bot]", "id": 999}, "commits": 1}), patch.object(cla, "contributors", return_value={"dependabot[bot]": 999}), patch.object(cla, "signatures", return_value=set()):
            self.assertEqual(cla.audit("owner/repo", 1)["unsigned"], ["dependabot[bot]"])

    def test_bot_cross_paired_id_is_unsigned(self):
        # dependabot[bot] with github-actions[bot]'s ID must not be exempted.
        # Independent set membership (login in BOT_SET and uid in ID_SET) would
        # incorrectly exempt this pair; a dict lookup does not.
        actions_id = 41898282  # github-actions[bot]'s ID, NOT dependabot's
        with patch.object(cla, "get", return_value={"user": {"login": "dependabot[bot]", "id": actions_id}, "commits": 1}), patch.object(cla, "contributors", return_value={"dependabot[bot]": actions_id}), patch.object(cla, "signatures", return_value=set()):
            self.assertEqual(cla.audit("owner/repo", 1)["unsigned"], ["dependabot[bot]"])

    def test_correct_bot_identity_is_exempted(self):
        with patch.object(cla, "get", return_value={"user": {"login": "dependabot[bot]", "id": 49699333}, "commits": 1}), patch.object(cla, "contributors", return_value={"dependabot[bot]": 49699333}), patch.object(cla, "signatures", return_value=set()):
            self.assertEqual(cla.audit("owner/repo", 1)["unsigned"], [])

    def test_api_error_fails_closed(self):
        with patch.object(cla, "get", return_value={"user": {"login": "alice", "id": 42}, "commits": 1}), patch.object(cla, "contributors", side_effect=cla.AuditError("API unavailable")):
            with self.assertRaises(cla.AuditError):
                cla.audit("owner/repo", 3)

class AiAttributionPolicyTests(unittest.TestCase):
    """Exact-match AI attribution policy: positive and negative cases."""

    def _run(self, message, login="alice", uid=42):
        commit = {"author": {"login": login, "id": uid}, "commit": {"message": f"Change\n\n{message}"}}
        with patch.object(cla, "pages", return_value=[commit]):
            return cla.contributors("owner/repo", 1, expected_count=1)

    def test_exact_haiku_attribution_accepted_in_both_casings(self):
        for trailer in ("Co-authored-by: Claude Haiku 5.5 <noreply@anthropic.com>",
                        "Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>"):
            with self.subTest(trailer=trailer):
                self.assertEqual(self._run(trailer, "MonikaDvorackova", 95243292),
                                 {"MonikaDvorackova": 95243292})

    def test_haiku_attribution_does_not_sign_for_author(self):
        # The AI trailer is metadata. The human author still needs a signature.
        with patch.object(cla, "get", return_value={"user": {"login": "alice", "id": 42}, "commits": 1}), \
             patch.object(cla, "contributors", return_value=self._run("Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>")), \
             patch.object(cla, "signatures", return_value=set()):
            self.assertEqual(cla.audit("owner/repo", 1)["unsigned"], ["alice"])

    def test_negative_cases_fail_closed(self):
        rejected = [
            "Co-authored-by: Claude Haiku 5.5 <attacker@example.com>",        # spoofed address
            "Co-authored-by: Claude Haiku 5.5 <noreply@anthropic.com.evil.test>",  # lookalike domain
            "Co-authored-by: Claude Haiku 5.6 <noreply@anthropic.com>",       # unknown version
            "Co-authored-by: Claude Haiku 5 <noreply@anthropic.com>",         # truncated version
            "Co-authored-by: Claude Haiku 5.5 (fast) <noreply@anthropic.com>",  # variant suffix
            "Co-authored-by: Claude Opus 5.5 <noreply@anthropic.com>",        # other model family
            "Co-authored-by: Claude Haiku <noreply@anthropic.com>",           # family without version
            "Co-authored-by:Claude Haiku 5.5 <noreply@anthropic.com>",        # malformed: missing space
            "CO-AUTHORED-BY: Claude Haiku 5.5 <noreply@anthropic.com>",       # unlisted casing
            "Co-authored-by: Claude Haiku 5.5 <noreply@anthropic.com> extra", # trailing text
            "Co-authored-by: Claude Haiku 5.5",                               # missing address
        ]
        for trailer in rejected:
            with self.subTest(trailer=trailer):
                with self.assertRaises(cla.AuditError):
                    self._run(trailer)

    def test_haiku_plus_human_coauthor_still_blocks(self):
        message = ("Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>\n"
                   "Co-authored-by: Bob <bob@example.com>")
        with self.assertRaises(cla.AuditError):
            self._run(message)

    def test_haiku_trailer_spoofed_as_human_author_still_needs_signature(self):
        # A human-looking author with the AI trailer is not exempted, and the
        # trailer does not create a signer for anyone else.
        self.assertEqual(self._run("Co-authored-by: Claude Haiku 5.5 <noreply@anthropic.com>", "bob", 7), {"bob": 7})


if __name__ == "__main__":
    unittest.main()
