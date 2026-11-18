"""First-party CLA v2 production security regression tests (offline)."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1] / "scripts"
import sys
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("cla_v2_production", ROOT / "cla_v2_production.py")
cla = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cla)

class ProductionTests(unittest.TestCase):
    def test_unsigned_contributor_blocks(self):
        pr = {"commits": 1, "user": {"login": "alice", "id": 123}}
        with patch.object(cla.legacy, "get", return_value=pr), patch.object(cla.legacy, "contributors", return_value={"alice": 123}), patch.object(cla.legacy, "signatures", return_value=set()), patch.object(cla, "verify_evidence", return_value=False):
            _, missing = cla.audit("owner/repo", 1)
            self.assertEqual(missing, ["alice"])

    def test_verified_contributor_approves(self):
        pr = {"commits": 1, "user": {"login": "alice", "id": 123}}
        with patch.object(cla.legacy, "get", return_value=pr), patch.object(cla.legacy, "contributors", return_value={"alice": 123}), patch.object(cla.legacy, "signatures", return_value=set()), patch.object(cla, "verify_evidence", return_value=True):
            self.assertEqual(cla.audit("owner/repo", 1)[1], [])

    def test_api_failure_posts_error_status(self):
        pr = {"head": {"sha": "a" * 40}}
        with patch.object(cla, "request", return_value=pr), patch.object(cla, "audit", side_effect=cla.legacy.AuditError("API unavailable")), patch.object(cla, "set_status") as status:
            self.assertFalse(cla.check("owner/repo", 1))
            self.assertEqual(status.call_args.args[2], "error")

    def test_wrong_bot_identity_not_exempt(self):
        pr = {"commits": 1, "user": {"login": "dependabot[bot]", "id": 999}}
        with patch.object(cla.legacy, "get", return_value=pr), patch.object(cla.legacy, "contributors", return_value={"dependabot[bot]": 999}), patch.object(cla.legacy, "signatures", return_value=set()), patch.object(cla, "verify_evidence", return_value=False):
            self.assertEqual(cla.audit("owner/repo", 1)[1], ["dependabot[bot]"])

    def test_bot_cross_paired_id_not_exempt(self):
        # dependabot[bot] with github-actions[bot]'s ID must not be exempted.
        actions_id = 41898282
        pr = {"commits": 1, "user": {"login": "dependabot[bot]", "id": actions_id}}
        with patch.object(cla.legacy, "get", return_value=pr), patch.object(cla.legacy, "contributors", return_value={"dependabot[bot]": actions_id}), patch.object(cla.legacy, "signatures", return_value=set()), patch.object(cla, "verify_evidence", return_value=False):
            self.assertEqual(cla.audit("owner/repo", 1)[1], ["dependabot[bot]"])

    def test_existing_signature_is_idempotent(self):
        with patch.object(cla, "request", side_effect=[
            {"id": 9, "user": {"login": "alice", "id": 42}, "body": cla.CONSENT,
             "created_at": "2026-11-17T00:00:00Z", "updated_at": "2026-11-17T00:00:00Z",
             "html_url": "https://github.com/owner/repo/pull/2#issuecomment-9"},
            {"number": 2}
        ]), patch.object(cla, "agreement_hash", return_value="a"*64), patch.object(cla, "load_evidence", return_value={"present": True}), patch.object(cla, "verify_evidence", return_value=True):
            cla.save_consent("owner/repo", {"issue": {"number": 2}, "comment": {"id": 9}})

    def test_concurrent_writer_conflict_requires_verified_winner(self):
        comment = {"id": 9, "user": {"login": "alice", "id": 42}, "body": cla.CONSENT,
                   "created_at": "2026-11-17T00:00:00Z", "updated_at": "2026-11-17T00:00:00Z",
                   "html_url": "https://github.com/owner/repo/pull/2#issuecomment-9"}
        def api(method, path, payload=None, missing_ok=False):
            if method == "PUT":
                raise cla.legacy.AuditError("409 conflict")
            return comment if "comments/" in path else {"number": 2}
        with patch.object(cla, "request", side_effect=api), patch.object(cla, "agreement_hash", return_value="a"*64), patch.object(cla, "load_evidence", return_value=None), patch.object(cla, "verify_evidence", return_value=False):
            with self.assertRaises(cla.legacy.AuditError):
                cla.save_consent("owner/repo", {"issue": {"number": 2}, "comment": {"id": 9}})

    def test_tampered_stored_evidence_rejected(self):
        import base64, json
        forged = {"schema": "aigov-cla-evidence-v1", "repo": "owner/repo",
                  "github_user_id": 42, "evidence_sha256": "0"*64}
        with patch.object(cla, "request", return_value={"encoding": "base64", "content": base64.b64encode(json.dumps(forged).encode()).decode()}):
            with self.assertRaises(cla.legacy.AuditError):
                cla.load_evidence("owner/repo", 42)

if __name__ == "__main__":
    unittest.main()
