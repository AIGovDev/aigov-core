from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from public_launch_lib import evaluate_snapshot, load_snapshot, report_text


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples/launch/sample-standardization-readiness-snapshot.json"


class PublicLaunchToolTests(unittest.TestCase):
    def test_sample_snapshot_is_complete_and_report_is_deterministic(self) -> None:
        snapshot, errors = load_snapshot(SAMPLE)
        self.assertFalse(errors)
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        result = evaluate_snapshot(snapshot)
        self.assertTrue(result["ok"])
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["checks_passed"], 13)
        self.assertEqual(result["checks_total"], 13)
        self.assertEqual(report_text(result), report_text(result))
        self.assertIn("not adoption metrics", result["scope"])

    def test_open_blocking_issue_fails_closed(self) -> None:
        snapshot, errors = load_snapshot(SAMPLE)
        self.assertFalse(errors)
        assert snapshot is not None
        snapshot["risks"]["open_blocking_issues"] = 1
        result = evaluate_snapshot(snapshot)
        self.assertFalse(result["ok"])
        self.assertLess(result["score"], 100)
        self.assertTrue(any(
            check["name"] == "risks.open_blocking_issues" and not check["passed"]
            for check in result["checks"]
        ))

    def test_wrong_field_type_is_reported(self) -> None:
        snapshot, errors = load_snapshot(SAMPLE)
        self.assertFalse(errors)
        assert snapshot is not None
        snapshot["documentation"]["index_linked"] = "true"
        result = evaluate_snapshot(snapshot)
        self.assertFalse(result["ok"])
        self.assertIn("documentation.index_linked: expected a boolean", result["errors"])

    def test_unhashable_status_value_is_reported(self) -> None:
        snapshot, errors = load_snapshot(SAMPLE)
        self.assertFalse(errors)
        assert snapshot is not None
        snapshot["standardization"]["registry_alignment"] = []
        result = evaluate_snapshot(snapshot)
        self.assertFalse(result["ok"])
        self.assertTrue(
            any(
                "registry_alignment: expected one of" in error
                for error in result["errors"]
            )
        )

    def test_invalid_json_is_reported(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{nope", encoding="utf-8")
            snapshot, errors = load_snapshot(path)
        self.assertIsNone(snapshot)
        self.assertTrue(errors)
        self.assertTrue(errors[0].startswith("invalid JSON at line 1"))


if __name__ == "__main__":
    unittest.main()
