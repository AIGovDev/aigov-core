import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from verify_benchmark_ledger import verify


class LedgerVerificationTests(unittest.TestCase):
    def ledger(self, ids):
        previous = "GENESIS"
        lines = []
        for event_id in ids:
            event = json.dumps({"run_id": "run", "event_id": event_id})
            digest = hashlib.sha256((previous + "\n" + event).encode()).hexdigest()
            lines.append(json.dumps({"prev_hash": previous, "record_hash": digest,
                                     "event_json": event}) + "\n")
            previous = digest
        return "".join(lines)

    def check(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            path.write_text(data, encoding="utf-8")
            return verify(path, "run", 2)

    def test_valid(self):
        self.assertTrue(self.check(self.ledger(["run-0", "run-1"]))["verified"])

    def test_tampering(self):
        with self.assertRaises(ValueError):
            self.check(self.ledger(["run-0", "run-1"]).replace("run-0", "run-9"))

    def test_truncation(self):
        with self.assertRaises(ValueError):
            self.check(self.ledger(["run-0", "run-1"])[:-1])

    def test_duplicate(self):
        with self.assertRaises(ValueError):
            self.check(self.ledger(["run-0", "run-0"]))

    def test_missing(self):
        with self.assertRaises(ValueError):
            self.check(self.ledger(["run-0"]))


if __name__ == "__main__":
    unittest.main()
