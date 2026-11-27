from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from generate_hf_space_sample import OUTPUT, build_sample


class HuggingFaceStaticSpaceTests(unittest.TestCase):
    def test_space_package_is_synchronized_and_passes_safety_checks(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/prepare_hf_space.py"), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_viewer_security_contract(self):
        source = (ROOT / "examples/reconstructible-agent-demo/viewer/index.html").read_text(
            encoding="utf-8"
        )
        lowered = source.lower()
        self.assertIn("file.size > max_file_bytes", lowered)
        self.assertIn("new textencoder().encode(text).bytelength > max_file_bytes", lowered)
        self.assertIn('url.origin !== location.origin', source)
        self.assertIn('new Set(["http:", "https:"])', source)
        self.assertIn('redirect: "error"', source)
        self.assertIn('credentials: "omit"', source)
        self.assertIn(".textContent =", source)
        self.assertIn("document.createTextNode", source)
        for unsafe_sink in ("innerhtml", "outerhtml", "insertadjacenthtml"):
            self.assertNotIn(unsafe_sink, lowered)

    def test_bundled_sample_is_reproducible_and_synthetic(self):
        import json

        sample = json.loads(OUTPUT.read_text(encoding="utf-8"))
        self.assertEqual(sample, build_sample())
        self.assertIn("Synthetic demonstration data", sample["sample_notice"])
        self.assertEqual(sample["evidence_hashes"]["log_chain"][0]["prev_hash"], "GENESIS")


if __name__ == "__main__":
    unittest.main()
