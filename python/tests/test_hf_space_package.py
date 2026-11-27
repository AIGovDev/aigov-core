from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


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


if __name__ == "__main__":
    unittest.main()
