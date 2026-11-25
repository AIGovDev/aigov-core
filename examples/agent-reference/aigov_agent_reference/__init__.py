"""AIGov Core reference integration for tool-using agents.

The enforcement primitives (policy records, replay protection, revocation, execution
tokens, and the sandboxed tool executor) live in ``benchmarks/agent-verification``.
This package composes them into a pre-execution gate and adds a human approval store,
a hash-chained decision log, and a smolagents integration.

Importing the package makes the benchmark modules importable by their bare names, as
the benchmark's own runners do.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
BENCH_DIR = REPO_ROOT / "benchmarks" / "agent-verification"

if str(BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(BENCH_DIR))
