"""Service-backed regression tests: every decision is made by a running AIGov Core.

Needs ``GOVAI_CORE_URL`` and ``GOVAI_CORE_API_KEY`` pointing at a Core started with the signed reference
policy (see ``examples/agent-reference/service/start_local_core.py``, or the CI job that starts the
release binary). Without them the tests skip, unless ``AIGOV_REF_REQUIRE_CORE=1`` is set. CI sets that
flag, so a missing Core fails the run instead of skipping it.

The fail-closed test needs no Core at all. It uses an address where nothing listens.
"""

from __future__ import annotations

import json
import os
import sys
import warnings
from pathlib import Path

import pytest

pytest.importorskip(
    "smolagents"
)  # the reference package is part of the agent-reference extra

REPO_ROOT = Path(__file__).resolve().parents[2]
REF_DIR = REPO_ROOT / "examples" / "agent-reference"
if str(REF_DIR) not in sys.path:
    sys.path.insert(0, str(REF_DIR))

warnings.filterwarnings("ignore", category=RuntimeWarning)

from aigov_agent_reference.core_benchmark import run_core_benchmark
from aigov_agent_reference.core_gate import CoreClient
from aigov_agent_reference.core_policy import policy_document
from aigov_agent_reference.core_runner import unavailable_core
from aigov_agent_reference.core_scenarios import SCENARIOS
from aigov_agent_reference.gate import Decision

COMMITTED_POLICY = REF_DIR / "policies" / "core_policy.unsigned.json"


def _core() -> CoreClient:
    url = os.environ.get("GOVAI_CORE_URL")
    key = os.environ.get("GOVAI_CORE_API_KEY")
    if not url or not key:
        if os.environ.get("AIGOV_REF_REQUIRE_CORE") == "1":
            pytest.fail(
                "AIGOV_REF_REQUIRE_CORE=1 but GOVAI_CORE_URL / GOVAI_CORE_API_KEY are not set"
            )
        pytest.skip(
            "GOVAI_CORE_URL / GOVAI_CORE_API_KEY not set; start a local Core to run these tests"
        )
    return CoreClient(url, key)


def test_core_unreachable_fails_closed_and_runs_nothing(tmp_path):
    """No Core is needed. A call to an address where nothing listens must not execute."""
    from aigov_agent_reference.core_runner import CoreRunner

    runner = CoreRunner(unavailable_core())
    repo = "acme-corp/offline"
    out = runner.read(
        "run-offline", "read_repo_metadata", {"repo_id": repo}, repo, "tc-offline"
    )
    assert out.decision == Decision.INDETERMINATE
    assert not out.executed
    assert runner.sandbox.execution_history() == []


def test_committed_policy_matches_the_code():
    """The reviewed policy file is the policy the code produces."""
    assert json.loads(COMMITTED_POLICY.read_text()) == policy_document()


@pytest.mark.parametrize(
    "scenario", SCENARIOS, ids=lambda fn: fn.__name__.removeprefix("scenario_")
)
def test_core_scenario(scenario):
    result = scenario(_core())
    failing = [(name, detail) for name, ok, detail in result.checks if not ok]
    assert result.passed, (
        f"{result.name} failed: checks={failing} evidence={result.evidence_problems}"
    )


def test_core_benchmark_invariants():
    bench = run_core_benchmark(_core(), cases_per_category=1)
    s = bench["summary"]
    assert s["unauthorized_executed"] == 0
    assert s["consequential_without_approval_executed"] == 0
    assert s["false_denials"] == 0
    assert s["authorized_completed"] == s["authorized_calls"]
    assert s["evidence_verified_cases"] == s["cases"], [
        c["problems"] for c in bench["cases"] if c["problems"]
    ]
    lat = s["http_latency_ms"]["overall"]
    assert (
        lat["p50_ms"] is not None
        and lat["p95_ms"] is not None
        and lat["p99_ms"] is not None
    )
    assert bench["model_based_experiments"] == "not run"
