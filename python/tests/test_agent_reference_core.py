"""Trusted-execution regression tests for the agent reference.

Service-backed tests need ``GOVAI_TRUST_STATE`` to point at the state file written by a Core started with the
trusted-execution configuration (``examples/agent-reference/service/start_local_core.py`` or ``start_core_binary.py``).
Without it they skip, unless ``AIGOV_REF_REQUIRE_CORE=1`` is set. CI sets that flag, so a missing Core fails the run
rather than skipping it.

The tests that need no Core are: the fail-closed check against an address where nothing listens, the committed policy
check, the signature and domain checks on authorizations, and the atomic single-use reservation of the executor's store.
"""

from __future__ import annotations

import base64
import concurrent.futures
import copy
import json
import os
import sys
import uuid
import warnings
from pathlib import Path

import pytest
from nacl.signing import SigningKey

pytest.importorskip(
    "smolagents"
)  # the reference package is part of the agent-reference extra

REPO_ROOT = Path(__file__).resolve().parents[2]
REF_DIR = REPO_ROOT / "examples" / "agent-reference"
if str(REF_DIR) not in sys.path:
    sys.path.insert(0, str(REF_DIR))

warnings.filterwarnings("ignore", category=RuntimeWarning)

from aigov_agent_reference.core_gate import CoreClient
from aigov_agent_reference.core_policy import policy_document
from aigov_agent_reference.core_trusted import (
    ExecutionStore,
    Refused,
    verify_authorization_signature,
)
from aigov_agent_reference.gate import Decision
from aigov_agent_reference.trusted_benchmark import run_trusted_benchmark
from aigov_agent_reference.trusted_scenarios import SCENARIOS, make_trust

COMMITTED_POLICY = REF_DIR / "policies" / "core_policy.unsigned.json"
AUTH_DOMAIN = b"govai.execution_authorization.v1\x00"


def _state() -> dict:
    path = os.environ.get("GOVAI_TRUST_STATE")
    if not path or not Path(path).exists():
        if os.environ.get("AIGOV_REF_REQUIRE_CORE") == "1":
            pytest.fail(
                "AIGOV_REF_REQUIRE_CORE=1 but GOVAI_TRUST_STATE does not point at a state file"
            )
        pytest.skip(
            "GOVAI_TRUST_STATE not set; start a local trusted Core to run these tests"
        )
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------- no Core needed


def test_core_unreachable_fails_closed_and_runs_nothing(tmp_path):
    """A read through an address where nothing listens must not execute."""
    from aigov_agent_reference.core_trusted import AgentActor

    dead = CoreClient("http://127.0.0.1:9", "unused-key", timeout_sec=2.0)
    out = AgentActor(dead, "run-offline").read(
        "read_repo_metadata", {"repo_id": "acme-corp/offline"}, "tc"
    )
    assert out.decision == Decision.INDETERMINATE
    assert out.authorization is None


def test_committed_policy_matches_the_code():
    """The reviewed policy file is the policy the code produces."""
    assert json.loads(COMMITTED_POLICY.read_text()) == policy_document()


def _signed(payload: dict, key: SigningKey) -> dict:
    import base64 as b64

    from aigov_py.canonical_json import canonical_bytes

    sig = key.sign(AUTH_DOMAIN + canonical_bytes(payload)).signature
    return {
        "payload": payload,
        "signature": b64.b64encode(sig).decode("ascii"),
        "public_key": b64.b64encode(bytes(key.verify_key)).decode("ascii"),
    }


def _payload() -> dict:
    return {
        "schema": "govai.execution_authorization.v1",
        "authorization_id": "auth_test",
        "run_id": "run-1",
        "tool_name": "create_file",
        "args_binding_hash": "a" * 64,
        "policy_revision": "1",
        "executor_audience": "executor:ref",
        "approval_event_id": "human_approved-1",
        "consequential_record_hash": "b" * 64,
        "issued_at_utc": "2026-11-25T10:00:00+00:00",
        "expires_at_utc": "2026-11-25T10:01:00+00:00",
    }


def test_valid_authorization_verifies_against_the_pinned_key():
    key = SigningKey.generate()
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    verify_authorization_signature(_signed(_payload(), key), pub)


def test_modified_authorization_is_refused():
    key = SigningKey.generate()
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    signed = _signed(_payload(), key)
    signed["payload"]["tool_name"] = "request_deployment"
    with pytest.raises(Refused) as exc:
        verify_authorization_signature(signed, pub)
    assert exc.value.reason == "authorization_signature_invalid"


def test_authorization_from_another_key_is_refused():
    key = SigningKey.generate()
    other = SigningKey.generate()
    pub = base64.b64encode(bytes(other.verify_key)).decode("ascii")
    with pytest.raises(Refused) as exc:
        verify_authorization_signature(_signed(_payload(), key), pub)
    assert exc.value.reason == "authorization_signature_invalid"


def test_signature_over_the_bare_payload_without_the_domain_is_refused():
    """A signature made for another purpose (no domain prefix) must not verify as an authorization."""
    from aigov_py.canonical_json import canonical_bytes

    key = SigningKey.generate()
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    sig = key.sign(canonical_bytes(_payload())).signature
    forged = {
        "payload": _payload(),
        "signature": base64.b64encode(sig).decode("ascii"),
        "public_key": pub,
    }
    with pytest.raises(Refused):
        verify_authorization_signature(forged, pub)


def test_single_use_reservation_is_atomic_under_concurrency(tmp_path):
    store = ExecutionStore(tmp_path / "exec.sqlite")
    args = {
        "run_id": "run-r",
        "tool": "create_file",
        "digest": "d" * 64,
        "signed_json": "{}",
        "now": "2026-11-25T10:00:00+00:00",
    }

    def reserve(i: int) -> bool:
        return store.reserve(authorization_id="auth_one", **args)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(8)))
    assert results.count(True) == 1


# ---------------------------------------------------------------------------- live Core


@pytest.mark.parametrize(
    "scenario", SCENARIOS, ids=lambda fn: fn.__name__.removeprefix("scenario_")
)
def test_trusted_scenario(scenario, tmp_path):
    state = _state()
    result = scenario(make_trust(state["core_url"], state, tmp_path))
    failing = [(name, detail) for name, ok, detail in result.checks if not ok]
    assert result.passed, (
        f"{result.name} failed: checks={failing} evidence={result.evidence_problems}"
    )


def test_trusted_benchmark_invariants(tmp_path):
    state = _state()
    bench = run_trusted_benchmark(state["core_url"], state, 1, tmp_path)
    s = bench["summary"]
    assert s["unauthorized_executed"] == 0
    assert s["consequential_without_approval_executed"] == 0
    assert s["false_denials"] == 0
    assert s["authorized_completed"] == s["authorized_calls"]
    assert s["evidence_verified_cases"] == s["cases"], [
        c["problems"] for c in bench["cases"] if c["problems"]
    ]
    for key in (
        "authorization_latency_ms",
        "executor_verification_latency_ms",
        "end_to_end_latency_ms",
    ):
        assert s[key]["count"] > 0, key
        assert (
            s[key]["p50_ms"] is not None
            and s[key]["p95_ms"] is not None
            and s[key]["p99_ms"] is not None
        )
    assert bench["model_based_experiments"] == "not run"


def test_live_authorization_is_refused_when_its_payload_is_altered(tmp_path):
    """Against a live Core: a real authorization, altered, is refused by the executor."""
    state = _state()
    trust = make_trust(state["core_url"], state, tmp_path)
    from aigov_agent_reference.trusted_scenarios import REPO

    args = {"repo_id": REPO, "path": "docs/LIVE.md", "content": "live"}
    run = "run-live-" + uuid.uuid4().hex[:10]
    request = trust.agent(run).request_approval("create_file", args, "tc-live")
    decision = trust.maintainer.decide(
        run_id=run,
        request=request,
        tool="create_file",
        args=args,
        tool_call_id="tc-live",
        approve=True,
    )
    write = trust.agent(run).submit_write(
        "create_file", args, "tc-live", decision.event_id or ""
    )
    assert write.decision == Decision.ALLOW and write.authorization
    altered = copy.deepcopy(write.authorization)
    altered["payload"]["executor_audience"] = "executor:attacker"
    out = trust.executor.execute(
        run_id=run, tool="create_file", arguments=args, signed=altered
    )
    assert not out.executed and out.reason == "authorization_signature_invalid"
