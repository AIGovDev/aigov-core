"""
Agent-tool integration evaluation runner.

Measures actual tool-execution outcomes, not authorization labels alone.

Key metrics:
  unauthorized_executed   — unauthorized attempts that actually ran (security failure)
  authorized_executed     — authorized operations that actually ran (true positive)
  authorized_blocked      — authorized operations blocked (false rejection)
  unauthorized_blocked    — unauthorized operations blocked (true negative)
  FAR                     — false authorization rate (unauthorized_executed / N_negative)
  FRR                     — false rejection rate (authorized_blocked / N_positive)

Success criterion: unauthorized_executed == 0 (no security failures).

Usage:
    uv run python3 run_agent_integration.py [--out <path>] [--smoke]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_BENCH_DIR = Path(__file__).parent
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))

from agent_integration_scenarios import (  # noqa: E402
    CATEGORIES,
    DATASET_HASH,
    N_NEGATIVE,
    N_POSITIVE,
    POLICY_FIXTURE,
    SCENARIOS,
    AgentToolScenario,
    _NOW,
)
from replay_protection import ReplayRegistry  # noqa: E402
from revocation_list import RevocationList  # noqa: E402
from sandboxed_tools import SandboxedGitHubTools  # noqa: E402
from tool_gateway import ToolGateway, ToolRequest  # noqa: E402
from trusted_policy_provider import TrustedPolicyProvider  # noqa: E402


def run_scenario(
    scenario: AgentToolScenario,
    gateway: ToolGateway,
) -> dict:
    """Run one scenario and return a result trace."""
    req = ToolRequest(
        tool_name=scenario.tool_name,
        arguments=scenario.tool_arguments,
        proposal_id=scenario.proposal_id,
        approval_id=scenario.approval_id,
        record_id=scenario.record_id,
        action_type=scenario.action_type,
        resource_id=scenario.resource_id,
        tenant_id=scenario.tenant_id,
        dvo_state=scenario.to_dvo_state(),
        model_verdict=scenario.model_verdict,
        model_reasoning=f"model assessment for {scenario.scenario_id}",
    )
    result = gateway.request(req)

    executed = result.executed
    should = scenario.should_execute
    correct = executed == should

    return {
        "scenario_id": scenario.scenario_id,
        "category": scenario.category,
        "tool_name": scenario.tool_name,
        "should_execute": should,
        "executed": executed,
        "correct": correct,
        "decision": result.decision_record.decision.value,
        "failure_reasons": (
            result.decision_record.policy_failure_reasons
            + result.decision_record.indeterminate_reasons
            + result.decision_record.review_flags
        ),
        "execution_id": result.execution_id,
        "args_binding_hash": result.args_binding_hash,
        "enforcement_latency_ms": round(result.enforcement_latency_ms, 1),
        "capability_mismatch": result.capability_mismatch,
    }


def compute_metrics(traces: list[dict]) -> dict:
    """Compute security and availability metrics from execution traces."""
    total_positive = sum(1 for t in traces if t["should_execute"])
    total_negative = sum(1 for t in traces if not t["should_execute"])

    authorized_executed   = sum(1 for t in traces if t["should_execute"] and t["executed"])
    authorized_blocked    = sum(1 for t in traces if t["should_execute"] and not t["executed"])
    unauthorized_executed = sum(1 for t in traces if not t["should_execute"] and t["executed"])
    unauthorized_blocked  = sum(1 for t in traces if not t["should_execute"] and not t["executed"])

    far = unauthorized_executed / total_negative if total_negative > 0 else 0.0
    frr = authorized_blocked / total_positive if total_positive > 0 else 0.0

    precision = (
        authorized_executed / (authorized_executed + unauthorized_executed)
        if (authorized_executed + unauthorized_executed) > 0 else 0.0
    )
    recall = authorized_executed / total_positive if total_positive > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)

    # Decision distribution
    decisions = {}
    for t in traces:
        d = t["decision"]
        decisions[d] = decisions.get(d, 0) + 1

    # Category breakdown
    cats: dict[str, dict] = {}
    for t in traces:
        cat = t["category"]
        if cat not in cats:
            cats[cat] = {"total": 0, "correct": 0, "unauthorized_executed": 0, "authorized_blocked": 0}
        cats[cat]["total"] += 1
        if t["correct"]:
            cats[cat]["correct"] += 1
        if not t["should_execute"] and t["executed"]:
            cats[cat]["unauthorized_executed"] += 1
        if t["should_execute"] and not t["executed"]:
            cats[cat]["authorized_blocked"] += 1

    latencies = [t["enforcement_latency_ms"] for t in traces if t["enforcement_latency_ms"] > 0]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    p95_latency = sorted(latencies)[int(len(latencies) * 0.95)] if len(latencies) > 10 else max(latencies) if latencies else 0.0

    return {
        "total": len(traces),
        "total_positive": total_positive,
        "total_negative": total_negative,
        "authorized_executed": authorized_executed,
        "authorized_blocked": authorized_blocked,
        "unauthorized_executed": unauthorized_executed,
        "unauthorized_blocked": unauthorized_blocked,
        "far": round(far, 4),
        "frr": round(frr, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "decisions": decisions,
        "categories": cats,
        "avg_enforcement_latency_ms": round(avg_latency, 1),
        "p95_enforcement_latency_ms": round(p95_latency, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent-tool integration evaluation")
    parser.add_argument("--out", default=None, help="Output JSON path")
    parser.add_argument("--smoke", action="store_true", help="Run first 5 scenarios only")
    args = parser.parse_args()

    scenarios = SCENARIOS[:5] if args.smoke else SCENARIOS

    print(f"Dataset hash: {DATASET_HASH}")
    print(f"Running {len(scenarios)} scenarios (positive={N_POSITIVE}, negative={N_NEGATIVE})")
    print("-" * 70)

    # Build shared infrastructure
    policy_provider = TrustedPolicyProvider(POLICY_FIXTURE)
    tools = SandboxedGitHubTools()
    replay_registry = ReplayRegistry()
    revocation_list = RevocationList()

    # Pre-revoke appr-j-pr02-revoked for scenario J-PR02
    revocation_list.revoke(
        approval_id="appr-j-pr02-revoked",
        tenant_id="alpha-corp",
        reason="revoked_for_integration_test",
    )

    gateway = ToolGateway(
        policy_provider=policy_provider,
        tools=tools,
        replay_registry=replay_registry,
        revocation_list=revocation_list,
        current_time=_NOW,
    )

    traces = []
    t_start = time.perf_counter()

    for i, scenario in enumerate(scenarios, 1):
        trace = run_scenario(scenario, gateway)
        traces.append(trace)

        mark = "✓" if trace["correct"] else "✗"
        sec = " ← SECURITY FAILURE" if (not scenario.should_execute and trace["executed"]) else ""
        print(f"  [{i:02d}/{len(scenarios)}] {scenario.scenario_id:12s} "
              f"exec={str(trace['executed']):5s} "
              f"decision={trace['decision']:15s} "
              f"{mark}{sec}")

    total_elapsed_ms = (time.perf_counter() - t_start) * 1000
    metrics = compute_metrics(traces)
    metrics["total_elapsed_ms"] = round(total_elapsed_ms, 1)

    # --- Security summary ---
    print()
    print("=" * 70)
    print("INTEGRATION EVALUATION RESULTS")
    print("=" * 70)
    print(f"  Unauthorized operations executed (must be 0): {metrics['unauthorized_executed']}")
    print(f"  Authorized operations executed:               {metrics['authorized_executed']}")
    print(f"  Authorized operations blocked (false reject): {metrics['authorized_blocked']}")
    print(f"  FAR (false authorization rate):               {metrics['far']:.4f}")
    print(f"  FRR (false rejection rate):                   {metrics['frr']:.4f}")
    print(f"  F1:                                           {metrics['f1']:.4f}")
    print(f"  Avg enforcement latency:                      {metrics['avg_enforcement_latency_ms']:.1f} ms")
    print()
    print("  Category breakdown:")
    for cat in CATEGORIES:
        if cat in metrics["categories"]:
            c = metrics["categories"][cat]
            sec_fail = f"  ← {c['unauthorized_executed']} SECURITY FAIL" if c["unauthorized_executed"] > 0 else ""
            avail_cost = f"  (avail cost: {c['authorized_blocked']})" if c["authorized_blocked"] > 0 else ""
            print(f"    {cat:35s} total={c['total']:2d}  correct={c['correct']:2d}{sec_fail}{avail_cost}")

    if metrics["unauthorized_executed"] == 0:
        print()
        print("SECURITY VERDICT: PASS — zero unauthorized tool executions")
    else:
        print()
        print(f"SECURITY VERDICT: FAIL — {metrics['unauthorized_executed']} unauthorized execution(s)")

    print("=" * 70)

    # --- Write output ---
    output = {
        "dataset_hash": DATASET_HASH,
        "n_scenarios": len(scenarios),
        "n_positive": N_POSITIVE if not args.smoke else sum(1 for s in scenarios if s.should_execute),
        "n_negative": N_NEGATIVE if not args.smoke else sum(1 for s in scenarios if not s.should_execute),
        "metrics": metrics,
        "traces": traces,
        "execution_history": [
            {
                "execution_id": r.execution_id,
                "tool_name": r.tool_name,
                "authorized": r.authorized,
                "token_verified": r.token_verified,
                "decision": r.decision,
                "tenant_id": r.tenant_id,
                "args_binding_hash": r.args_binding_hash,
                "block_reason": r.block_reason,
            }
            for r in tools.execution_history()
        ],
    }

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(output, indent=2))
        print(f"\nResults written to {args.out}")


if __name__ == "__main__":
    main()
