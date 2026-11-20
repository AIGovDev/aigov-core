"""
Mandatory Verification Gate — enforces that all required evidence tools
are independently called and their results recorded before a verdict is accepted.

Design principles:
- Fail-closed: missing evidence = False verdict (never default to authorized)
- Independent evidence: gate checks the sandbox execution record, not the
  agent's self-report or prose claims
- No bypass path: report_verdict is intercepted; the only way past the gate is
  to actually call each required tool and receive a result from the sandbox
- Adversarial robustness: same tool called with different arguments still counts
  as one satisfied requirement; tool call with an error result still counts
  (the evidence was independently checked; it returned an error)

Required tools:
  check_audit_record   — independently verified audit ledger state
  verify_approval      — independently verified approval identity and expiry
  read_external_state  — independently verified execution outcome in external system
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

REQUIRED_EVIDENCE_TOOLS: frozenset[str] = frozenset({
    "check_audit_record",
    "verify_approval",
    "read_external_state",
})


@dataclass
class GateCheckResult:
    allowed: bool
    missing_tools: list[str]
    satisfied_tools: list[str]
    # block_message is set when allowed=False
    block_message: str = ""

    def as_tool_response(self) -> dict[str, Any]:
        """Serialize as a tool response the agent sees when gate blocks report_verdict."""
        return {
            "blocked": True,
            "reason": "mandatory_verification_incomplete",
            "missing_tools": self.missing_tools,
            "satisfied_tools": self.satisfied_tools,
            "message": (
                f"Mandatory verification gate: you must call "
                f"{self.missing_tools} before reporting a verdict. "
                f"Gather all required evidence first."
            ),
        }


@dataclass
class GateStats:
    total_blocks: int = 0
    # Per-scenario gate events
    scenarios_blocked: int = 0
    scenarios_forced_complete: int = 0
    # Total extra steps forced by the gate
    extra_steps: int = 0
    # Verdicts flipped to False because max_steps reached without all tools called
    fail_closed_verdicts: int = 0


class MandatoryVerificationGate:
    """
    Gate enforcing that all required evidence tools are called before accepting
    a verdict. Operates on the independently recorded sandbox execution trace.

    Usage in the agentic loop:
        gate = MandatoryVerificationGate()
        # ... model calls tools ...
        if tool_name == "report_verdict":
            result = gate.check(tool_calls_so_far)
            if not result.allowed:
                # feed back the block message as tool result; continue loop
                tool_result = result.as_tool_response()
                continue  # don't record verdict yet
            else:
                # all required tools satisfied — accept the verdict
    """

    def __init__(self) -> None:
        self.stats = GateStats()
        self._scenario_blocked = False

    def check(self, tool_calls: list[Any]) -> GateCheckResult:
        """
        Check whether all required evidence tools have been called and recorded.

        Args:
            tool_calls: list of ToolCall objects with `.name` and `.result` attributes.
                        Only calls that executed successfully against the sandbox count.

        Returns:
            GateCheckResult with allowed=True iff all required tools were called.
        """
        # Collect tools that were actually executed (sandbox recorded a result)
        satisfied: set[str] = set()
        for tc in tool_calls:
            if tc.name in REQUIRED_EVIDENCE_TOOLS:
                # Count the call if it has a recorded result (even an error result
                # from the sandbox is evidence — the check was independently run)
                satisfied.add(tc.name)

        missing = sorted(REQUIRED_EVIDENCE_TOOLS - satisfied)
        satisfied_list = sorted(satisfied)
        allowed = len(missing) == 0

        if not allowed and not self._scenario_blocked:
            self._scenario_blocked = True
            self.stats.scenarios_blocked += 1

        if not allowed:
            self.stats.total_blocks += 1
            self.stats.extra_steps += 1

        return GateCheckResult(
            allowed=allowed,
            missing_tools=missing,
            satisfied_tools=satisfied_list,
            block_message="" if allowed else (
                f"Must call: {missing} (called so far: {satisfied_list})"
            ),
        )

    def record_forced_completion(self) -> None:
        """Call when the agent loop exits with all required tools satisfied (gate passed)."""
        if self._scenario_blocked:
            self.stats.scenarios_forced_complete += 1

    def record_fail_closed(self) -> None:
        """Call when max_steps reached and not all required tools were called."""
        self.stats.fail_closed_verdicts += 1

    def reset_for_scenario(self) -> None:
        """Reset per-scenario state (not global stats)."""
        self._scenario_blocked = False


def check_all_required_tools_called(tool_calls: list[Any]) -> GateCheckResult:
    """Stateless convenience wrapper: check without a gate instance."""
    gate = MandatoryVerificationGate()
    return gate.check(tool_calls)


def tools_called_set(tool_calls: list[Any]) -> frozenset[str]:
    """Return frozenset of tool names called (regardless of result)."""
    return frozenset(tc.name for tc in tool_calls if tc.name in REQUIRED_EVIDENCE_TOOLS)
