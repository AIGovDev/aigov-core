"""smolagents integration: governed tools and a scripted model.

Only the tools built here are given to the agent. Each one sends its call through
``AgentGate.request``. The gate, not the framework, decides whether the sandbox runs it.

The agent uses ``ToolCallingAgent``, which passes structured JSON tool calls. It does not
use ``CodeAgent``, which executes model-written Python. Running model-generated code would
be a separate execution path that this gate does not control.

``ScriptedModel`` is a deterministic stand-in for the language model. It implements the
smolagents ``Model`` interface and emits tool calls from a fixed plan. A plan step may be
a function of the previous tool output, so a scenario can react to what a tool returned,
including attacker-controlled text. Results from this model show how the gate behaves.
They say nothing about how any real model behaves. Model-based experiments are not part of
this change.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from typing import Any, ClassVar

from smolagents import Tool, ToolCallingAgent
from smolagents.models import (
    ChatMessage,
    ChatMessageToolCall,
    ChatMessageToolCallFunction,
    MessageRole,
    Model,
)

from .gate import AgentGate, ToolCall

PlanStep = tuple[str, dict[str, Any]] | Callable[[str], tuple[str, dict[str, Any]]]


class Transcript:
    """Every gate decision made on behalf of the agent, in order, and the last tool output."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self.last_output: str = ""

    def add(self, tool: str, outcome: Any) -> str:
        self.entries.append(
            {
                "tool": tool,
                "decision": outcome.decision.value,
                "reason": outcome.reason,
                "executed": outcome.executed,
                "approval_id": outcome.approval_id,
            }
        )
        if outcome.executed:
            text = f"OK: {tool} executed. result={json.dumps(outcome.data, sort_keys=True, default=str)}"
        else:
            hint = f" approval_id={outcome.approval_id}" if outcome.approval_id else ""
            text = f"BLOCKED: {tool} was not executed ({outcome.decision.value}: {outcome.reason}).{hint}"
        self.last_output = text
        return text


def _gated(
    gate: AgentGate,
    transcript: Transcript,
    tool: str,
    principal: str,
    repo_id: str,
    arguments: dict[str, Any],
    approval_id: str | None,
) -> str:
    outcome = gate.request(
        ToolCall(
            tool_name=tool,
            arguments=arguments,
            principal=principal,
            repo_id=repo_id,
            approval_id=approval_id or None,
        )
    )
    return transcript.add(tool, outcome)


def build_governed_tools(
    gate: AgentGate, transcript: Transcript, principal: str
) -> list[Tool]:
    """Return every tool the agent can call. Each call is gated; the policy allowlist is enforced there."""

    class ReadRepoMetadata(Tool):
        name = "read_repo_metadata"
        description = "Read metadata of a repository, including its settings."
        inputs: ClassVar[dict[str, dict[str, Any]]] = {
            "repo_id": {
                "type": "string",
                "description": "Repository identifier, e.g. acme-corp/widgets",
            }
        }
        output_type = "string"

        def forward(self, repo_id: str) -> str:
            return _gated(
                gate,
                transcript,
                self.name,
                principal,
                repo_id,
                {"repo_id": repo_id},
                None,
            )

    class CreateFile(Tool):
        name = "create_file"
        description = "Create a file in a repository. Requires human approval."
        inputs: ClassVar[dict[str, dict[str, Any]]] = {
            "repo_id": {"type": "string", "description": "Repository identifier"},
            "path": {"type": "string", "description": "File path"},
            "content": {"type": "string", "description": "File content"},
            "approval_id": {
                "type": "string",
                "description": "Approval identifier, if one was granted",
                "nullable": True,
            },
        }
        output_type = "string"

        def forward(
            self, repo_id: str, path: str, content: str, approval_id: str | None = None
        ) -> str:
            args = {"repo_id": repo_id, "path": path, "content": content}
            return _gated(
                gate, transcript, self.name, principal, repo_id, args, approval_id
            )

    class OpenPullRequest(Tool):
        name = "open_pull_request"
        description = "Open a pull request. Requires human approval."
        inputs: ClassVar[dict[str, dict[str, Any]]] = {
            "repo_id": {"type": "string", "description": "Repository identifier"},
            "title": {"type": "string", "description": "Pull request title"},
            "description": {"type": "string", "description": "Pull request body"},
            "head": {"type": "string", "description": "Source branch"},
            "base": {"type": "string", "description": "Target branch"},
            "approval_id": {
                "type": "string",
                "description": "Approval identifier, if one was granted",
                "nullable": True,
            },
        }
        output_type = "string"

        def forward(
            self,
            repo_id: str,
            title: str,
            description: str,
            head: str,
            base: str,
            approval_id: str | None = None,
        ) -> str:
            args = {
                "repo_id": repo_id,
                "title": title,
                "description": description,
                "head": head,
                "base": base,
            }
            return _gated(
                gate, transcript, self.name, principal, repo_id, args, approval_id
            )

    class RequestDeployment(Tool):
        # Exposed on purpose: the gate, not the tool list, must refuse it. The policy allowlist
        # does not include it, so a prompt-injected call is denied before any token is issued.
        name = "request_deployment"
        description = "Request a deployment to an environment. Requires human approval."
        inputs: ClassVar[dict[str, dict[str, Any]]] = {
            "repo_id": {"type": "string", "description": "Repository identifier"},
            "environment": {"type": "string", "description": "Target environment"},
            "approval_id": {
                "type": "string",
                "description": "Approval identifier, if one was granted",
                "nullable": True,
            },
        }
        output_type = "string"

        def forward(
            self, repo_id: str, environment: str, approval_id: str | None = None
        ) -> str:
            args = {"repo_id": repo_id, "environment": environment}
            return _gated(
                gate, transcript, self.name, principal, repo_id, args, approval_id
            )

    catalog = {
        "read_repo_metadata": ReadRepoMetadata,
        "create_file": CreateFile,
        "open_pull_request": OpenPullRequest,
        "request_deployment": RequestDeployment,
    }
    # Expose every catalog tool. The policy allowlist is enforced by the gate on each call.
    return [cls() for cls in catalog.values()]


class ScriptedModel(Model):
    """Deterministic tool-calling model driven by a plan. Each call returns one tool call.

    A plan step that is a function receives the most recent tool output (from the
    transcript), so a scenario can act on what a tool returned.
    """

    def __init__(self, plan: list[PlanStep], transcript: Transcript) -> None:
        super().__init__(model_id="scripted-reference")
        self._plan = list(plan)
        self._transcript = transcript
        self._ids = itertools.count(1)

    def generate(
        self,
        messages,
        stop_sequences=None,
        response_format=None,
        tools_to_call_from=None,
        **kwargs,
    ):
        if not self._plan:
            raise RuntimeError("scripted plan exhausted without a final answer")
        step = self._plan.pop(0)
        name, arguments = step(self._transcript.last_output) if callable(step) else step
        call = ChatMessageToolCall(
            id=f"call_{next(self._ids)}",
            type="function",
            function=ChatMessageToolCallFunction(name=name, arguments=arguments),
        )
        return ChatMessage(role=MessageRole.ASSISTANT, content="", tool_calls=[call])


def run_agent(
    tools: list[Tool],
    plan: list[PlanStep],
    transcript: Transcript,
    task: str,
    max_steps: int,
) -> str:
    """Run a smolagents ToolCallingAgent with the given tools and scripted plan."""
    agent = ToolCallingAgent(
        tools=tools,
        model=ScriptedModel(plan, transcript),
        max_steps=max_steps,
        verbosity_level=0,
    )
    return str(agent.run(task))


FINAL = "final_answer"


def final(answer: str) -> tuple[str, dict[str, Any]]:
    return (FINAL, {"answer": answer})
