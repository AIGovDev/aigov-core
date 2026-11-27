"""Run against release Core and PostgreSQL; no model API or remote code."""

import argparse
import json
import tempfile
from pathlib import Path

from smolagents import ToolCallingAgent
from smolagents.models import (
    ChatMessage,
    ChatMessageToolCall,
    ChatMessageToolCallFunction,
    MessageRole,
    Model,
)

from aigov_py.runtime.adapters.smolagents import (
    invoke_registered_tool,
    make_smolagents_tool,
    take_pending_approval,
)
from aigov_py.trusted import (
    Integration,
    IntegrationConfig,
    Tool,
    migrate,
    start_core,
    stop_core,
)


class ScriptedModel(Model):
    """Local deterministic model stub; it makes no API calls or model downloads."""

    def __init__(self, plan):
        super().__init__(model_id="aigov-smolagents-integration-test")
        self.plan = list(plan)
        self.inputs = []

    def generate(
        self,
        messages,
        stop_sequences=None,
        response_format=None,
        tools_to_call_from=None,
        **kwargs,
    ):
        self.inputs.extend(str(message) for message in messages)
        name, arguments = self.plan.pop(0)
        call = ChatMessageToolCall(
            id=f"test-call-{len(self.plan)}",
            type="function",
            function=ChatMessageToolCallFunction(name=name, arguments=arguments),
        )
        return ChatMessage(
            role=MessageRole.ASSISTANT,
            content="",
            tool_calls=[call],
        )


def run_agent(tools, plan, task):
    model = ScriptedModel(plan)
    agent = ToolCallingAgent(
        tools=tools,
        model=model,
        max_steps=len(plan) + 1,
        verbosity_level=0,
    )
    return agent.run(task), model


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--database-url", required=True)
    args = parser.parse_args()
    config = IntegrationConfig(
        tenant="smolagents-test",
        policy_id="smolagents-test",
        tools=(
            Tool("read_order", "order:read", "read", resource_key="order_id"),
            Tool("refund_order", "order:refund", "write", resource_key="order_id"),
        ),
        approvers={"lead": "lead@example.test"},
        agent_identity="agent:smol",
        executor_identity="executor:smol",
    )
    performed = []

    def perform(tool, arguments, execution_id):
        performed.append((tool, arguments))
        return {"success": True, "data": {"ok": True}}

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "core"
        running, prefix = start_core(
            config,
            root,
            port=18588,
            mode="binary",
            binary=args.binary,
            database_url=args.database_url,
        )
        try:
            state = json.loads(running.state_file.read_text())
            work = root / "run"
            work.mkdir(exist_ok=True)
            migrate(work / "executor.sqlite", backup_dir=None)
            integration = Integration(config, running.core_url, state, work, perform)
            inputs = {"order_id": {"type": "string", "description": "Order identifier"}}
            read = make_smolagents_tool(
                integration.agent,
                integration.executor,
                "read_order",
                description="Read order",
                inputs=inputs,
            )
            write = make_smolagents_tool(
                integration.agent,
                integration.executor,
                "refund_order",
                description="Refund order",
                inputs=inputs,
            )
            read_result, _ = run_agent(
                [read, write],
                [
                    ("read_order", {"order_id": "one"}),
                    ("final_answer", {"answer": "read checked"}),
                ],
                "Read order one",
            )
            assert read_result == "read checked"
            assert len(performed) == 1

            write_result, write_model = run_agent(
                [read, write],
                [
                    ("refund_order", {"order_id": "one"}),
                    ("final_answer", {"answer": "approval required"}),
                ],
                "Refund order one",
            )
            assert write_result == "approval required"
            from aigov_py.trusted import Decision

            # Consume the original agent request, arguments, and call ID from
            # host-only state; do not create a second request or expose IDs to the model.
            handle = take_pending_approval(write)
            cid = handle.call_id
            original = handle.arguments
            request = handle.request
            assert request.event_id not in "\n".join(write_model.inputs)
            assert "request_event_id" not in "\n".join(write_model.inputs)
            assert "call_id" not in "\n".join(write_model.inputs)
            assert len(performed) == 1
            approval = integration.approve(
                "lead", request, "refund_order", original, cid
            )
            assert approval.decision is Decision.ALLOW and approval.event_id
            changed = invoke_registered_tool(
                integration.agent,
                integration.executor,
                "refund_order",
                {"order_id": "two"},
                call_id=cid,
                approval_event_id=approval.event_id,
            )
            assert not changed["executed"]
            allowed = invoke_registered_tool(
                integration.agent,
                integration.executor,
                "refund_order",
                original,
                call_id=cid,
                approval_event_id=approval.event_id,
            )
            assert allowed["executed"] and allowed["receipt_recorded"]
            replay = invoke_registered_tool(
                integration.agent,
                integration.executor,
                "refund_order",
                original,
                call_id=cid,
                approval_event_id=approval.event_id,
            )
            assert not replay["executed"]
            assert len(performed) == 2
        finally:
            stop_core(root, prefix)


if __name__ == "__main__":
    main()
