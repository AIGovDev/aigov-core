import json
from concurrent.futures import ThreadPoolExecutor
from itertools import count
from unittest.mock import Mock

import pytest

from aigov_py.runtime.adapters.smolagents import (
    MAX_PENDING_APPROVALS,
    invoke_registered_tool,
    make_smolagents_tool,
    take_pending_approval,
)
from aigov_py.trusted import CoreDecision, Decision, Refused, ToolSpec


def setup(kind="read"):
    agent = Mock()
    agent.run_id = "run"
    agent.tools = {"tool": ToolSpec("tool", "repo:read", kind)}
    return agent, Mock()


@pytest.mark.parametrize(
    "decision", [Decision.DENY, Decision.INDETERMINATE, Decision.REQUIRE_APPROVAL]
)
def test_no_execution_on_refusal(decision):
    agent, executor = setup()
    agent.read.return_value = CoreDecision(decision, "test", None, None, 400, 0)
    assert not invoke_registered_tool(agent, executor, "tool", {})["executed"]
    executor.execute.assert_not_called()


def test_write_requests_approval_without_execution():
    agent, executor = setup("write")
    agent.request_approval.return_value = CoreDecision(
        Decision.ALLOW, "ok", "request", None, 200, 0
    )
    result = invoke_registered_tool(agent, executor, "tool", {})
    assert result["decision"] == "REQUIRE_APPROVAL"
    executor.execute.assert_not_called()


def test_unknown_tool_refused():
    agent, executor = setup()
    with pytest.raises(Refused):
        invoke_registered_tool(agent, executor, "unknown", {})
    executor.execute.assert_not_called()


def test_allow_without_signed_authorization_is_fail_closed():
    agent, executor = setup()
    agent.read.return_value = CoreDecision(Decision.ALLOW, "ok", "event", None, 200, 0)
    result = invoke_registered_tool(agent, executor, "tool", {})
    assert result["decision"] == "INDETERMINATE"
    executor.execute.assert_not_called()


def test_signed_authorization_is_forwarded_to_executor():
    agent, executor = setup()
    signed = {"payload": {"args_binding_hash": "digest"}, "signature": "fixture"}
    agent.read.return_value = CoreDecision(
        Decision.ALLOW, "ok", "event", None, 200, 0, authorization=signed
    )
    executor.execute.return_value = Mock(
        executed=True, reason="ok", receipt_recorded=True
    )
    assert invoke_registered_tool(agent, executor, "tool", {"x": 1})["executed"]
    executor.execute.assert_called_once_with(
        run_id="run", tool="tool", arguments={"x": 1}, signed=signed
    )


def test_executor_refusal_is_not_bypassed():
    agent, executor = setup()
    agent.read.return_value = CoreDecision(
        Decision.ALLOW, "ok", "event", None, 200, 0, authorization={"fixture": True}
    )
    executor.execute.side_effect = Refused("authorization_arguments_mismatch")
    with pytest.raises(Refused, match="authorization_arguments_mismatch"):
        invoke_registered_tool(agent, executor, "tool", {"x": 2})


def test_approval_requires_original_call_id():
    agent, executor = setup("write")
    with pytest.raises(Refused, match="approval_call_id_required"):
        invoke_registered_tool(
            agent, executor, "tool", {}, approval_event_id="approval"
        )
    executor.execute.assert_not_called()


def test_real_smolagents_tool():
    smolagents = pytest.importorskip("smolagents")
    from aigov_py.runtime.adapters.smolagents import make_smolagents_tool

    agent, executor = setup()
    agent.read.return_value = CoreDecision(Decision.DENY, "blocked", None, None, 400, 0)
    tool = make_smolagents_tool(
        agent,
        executor,
        "tool",
        description="Governed test",
        inputs={"x": {"type": "string", "description": "Input"}},
    )
    assert isinstance(tool, smolagents.Tool)
    assert json.loads(tool(x="hello"))["decision"] == "DENY"
    executor.execute.assert_not_called()


def test_smolagents_tool_hides_approval_reference_from_model_and_host_consumes_once():
    pytest.importorskip("smolagents")
    agent, executor = setup("write")
    request = CoreDecision(
        Decision.ALLOW,
        "request_recorded",
        "request-event-secret-to-host",
        "record-hash",
        200,
        1,
        policy_revision="policy-revision-host-only",
    )
    agent.request_approval.return_value = request
    tool = make_smolagents_tool(
        agent,
        executor,
        "tool",
        description="Governed write",
        inputs={"x": {"type": "string", "description": "Input"}},
    )

    visible_to_model = json.loads(tool(x="value"))
    assert set(visible_to_model) == {"decision", "executed"}
    assert visible_to_model["decision"] == "REQUIRE_APPROVAL"
    assert visible_to_model["executed"] is False
    assert request.event_id not in json.dumps(visible_to_model)
    assert request.policy_revision not in json.dumps(visible_to_model)
    assert executor.execute.call_count == 0

    host_handle = take_pending_approval(tool)
    assert host_handle.request is request
    assert host_handle.tool == "tool"
    assert host_handle.arguments == {"x": "value"}
    with pytest.raises(Refused, match="pending_approval_not_found"):
        take_pending_approval(tool)


def test_missing_request_event_fails_closed_without_creating_pending_handle():
    agent, executor = setup("write")
    agent.request_approval.return_value = CoreDecision(
        Decision.ALLOW, "ok", None, None, 200, 0
    )
    tool = make_smolagents_tool(
        agent,
        executor,
        "tool",
        description="Governed write",
        inputs={"x": {"type": "string", "description": "Input"}},
    )

    assert json.loads(tool(x="value")) == {
        "decision": "INDETERMINATE",
        "executed": False,
    }
    with pytest.raises(Refused, match="pending_approval_not_found"):
        take_pending_approval(tool)
    executor.execute.assert_not_called()


def test_pending_approval_capacity_is_bounded_and_released_on_host_consumption():
    pytest.importorskip("smolagents")
    agent, executor = setup("write")
    agent.request_approval.side_effect = lambda *args: CoreDecision(
        Decision.ALLOW,
        "request_recorded",
        f"request-{agent.request_approval.call_count}",
        "record-hash",
        200,
        1,
        policy_revision="policy-1",
    )
    tool = make_smolagents_tool(
        agent,
        executor,
        "tool",
        description="Governed write",
        inputs={"x": {"type": "string", "description": "Input"}},
    )

    for index in range(MAX_PENDING_APPROVALS):
        assert json.loads(tool(x=str(index))) == {
            "decision": "REQUIRE_APPROVAL",
            "executed": False,
        }
    with pytest.raises(Refused, match="pending_approval_capacity_exceeded"):
        tool(x="over-capacity")
    assert agent.request_approval.call_count == MAX_PENDING_APPROVALS

    first = take_pending_approval(tool)
    assert first.arguments == {"x": "0"}
    assert json.loads(tool(x="capacity-released")) == {
        "decision": "REQUIRE_APPROVAL",
        "executed": False,
    }
    assert agent.request_approval.call_count == MAX_PENDING_APPROVALS + 1
    executor.execute.assert_not_called()


def test_concurrent_write_requests_keep_distinct_host_only_bindings():
    pytest.importorskip("smolagents")
    agent, executor = setup("write")
    event_ids = count()

    def record_request(*_args):
        return CoreDecision(
            Decision.ALLOW,
            "request_recorded",
            f"request-{next(event_ids)}",
            "record-hash",
            200,
            1,
            policy_revision="policy-1",
        )

    agent.request_approval.side_effect = record_request
    tool = make_smolagents_tool(
        agent,
        executor,
        "tool",
        description="Governed write",
        inputs={"x": {"type": "string", "description": "Input"}},
    )

    with ThreadPoolExecutor(max_workers=8) as pool:
        outputs = list(
            pool.map(lambda value: json.loads(tool(x=value)), map(str, range(32)))
        )

    assert all(
        output == {"decision": "REQUIRE_APPROVAL", "executed": False}
        for output in outputs
    )
    handles = [take_pending_approval(tool) for _ in outputs]
    assert len({handle.call_id for handle in handles}) == len(handles)
    assert len({handle.request.event_id for handle in handles}) == len(handles)
    assert {handle.arguments["x"] for handle in handles} == {
        str(value) for value in range(32)
    }
    executor.execute.assert_not_called()


def test_toolcalling_agent_dispatches_through_adapter_without_host_ids_in_context():
    smolagents = pytest.importorskip("smolagents")
    from smolagents.models import (
        ChatMessage,
        ChatMessageToolCall,
        ChatMessageToolCallFunction,
        MessageRole,
        Model,
    )

    class ScriptedModel(Model):
        def __init__(self):
            super().__init__(model_id="aigov-deterministic-test")
            self.plan = [
                ("tool", {"x": "value"}),
                ("final_answer", {"answer": "approval requested"}),
            ]
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
                id=f"test-call-{len(self.inputs)}",
                type="function",
                function=ChatMessageToolCallFunction(
                    name=name,
                    arguments=arguments,
                ),
            )
            return ChatMessage(
                role=MessageRole.ASSISTANT,
                content="",
                tool_calls=[call],
            )

    agent, executor = setup("write")
    request = CoreDecision(
        Decision.ALLOW,
        "request_recorded",
        "private-request-event-id",
        "record-hash",
        200,
        1,
        policy_revision="private-policy-revision",
    )
    agent.request_approval.return_value = request
    tool = make_smolagents_tool(
        agent,
        executor,
        "tool",
        description="Governed write",
        inputs={"x": {"type": "string", "description": "Input"}},
    )
    model = ScriptedModel()
    runner = smolagents.ToolCallingAgent(
        tools=[tool], model=model, max_steps=3, verbosity_level=0
    )

    assert runner.run("Request the governed write") == "approval requested"
    observed = "\n".join(model.inputs)
    assert request.event_id not in observed
    assert request.policy_revision not in observed
    assert "request_event_id" not in observed
    assert executor.execute.call_count == 0
    handle = take_pending_approval(tool)
    assert handle.request is request
    assert handle.arguments == {"x": "value"}


def test_smolagents_tool_rejects_host_approval_fields_in_model_schema():
    pytest.importorskip("smolagents")
    agent, executor = setup("write")
    with pytest.raises(ValueError, match="Reserved host-only input"):
        make_smolagents_tool(
            agent,
            executor,
            "tool",
            description="Governed write",
            inputs={
                "approval_event_id": {
                    "type": "string",
                    "description": "Must stay host-only",
                }
            },
        )
    executor.execute.assert_not_called()
