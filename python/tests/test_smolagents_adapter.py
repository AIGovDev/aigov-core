from unittest.mock import Mock

import pytest

from aigov_py.runtime.adapters.smolagents import invoke_registered_tool
from aigov_py.trusted import CoreDecision, Decision, Refused, ToolSpec


def setup(kind="read"):
    agent = Mock()
    agent.run_id = "run"
    agent.tools = {"tool": ToolSpec("tool", "repo:read", kind)}
    return agent, Mock()


@pytest.mark.parametrize("decision", [Decision.DENY, Decision.INDETERMINATE, Decision.REQUIRE_APPROVAL])
def test_no_execution_on_refusal(decision):
    agent, executor = setup()
    agent.read.return_value = CoreDecision(decision, "test", None, None, 400, 0)
    assert not invoke_registered_tool(agent, executor, "tool", {})["executed"]
    executor.execute.assert_not_called()


def test_write_requests_approval_without_execution():
    agent, executor = setup("write")
    agent.request_approval.return_value = CoreDecision(Decision.ALLOW, "ok", "request", None, 200, 0)
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
        Decision.ALLOW, "ok", "event", None, 200, 0, authorization=signed)
    executor.execute.return_value = Mock(executed=True, reason="ok", receipt_recorded=True)
    assert invoke_registered_tool(agent, executor, "tool", {"x": 1})["executed"]
    executor.execute.assert_called_once_with(
        run_id="run", tool="tool", arguments={"x": 1}, signed=signed)


def test_executor_refusal_is_not_bypassed():
    agent, executor = setup()
    agent.read.return_value = CoreDecision(
        Decision.ALLOW, "ok", "event", None, 200, 0, authorization={"fixture": True})
    executor.execute.side_effect = Refused("authorization_arguments_mismatch")
    with pytest.raises(Refused, match="authorization_arguments_mismatch"):
        invoke_registered_tool(agent, executor, "tool", {"x": 2})


def test_approval_requires_original_call_id():
    agent, executor = setup("write")
    with pytest.raises(Refused, match="approval_call_id_required"):
        invoke_registered_tool(agent, executor, "tool", {}, approval_event_id="approval")
    executor.execute.assert_not_called()


def test_real_smolagents_tool():
    import json
    smolagents = pytest.importorskip("smolagents")
    from aigov_py.runtime.adapters.smolagents import make_smolagents_tool

    agent, executor = setup()
    agent.read.return_value = CoreDecision(Decision.DENY, "blocked", None, None, 400, 0)
    tool = make_smolagents_tool(agent, executor, "tool", description="Governed test",
                                inputs={"x": {"type": "string", "description": "Input"}})
    assert isinstance(tool, smolagents.Tool)
    assert json.loads(tool(x="hello"))["decision"] == "DENY"
    executor.execute.assert_not_called()
