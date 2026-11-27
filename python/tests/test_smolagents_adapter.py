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
