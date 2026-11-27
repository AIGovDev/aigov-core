"""Run against release Core and PostgreSQL; no model API or remote code."""
import argparse
import json
import tempfile
from pathlib import Path

from aigov_py.runtime.adapters.smolagents import make_smolagents_tool, invoke_registered_tool
from aigov_py.trusted import Integration, IntegrationConfig, Tool, migrate, start_core, stop_core


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--database-url", required=True)
    args = parser.parse_args()
    config = IntegrationConfig(
        tenant="smolagents-test", policy_id="smolagents-test",
        tools=(Tool("read_order", "order:read", "read", resource_key="order_id"),
               Tool("refund_order", "order:refund", "write", resource_key="order_id")),
        approvers={"lead": "lead@example.test"},
        agent_identity="agent:smol", executor_identity="executor:smol")
    performed = []

    def perform(tool, arguments, execution_id):
        performed.append((tool, arguments))
        return {"success": True, "data": {"ok": True}}

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "core"
        running, prefix = start_core(config, root, port=18588, mode="binary",
                                     binary=args.binary, database_url=args.database_url)
        try:
            state = json.loads(running.state_file.read_text())
            work = root / "run"
            work.mkdir(exist_ok=True)
            migrate(work / "executor.sqlite", backup_dir=None)
            integration = Integration(config, running.core_url, state, work, perform)
            inputs = {"order_id": {"type": "string", "description": "Order identifier"}}
            read = make_smolagents_tool(integration.agent, integration.executor, "read_order",
                                       description="Read order", inputs=inputs)
            write = make_smolagents_tool(integration.agent, integration.executor, "refund_order",
                                        description="Refund order", inputs=inputs)
            assert json.loads(read(order_id="one"))["executed"]
            pending = json.loads(write(order_id="one"))
            assert pending["decision"] == "REQUIRE_APPROVAL"
            assert len(performed) == 1
            # Obtain a separate trusted host approval using the original call binding.
            from aigov_py.trusted import Decision
            # Retrieve the original request's policy revision via a fresh host request.
            cid = pending["call_id"]
            original = {"order_id": "one"}
            request = integration.request_approval("refund_order", original, cid)
            approval = integration.approve("lead", request, "refund_order", original, cid)
            assert approval.decision is Decision.ALLOW and approval.event_id
            changed = invoke_registered_tool(integration.agent, integration.executor, "refund_order",
                {"order_id": "two"}, call_id=cid, approval_event_id=approval.event_id)
            assert not changed["executed"]
            allowed = invoke_registered_tool(integration.agent, integration.executor, "refund_order",
                original, call_id=cid, approval_event_id=approval.event_id)
            assert allowed["executed"] and allowed["receipt_recorded"]
            replay = invoke_registered_tool(integration.agent, integration.executor, "refund_order",
                original, call_id=cid, approval_event_id=approval.event_id)
            assert not replay["executed"]
            assert len(performed) == 2
        finally:
            stop_core(root, prefix)


if __name__ == "__main__":
    main()
