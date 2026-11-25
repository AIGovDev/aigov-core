"""Minimal AIGov Core integration: copy this file, then change the tools and the performer.

What a customer writes is in the two marked sections. Everything else is the integration: Core starts with a policy
built from the tools below, each actor gets its own credential, and the executor verifies every authorization before
calling the performer.

    python examples/customer-integration/quickstart.py          # starts Core, runs the flow, verifies, cleans up
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import sqlite3

from aigov_py.trusted import (
    Integration,
    IntegrationConfig,
    Tool,
    executor_store_migration,
    start_core,
    stop_core,
)

# ---- Customer section 1: your tools and who may approve them ------------------------------------------------------
CONFIG = IntegrationConfig(
    tenant="quickstart-tenant",
    policy_id="quickstart-policy",
    tools=(
        Tool("read_order", "order:read", "read", resource_key="order_id"),
        Tool("refund_order", "order:refund", "write", resource_key="order_id"),
    ),
    approvers={"support_lead": "lead@quickstart.example"},
    agent_identity="agent:support-bot",
    executor_identity="executor:orders-service",
)

# ---- Customer section 2: the side effects, against your real system -----------------------------------------------
ORDERS = {"ORD-1": {"total": 80.0, "refunded": False}}


def perform(tool: str, args: dict, execution_id: str) -> dict:
    order = ORDERS.get(args.get("order_id", ""))
    if order is None:
        return {"success": False, "data": None, "blocked_reason": "unknown_order"}
    if tool == "read_order":
        return {"success": True, "data": dict(order)}
    if tool == "refund_order":
        order["refunded"] = True  # your refund API call goes here
        return {
            "success": True,
            "data": {"refunded": args["order_id"], "execution_id": execution_id},
        }
    return {"success": False, "data": None, "blocked_reason": "unsupported_tool"}


# ---- The flow: this is the part you adapt --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--mode", choices=["docker", "binary"], default="docker")
    parser.add_argument("--binary", help="release aigov_audit (binary mode)")
    parser.add_argument("--database-url", help="PostgreSQL URL (binary mode)")
    parser.add_argument("--port", type=int, default=18299)
    args = parser.parse_args(argv)
    if args.mode == "binary" and not (args.binary and args.database_url):
        parser.error("binary mode needs --binary and --database-url")
    # Keep the run's files under the home cache. Docker Desktop shares the home directory with its VM, but not the
    # system temporary directory, so a file mounted from /var/folders is empty inside the container.
    state_dir = (
        Path.home()
        / ".cache"
        / "aigov-customer-integration"
        / f"quickstart-{uuid.uuid4().hex[:8]}"
    )
    running, prefix = start_core(
        CONFIG,
        state_dir,
        port=args.port,
        mode=args.mode,
        binary=Path(args.binary) if args.binary else None,
        database_url=args.database_url,
    )
    try:
        import json

        state = json.loads(running.state_file.read_text())
        store_path = state_dir / "run" / "executor.sqlite"
        store_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(
            store_path
        ) as conn:  # the executor store's migration, applied once before first use
            conn.executescript(executor_store_migration())
        integ = Integration(CONFIG, running.core_url, state, state_dir / "run", perform)
        args = {"order_id": "ORD-1"}

        # A read needs no approval. Core decides, the executor verifies and runs it, and a receipt is recorded.
        read = integ.call("read_order", args, "call-read")
        print(
            "read:",
            read.decision.value,
            "-",
            integ.execute("read_order", args, read).reason,
        )

        # A refund needs a named approver. The request, the approval, and the call are separate Core events.
        request = integ.request_approval("refund_order", args, "call-refund")
        approval = integ.approve(
            "support_lead", request, "refund_order", args, "call-refund"
        )
        call = integ.call("refund_order", args, "call-refund", approval.event_id or "")
        outcome = integ.execute("refund_order", args, call)
        print("refund:", outcome.reason, "| refunded:", ORDERS["ORD-1"]["refunded"])

        # Evidence: Core's chain check plus offline checks against the pinned public key. Every authorization the run
        # issued must be passed, because each execution receipt is checked against its authorization.
        issued = [d.authorization for d in (read, call) if d.authorization]
        checks = integ.verify(issued)
        failed = [c["name"] for c in checks if not c["ok"]]
        print(
            "evidence:",
            "all checks pass" if not failed else f"FAILED: {', '.join(failed)}",
        )
        return 0 if outcome.executed and not failed else 1
    finally:
        print("cleaned up:", "; ".join(stop_core(state_dir, prefix)) or "nothing")


if __name__ == "__main__":
    raise SystemExit(main())
