#!/usr/bin/env python3
"""Human-operated approval step for the local MCP report-template example."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "python"))
sys.path.insert(0, str(REPO_ROOT / "mcp"))

from aigov_mcp_server import _template_arguments  # noqa: E402
from aigov_py.trusted import (  # noqa: E402
    ApproverActor,
    CoreClient,
    CoreDecision,
    Decision,
    ToolSpec,
    args_binding_hash,
)

TOOL = "govai_generate_audit_report_template"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tool-call-id", required=True)
    parser.add_argument("--request-event-id", required=True)
    parser.add_argument("--policy-revision", required=True)
    parser.add_argument("--args-binding-hash", required=True)
    parser.add_argument("--stem", required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if not sys.stdin.isatty():
        parser.error("approval requires an interactive terminal")
    normalized = _template_arguments({"stem": args.stem, "force": args.force})
    tool = ToolSpec(TOOL, action="docs:write", kind="write", resource_key="stem")
    binding_hash = args_binding_hash(tool, normalized)
    if binding_hash != args.args_binding_hash:
        parser.error("arguments do not match the request's binding hash")
    mode = "overwrite" if normalized["force"] else "create"
    print(f"Approve {mode}: {TOOL} for docs/reports/{normalized['stem']}.md")
    print(f"Run: {args.run_id}; call: {args.tool_call_id}; policy: {args.policy_revision}")
    print(f"Argument binding: {binding_hash}")
    print("Type APPROVE to authorize this exact, single-use request:", end=" ", flush=True)
    if input().strip() != "APPROVE":
        print("Approval not submitted.", file=sys.stderr)
        return 1

    base_url = (os.environ.get("GOVAI_RUNTIME_AUTH_URL") or "").strip()
    api_key = (os.environ.get("GOVAI_APPROVER_API_KEY") or "").strip()
    identity = (os.environ.get("GOVAI_APPROVER_IDENTITY") or "").strip()
    if not base_url or not api_key or not identity:
        parser.error(
            "GOVAI_RUNTIME_AUTH_URL, GOVAI_APPROVER_API_KEY, and "
            "GOVAI_APPROVER_IDENTITY are required"
        )
    try:
        parsed = urlsplit(base_url)
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        secure_url = parsed.scheme == "https" or (
            parsed.scheme == "http" and parsed.hostname in local_hosts
        )
        if (
            not parsed.hostname
            or not secure_url
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or len(api_key) > 4096
            or "\r" in api_key
            or "\n" in api_key
        ):
            raise ValueError
    except ValueError:
        parser.error("Core URL or approver credential is invalid")

    core = CoreClient(base_url, api_key, actor=identity, system="aigov-mcp-human-approval")
    actor = ApproverActor(core, identity, {TOOL: tool})
    request = CoreDecision(
        decision=Decision.ALLOW,
        reason="approval request was separately reviewed",
        event_id=args.request_event_id,
        record_hash=None,
        http_status=200,
        latency_ms=0.0,
        policy_revision=args.policy_revision,
    )
    decision = actor.decide(
        run_id=args.run_id,
        request=request,
        tool=TOOL,
        args=normalized,
        tool_call_id=args.tool_call_id,
        approve=True,
    )
    print(
        {
            "decision": decision.decision.value,
            "event_id": decision.event_id,
            "reason": decision.reason,
        }
    )
    return 0 if decision.decision == Decision.ALLOW else 1


if __name__ == "__main__":
    raise SystemExit(main())
