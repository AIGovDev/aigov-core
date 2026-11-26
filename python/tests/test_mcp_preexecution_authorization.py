from __future__ import annotations

import base64
import importlib.util
import io
import json
import sys
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "aigov_mcp_server_under_test", REPO_ROOT / "mcp" / "aigov_mcp_server.py"
)
assert SPEC is not None and SPEC.loader is not None
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)


TOOL = "govai_generate_audit_report_template"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    INDETERMINATE = "INDETERMINATE"


def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOVAI_RUNTIME_AUTH_URL", "https://core.example")
    monkeypatch.setenv("GOVAI_AGENT_API_KEY", "agent-secret")
    monkeypatch.setenv("GOVAI_EXECUTOR_API_KEY", "executor-secret")
    monkeypatch.setenv(
        "GOVAI_EXECUTION_AUTH_PUBLIC_KEY_B64", base64.b64encode(b"p" * 32).decode()
    )
    monkeypatch.setenv("GOVAI_EXECUTOR_AUDIENCE", "mcp-executor")
    monkeypatch.setenv("GOVAI_EXECUTOR_STORE_PATH", "/tmp/aigov-executor.sqlite")


def _sdk(*, agent_decision: Decision = Decision.ALLOW, should_execute: bool = True):
    observed: dict[str, object] = {}

    class ToolSpec:
        def __init__(self, name: str, *, action: str, kind: str, resource_key: str):
            self.name = name
            self.action = action
            self.kind = kind
            self.resource_key = resource_key

    class CoreClient:
        def __init__(self, url: str, key: str, **kwargs):
            observed.setdefault("clients", []).append((url, key, kwargs))

    class AgentActor:
        def __init__(self, core, run_id, tools):
            self.run_id = run_id
            self.tools = tools

        def request_approval(self, tool, args, call_id):
            observed["request"] = (self.run_id, tool, args, call_id)
            return SimpleNamespace(
                decision=Decision.ALLOW,
                event_id="tool_approval_requested-1",
                record_hash="a" * 64,
                policy_revision="policy-v2",
                reason="accepted",
            )

        def submit_write(self, tool, args, call_id, approval_id):
            observed["submit"] = (self.run_id, tool, args, call_id, approval_id)
            return SimpleNamespace(
                decision=agent_decision,
                event_id="consequential_tool_call-1",
                record_hash="b" * 64,
                policy_revision="policy-v2",
                reason="accepted" if agent_decision == Decision.ALLOW else "approval_not_found",
                authorization={"payload": {"authorization_id": "auth-1"}}
                if agent_decision == Decision.ALLOW
                else None,
            )

    class ExecutionStore:
        def __init__(self, path):
            observed["store_path"] = str(path)

    class Executor:
        def __init__(self, **kwargs):
            observed["executor_config"] = kwargs
            self.performer = kwargs["performer"]

        def execute(self, **kwargs):
            observed["execution"] = kwargs
            if should_execute:
                observed["performed"] = self.performer(
                    kwargs["tool"], kwargs["arguments"], "stable-execution-id"
                )
            return SimpleNamespace(
                executed=should_execute,
                reason="executed" if should_execute else "authorization_replayed",
                authorization_id="auth-1",
                receipt_recorded=True,
                execution_state="succeeded" if should_execute else None,
            )

    def args_binding_hash(tool, args):
        observed["binding"] = (tool.name, dict(args), tool.action, tool.resource_key)
        return "c" * 64

    sdk = (
        AgentActor,
        CoreClient,
        Decision,
        ExecutionStore,
        Executor,
        ToolSpec,
        args_binding_hash,
    )
    return sdk, observed


def test_approval_request_records_agent_request_but_does_not_approve(monkeypatch):
    _configure(monkeypatch)
    sdk, observed = _sdk()
    monkeypatch.setattr(mcp, "_trusted_sdk", lambda: sdk)

    result = mcp._request_template_approval({"stem": "partner-a", "force": False})

    assert result["ok"] is True
    assert result["approval_status"] == "pending_human_approval"
    assert result["request_event_id"] == "tool_approval_requested-1"
    assert observed["binding"][1] == {"stem": "partner-a", "force": False}
    assert len(observed["clients"]) == 1
    assert observed["clients"][0][1] == "agent-secret"


def test_execution_requires_distinct_human_approval_and_refuses_core_denial(monkeypatch):
    _configure(monkeypatch)
    sdk, observed = _sdk(agent_decision=Decision.REQUIRE_APPROVAL)
    monkeypatch.setattr(mcp, "_trusted_sdk", lambda: sdk)

    result = mcp._execute_approved_template(
        {
            "run_id": "run-1",
            "tool_call_id": "call-1",
            "approval_event_id": "approval-1",
            "stem": "denied",
            "force": False,
        }
    )

    assert result["error"] == "execution_authorization_refused"
    assert result["decision"] == "REQUIRE_APPROVAL"
    assert "executor_config" not in observed
    assert len(observed["clients"]) == 1


def test_execution_uses_signed_core_authorization_and_separate_executor_key(monkeypatch):
    _configure(monkeypatch)
    sdk, observed = _sdk()
    monkeypatch.setattr(mcp, "_trusted_sdk", lambda: sdk)
    write = Mock(return_value={"ok": True, "wrote_file": True, "path": "docs/reports/approved.md"})
    monkeypatch.setattr(mcp, "tool_govai_generate_audit_report_template", write)

    result = mcp._execute_approved_template(
        {
            "run_id": "run-1",
            "tool_call_id": "call-1",
            "approval_event_id": "approval-1",
            "stem": "approved",
            "force": True,
        }
    )

    assert result["ok"] is True
    assert result["receipt_recorded"] is True
    assert result["path"] == "docs/reports/approved.md"
    assert result["wrote_file"] is True
    assert observed["submit"] == (
        "run-1",
        TOOL,
        {"stem": "approved", "force": True},
        "call-1",
        "approval-1",
    )
    assert observed["clients"][0][1] == "agent-secret"
    assert observed["clients"][1][1] == "executor-secret"
    assert observed["executor_config"]["public_key_b64"] == base64.b64encode(b"p" * 32).decode()
    assert observed["executor_config"]["audience"] == "mcp-executor"
    assert observed["execution"]["signed"] == {
        "payload": {"authorization_id": "auth-1"}
    }
    write.assert_called_once_with(stem="approved", force=True, dry_run=False)


def test_missing_credentials_and_bad_public_key_fail_closed(monkeypatch):
    for name in (
        "GOVAI_RUNTIME_AUTH_URL",
        "GOVAI_AGENT_API_KEY",
        "GOVAI_EXECUTOR_API_KEY",
        "GOVAI_EXECUTION_AUTH_PUBLIC_KEY_B64",
        "GOVAI_EXECUTOR_AUDIENCE",
        "GOVAI_EXECUTOR_STORE_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    result = mcp._execute_approved_template({})
    assert result["ok"] is False
    assert result["error"] == "trusted_authorization_unavailable"

    _configure(monkeypatch)
    monkeypatch.setenv("GOVAI_EXECUTION_AUTH_PUBLIC_KEY_B64", "not-base64")
    result = mcp._execute_approved_template({})
    assert result["ok"] is False
    assert result["reason"] == "ValueError"


def test_path_identifiers_are_restricted_before_core_requests(monkeypatch):
    _configure(monkeypatch)
    sdk, observed = _sdk()
    monkeypatch.setattr(mcp, "_trusted_sdk", lambda: sdk)

    result = mcp._execute_approved_template(
        {
            "run_id": "../other-run",
            "tool_call_id": "call-1",
            "approval_event_id": "approval-1",
            "stem": "blocked",
            "force": False,
        }
    )

    assert result["ok"] is False
    assert result["reason"] == "ValueError"
    assert "clients" not in observed


def test_governed_write_binds_normalized_target_and_requires_explicit_stem(monkeypatch):
    _configure(monkeypatch)
    sdk, observed = _sdk()
    monkeypatch.setattr(mcp, "_trusted_sdk", lambda: sdk)

    result = mcp._request_template_approval({"stem": "../Brand Review", "force": False})

    assert result["ok"] is True
    assert result["target_path"] == "docs/reports/---brand-review.md"
    assert observed["binding"][1] == {"stem": "---brand-review", "force": False}
    assert mcp._request_template_approval({"stem": "   "})["ok"] is False


def test_executor_replay_refusal_does_not_call_file_writer(monkeypatch):
    _configure(monkeypatch)
    sdk, _observed = _sdk(should_execute=False)
    monkeypatch.setattr(mcp, "_trusted_sdk", lambda: sdk)
    writer = Mock()
    monkeypatch.setattr(mcp, "tool_govai_generate_audit_report_template", writer)

    result = mcp._execute_approved_template(
        {
            "run_id": "run-1",
            "tool_call_id": "call-1",
            "approval_event_id": "approval-1",
            "stem": "replay",
            "force": False,
        }
    )

    assert result["ok"] is False
    assert result["reason"] == "authorization_replayed"
    writer.assert_not_called()


def test_dispatch_routes_dry_run_locally_and_real_write_through_executor(monkeypatch):
    local = Mock(return_value={"ok": True, "wrote_file": False})
    authorized = Mock(return_value={"ok": True, "authorization_id": "auth-1"})
    monkeypatch.setattr(mcp, "tool_govai_generate_audit_report_template", local)
    monkeypatch.setattr(mcp, "_execute_approved_template", authorized)

    preview = mcp._dispatch_tool(
        TOOL, {"stem": "preview", "force": False, "dry_run": True}
    )
    result = mcp._dispatch_tool(
        TOOL,
        {
            "stem": "approved",
            "force": False,
            "dry_run": False,
            "run_id": "run-1",
            "tool_call_id": "call-1",
            "approval_event_id": "approval-1",
        },
    )

    local.assert_called_once_with(stem="preview", force=False, dry_run=True)
    authorized.assert_called_once()
    assert preview["wrote_file"] is False
    assert result["authorization_id"] == "auth-1"


def test_create_is_exclusive_and_force_overwrite_is_atomic(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp, "REPO_ROOT", tmp_path)
    created = mcp.tool_govai_generate_audit_report_template(
        stem="concurrent", force=False, dry_run=False
    )
    path = tmp_path / "docs" / "reports" / "concurrent.md"
    original = path.read_text(encoding="utf-8")

    duplicate = mcp.tool_govai_generate_audit_report_template(
        stem="concurrent", force=False, dry_run=False
    )
    overwritten = mcp.tool_govai_generate_audit_report_template(
        stem="concurrent", force=True, dry_run=False
    )

    assert created["wrote_file"] is True
    assert duplicate["error"] == "file_exists"
    assert path.read_text(encoding="utf-8") == original
    assert overwritten["wrote_file"] is True
    assert not list(path.parent.glob(".concurrent-*.tmp"))


def test_report_directory_symlink_cannot_escape_repository(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    (repo / "docs").mkdir(parents=True)
    outside.mkdir()
    (repo / "docs" / "reports").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(mcp, "REPO_ROOT", repo)

    result = mcp.tool_govai_generate_audit_report_template(
        stem="escape", force=True, dry_run=False
    )

    assert result["error"] == "report_directory_outside_repository"
    assert not (outside / "escape.md").exists()


def test_cli_real_write_routes_through_trusted_executor(monkeypatch):
    direct_writer = Mock()
    governed = Mock(return_value={"ok": False, "error": "authorization_refused"})
    stdout = io.StringIO()
    monkeypatch.setattr(mcp, "tool_govai_generate_audit_report_template", direct_writer)
    monkeypatch.setattr(mcp, "_execute_approved_template", governed)
    monkeypatch.setattr(mcp.sys, "stdout", stdout)

    code = mcp.main(["govai-generate-audit-report-template", "--stem", "blocked"])

    assert code == 1
    direct_writer.assert_not_called()
    governed.assert_called_once()
    assert json.loads(stdout.getvalue())["error"] == "authorization_refused"
