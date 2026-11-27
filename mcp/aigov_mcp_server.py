"""AIGov local MCP-style bridge: subprocess wrappers with JSON results.

- CLI: ``python mcp/aigov_mcp_server.py <command> [options]``
- MCP stdio: ``python mcp/aigov_mcp_server.py mcp-stdio`` (newline-delimited JSON-RPC)

Subprocesses always use explicit argv lists (never ``shell=True``). Default commands avoid
network I/O. MCP file writes use the existing trusted Core authorization and executor path;
``dry_run`` is local and does not write.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

_STDIO_MAX_CHARS: Final[int] = 256 * 1024

_TOOLS_READ_ONLY: Final[frozenset[str]] = frozenset(
    {
        "govai_check",
        "govai_verify_evidence_pack",
        "govai_gate_reports",
        "govai_make_gate",
    }
)
_TOOLS_WRITE: Final[frozenset[str]] = frozenset({"govai_generate_audit_report_template"})
_TOOLS_GOVERNANCE: Final[frozenset[str]] = frozenset({"govai_request_audit_template_approval"})

_MCP_SILENT_NOTIFICATIONS: Final[frozenset[str]] = frozenset(
    {
        "initialized",
        "notifications/initialized",
        "notifications/cancelled",
    }
)


def resolve_repo_root(start: Path | None = None) -> Path:
    """Locate repository root (directory containing ``.cursor-plugin/plugin.json``).

    Falls back to the parent of ``mcp/`` when the manifest is not found (e.g. sparse checkouts).
    """
    here = (start or Path(__file__)).resolve()
    candidates = [here.parent, *here.parents]
    for p in candidates:
        if (p / ".cursor-plugin" / "plugin.json").is_file():
            return p
        if (p / "rust" / "Cargo.toml").is_file() and (p / "mcp" / "aigov_mcp_server.py").is_file():
            return p
    return here.parent


REPO_ROOT = resolve_repo_root()
PYTHON_DIR = REPO_ROOT / "python"
VENV_PY = PYTHON_DIR / ".venv" / "bin" / "python"
SCRIPTS_GATE = REPO_ROOT / "scripts" / "gate_reports.py"

_TIMEOUT_DEFAULT_S = 300
_TIMEOUT_GATE_REPORTS_S = 180
_TIMEOUT_VERIFY_EVIDENCE_S = 300
_TIMEOUT_MAKE_GATE_S = 900
_TIMEOUT_PYTEST_S = 7200


def _resolve_python_for_package() -> list[str]:
    """Prefer project venv interpreter so ``-m aigov_py`` resolves."""
    if VENV_PY.is_file():
        return [str(VENV_PY)]
    return [sys.executable or "python3"]


def _tool_access(tool: str) -> str:
    if tool in _TOOLS_WRITE:
        return "write"
    if tool in _TOOLS_GOVERNANCE:
        return "governance"
    if tool in _TOOLS_READ_ONLY:
        return "read_only"
    return "unknown"


def _truncate(s: str) -> tuple[str, bool]:
    if len(s) <= _STDIO_MAX_CHARS:
        return s, False
    return s[:_STDIO_MAX_CHARS], True


def _run_subprocess(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_s: float = _TIMEOUT_DEFAULT_S,
) -> dict[str, Any]:
    command = [str(x) for x in argv]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd) if cwd else str(REPO_ROOT),
            env=dict(os.environ) | (dict(env) if env else {}),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        duration_ms = int((time.monotonic() - t0) * 1000)
        out, out_trunc = _truncate((e.stdout or "") if isinstance(e.stdout, str) else "")
        err, err_trunc = _truncate((e.stderr or "") if isinstance(e.stderr, str) else "")
        return {
            "ok": False,
            "command": command,
            "exit_code": None,
            "stdout": out,
            "stderr": err,
            "stdout_truncated": out_trunc,
            "stderr_truncated": err_trunc,
            "duration_ms": duration_ms,
            "error": "timeout",
            "message": str(e),
        }
    except OSError as e:
        duration_ms = int((time.monotonic() - t0) * 1000)
        return {
            "ok": False,
            "command": command,
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "duration_ms": duration_ms,
            "error": "os_error",
            "message": str(e),
        }
    duration_ms = int((time.monotonic() - t0) * 1000)
    raw_out = proc.stdout or ""
    raw_err = proc.stderr or ""
    out, out_trunc = _truncate(raw_out)
    err, err_trunc = _truncate(raw_err)
    return {
        "ok": proc.returncode == 0,
        "command": command,
        "exit_code": proc.returncode,
        "stdout": out,
        "stderr": err,
        "stdout_truncated": out_trunc,
        "stderr_truncated": err_trunc,
        "duration_ms": duration_ms,
    }


def tool_installation_check() -> dict[str, Any]:
    """Report whether the workspace supports plugin-only vs full-repository MCP tooling."""
    root = REPO_ROOT
    checks = {
        "plugin_json": (root / ".cursor-plugin" / "plugin.json").is_file(),
        "mcp_server": (root / "mcp" / "aigov_mcp_server.py").is_file(),
        "python_tree": (root / "python").is_dir(),
        "gate_script": (root / "scripts" / "gate_reports.py").is_file(),
        "evidence_example": (
            root / "examples" / "standards" / "governance_evidence_pack.valid.json"
        ).is_file(),
    }
    full_repo = all(checks.values())
    mode = "full_repository" if full_repo else "incomplete_workspace"
    return {
        "ok": full_repo,
        "tool": "installation_check",
        "installation_mode": mode,
        "rules_skills_available": checks["plugin_json"],
        "mcp_tools_available": full_repo,
        "marketplace_plugin_only_insufficient_for_mcp": not full_repo,
        "checks": checks,
        "repo_root": str(root),
        "note": (
            "MCP tools require the full AIGov repository checkout as the Cursor workspace root. "
            "Rules and skills may still load from .cursor-plugin/ alone."
        ),
        "command": [],
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "duration_ms": 0,
    }


def tool_govai_check(pytest_extra: list[str] | None = None) -> dict[str, Any]:
    """Local repository test suite (``python -m pytest`` from ``python/``)."""
    pytest_extra = pytest_extra or []
    py = _resolve_python_for_package()
    argv = [*py, "-m", "pytest", "-q", *pytest_extra]
    body = _run_subprocess(argv, cwd=PYTHON_DIR, timeout_s=_TIMEOUT_PYTEST_S)
    body["tool"] = "govai_check"
    body["govai_access"] = _tool_access("govai_check")
    body["note"] = "Runs pytest in python/; not the hosted govai check HTTP verdict."
    return body


def tool_govai_verify_evidence_pack(path: str) -> dict[str, Any]:
    """Offline validation of a Governance Evidence Pack JSON/YAML file."""
    p = (REPO_ROOT / path).resolve() if not os.path.isabs(path) else Path(path).resolve()
    try:
        p.relative_to(REPO_ROOT)
    except ValueError:
        return {
            "ok": False,
            "error": "path_outside_repo",
            "path": str(p),
            "tool": "govai_verify_evidence_pack",
            "govai_access": _tool_access("govai_verify_evidence_pack"),
            "command": [],
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "duration_ms": 0,
        }
    if not p.is_file():
        return {
            "ok": False,
            "error": "not_a_file",
            "path": str(p),
            "tool": "govai_verify_evidence_pack",
            "govai_access": _tool_access("govai_verify_evidence_pack"),
            "command": [],
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "duration_ms": 0,
        }
    py = _resolve_python_for_package()
    argv = [*py, "-m", "aigov_py.standards.cli", "validate-evidence-pack", str(p)]
    body = _run_subprocess(argv, cwd=PYTHON_DIR, timeout_s=_TIMEOUT_VERIFY_EVIDENCE_S)
    body["tool"] = "govai_verify_evidence_pack"
    body["govai_access"] = _tool_access("govai_verify_evidence_pack")
    body["path"] = str(p)
    return body


def tool_govai_gate_reports() -> dict[str, Any]:
    py = sys.executable or "python3"
    argv = [py, str(SCRIPTS_GATE)]
    body = _run_subprocess(argv, cwd=REPO_ROOT, timeout_s=_TIMEOUT_GATE_REPORTS_S)
    body["tool"] = "govai_gate_reports"
    body["govai_access"] = _tool_access("govai_gate_reports")
    return body


def tool_govai_make_gate() -> dict[str, Any]:
    body = _run_subprocess(["make", "gate"], cwd=REPO_ROOT, timeout_s=_TIMEOUT_MAKE_GATE_S)
    body["tool"] = "govai_make_gate"
    body["govai_access"] = _tool_access("govai_make_gate")
    return body


def _audit_template_markdown(safe: str) -> str:
    return (
        f"# Audit report: {safe}\n\n"
        "## Evaluation gate\n\n"
        "Describe automated checks, test scope, and pass/fail criteria for this change set.\n\n"
        "## Human approval gate\n\n"
        "List required human reviewers, policy sign-off, and any staged rollout approvals.\n\n"
        "## Risk assessment\n\n"
        "Identify user, safety, security, and operational risks; note mitigations and residual risk.\n\n"
        "## Rollback plan\n\n"
        "Document how to revert or disable the change, data migration rollback (if any), and communication steps.\n"
    )


_MCP_TEMPLATE_TOOL = "govai_generate_audit_report_template"
_SAFE_CORE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


def _trusted_runtime_config() -> dict[str, str]:
    """Load the separate agent/executor credentials required by trusted execution."""
    names = {
        "core_url": "GOVAI_RUNTIME_AUTH_URL",
        "agent_key": "GOVAI_AGENT_API_KEY",
        "executor_key": "GOVAI_EXECUTOR_API_KEY",
        "public_key": "GOVAI_EXECUTION_AUTH_PUBLIC_KEY_B64",
        "audience": "GOVAI_EXECUTOR_AUDIENCE",
        "store_path": "GOVAI_EXECUTOR_STORE_PATH",
    }
    values = {
        key: (os.environ.get(env_name) or "").strip()
        for key, env_name in names.items()
    }
    missing = [env_name for key, env_name in names.items() if not values[key]]
    if missing:
        raise ValueError("trusted MCP execution is not configured: " + ", ".join(missing))
    for key in ("agent_key", "executor_key"):
        if len(values[key]) > 4096 or "\r" in values[key] or "\n" in values[key]:
            raise ValueError("trusted MCP API credential is invalid")
    if values["agent_key"] == values["executor_key"]:
        raise ValueError("agent and executor must use separate API credentials")
    try:
        parsed = urlsplit(values["core_url"])
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or (
                parsed.scheme != "https"
                and not (parsed.scheme == "http" and parsed.hostname in local_hosts)
            )
        ):
            raise ValueError
        public_key = base64.b64decode(values["public_key"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("trusted MCP Core URL or authorization public key is invalid") from exc
    if len(public_key) != 32:
        raise ValueError("trusted MCP authorization public key must decode to 32 bytes")
    if not _SAFE_CORE_ID.fullmatch(values["audience"]):
        raise ValueError("trusted MCP executor audience is invalid")
    return values


def _trusted_sdk() -> tuple[Any, ...]:
    """Import the already-shipped trusted execution SDK only when a governed write is requested."""
    from aigov_py.trusted import (
        AgentActor,
        CoreClient,
        Decision,
        ExecutionStore,
        Executor,
        ToolSpec,
        args_binding_hash,
    )

    return (
        AgentActor,
        CoreClient,
        Decision,
        ExecutionStore,
        Executor,
        ToolSpec,
        args_binding_hash,
    )


def _template_tool_spec(ToolSpec: Any) -> Any:
    return ToolSpec(
        _MCP_TEMPLATE_TOOL,
        action="docs:write",
        kind="write",
        resource_key="stem",
    )


def _template_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    stem = arguments.get("stem")
    if not isinstance(stem, str) or not stem.strip():
        raise ValueError("a non-empty stem is required for a governed write")
    stem = "".join(
        char if char.isalnum() or char in {"-", "_"} else "-"
        for char in stem.strip().lower()
    )
    if len(stem) > 120:
        raise ValueError("stem must be at most 120 characters after normalization")
    force = arguments.get("force", False)
    if not isinstance(force, bool):
        raise TypeError("force must be a boolean")
    return {"stem": stem, "force": force}


def _request_template_approval(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Record a write request. An independent approver must approve it before execution."""
    try:
        config = _trusted_runtime_config()
        (
            AgentActor,
            CoreClient,
            Decision,
            _Store,
            _Executor,
            ToolSpec,
            args_binding_hash,
        ) = _trusted_sdk()
        supplied_run_id = arguments.get("run_id")
        if supplied_run_id is not None and not isinstance(supplied_run_id, str):
            raise ValueError("run_id must be a string")
        run_id = supplied_run_id or f"run-{uuid.uuid4().hex}"
        if not _SAFE_CORE_ID.fullmatch(run_id):
            raise ValueError("run_id is invalid")
        tool_call_id = f"mcp-call-{uuid.uuid4().hex}"
        tool = _template_tool_spec(ToolSpec)
        core = CoreClient(
            config["core_url"],
            config["agent_key"],
            actor="mcp-agent",
            system="aigov-mcp",
        )
        actor = AgentActor(core, run_id, {tool.name: tool})
        business_args = _template_arguments(arguments)
        decision = actor.request_approval(tool.name, business_args, tool_call_id)
        if decision.decision != Decision.ALLOW or not decision.event_id:
            return {
                "ok": False,
                "error": "approval_request_refused",
                "reason": decision.reason,
                "decision": decision.decision.value,
            }
        return {
            "ok": True,
            "approval_status": "pending_human_approval",
            "run_id": run_id,
            "tool_call_id": tool_call_id,
            "request_event_id": decision.event_id,
            "args_binding_hash": args_binding_hash(tool, business_args),
            "target_path": f"docs/reports/{business_args['stem']}.md",
            "policy_revision": decision.policy_revision,
            "hint": (
                "A separately authenticated approver must approve this exact request "
                "before the write can execute."
            ),
        }
    except Exception as exc:  # noqa: BLE001 - all configuration and transport failures must deny
        return {
            "ok": False,
            "error": "trusted_authorization_unavailable",
            "reason": type(exc).__name__,
        }


def _execute_approved_template(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Submit the approved call to Core and execute only through the trusted SDK executor."""
    try:
        config = _trusted_runtime_config()
        (
            AgentActor,
            CoreClient,
            Decision,
            ExecutionStore,
            Executor,
            ToolSpec,
            _args_hash,
        ) = _trusted_sdk()
        run_id = arguments.get("run_id")
        tool_call_id = arguments.get("tool_call_id")
        approval_event_id = arguments.get("approval_event_id")
        identifiers = (run_id, tool_call_id, approval_event_id)
        if not all(
            isinstance(value, str) and _SAFE_CORE_ID.fullmatch(value)
            for value in identifiers
        ):
            raise ValueError(
                "run_id, tool_call_id, and approval_event_id must be safe identifiers"
            )
        business_args = _template_arguments(arguments)
        tool = _template_tool_spec(ToolSpec)
        tools = {tool.name: tool}
        agent_core = CoreClient(
            config["core_url"],
            config["agent_key"],
            actor="mcp-agent",
            system="aigov-mcp",
        )
        agent = AgentActor(agent_core, run_id, tools)
        decision = agent.submit_write(tool.name, business_args, tool_call_id, approval_event_id)
        if decision.decision != Decision.ALLOW or not decision.authorization:
            return {
                "ok": False,
                "error": "execution_authorization_refused",
                "reason": decision.reason,
                "decision": decision.decision.value,
            }

        executor_core = CoreClient(
            config["core_url"],
            config["executor_key"],
            actor="mcp-executor",
            system="aigov-mcp",
        )

        performed: list[dict[str, Any]] = []

        def perform(_tool: str, args: dict[str, Any], _execution_id: str) -> dict[str, Any]:
            result = tool_govai_generate_audit_report_template(
                stem=args.get("stem"), force=args["force"], dry_run=False
            )
            performed.append(result)
            return {
                "success": bool(result.get("ok") and result.get("wrote_file")),
                "data": {"path": result.get("path"), "wrote_file": result.get("wrote_file")},
                "blocked_reason": result.get("error"),
            }

        store = ExecutionStore(Path(config["store_path"]))
        executor = Executor(
            core=executor_core,
            public_key_b64=config["public_key"],
            audience=config["audience"],
            store=store,
            tools=tools,
            performer=perform,
        )
        outcome = executor.execute(
            run_id=run_id,
            tool=tool.name,
            arguments=business_args,
            signed=decision.authorization,
        )
        response = {
            "ok": outcome.executed and outcome.reason == "executed",
            "error": (
                None
                if outcome.executed and outcome.reason == "executed"
                else "execution_refused"
            ),
            "reason": outcome.reason,
            "authorization_id": outcome.authorization_id,
            "receipt_recorded": outcome.receipt_recorded,
            "execution_state": outcome.execution_state,
        }
        if performed:
            response["path"] = performed[0].get("path")
            response["wrote_file"] = performed[0].get("wrote_file", False)
        return response
    except Exception as exc:  # noqa: BLE001 - all auth, storage, and transport failures must deny
        return {
            "ok": False,
            "error": "trusted_authorization_unavailable",
            "reason": type(exc).__name__,
        }


def tool_govai_generate_audit_report_template(
    *, stem: str | None, force: bool, dry_run: bool
) -> dict[str, Any]:
    """Write ``docs/reports/<stem>.md`` with required audit headings (mutating unless dry_run)."""
    slug = stem or f"govai-audit-template-{uuid.uuid4().hex[:10]}"
    safe = "".join(c if c.isalnum() or c in {"-", "_"} else "-" for c in slug.strip().lower())
    reports = REPO_ROOT / "docs" / "reports"
    target = reports / f"{safe}.md"
    content = _audit_template_markdown(safe)

    if dry_run:
        return {
            "ok": True,
            "tool": "govai_generate_audit_report_template",
            "govai_access": "read_only",
            "dry_run": True,
            "wrote_file": False,
            "path": str(target),
            "would_write_bytes": len(content.encode("utf-8")),
            "preview": content[:1200],
            "command": [],
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "duration_ms": 0,
        }

    reports.mkdir(parents=True, exist_ok=True)
    try:
        reports.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return {
            "ok": False,
            "error": "report_directory_outside_repository",
            "path": str(reports),
            "tool": _MCP_TEMPLATE_TOOL,
            "govai_access": _tool_access(_MCP_TEMPLATE_TOOL),
            "wrote_file": False,
        }

    if not force:
        try:
            with target.open("x", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            return {
                "ok": False,
                "error": "file_exists",
                "path": str(target),
                "tool": _MCP_TEMPLATE_TOOL,
                "govai_access": _tool_access(_MCP_TEMPLATE_TOOL),
                "hint": "Pass --force to overwrite.",
                "dry_run": False,
                "wrote_file": False,
                "command": [],
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "duration_ms": 0,
            }
    else:
        fd, temporary_path = tempfile.mkstemp(prefix=f".{safe}-", suffix=".tmp", dir=reports)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, target)
        except Exception:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise
    return {
        "ok": True,
        "path": str(target),
        "tool": "govai_generate_audit_report_template",
        "govai_access": _tool_access("govai_generate_audit_report_template"),
        "dry_run": False,
        "wrote_file": True,
        "command": [],
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "duration_ms": 0,
    }


_MCP_TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "installation_check",
        "description": "[read-only] Report plugin-only vs full-repository MCP capability for this workspace.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "govai_gate_reports",
        "description": "[read-only] Run scripts/gate_reports.py (required markdown headings in docs/reports).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "govai_verify_evidence_pack",
        "description": "[read-only] Offline validate a Governance Evidence Pack JSON/YAML file via aigov_py.standards.cli.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repo-relative or absolute path to the document."}
            },
            "required": ["path"],
        },
    },
    {
        "name": "govai_request_audit_template_approval",
        "description": (
            "[governed] Record a request to create or overwrite an audit report template. "
            "Returns a run_id, tool_call_id, and request_event_id. A separately authenticated "
            "human approver must approve the exact request before the write tool can execute."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["stem"],
            "properties": {
                "stem": {"type": "string"},
                "force": {"type": "boolean", "default": False},
                "run_id": {"type": "string", "description": "Optional run identifier; generated when omitted."},
            },
        },
    },
    {
        "name": "govai_generate_audit_report_template",
        "description": (
            "[write; trusted execution required] Create docs/reports/<stem>.md. For a real write, "
            "first request and obtain separate human approval, then provide its run_id, tool_call_id, "
            "and approval_event_id here. Core issues a signed execution authorization and the local "
            "trusted executor verifies it before writing. Use dry_run=true for a local preview."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "stem": {"type": "string"},
                "force": {"type": "boolean", "default": False},
                "run_id": {"type": "string"},
                "tool_call_id": {"type": "string"},
                "approval_event_id": {"type": "string"},
                "dry_run": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, return preview only; do not write to disk.",
                },
            },
        },
    },
]


def _dispatch_tool(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    arguments = arguments or {}
    if name == "installation_check":
        return tool_installation_check()
    if name == "govai_check":
        raw = arguments.get("pytest_args") or []
        extra = [str(x) for x in raw] if isinstance(raw, list) else []
        return tool_govai_check(extra)
    if name == "govai_verify_evidence_pack":
        path = str(arguments.get("path") or "").strip()
        if not path:
            return {
                "ok": False,
                "error": "missing_path",
                "tool": name,
                "govai_access": _tool_access(name),
                "command": [],
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "duration_ms": 0,
            }
        return tool_govai_verify_evidence_pack(path)
    if name == "govai_gate_reports":
        return tool_govai_gate_reports()
    if name == "govai_make_gate":
        return tool_govai_make_gate()
    if name == "govai_request_audit_template_approval":
        return _request_template_approval(arguments)
    if name == "govai_generate_audit_report_template":
        stem = arguments.get("stem")
        if stem is not None and not isinstance(stem, str):
            return {"ok": False, "error": "invalid_write_arguments", "reason": "stem must be a string"}
        force = arguments.get("force", False)
        dry_run = arguments.get("dry_run", False)
        if not isinstance(force, bool) or not isinstance(dry_run, bool):
            return {"ok": False, "error": "invalid_write_arguments", "reason": "force and dry_run must be booleans"}
        if dry_run:
            return tool_govai_generate_audit_report_template(
                stem=stem.strip() if stem else None, force=force, dry_run=True
            )
        return _execute_approved_template(arguments)
    return {
        "ok": False,
        "error": "unknown_tool",
        "tool": name,
        "govai_access": "unknown",
        "command": [],
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "duration_ms": 0,
    }


def _log_stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _write_jsonrpc_line(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _read_jsonrpc_line() -> dict[str, Any] | None:
    while True:
        line = sys.stdin.readline()
        if not line:
            return None
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as e:
            _log_stderr(f"aigov_mcp_server: invalid JSON-RPC line: {e}")
            continue
        if isinstance(parsed, dict):
            return parsed
        _log_stderr("aigov_mcp_server: JSON-RPC payload must be an object")


def _is_jsonrpc_notification(msg: dict[str, Any]) -> bool:
    return "id" not in msg or msg.get("id") is None


def run_mcp_stdio() -> int:
    """Minimal MCP server (tools only) over newline-delimited JSON-RPC on stdio."""
    while True:
        msg = _read_jsonrpc_line()
        if msg is None:
            return 0
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        has_id = not _is_jsonrpc_notification(msg)

        if method in _MCP_SILENT_NOTIFICATIONS:
            continue
        if method == "initialize":
            _write_jsonrpc_line(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "govai-local", "version": "0.1.0"},
                    },
                }
            )
        elif method == "tools/list":
            _write_jsonrpc_line(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {"tools": _MCP_TOOL_SPECS},
                }
            )
        elif method == "tools/call":
            name = str(params.get("name") or "").strip()
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            result = _dispatch_tool(name, arguments)
            _write_jsonrpc_line(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}],
                        "isError": not bool(result.get("ok")),
                    },
                }
            )
        elif method == "ping":
            if has_id:
                _write_jsonrpc_line({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif has_id:
            _write_jsonrpc_line(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "error": {"code": -32601, "message": f"Method not found: {method!r}"},
                }
            )
        elif _is_jsonrpc_notification(msg):
            _log_stderr(f"aigov_mcp_server: ignored notification for unknown method {method!r}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="AIGov local MCP bridge")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_stdio = sub.add_parser("mcp-stdio", help="MCP JSON-RPC over stdio (newline-delimited JSON).")
    p_stdio.set_defaults(func=lambda _: run_mcp_stdio())

    p_inst = sub.add_parser(
        "installation-check",
        help="Report plugin-only vs full-repository MCP capability for this workspace.",
    )
    p_inst.set_defaults(func=lambda _: _emit(tool_installation_check()))

    p_check = sub.add_parser("govai-check", help="Run pytest in python/ (local check).")
    p_check.add_argument("pytest_arg", nargs="*", help="Extra args forwarded to pytest.")
    p_check.set_defaults(func=lambda ns: _emit(tool_govai_check(list(ns.pytest_arg))))

    p_vep = sub.add_parser("govai-verify-evidence-pack", help="Offline validate governance evidence pack file.")
    p_vep.add_argument("--path", required=True)
    p_vep.set_defaults(func=lambda ns: _emit(tool_govai_verify_evidence_pack(ns.path)))

    p_gr = sub.add_parser("govai-gate-reports", help="Run scripts/gate_reports.py.")
    p_gr.set_defaults(func=lambda _: _emit(tool_govai_gate_reports()))

    p_mg = sub.add_parser("govai-make-gate", help="Run make gate.")
    p_mg.set_defaults(func=lambda _: _emit(tool_govai_make_gate()))

    p_tpl = sub.add_parser(
        "govai-generate-audit-report-template",
        help="Preview a report template or execute an approved template write.",
    )
    p_tpl.add_argument("--stem", default=None, help="Filename stem (no extension).")
    p_tpl.add_argument("--force", action="store_true", help="Overwrite if exists.")
    p_tpl.add_argument("--dry-run", action="store_true", help="Print preview JSON only; do not write.")
    p_tpl.add_argument("--run-id", help="Run ID returned by the MCP approval request.")
    p_tpl.add_argument("--tool-call-id", help="Tool call ID returned by the MCP approval request.")
    p_tpl.add_argument("--approval-event-id", help="Human approval event ID.")
    p_tpl.set_defaults(
        func=lambda ns: _emit(
            tool_govai_generate_audit_report_template(
                stem=ns.stem, force=ns.force, dry_run=True
            )
            if ns.dry_run
            else _execute_approved_template(
                {
                    "stem": ns.stem,
                    "force": ns.force,
                    "run_id": ns.run_id,
                    "tool_call_id": ns.tool_call_id,
                    "approval_event_id": ns.approval_event_id,
                }
            )
        )
    )

    ns = p.parse_args(argv)
    code: int = int(ns.func(ns))
    return code


def _emit(obj: dict[str, Any]) -> int:
    sys.stdout.write(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")
    return 0 if obj.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
