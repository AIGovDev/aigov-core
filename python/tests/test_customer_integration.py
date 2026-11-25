"""Customer integration interface: checks that need no running Core. CI runs these on every change.

They cover the configuration rules a customer can get wrong, the generated policy, and the separation of credentials.
The live validation (``examples/customer-integration/acme/validate.py``) is the end-to-end check, and CI runs it against
a release Core.
"""

from __future__ import annotations

import json
import sys
import tempfile
import warnings
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INT_DIR = REPO_ROOT / "examples" / "customer-integration"
if str(INT_DIR / "acme") not in sys.path:
    sys.path.insert(0, str(INT_DIR / "acme"))

warnings.filterwarnings("ignore", category=RuntimeWarning)

from aigov_py.trusted import IntegrationConfig, Tool
from app import CONFIG


def _config(**overrides):
    base = {
        "tenant": "t",
        "policy_id": "p",
        "tools": (
            Tool("read_x", "x:read", "read"),
            Tool("write_x", "x:write", "write"),
        ),
        "approvers": {"a": "a@example.test"},
        "agent_identity": "agent:one",
        "executor_identity": "executor:one",
    }
    base.update(overrides)
    return IntegrationConfig(**base)


def test_policy_splits_reads_and_writes_and_allowlists_approvers():
    doc = _config().policy_document()
    text = json.dumps(doc)
    assert "read_x" in text and "write_x" in text
    assert "a@example.test" in text


def test_example_policy_names_the_example_tools_and_approvers():
    doc = json.dumps(CONFIG.policy_document())
    for tool in ("read_invoice", "pay_vendor", "adjust_budget"):
        assert tool in doc
    assert CONFIG.tool("pay_vendor").kind == "write"


def test_unknown_tool_is_refused_before_any_call():
    with pytest.raises(KeyError):
        CONFIG.tool("delete_everything")


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"tools": (Tool("a", "a", "read"), Tool("a", "a", "write"))}, "duplicate"),
        ({"tools": (Tool("a", "a", "read"),)}, "at least one write"),
        ({"approvers": {}}, "at least one approver"),
        ({"executor_identity": "agent:one"}, "different identities"),
        ({"approvers": {"a": "agent:one"}}, "agent identity"),
    ],
)
def test_misconfiguration_is_rejected_at_definition_time(overrides, message):
    with pytest.raises(ValueError, match=message):
        _config(**overrides)


def test_generated_state_gives_every_principal_its_own_key_and_role():
    with tempfile.TemporaryDirectory() as tmp:
        built = _config().generate(Path(tmp))
    keys = built["state"]["keys"]
    assert len(set(keys.values())) == len(keys)
    roles = {}
    for entry in json.loads(built["env"]["GOVAI_PRINCIPALS_JSON"]).values():
        roles.setdefault(entry["role"], []).append(entry["principal"])
    assert roles["agent"] == ["agent:one"]
    assert roles["executor"] == ["executor:one"]
    assert roles["approver"] == ["approver:a"]


def test_an_unknown_tool_kind_is_rejected_when_the_tool_is_defined():
    with pytest.raises(ValueError, match="kind"):
        Tool("a", "a", "delete")
