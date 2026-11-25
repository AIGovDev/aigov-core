"""Customer pilot: checks that need no running Core. CI runs these on every change.

They cover what the pilot depends on for correctness without a server: the reference policy is unchanged by the
parametrization, the pilot's policy and identities are generated as configured, the tool registry routes the pilot's
tools, and the synthetic records behave as the workflow assumes. The live run (``examples/customer-pilot/pilot.py``) is
the end-to-end check and runs in its own CI job.
"""

from __future__ import annotations

import json
import sys
import tempfile
import warnings
from pathlib import Path

import pytest

pytest.importorskip(
    "smolagents"
)  # the reference package is part of the agent-reference extra

REPO_ROOT = Path(__file__).resolve().parents[2]
PILOT_DIR = REPO_ROOT / "examples" / "customer-pilot"
REF_DIR = REPO_ROOT / "examples" / "agent-reference"
for p in (str(PILOT_DIR), str(REF_DIR), str(REF_DIR / "service")):
    if p not in sys.path:
        sys.path.insert(0, p)

warnings.filterwarnings("ignore", category=RuntimeWarning)

import pilot_config
from aigov_agent_reference.core_policy import policy_document
from aigov_agent_reference.core_trusted import TOOL_ACTIONS, args_digest
from pilot_workflow import RecordStore
from trust_setup import build


def test_reference_policy_default_is_unchanged_by_parametrization():
    committed = json.loads(
        (REF_DIR / "policies" / "core_policy.unsigned.json").read_text()
    )
    assert policy_document() == committed


def test_pilot_policy_uses_pilot_tools_approvers_and_ttl():
    doc = pilot_config.pilot_policy_document()
    assert doc["policy_id"] == pilot_config.POLICY_ID
    assert pilot_config.APPROVER_ALLOWLIST == [
        pilot_config.APPROVER_IDENTITIES["steward"],
        pilot_config.APPROVER_IDENTITIES["owner"],
    ]
    text = json.dumps(doc)
    for tool in pilot_config.READ_TOOLS + pilot_config.WRITE_TOOLS:
        assert tool in text
    assert (
        "maintainer@acme-corp.example" not in text
    )  # no reference identity leaks into the pilot policy
    assert f'"max_age_seconds": {pilot_config.APPROVAL_MAX_AGE_SECONDS}' in text


def test_pilot_tools_are_registered_with_their_resource_keys():
    for tool, (action, _) in pilot_config.TOOLS.items():
        assert TOOL_ACTIONS[tool] == action
    digest = args_digest(
        "update_customer_record",
        {"customer_id": "CUST-1002", "changes": {"tier": "gold"}},
    )
    assert len(digest) == 64


def test_generated_identities_are_distinct_and_role_correct():
    with tempfile.TemporaryDirectory() as tmp:
        built = build(
            Path(tmp),
            approver_identities=pilot_config.APPROVER_IDENTITIES,
            document=pilot_config.pilot_policy_document(),
            tenant=pilot_config.TENANT,
            agent_principal=pilot_config.AGENT_IDENTITY,
            executor_principal=pilot_config.EXECUTOR_IDENTITY,
            executor_audience=pilot_config.EXECUTOR_AUDIENCE,
        )
    keys = built["state"]["keys"]
    assert len(set(keys.values())) == len(keys), "every principal has its own key"
    assert set(built["state"]["approver_identities"]) == {
        "steward",
        "owner",
        "outsider",
    }
    principals = json.loads(built["env"]["GOVAI_PRINCIPALS_JSON"])
    roles = {}
    for entry in principals.values():
        roles.setdefault(entry["role"], []).append(entry["principal"])
    assert sorted(roles["approver"]) == [
        "approver:outsider",
        "approver:owner",
        "approver:steward",
    ]
    assert roles["agent"] == [pilot_config.AGENT_IDENTITY]
    assert roles["executor"] == [pilot_config.EXECUTOR_IDENTITY]
    assert built["env"]["GOVAI_EXECUTOR_AUDIENCE"] == pilot_config.EXECUTOR_AUDIENCE


def test_synthetic_records_behave_as_the_workflow_assumes():
    with tempfile.TemporaryDirectory() as tmp:
        store = RecordStore(Path(tmp))
        read = store.performer(
            "read_customer_record", {"customer_id": "CUST-1001"}, "x"
        )
        assert read["success"] and read["data"]["name"] == "Ada Example"
        before = store.digest("CUST-1002")
        upd = store.performer(
            "update_customer_record",
            {
                "customer_id": "CUST-1002",
                "changes": {"email": "new@customer.example.test"},
            },
            "x",
        )
        assert upd["success"] and store.digest("CUST-1002") != before
        exp = store.performer(
            "export_customer_data",
            {"customer_id": "CUST-1001", "purpose": "test"},
            "exe_1",
        )
        assert (
            exp["success"] and (Path(tmp) / "exports" / "CUST-1001-exe_1.json").exists()
        )
        missing = store.performer(
            "read_customer_record", {"customer_id": "CUST-9999"}, "x"
        )
        assert (
            not missing["success"] and missing["blocked_reason"] == "unknown_customer"
        )
        store.performer("delete_customer_record", {"customer_id": "CUST-1003"}, "x")
        assert store.deleted == ["CUST-1003"]
