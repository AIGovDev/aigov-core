"""Receipt provenance on Core: an execution receipt is accepted only from an authenticated executor principal, and only for an
authorization Core issued for the same run. Negative controls first, then the legitimate path."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

from test_crash_consistency_core import (
    KEY,
    RUN,
    SEED_HEX,
    KEY_ID,
    TENANT,
    _append_injected,
    _approval,
    _consequential,
    _drop_sidecars,
    _records,
    free_port,
)

REPO = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("AIGOV_TEST_CORE_BIN", REPO / "rust" / "target" / "release" / "aigov_audit"))
pytestmark = pytest.mark.skipif(not BIN.exists(), reason=f"Core binary not built: {BIN}")

AGENT = "agent-key-rp"
EXEC = "executor-key-rp"


class Node:
    def __init__(self, ledger: Path, principals: bool) -> None:
        self.url = f"http://127.0.0.1:{free_port()}"
        port = self.url.rsplit(":", 1)[1]
        env = {k: v for k, v in os.environ.items() if k not in ("DATABASE_URL", "GOVAI_DATABASE_URL", "AIGOV_DATABASE_URL")}
        env.update({
            "AIGOV_ENVIRONMENT": "dev", "GOVAI_LEDGER_DIR": str(ledger), "AIGOV_BIND": f"127.0.0.1:{port}",
            "GOVAI_API_KEYS": f"{AGENT},{EXEC}", "GOVAI_API_KEYS_JSON": json.dumps({AGENT: TENANT, EXEC: TENANT}),
        })
        if principals:
            # Execution authorization requires principals, so only the principal-configured node issues authorizations.
            env.update({"GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX": SEED_HEX, "GOVAI_EXECUTION_AUTH_KEY_ID": KEY_ID})
        env.pop("AIGOV_TEST_FAULT_INJECTION", None)
        env.pop("AIGOV_TEST_CRASH_AT", None)
        if principals:
            env["GOVAI_PRINCIPALS_JSON"] = json.dumps({
                AGENT: {"principal": "agent:rp", "identity": "agent:rp", "role": "agent", "tenant": TENANT},
                EXEC: {"principal": "executor:rp", "identity": "executor:rp", "role": "executor", "tenant": TENANT},
            })
        self.log = open(ledger.parent / f"rp-{port}.log", "w")  # noqa: SIM115
        self.proc = subprocess.Popen([str(BIN)], env=env, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"Core exited at start with {self.proc.returncode}")
            try:
                if urllib.request.urlopen(self.url + "/health", timeout=2).status == 200:
                    return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("Core did not start")

    def post(self, key: str, body: dict) -> tuple[int, dict]:
        req = urllib.request.Request(self.url + "/evidence", data=json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


def _receipt(event_id: str, auth_id: str) -> dict:
    return {
        "event_id": event_id, "event_type": "execution_receipt", "ts_utc": "2026-11-26T10:00:00Z",
        "actor": "executor", "system": "rp-test", "run_id": RUN,
        "payload": {"execution_authorization_id": auth_id, "tool_name": "create_file",
                    "args_binding_hash": "a" * 64, "outcome": "success"},
    }


@pytest.fixture
def ledger():
    with tempfile.TemporaryDirectory(prefix="rp-core-") as d:
        p = Path(d) / "ledger"
        p.mkdir()
        yield p


def test_forged_receipt_without_principals_is_refused(ledger):
    node = Node(ledger, principals=False)
    try:
        status, body = node.post(EXEC, _receipt(f"rc-{uuid.uuid4().hex}", "auth_never_issued"))
    finally:
        node.close()
    assert status == 403 and body["error"]["code"] == "RECEIPT_REQUIRES_EXECUTOR", (status, body)
    assert _records(ledger) == []


def test_receipt_for_an_authorization_never_issued_is_refused(ledger):
    node = Node(ledger, principals=True)
    try:
        status, body = node.post(EXEC, _receipt(f"rc-{uuid.uuid4().hex}", "auth_never_issued"))
    finally:
        node.close()
    assert status == 422 and body["error"]["code"] == "RECEIPT_FOR_UNISSUED_AUTHORIZATION", (status, body)
    assert _records(ledger) == []


def test_agent_cannot_post_a_receipt(ledger):
    node = Node(ledger, principals=True)
    try:
        status, body = node.post(AGENT, _receipt(f"rc-{uuid.uuid4().hex}", "auth_never_issued"))
    finally:
        node.close()
    assert status == 403 and body["error"]["code"] == "ROLE_NOT_PERMITTED", (status, body)


def test_receipt_for_an_authorization_issued_in_the_run_is_accepted(ledger):
    approval_id = f"human_approved-{uuid.uuid4().hex}"
    tool_call_id = f"call-{uuid.uuid4().hex[:8]}"
    _append_injected(ledger, _approval(approval_id, tool_call_id))
    _drop_sidecars(ledger)
    node = Node(ledger, principals=True)
    try:
        call_id = f"call-{uuid.uuid4().hex}"
        status, body = node.post(AGENT, _consequential(call_id, tool_call_id, approval_id))
        assert status == 200 and body.get("execution_authorization"), (status, body)
        auth_id = body["execution_authorization"]["payload"]["authorization_id"]
        status2, body2 = node.post(EXEC, _receipt(f"rc-{uuid.uuid4().hex}", auth_id))
    finally:
        node.close()
    assert status2 == 200, (status2, body2)
    assert len([r for r in _records(ledger) if "execution_receipt" in r["event_json"]]) == 1
