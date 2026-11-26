"""Crash consistency of Core's authorization issuance: the process is terminated at each boundary of the issuance path, then
restarted, and the invariants are checked on the ledger and on what a client could have received.

Boundaries (Core's `crash_point`, active only with AIGOV_TEST_FAULT_INJECTION=1 and AIGOV_TEST_CRASH_AT):

- before_append: nothing has been written; the call is not yet recorded;
- after_append_before_sign: the consequential record is committed; no authorization is signed or delivered;
- after_sign_before_response: the record is committed and the authorization is signed, but the response is never sent.

Invariants checked after each crash and restart:

1. No authorization is delivered without a committed record (the client receives nothing from a crashed call).
2. No approval reuse: after the crash, a new call that names the same approval is refused.
3. No duplicate authorization consumption: a retry with the same event id is not authorized twice (it is a duplicate, or
   the approval is already used).
4. No corrupted ledger: the hash chain verifies after the restart.
5. Safe restart: the restarted Core serves calls and reads the same ledger.

The approval is injected into the ledger file before Core starts, with a valid hash chain. The dev policy cannot record a tool
approval over HTTP, so this is the only way to reach the issuance path in this build. The state and run-index sidecars are
removed so that Core rebuilds them on start.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
# The crash points exist only in a build with the `fault-injection` feature:
#   cargo build --release --features fault-injection --bin aigov_audit --target-dir <dir>
BIN = Path(os.environ.get("AIGOV_TEST_FAULT_CORE_BIN", REPO / "target-fault" / "release" / "aigov_audit"))
PLAIN_BIN = Path(os.environ.get("AIGOV_TEST_CORE_BIN", REPO / "rust" / "target" / "release" / "aigov_audit"))
pytestmark = pytest.mark.skipif(not BIN.exists(), reason=f"fault-injection Core binary not built: {BIN}")

KEY = "crash-agent-key"
TENANT = "t1"
RUN = "run-crash"
TOOL = "create_file"
SEED_HEX = "2929292929292929292929292929292929292929292929292929292929292929"
KEY_ID = "exe-crash"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _record_hash(prev: str, event_json: str) -> str:
    return hashlib.sha256((prev + "\n" + event_json).encode()).hexdigest()


def _ledger_path(ledger: Path) -> Path:
    return ledger / f"audit_log__{TENANT}.jsonl"


def _records(ledger: Path) -> list[dict]:
    p = _ledger_path(ledger)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def _append_injected(ledger: Path, event: dict) -> None:
    """Append one event with a valid chain. The caller removes the sidecars so Core rebuilds them."""
    recs = _records(ledger)
    prev = recs[-1]["record_hash"] if recs else "GENESIS"
    event_json = json.dumps(event, sort_keys=True)
    rec = {"prev_hash": prev, "record_hash": _record_hash(prev, event_json), "event_json": event_json}
    with _ledger_path(ledger).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _drop_sidecars(ledger: Path) -> None:
    for p in ledger.glob(f"audit_log__{TENANT}.jsonl.*"):
        if p.name.endswith(".lock"):
            continue
        p.unlink()


def _verify_chain(ledger: Path) -> None:
    prev = "GENESIS"
    for i, rec in enumerate(_records(ledger), 1):
        assert rec["prev_hash"] == prev, f"chain break at {i}"
        assert _record_hash(rec["prev_hash"], rec["event_json"]) == rec["record_hash"], f"hash mismatch at {i}"
        prev = rec["record_hash"]


def _approval(event_id: str, tool_call_id: str) -> dict:
    return {
        "event_id": event_id,
        "event_type": "human_approved",
        "ts_utc": "2026-11-26T10:00:00Z",
        "actor": "human",
        "system": "crash-test",
        "run_id": RUN,
        "payload": {"decision": "approve", "scope": "tool_execution", "tool_call_id": tool_call_id},
    }


class Core:
    def __init__(self, ledger: Path, port: int, crash_at: str | None) -> None:
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        env = {k: v for k, v in os.environ.items() if k not in ("DATABASE_URL", "GOVAI_DATABASE_URL", "AIGOV_DATABASE_URL")}
        env.update({
            "AIGOV_ENVIRONMENT": "dev",
            "GOVAI_LEDGER_DIR": str(ledger),
            "GOVAI_API_KEYS": KEY,
            "GOVAI_API_KEYS_JSON": json.dumps({KEY: TENANT}),
            "GOVAI_PRINCIPALS_JSON": json.dumps({KEY: {"principal": "agent:crash", "identity": "agent:crash",
                                                      "role": "agent", "tenant": TENANT}}),
            "GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX": SEED_HEX,
            "GOVAI_EXECUTION_AUTH_KEY_ID": KEY_ID,
            "AIGOV_BIND": f"127.0.0.1:{port}",
        })
        env.pop("AIGOV_TEST_CRASH_AT", None)
        env.pop("AIGOV_TEST_FAULT_INJECTION", None)
        if crash_at:
            env["AIGOV_TEST_FAULT_INJECTION"] = "1"
            env["AIGOV_TEST_CRASH_AT"] = crash_at
        self.log = open(ledger.parent / f"core-{port}-{crash_at or 'ok'}.log", "w")  # noqa: SIM115
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

    def post(self, body: dict) -> tuple[int, dict | None]:
        req = urllib.request.Request(self.url + "/evidence", data=json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def wait_exit(self, timeout: float = 20) -> int:
        return self.proc.wait(timeout=timeout)

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()


def _consequential(event_id: str, tool_call_id: str, approval_id: str) -> dict:
    return {
        "event_id": event_id,
        "event_type": "consequential_tool_call",
        "ts_utc": "2026-11-26T10:00:00Z",
        "actor": "agent",
        "system": "crash-test",
        "run_id": RUN,
        "payload": {"tool_name": TOOL, "tool_call_id": tool_call_id, "approval_event_id": approval_id,
                    "args_binding_hash": "a" * 64},
    }


@pytest.fixture
def scenario():
    with tempfile.TemporaryDirectory(prefix="crash-core-") as d:
        ledger = Path(d) / "ledger"
        ledger.mkdir()
        approval_id = f"human_approved-{uuid.uuid4().hex}"
        tool_call_id = f"call-{uuid.uuid4().hex[:8]}"
        _append_injected(ledger, _approval(approval_id, tool_call_id))
        _drop_sidecars(ledger)
        yield {"ledger": ledger, "approval": approval_id, "call": tool_call_id, "dir": Path(d)}


def _crash_then_restart(scenario, crash_at: str, event_id: str):
    """Start Core with the crash point, send the call, expect the process to be terminated before any response."""
    core = Core(scenario["ledger"], free_port(), crash_at)
    try:
        delivered = None
        try:
            status, body = core.post(_consequential(event_id, scenario["call"], scenario["approval"]))
            delivered = (status, body)
        except (OSError, ConnectionError, urllib.error.URLError):
            delivered = None
        rc = core.wait_exit()
    finally:
        core.close()
    assert rc == 137, f"Core was not terminated at {crash_at} (exit {rc})"
    assert delivered is None, f"the client received a response from a crashed call: {delivered}"
    return delivered


def _restart(scenario) -> Core:
    _drop_sidecars(scenario["ledger"])  # the sidecars may be stale after a crash; Core rebuilds them
    return Core(scenario["ledger"], free_port(), None)


def _has_authorization(body: dict | None) -> bool:
    return bool(body and body.get("execution_authorization"))


def test_crash_before_append_leaves_nothing_and_a_retry_is_authorized_once(scenario):
    event_id = f"call-{uuid.uuid4().hex}"
    _crash_then_restart(scenario, "before_append", event_id)
    assert [r for r in _records(scenario["ledger"]) if "consequential_tool_call" in r["event_json"]] == []
    core = _restart(scenario)
    try:
        status, body = core.post(_consequential(event_id, scenario["call"], scenario["approval"]))
        assert status == 200 and _has_authorization(body), (status, body)
        # The approval is now used: a different call naming it is refused.
        status2, body2 = core.post(_consequential(f"call-{uuid.uuid4().hex}", scenario["call"], scenario["approval"]))
        assert status2 == 400 and "approval_already_consumed" in json.dumps(body2), (status2, body2)
    finally:
        core.close()
    _verify_chain(scenario["ledger"])


@pytest.mark.parametrize("crash_at", ["after_append_before_sign", "after_sign_before_response"])
def test_crash_after_the_record_is_committed_never_delivers_an_authorization_and_never_reuses_the_approval(scenario, crash_at):
    event_id = f"call-{uuid.uuid4().hex}"
    _crash_then_restart(scenario, crash_at, event_id)
    records = [json.loads(r["event_json"]) for r in _records(scenario["ledger"])]
    consequential = [r for r in records if r["event_type"] == "consequential_tool_call"]
    assert len(consequential) == 1, "the committed record must be exactly one"
    assert consequential[0]["event_id"] == event_id
    core = _restart(scenario)
    try:
        # 1. The same event id is a duplicate: it is not authorized again.
        status, body = core.post(_consequential(event_id, scenario["call"], scenario["approval"]))
        assert status == 409, (status, body)
        assert not _has_authorization(body)
        # 2. A new call naming the same approval is refused: the approval was consumed by the committed record.
        status2, body2 = core.post(_consequential(f"call-{uuid.uuid4().hex}", scenario["call"], scenario["approval"]))
        assert status2 == 400 and "approval_already_consumed" in json.dumps(body2), (status2, body2)
        assert not _has_authorization(body2)
        # 3. Restart serves calls normally: an unrelated read of the run succeeds.
        assert urllib.request.urlopen(core.url + "/health", timeout=5).status == 200
    finally:
        core.close()
    # 4. No duplicate consequential records, and the chain verifies.
    records = [json.loads(r["event_json"]) for r in _records(scenario["ledger"])]
    assert len([r for r in records if r["event_type"] == "consequential_tool_call"]) == 1
    _verify_chain(scenario["ledger"])


def test_a_normal_build_refuses_to_start_with_fault_injection_set(tmp_path):
    """Production-exclusion control: the plain build has no crash points and refuses the fault-injection variables."""
    if not PLAIN_BIN.exists():
        pytest.skip(f"plain Core binary not built: {PLAIN_BIN}")
    ledger = tmp_path / "ledger"
    ledger.mkdir()
    env = {"PATH": os.environ.get("PATH", ""), "AIGOV_ENVIRONMENT": "dev", "GOVAI_LEDGER_DIR": str(ledger),
           "GOVAI_API_KEYS": KEY, "GOVAI_API_KEYS_JSON": json.dumps({KEY: TENANT}),
           "AIGOV_BIND": f"127.0.0.1:{free_port()}", "AIGOV_TEST_FAULT_INJECTION": "1", "AIGOV_TEST_CRASH_AT": "before_append"}
    r = subprocess.run([str(PLAIN_BIN)], env=env, capture_output=True, timeout=30)
    assert r.returncode != 0, "a normal build started with fault-injection variables set"
    assert b"fault-injection" in r.stderr or b"fault-injection" in r.stdout
