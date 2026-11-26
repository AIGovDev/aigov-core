"""Two Core processes on one ledger directory (one host, a shared filesystem with working flock).

The test that reproduced the defect: before the cross-process ledger lock, two instances interleaved appends, corrupted the
hash chain, and left the tenant's ledger unreadable (HTTP 500 "ledger corruption before EOF"). These tests run against a real
Core binary. Set AIGOV_TEST_CORE_BIN to the binary (default: rust/target/release/aigov_audit).
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
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("AIGOV_TEST_CORE_BIN", REPO / "rust" / "target" / "release" / "aigov_audit"))
pytestmark = pytest.mark.skipif(not BIN.exists(), reason=f"Core binary not built: {BIN}")
KEY = "dist-ledger-key"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Core:
    def __init__(self, ledger: Path, port: int) -> None:
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        env = {k: v for k, v in os.environ.items() if k not in ("DATABASE_URL", "GOVAI_DATABASE_URL", "AIGOV_DATABASE_URL")}
        env.update({
            "AIGOV_ENVIRONMENT": "dev",
            "GOVAI_LEDGER_DIR": str(ledger),
            "GOVAI_API_KEYS": KEY,
            "GOVAI_API_KEYS_JSON": json.dumps({KEY: "t1"}),
            "GOVAI_PRINCIPALS_JSON": json.dumps({KEY: {"principal": "agent:dist", "identity": "agent:dist",
                                                      "role": "agent", "tenant": "t1"}}),
            "AIGOV_BIND": f"127.0.0.1:{port}",
        })
        self.log = open(ledger.parent / f"core-{port}.log", "w")  # noqa: SIM115
        self.proc = subprocess.Popen([str(BIN)], env=env, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                if urllib.request.urlopen(self.url + "/health", timeout=2).status == 200:
                    return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("Core did not start")

    def close(self) -> None:
        self.proc.terminate()
        self.proc.wait(timeout=20)
        self.log.close()


def _post(url: str, run_id: str, event_id: str) -> int:
    body = {"event_id": event_id, "event_type": "tool_call", "ts_utc": "2026-11-26T10:00:00Z", "actor": "agent",
            "system": "dist", "run_id": run_id, "payload": {"tool_name": "create_file", "n": event_id}}
    req = urllib.request.Request(url + "/evidence", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _verify_chain(path: Path) -> tuple[int, int, int]:
    """(records, duplicate event ids, chain violations) for one ledger file."""
    prev, ids, dups, bad, n = "GENESIS", set(), 0, 0, 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        n += 1
        rec = json.loads(line)
        if rec["prev_hash"] != prev:
            bad += 1
        if hashlib.sha256((rec["prev_hash"] + "\n" + rec["event_json"]).encode()).hexdigest() != rec["record_hash"]:
            bad += 1
        eid = json.loads(rec["event_json"])["event_id"]
        dups += eid in ids
        ids.add(eid)
        prev = rec["record_hash"]
    return n, dups, bad


@pytest.fixture
def two_cores():
    with tempfile.TemporaryDirectory(prefix="dist-core-") as d:
        ledger = Path(d) / "ledger"
        ledger.mkdir()
        a, b = Core(ledger, _free_port()), Core(ledger, _free_port())
        try:
            yield a, b, ledger / "audit_log__t1.jsonl"
        finally:
            a.close()
            b.close()


def test_concurrent_appends_through_two_instances_keep_one_valid_chain(two_cores):
    a, b, log = two_cores
    run = "run-dist-" + uuid.uuid4().hex[:8]
    jobs = [(a.url if i % 2 == 0 else b.url, f"evt-{i}") for i in range(200)]
    with ThreadPoolExecutor(max_workers=16) as pool:
        codes = list(pool.map(lambda j: _post(j[0], run, j[1]), jobs))
    assert Counter(codes) == Counter({200: 200}), Counter(codes)
    records, dups, bad = _verify_chain(log)
    assert records == 200 and dups == 0 and bad == 0
    # The ledger is readable through either instance afterwards.
    assert _post(a.url, run, "after-read-check") == 200


def test_a_duplicate_event_id_is_accepted_exactly_once_across_instances(two_cores):
    a, b, _log = two_cores
    run = "run-dup-" + uuid.uuid4().hex[:8]
    outcomes = []
    for trial in range(10):
        eid = f"dup-{trial}-{uuid.uuid4().hex}"
        with ThreadPoolExecutor(max_workers=2) as pool:
            codes = list(pool.map(lambda u: _post(u, run, eid), [a.url, b.url]))
        outcomes.append(tuple(sorted(codes)))
    assert Counter(outcomes) == Counter({(200, 409): 10}), Counter(outcomes)
