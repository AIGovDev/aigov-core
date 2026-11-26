"""R-6, policy changes: a process serving a superseded revision stops writing evidence.

Two staging Core processes share one PostgreSQL database (the policy revision anchor). Process A starts on revision 1. Process B
starts on revision 2 and commits it to the anchor. Afterwards A must refuse evidence writes (POLICY_REVISION_SUPERSEDED), because
it serves a revision the anchor has superseded; B must keep accepting them. A missing anchor row is a refusal too
(POLICY_ANCHOR_UNAVAILABLE), and writes resume once the row is restored.

Requires AIGOV_TEST_POLICY_PG_URL, a disposable PostgreSQL database, and the release binary. The test drops nothing else.
"""

from __future__ import annotations

import importlib.util
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

REPO = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("AIGOV_TEST_CORE_BIN", REPO / "rust" / "target" / "release" / "aigov_audit"))
PG_URL = os.environ.get("AIGOV_TEST_POLICY_PG_URL", "").strip()
pytestmark = [
    pytest.mark.skipif(not PG_URL, reason="set AIGOV_TEST_POLICY_PG_URL to a disposable PostgreSQL database"),
    pytest.mark.skipif(not BIN.exists(), reason=f"Core binary not built: {BIN}"),
]

AGENT = "agent-policy-r6"
TENANT = "t-policy"


def _harness():
    spec = importlib.util.spec_from_file_location("staging_policy_verify", REPO / "scripts" / "staging_policy_verify.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def harness():
    return _harness()


@pytest.fixture
def bundles(harness):
    """Revisions 1 and 2 of one policy. Revisions of a policy share its id, which is what the anchor compares."""
    policy_id = f"r6-policy-{uuid.uuid4().hex[:8]}"
    with tempfile.TemporaryDirectory(prefix="r6-policy-") as d:
        work = Path(d)
        keys = harness.Keys()
        trust = harness.trust_json(keys.pub_b64)
        out = {}
        for v in ("1", "2"):
            doc = harness.synthetic_policy(policy_id=policy_id, version=v)
            out[v] = harness.write_signed_bundle(work / f"bundle-{v}.json", doc, seed_b64=keys.seed_b64, expires=harness.FUTURE)
        yield {"rev1": out["1"], "rev2": out["2"], "trust": trust, "policy_id": policy_id}


class Process:
    def __init__(self, harness, work: Path, name: str, bundle: Path, trust: str, pg: str) -> None:
        d = work / name
        (d / "ledger").mkdir(parents=True)
        (d / "policies").mkdir()
        self.port = harness._free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        env = {k: v for k, v in os.environ.items() if not k.startswith(("AIGOV_", "GOVAI_")) and k != "DATABASE_URL"}
        env.update({
            "AIGOV_ENVIRONMENT": "staging",
            "GOVAI_LEDGER_DIR": str(d / "ledger"),
            "AIGOV_BIND": f"127.0.0.1:{self.port}",
            "AIGOV_POLICY_DIR": str(d / "policies"),
            "AIGOV_POLICY_BUNDLE_FILE": str(bundle),
            "AIGOV_POLICY_TRUST_ED25519_JSON": trust,
            "GOVAI_API_KEYS": AGENT,
            "GOVAI_API_KEYS_JSON": json.dumps({AGENT: TENANT}),
            "GOVAI_PRINCIPALS_JSON": json.dumps({AGENT: {"principal": "agent:r6", "identity": "agent:r6", "role": "agent", "tenant": TENANT}}),
            "GOVAI_DATABASE_URL": pg,
            "GOVAI_AUTO_MIGRATE": "true",
            "GOVAI_API_USAGE_STORE": "memory",
        })
        self.log_path = d / "core.log"
        self.log = open(self.log_path, "w")  # noqa: SIM115
        self.proc = subprocess.Popen([str(BIN)], env=env, stdout=self.log, stderr=subprocess.STDOUT)

    def wait_ready(self) -> str | None:
        """None when the process serves; otherwise the refusal text it printed."""
        for _ in range(300):
            if self.proc.poll() is not None:
                return self.log_path.read_text().strip().splitlines()[-1] if self.log_path.read_text().strip() else "exited"
            try:
                if urllib.request.urlopen(self.url + "/health", timeout=1).status == 200:
                    return None
            except OSError:
                time.sleep(0.1)
        return "timed out"

    def ingest(self) -> tuple[int, dict]:
        body = {
            "event_id": f"d-{uuid.uuid4().hex}",
            "event_type": "ai_discovery_reported",
            "ts_utc": "2026-11-26T10:00:00Z",
            "actor": "a",
            "system": "s",
            "run_id": f"r-{uuid.uuid4().hex[:8]}",
            "payload": {"openai": False},
        }
        req = urllib.request.Request(
            self.url + "/evidence",
            data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {AGENT}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()


def test_a_superseded_revision_stops_writes_and_a_missing_anchor_refuses(harness, bundles, tmp_path):
    import psycopg

    policy_id = bundles["policy_id"]
    a = Process(harness, tmp_path, "a", bundles["rev1"], bundles["trust"], PG_URL)
    b = None
    try:
        assert a.wait_ready() is None, a.log_path.read_text()[-400:]
        status, body = a.ingest()
        assert status == 200, body
        assert body["policy_version"] == "1"

        # B starts on revision 2 and commits it to the shared anchor.
        b = Process(harness, tmp_path, "b", bundles["rev2"], bundles["trust"], PG_URL)
        assert b.wait_ready() is None, b.log_path.read_text()[-400:]
        status_b, body_b = b.ingest()
        assert status_b == 200 and body_b["policy_version"] == "2", body_b

        # A serves revision 1, which the anchor has superseded. It must refuse, and it must write nothing.
        status_a, body_a = a.ingest()
        assert status_a == 409, body_a
        assert body_a["error"]["code"] == "POLICY_REVISION_SUPERSEDED", body_a
        status_b2, _ = b.ingest()
        assert status_b2 == 200

        # The anchor row is removed: nothing can be confirmed, so the process refuses, and it recovers when the row returns.
        with psycopg.connect(PG_URL, autocommit=True) as conn:
            row = conn.execute("SELECT revision, digest_sha256 FROM policy_revision_anchor WHERE policy_id = %s", (policy_id,)).fetchone()
            assert row == (2, row[1]), row
            conn.execute("DELETE FROM policy_revision_anchor WHERE policy_id = %s", (policy_id,))
        status_b3, body_b3 = b.ingest()
        assert status_b3 == 503 and body_b3["error"]["code"] == "POLICY_ANCHOR_UNAVAILABLE", body_b3
        with psycopg.connect(PG_URL, autocommit=True) as conn:
            conn.execute("INSERT INTO policy_revision_anchor (policy_id, revision, digest_sha256) VALUES (%s, %s, %s)", (policy_id, row[0], row[1]))
        status_b4, _ = b.ingest()
        assert status_b4 == 200
    finally:
        a.close()
        if b:
            b.close()
        with psycopg.connect(PG_URL, autocommit=True) as conn:
            conn.execute("DELETE FROM policy_revision_anchor WHERE policy_id = %s", (policy_id,))
