"""R-6: authorization issuance across independent Core processes during key rotation and revocation.

Three separate Core processes share one ledger directory, one PostgreSQL key-registry anchor, and one registry file. They run
in registry mode. Workers send consequential calls through all three processes at once. While they run, an operator rotates
the signing key (exe-a -> exe-b) and then revokes the old key (exe-a), using the same registry the processes read.

Checked afterwards, from the responses, the registry log, and the ledger (not from the processes' own reports):

- every authorization verifies against the public key of its key id (the registry key, not one the response supplies);
- no authorization is signed by exe-a at or after the revocation's issued time;
- every authorization after the rotation names exe-b;
- each approval authorizes at most one call; duplicates are refused with approval_already_consumed;
- the ledger chain verifies, and the number of consequential records equals the number of authorizations;
- every authorization carries the policy revision that Core reports as in force.

Requires AIGOV_TEST_REGISTRY_PG_URL (a disposable PostgreSQL database) and the release binary.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

import pytest

from aigov_py.trusted import keys as K
from aigov_py.trusted.authorization import verify_authorization_signature
from aigov_py.trusted.registry_anchor import PostgresAnchor
from test_crash_consistency_core import (
    SEED_HEX,  # noqa: F401  (kept for parity with the other Core tests)
    _append_injected,
    _approval,
    _consequential,
    _drop_sidecars,
    _records,
    _verify_chain,
    free_port,
)
from test_registry_postgres import _apply_migration_0004
from _registry_world import World

REPO = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("AIGOV_TEST_CORE_BIN", REPO / "rust" / "target" / "release" / "aigov_audit"))
PG_URL = os.environ.get("AIGOV_TEST_REGISTRY_PG_URL", "").strip()
pytestmark = [
    pytest.mark.skipif(not PG_URL, reason="set AIGOV_TEST_REGISTRY_PG_URL to a disposable PostgreSQL database"),
    pytest.mark.skipif(not BIN.exists(), reason=f"Core binary not built: {BIN}"),
]

AGENT = "agent-r6"
TENANT = "t1"  # the injection helper writes audit_log__t1.jsonl
RUN = "run-r6"
TOOL = "create_file"
CORES = 3
APPROVALS = 60


def _write_seed(seeds: Path, kid: str, seed_b64: str) -> None:
    p = seeds / f"{kid}.seed"
    p.write_text(seed_b64 + "\n")
    os.chmod(p, 0o600)


class Core:
    def __init__(self, ledger: Path, env_extra: dict[str, str], log: Path) -> None:
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        env = {k: v for k, v in os.environ.items() if k not in ("DATABASE_URL", "GOVAI_DATABASE_URL", "AIGOV_DATABASE_URL")}
        env.update({
            "AIGOV_ENVIRONMENT": "dev",
            "GOVAI_LEDGER_DIR": str(ledger),
            "GOVAI_API_KEYS": AGENT,
            "GOVAI_API_KEYS_JSON": json.dumps({AGENT: TENANT}),
            "GOVAI_PRINCIPALS_JSON": json.dumps({AGENT: {"principal": "agent:r6", "identity": "agent:r6", "role": "agent", "tenant": TENANT}}),
            "AIGOV_BIND": f"127.0.0.1:{self.port}",
        })
        env.update(env_extra)
        self.log = open(log, "w")  # noqa: SIM115
        self.proc = subprocess.Popen([str(BIN)], env=env, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"Core exited at start: {self.proc.returncode}: {log.read_text()[-500:]}")
            try:
                if urllib.request.urlopen(self.url + "/health", timeout=2).status == 200:
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("Core did not start")

    def post(self, body: dict) -> tuple[int, dict]:
        req = urllib.request.Request(
            self.url + "/evidence",
            data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {AGENT}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
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


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


@pytest.fixture
def world():
    rid = f"r6-{uuid.uuid4().hex[:12]}"
    _apply_migration_0004()
    with tempfile.TemporaryDirectory(prefix="r6-") as d:
        root = Path(d)
        w = World(root, registry_id=rid, anchor=PostgresAnchor(PG_URL, rid))
        w.install_operator("ops-admin")
        w.register_active("exe-a")
        (root / "seeds").mkdir()
        _write_seed(root / "seeds", "exe-a", w.keys["exe-a"][0])
        try:
            yield w
        finally:
            import psycopg

            with psycopg.connect(PG_URL, autocommit=True) as conn:
                conn.execute("DELETE FROM key_registry_anchor WHERE registry_id = %s", (rid,))


def test_rotation_and_revocation_during_concurrent_issuance_across_three_processes(world, tmp_path):
    ledger = tmp_path / "ledger"
    ledger.mkdir()
    approvals = [(f"human_approved-{uuid.uuid4().hex}", f"call-{i}-{uuid.uuid4().hex[:6]}") for i in range(APPROVALS)]
    for appr_id, tool_call in approvals:
        _append_injected(ledger, _approval(appr_id, tool_call))
    _drop_sidecars(ledger)

    registry_env = {
        "AIGOV_KEY_REGISTRY_PATH": str(world.registry_path),
        "AIGOV_KEY_REGISTRY_TRUST_FILE": str(world.trust_path),
        "AIGOV_KEY_REGISTRY_ANCHOR_URL": PG_URL,
        "AIGOV_EXECUTION_AUTH_SIGNING_SEEDS_DIR": str(world.root / "seeds"),
    }
    cores = [Core(ledger, registry_env, tmp_path / f"core-{i}.log") for i in range(CORES)]
    results: list[dict] = []
    lock = threading.Lock()
    done = threading.Event()
    ops: dict[str, str] = {}

    def operator() -> None:
        # Rotate once a third of the calls are in, revoke the old key once two thirds are in.
        while len(results) < APPROVALS // 3 and not done.is_set():
            time.sleep(0.02)
        world.rotate("exe-a", "exe-b")
        _write_seed(world.root / "seeds", "exe-b", world.keys["exe-b"][0])
        ops["rotated_at"] = datetime.now().astimezone().isoformat()
        while len(results) < (2 * APPROVALS) // 3 and not done.is_set():
            time.sleep(0.02)
        world.revoke("exe-a")
        ops["revoked_at"] = datetime.now().astimezone().isoformat()

    def worker(core: Core, mine: list[tuple[str, str]]) -> None:
        for appr_id, tool_call in mine:
            body = _consequential(f"call-{uuid.uuid4().hex}", tool_call, appr_id)
            status, resp = core.post(body)
            with lock:
                results.append({"approval": appr_id, "status": status, "body": resp, "core": core.port})
            # A second process tries the same approval with a new event id. It must be refused.
            other = cores[(cores.index(core) + 1) % len(cores)]
            status2, resp2 = other.post(_consequential(f"call-{uuid.uuid4().hex}", tool_call, appr_id))
            with lock:
                results.append({"approval": appr_id, "status": status2, "body": resp2, "core": other.port, "dup": True})

    try:
        op = threading.Thread(target=operator)
        op.start()
        threads = [
            threading.Thread(target=worker, args=(cores[i], approvals[i::CORES])) for i in range(CORES)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(600)
        done.set()
        op.join(120)
    finally:
        for c in cores:
            c.close()

    # --- Verification from the outside: responses, registry log, ledger.
    registry = world.reg
    registry.refresh()
    revoke_issued = None
    for ev in world.events():
        req = ev.get("request", {}).get("payload", {})
        if req.get("op") == "revoke" and req.get("kid") == "exe-a":
            revoke_issued = _parse(req["issued_at_utc"])
    assert revoke_issued is not None, "the revocation was not recorded in the registry log"

    authorized = [r for r in results if r["status"] == 200 and r["body"].get("execution_authorization")]
    dups = [r for r in results if r.get("dup")]
    # 1. Every authorization verifies against the registry key for its key id.
    kids_seen = set()
    for r in authorized:
        signed = r["body"]["execution_authorization"]
        kid = signed["payload"].get("signing_key_id")
        assert kid in ("exe-a", "exe-b"), f"unexpected key id {kid}"
        kids_seen.add(kid)
        pub = registry.get(kid).public_key_b64
        verify_authorization_signature(signed, pub)
        # 2. No exe-a authorization at or after the revocation's issued time.
        issued = _parse(signed["payload"]["issued_at_utc"])
        if kid == "exe-a":
            assert issued < revoke_issued, f"exe-a authorized at {issued} after its revocation at {revoke_issued}"

    # 3. Each approval authorizes at most once, and every approval authorizes exactly once (its first call succeeds).
    per_approval: dict[str, int] = {}
    for r in authorized:
        per_approval[r["approval"]] = per_approval.get(r["approval"], 0) + 1
    assert all(n == 1 for n in per_approval.values()), f"an approval authorized twice: {[a for a, n in per_approval.items() if n > 1]}"
    # A call whose key was retired between preparing and signing is refused after its record is committed. Its approval is
    # then consumed, and the human must approve again. That is fail closed: no authorization exists for it. Every other
    # approval authorizes exactly once.
    signing_refused = [r for r in results if r["status"] != 200 and not r.get("dup")]
    for r in signing_refused:
        err = r["body"].get("error") or {}
        assert err.get("code") == "AUTHORIZATION_SIGNING_REFUSED", f"unexpected refusal: {r['body']}"
        assert "retired" in err.get("message", "") or "revoked" in err.get("message", ""), err
        assert r["approval"] not in per_approval, "a refused call has an authorization"
    assert len(per_approval) + len(signing_refused) == APPROVALS, (len(per_approval), len(signing_refused))

    # 4. Duplicate submissions are refused with approval_already_consumed, and nothing is authorized twice.
    for r in dups:
        assert r["status"] != 200 or not r["body"].get("execution_authorization"), f"duplicate authorized: {r}"
    assert all("approval_already_consumed" in json.dumps(r["body"]) for r in dups), "a duplicate was refused for another reason"

    # 5. The ledger chain verifies. It holds one consequential record per call that reached signing: each authorized call and
    #    each signing refusal (the record is committed first, which is why a refusal consumes its approval).
    _verify_chain(ledger)
    consequential = [r for r in _records(ledger) if "consequential_tool_call" in r["event_json"]]
    assert len(consequential) == len(authorized) + len(signing_refused), (len(consequential), len(authorized), len(signing_refused))

    # 6. Policy revision binding: every authorization names the revision its Core reports as in force.
    revisions = {r["body"].get("policy_version") for r in results if r["status"] == 200}
    assert len(revisions) == 1, f"policy revisions in responses: {revisions}"
    for r in authorized:
        assert r["body"]["execution_authorization"]["payload"]["policy_revision"] == next(iter(revisions))

    # Record what happened, for the evidence file.
    summary = {
        "approvals": APPROVALS,
        "cores": CORES,
        "authorized": len(authorized),
        "duplicates_refused": len(dups),
        "key_ids_seen": sorted(kids_seen),
        "exe_a_revoked_at_utc": revoke_issued.isoformat(),
        "signing_refusals": len(signing_refused),
        "refusals_by_code": {},
    }
    for r in results:
        if r["status"] != 200:
            code = (r["body"].get("error") or {}).get("code", str(r["status"]))
            summary["refusals_by_code"][code] = summary["refusals_by_code"].get(code, 0) + 1
    out = os.environ.get("AIGOV_R6_EVIDENCE")
    if out:
        Path(out).write_text(json.dumps(summary, indent=2) + "\n")
