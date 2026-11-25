"""Shared harness for the executor lifecycle tests: a file-backed Core stand-in, a side-effect recorder, signed
authorizations, and a child-process runner that can be killed at a named boundary.

Real process termination: ``child_main`` runs an executor step in its own process. A fault point set to ``crash``
calls ``os._exit``, which skips every ``finally`` block and every cleanup, the way a power cut or a kill -9 does. The
store's transactions are the only thing that survives.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import json
import os
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aigov_py.canonical_json import canonical_bytes
from aigov_py.trusted.authorization import AUTH_DOMAIN, AUTH_SCHEMA
from aigov_py.trusted.core import CoreDecision, Decision, new_event
from aigov_py.trusted.tools import ToolSpec, args_binding_hash
from nacl.signing import SigningKey

TOOL = ToolSpec("create_file", "repo:write", "write", "repo_id")
TOOLS = {TOOL.name: TOOL}
AUDIENCE = "executor:ref"
RUN = "run-lifecycle"
ARGS = {"repo_id": "acme/app", "path": "docs/A.md", "content": "approved"}


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def new_authorization_key() -> tuple[str, str]:
    sk = SigningKey.generate()
    return bytes(sk).hex(), b64(bytes(sk.verify_key))


def signed_authorization(
    seed_hex: str,
    *,
    auth_id: str | None = None,
    args: dict | None = None,
    expires_at: datetime | None = None,
    policy_revision: str = "rev-1",
    run_id: str = RUN,
) -> dict[str, Any]:
    key = SigningKey(bytes.fromhex(seed_hex))
    digest = args_binding_hash(TOOL, args or ARGS)
    expires = expires_at or (datetime.now(UTC) + timedelta(hours=1))
    payload = {
        "schema": AUTH_SCHEMA,
        "authorization_id": auth_id or f"auth_{uuid.uuid4().hex}",
        "run_id": run_id,
        "tool_name": TOOL.name,
        "args_binding_hash": digest,
        "policy_revision": policy_revision,
        "executor_audience": AUDIENCE,
        "approval_event_id": f"human_approved-{uuid.uuid4().hex}",
        "consequential_record_hash": "f" * 64,
        "issued_at_utc": datetime.now(UTC).isoformat(),
        "expires_at_utc": expires.isoformat(),
    }
    sig = key.sign(AUTH_DOMAIN + canonical_bytes(payload)).signature
    return {"payload": payload, "signature": b64(sig)}


class FileCore:
    """A Core stand-in whose state is a JSON file, so that separate processes see the same ledger.

    It answers the three calls the executor makes: status, submit, export. It refuses a duplicate event id the way Core
    does (409, which the client maps to INDETERMINATE). ``down`` makes every call raise OSError, as an unreachable Core
    does.
    """

    actor = "executor:ref"
    system = "aigov-test"

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        if not self._path.exists():
            self._write({"events": [], "revoked": [], "down": False, "submits": 0})

    def _read(self) -> dict[str, Any]:
        with open(self._path, encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_SH)
            return json.load(fh)

    def _write(self, data: dict[str, Any]) -> None:
        tmp = self._path.with_suffix(".tmp")
        with open(self._path.with_suffix(".lock"), "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, self._path)

    @contextlib.contextmanager
    def _mutate(self):  # type: ignore[no-untyped-def]
        with open(self._path.with_suffix(".lock"), "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = json.loads(self._path.read_text(encoding="utf-8"))
            yield data
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, self._path)

    def set_down(self, down: bool) -> None:
        with self._mutate() as d:
            d["down"] = down

    def revoke(self, auth_id: str) -> None:
        with self._mutate() as d:
            d["revoked"].append(auth_id)

    def _check_up(self, data: dict[str, Any]) -> None:
        if data["down"]:
            raise ConnectionError("core is down (test)")

    def status(self, run_id: str, authorization_id: str) -> tuple[int, Any]:
        data = self._read()
        self._check_up(data)
        receipted = any(
            e["event_type"] == "execution_receipt"
            and e["payload"].get("execution_authorization_id") == authorization_id
            for e in data["events"]
        )
        if receipted:
            state = "receipt_recorded"
        elif authorization_id in data["revoked"]:
            state = "revoked"
        else:
            state = "authorized"
        return 200, {"state": state, "authorization_id": authorization_id}

    def submit(self, event) -> CoreDecision:  # type: ignore[no-untyped-def]
        with self._mutate() as d:
            if d["down"]:
                raise ConnectionError("core is down (test)")
            d["submits"] += 1
            if any(e["event_id"] == event.event_id for e in d["events"]):
                return CoreDecision(
                    Decision.INDETERMINATE, "core_http_409", None, None, 409, 0.0
                )
            d["events"].append(
                {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "run_id": event.run_id,
                    "payload": event.payload,
                }
            )
        return CoreDecision(
            Decision.ALLOW, "accepted", event.event_id, "h" * 64, 200, 0.0
        )

    def export(self, run_id: str) -> dict[str, Any]:
        data = self._read()
        self._check_up(data)
        return {
            "evidence_events": [
                {
                    "event_id": e["event_id"],
                    "event_type": e["event_type"],
                    "payload": e["payload"],
                }
                for e in data["events"]
                if e["run_id"] == run_id
            ]
        }

    def receipts_for(self, auth_id: str) -> list[dict[str, Any]]:
        return [
            e
            for e in self._read()["events"]
            if e["event_type"] == "execution_receipt"
            and e["payload"].get("execution_authorization_id") == auth_id
        ]

    def submit_count(self) -> int:
        return self._read()["submits"]


class SideEffects:
    """Records each real side effect as one line. The count of lines is the number of times the action ran."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.touch()

    def performer(self, *, crash_inside: bool = False, raise_inside: bool = False):  # type: ignore[no-untyped-def]
        def perform(
            tool: str, arguments: dict[str, Any], execution_id: str
        ) -> dict[str, Any]:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps({"tool": tool, "execution_id": execution_id}) + "\n"
                )
                fh.flush()
                os.fsync(fh.fileno())
            if crash_inside:
                os._exit(
                    137
                )  # the side effect has happened; the process dies before it can report
            if raise_inside:
                raise RuntimeError("connection reset by the external system")
            return {
                "success": True,
                "data": {"path": arguments["path"]},
                "blocked_reason": None,
            }

        return perform

    def count(self) -> int:
        return sum(
            1
            for line in self._path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )


def make_executor(
    *,
    db: Path,
    core: Any,
    public_key: str,
    performer,
    fault=None,
    clock=None,  # type: ignore[no-untyped-def]
    lease_seconds: int = 300,
    worker_id: str | None = None,
    audience: str = AUDIENCE,
):
    from aigov_py.trusted.executor import Executor
    from aigov_py.trusted.store import ExecutionStore

    kwargs: dict[str, Any] = {}
    if clock is not None:
        kwargs["clock"] = clock
    return Executor(
        core=core,
        public_key_b64=public_key,
        audience=audience,
        store=ExecutionStore(db),
        tools=TOOLS,
        performer=performer,
        lease_seconds=lease_seconds,
        worker_id=worker_id,
        fault=fault,
        **kwargs,
    )


def child_main(job_path: str) -> int:
    """Run one executor step in this process. Exit 137 if a crash point was reached; otherwise print the outcome."""
    job = json.loads(Path(job_path).read_text(encoding="utf-8"))
    crash_at = job.get("crash_at")

    def fault(point: str) -> None:
        if crash_at == point:
            os._exit(137)

    if job["step"] == "reconcile":
        return _child_reconcile(job, crash_at)
    if job.get("core_url"):
        from aigov_py.trusted.core import CoreClient

        core = CoreClient(job["core_url"], job["executor_key"])
    else:
        core = FileCore(Path(job["core"]))
    effects = SideEffects(Path(job["effects"]))
    performer = effects.performer(
        crash_inside=job.get("crash_inside", False),
        raise_inside=job.get("raise_inside", False),
    )
    executor = make_executor(
        db=Path(job["db"]),
        core=core,
        public_key=job["public_key"],
        performer=performer,
        fault=fault,
        worker_id=job.get("worker"),
        lease_seconds=int(job.get("lease", 300)),
        audience=job.get("audience", AUDIENCE),
    )
    if job["step"] == "execute":
        out = executor.execute(
            run_id=job["run_id"],
            tool=TOOL.name,
            arguments=job["arguments"],
            signed=job["signed"],
        )
        result = {
            "reason": out.reason,
            "executed": out.executed,
            "state": out.execution_state,
        }
    else:
        actions = executor.recover()
        result = {"actions": [a.as_dict() for a in actions]}
    print(json.dumps(result))
    return 0


def _child_reconcile(job: dict[str, Any], crash_at: str | None) -> int:
    from aigov_py.trusted.reconcile import ReconcilerRegistry, apply_reconciliation
    from aigov_py.trusted.store import ExecutionStore

    def fault(point: str) -> None:
        if crash_at == point:
            os._exit(137)

    registry = ReconcilerRegistry(keys=job["registry"]["reconcilers"])
    store = ExecutionStore(Path(job["db"]), fault=fault)
    evidence = apply_reconciliation(
        store, job["envelope"], registry, receipt_event_id="execution_receipt-child"
    )
    print(json.dumps({"reconciled": evidence["authorization_id"]}))
    return 0


def run_child(job: dict[str, Any], workdir: Path) -> tuple[int, str]:
    """Run a step in a separate process. Returns (exit code, stdout)."""
    import subprocess

    workdir.mkdir(parents=True, exist_ok=True)
    job_path = workdir / f"job-{uuid.uuid4().hex[:8]}.json"
    job_path.write_text(json.dumps(job), encoding="utf-8")
    tests_dir = str(Path(__file__).resolve().parent)
    code = f"import sys; sys.path.insert(0, {tests_dir!r}); import _lifecycle_harness as h; sys.exit(h.child_main({str(job_path)!r}))"
    # The working directory is the scratch directory, never the repository root (its aigov_py shim would shadow the package).
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
        cwd=str(workdir),
    )
    return proc.returncode, proc.stdout


def now_plus(seconds: int) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=seconds)


__all__ = [
    "ARGS",
    "AUDIENCE",
    "RUN",
    "TOOL",
    "TOOLS",
    "FileCore",
    "SideEffects",
    "b64",
    "child_main",
    "make_executor",
    "new_authorization_key",
    "now_plus",
    "run_child",
    "signed_authorization",
]

_ = (time, new_event)  # kept for test authors who extend the harness
