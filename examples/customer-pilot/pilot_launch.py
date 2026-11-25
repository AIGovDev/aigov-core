"""Start and stop the pilot's AIGov Core, with Docker or with a release binary.

Docker mode creates a private network, a PostgreSQL 18 container, and a Core container from this repository's
Dockerfile. Every name carries the pilot prefix. Binary mode runs a release ``aigov_audit`` against a PostgreSQL
database that you provide. Both modes generate fresh identities, keys, and a signed policy for the run.

``stop`` removes only resources this pilot created, and only a state directory that carries the pilot's marker.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pilot_config import (
    AGENT_IDENTITY,
    APPROVER_IDENTITIES,
    AUTH_TTL_SECONDS,
    EXECUTOR_AUDIENCE,
    EXECUTOR_IDENTITY,
    TENANT,
    pilot_policy_document,
)
from trust_setup import build

PREFIX = "aigov-pilot"
MARKER = ".aigov-pilot-state"
DEFAULT_PORT = 18188
DEFAULT_IMAGE = "aigov-core:pilot"
PG_IMAGE = "postgres:18-alpine"
DB_NAME = "govai"
DB_USER = "govai"


@dataclass
class Running:
    mode: str
    core_url: str
    state_file: Path
    started_seconds: float
    details: dict[str, Any]


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], check=check, capture_output=True, text=True
    )


def _docker_ok(*args: str) -> bool:
    return (
        subprocess.run(
            ["docker", *args], capture_output=True, text=True, check=False
        ).returncode
        == 0
    )


def _wait(predicate, timeout_s: float, what: str) -> None:
    deadline = time.time() + timeout_s
    last: Exception | None = None
    while time.time() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:  # noqa: BLE001 - retry until the deadline
            last = exc
        time.sleep(1)
    raise SystemExit(f"timed out waiting for {what}: {last}")


def _health(url: str) -> bool:
    try:
        return urllib.request.urlopen(url + "/health", timeout=3).status == 200
    except OSError:
        return False


def _generated(state_dir: Path) -> dict[str, Any]:
    """Identities, keys, policy, and environment for one Core. Written under the state directory only."""
    if state_dir.exists():
        shutil.rmtree(state_dir)
    state_dir.mkdir(parents=True)
    (state_dir / MARKER).write_text(
        "created by the AIGov customer pilot; safe to remove with `pilot.py down`\n"
    )
    built = build(
        state_dir,
        approver_identities=APPROVER_IDENTITIES,
        document=pilot_policy_document(),
        tenant=TENANT,
        agent_principal=AGENT_IDENTITY,
        executor_principal=EXECUTOR_IDENTITY,
        executor_audience=EXECUTOR_AUDIENCE,
        auth_ttl_seconds=AUTH_TTL_SECONDS,
    )
    return built


def _write_state(
    state_dir: Path,
    built: dict[str, Any],
    core_url: str,
    mode: str,
    extra: dict[str, Any],
) -> Path:
    state_file = state_dir / "state.json"
    state_file.write_text(
        json.dumps(
            {**built["state"], "core_url": core_url, "mode": mode, **extra}, indent=2
        )
    )
    state_file.chmod(0o600)
    return state_file


def start_docker(state_dir: Path, port: int, image: str) -> Running:
    t0 = time.time()
    if not _docker_ok("info"):
        raise SystemExit(
            "Docker is not running. Start Docker, then run `pilot.py up` again."
        )
    if not _docker_ok("image", "inspect", image):
        repo = Path(__file__).resolve().parents[2]
        print(
            f"building {image} from {repo} (first run only; this takes several minutes) ...",
            flush=True,
        )
        subprocess.run(["docker", "build", "-t", image, str(repo)], check=True)
    if _docker_ok("container", "inspect", f"{PREFIX}-core"):
        raise SystemExit(f"{PREFIX}-core already exists. Run `pilot.py down` first.")

    built = _generated(state_dir)
    env = dict(built["env"])
    env["AIGOV_POLICY_DIR"] = "/app/policies"
    env["AIGOV_POLICY_BUNDLE_FILE"] = "/app/policies/policy.bundle.staging.json"
    pg_password = secrets.token_urlsafe(24)
    env["DATABASE_URL"] = (
        f"postgres://{DB_USER}:{pg_password}@{PREFIX}-pg:5432/{DB_NAME}"
    )

    _docker("network", "create", f"{PREFIX}-net", check=False)
    _docker("volume", "create", f"{PREFIX}-ledger", check=False)
    _docker(
        "run",
        "-d",
        "--name",
        f"{PREFIX}-pg",
        "--network",
        f"{PREFIX}-net",
        "-e",
        f"POSTGRES_DB={DB_NAME}",
        "-e",
        f"POSTGRES_USER={DB_USER}",
        "-e",
        f"POSTGRES_PASSWORD={pg_password}",
        PG_IMAGE,
    )
    _wait(
        lambda: _docker_ok(
            "exec", f"{PREFIX}-pg", "pg_isready", "-U", DB_USER, "-d", DB_NAME
        ),
        90,
        "PostgreSQL",
    )
    run_args = [
        "run",
        "-d",
        "--name",
        f"{PREFIX}-core",
        "--network",
        f"{PREFIX}-net",
        "-p",
        f"127.0.0.1:{port}:8088",
        "-v",
        f"{state_dir / 'policies'}:/app/policies:ro",
        "-v",
        f"{PREFIX}-ledger:/var/lib/govai/ledger",
    ]
    for key, value in env.items():
        run_args += ["-e", f"{key}={value}"]
    run_args.append(image)
    _docker(*run_args)
    url = f"http://127.0.0.1:{port}"
    _wait(lambda: _health(url), 120, "Core /health")
    state_file = _write_state(state_dir, built, url, "docker", {"image": image})
    return Running("docker", url, state_file, time.time() - t0, {"image": image})


def start_binary(
    state_dir: Path, port: int, binary: Path, database_url: str
) -> Running:
    t0 = time.time()
    if not binary.exists():
        raise SystemExit(f"binary not found: {binary}")
    built = _generated(state_dir)
    ledger = state_dir / "ledger"
    ledger.mkdir()
    env = {
        **os.environ,
        **built["env"],
        "AIGOV_BIND": f"127.0.0.1:{port}",
        "GOVAI_DATABASE_URL": database_url,
        "GOVAI_LEDGER_DIR": str(ledger),
    }
    log = open(state_dir / "core.log", "w", encoding="utf-8")  # noqa: SIM115 - lives with the process
    proc = subprocess.Popen(
        [str(binary)],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        cwd=state_dir,
    )
    url = f"http://127.0.0.1:{port}"

    def ready() -> bool:
        if proc.poll() is not None:
            raise SystemExit(
                f"Core exited early with status {proc.returncode}; see {state_dir / 'core.log'}"
            )
        return _health(url)

    _wait(ready, 120, "Core /health")
    state_file = _write_state(state_dir, built, url, "binary", {"pid": proc.pid})
    return Running("binary", url, state_file, time.time() - t0, {"pid": proc.pid})


def stop(state_dir: Path) -> list[str]:
    """Remove the pilot's containers, network, volume, and state directory. Returns what was removed."""
    removed: list[str] = []
    for name in (f"{PREFIX}-core", f"{PREFIX}-pg"):
        if _docker_ok("container", "inspect", name):
            _docker("rm", "-f", name, check=False)
            removed.append(f"container {name}")
    if _docker_ok("network", "inspect", f"{PREFIX}-net"):
        _docker("network", "rm", f"{PREFIX}-net", check=False)
        removed.append(f"network {PREFIX}-net")
    if _docker_ok("volume", "inspect", f"{PREFIX}-ledger"):
        _docker("volume", "rm", f"{PREFIX}-ledger", check=False)
        removed.append(f"volume {PREFIX}-ledger")
    state_file = state_dir / "state.json"
    if state_file.exists():
        try:
            pid = json.loads(state_file.read_text()).get("pid")
        except (OSError, ValueError):
            pid = None
        if isinstance(pid, int):
            try:
                os.kill(pid, 15)
                removed.append(f"process {pid}")
            except OSError:
                pass
    if state_dir.exists() and (state_dir / MARKER).exists():
        shutil.rmtree(state_dir)
        removed.append(f"state directory {state_dir}")
    return removed
