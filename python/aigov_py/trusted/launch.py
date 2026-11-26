"""Start and stop a local AIGov Core for trusted execution, with Docker or with a release binary.

Every resource this module creates carries a name prefix that the caller chooses, and ``stop`` removes only resources
with that prefix. Two Cores on one machine, each with its own prefix and its own database, never touch each other.

Docker mode needs an image that already contains Core (``aigov-core`` built from the repository's ``rust/Dockerfile``
or pulled from your registry). The SDK does not build images. Binary mode needs a release ``aigov_audit`` and a
PostgreSQL database that you provide. Both modes generate fresh identities for each run, through ``generate``.

A run's files live in a state directory that carries a marker file. ``stop`` removes that directory only if the marker
is present, so it cannot delete a directory it did not create.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MARKER = ".aigov-trusted-state"
PG_IMAGE = "postgres:18-alpine"
DB_NAME = "govai"
DB_USER = "govai"
Generator = Callable[[Path], dict[str, Any]]


@dataclass
class Running:
    mode: str
    core_url: str
    state_file: Path
    started_seconds: float
    prefix: str
    details: dict[str, Any] = field(default_factory=dict)


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


def _wait(predicate: Callable[[], bool], timeout_s: float, what: str) -> None:
    deadline = time.time() + timeout_s
    last: Exception | None = None
    while time.time() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:  # noqa: BLE001 - retry until the deadline
            last = exc
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {what}: {last}")


def _health(url: str) -> bool:
    try:
        return urllib.request.urlopen(url + "/health", timeout=3).status == 200
    except OSError:
        return False


def prepare_state_dir(state_dir: Path) -> None:
    """Create a fresh state directory with the marker. An existing directory is replaced only if it has the marker."""
    if state_dir.exists():
        if not (state_dir / MARKER).exists():
            raise RuntimeError(
                f"{state_dir} exists and was not created by AIGov; refusing to remove it"
            )
        shutil.rmtree(state_dir)
    state_dir.mkdir(parents=True)
    (state_dir / MARKER).write_text(
        "created by aigov_py.trusted; removed by stop()\n", encoding="utf-8"
    )


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


def start_docker(
    state_dir: Path,
    port: int,
    image: str,
    *,
    prefix: str,
    generate: Generator,
    timeout_s: float = 120.0,
) -> Running:
    """Start Core and PostgreSQL in Docker under ``prefix``. Returns once ``/health`` answers."""
    t0 = time.time()
    if not _docker_ok("info"):
        raise RuntimeError("Docker is not running. Start Docker and try again.")
    if not _docker_ok("image", "inspect", image):
        raise RuntimeError(
            f"image {image!r} not found. Build Core's image from rust/Dockerfile, or pull it."
        )
    if _docker_ok("container", "inspect", f"{prefix}-core"):
        raise RuntimeError(
            f"{prefix}-core already exists; choose another prefix or call stop() first"
        )

    prepare_state_dir(state_dir)
    built = generate(state_dir)
    env = dict(built["env"])
    env["AIGOV_POLICY_DIR"] = "/app/policies"
    env["AIGOV_POLICY_BUNDLE_FILE"] = "/app/policies/policy.bundle.staging.json"
    pg_password = secrets.token_urlsafe(24)
    env["DATABASE_URL"] = (
        f"postgres://{DB_USER}:{pg_password}@{prefix}-pg:5432/{DB_NAME}"
    )

    try:
        _docker("network", "create", f"{prefix}-net", check=False)
        _docker("volume", "create", f"{prefix}-ledger", check=False)
        _docker(
            "run",
            "-d",
            "--name",
            f"{prefix}-pg",
            "--network",
            f"{prefix}-net",
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
                "exec", f"{prefix}-pg", "pg_isready", "-U", DB_USER, "-d", DB_NAME
            ),
            90,
            "PostgreSQL",
        )
        run_args = [
            "run",
            "-d",
            "--name",
            f"{prefix}-core",
            "--network",
            f"{prefix}-net",
            "-p",
            f"127.0.0.1:{port}:8088",
            "-v",
            f"{state_dir / 'policies'}:/app/policies:ro",
            "-v",
            f"{prefix}-ledger:/var/lib/govai/ledger",
        ]
        for key, value in env.items():
            run_args += ["-e", f"{key}={value}"]
        run_args.append(image)
        _docker(*run_args)
        url = f"http://127.0.0.1:{port}"
        _wait(lambda: _health(url), timeout_s, "Core /health")
    except BaseException:
        stop(state_dir, prefix=prefix)
        raise
    state_file = _write_state(
        state_dir, built, url, "docker", {"image": image, "prefix": prefix}
    )
    return Running(
        "docker", url, state_file, time.time() - t0, prefix, {"image": image}
    )


def start_binary(
    state_dir: Path,
    port: int,
    binary: Path,
    database_url: str,
    *,
    prefix: str,
    generate: Generator,
    timeout_s: float = 120.0,
) -> Running:
    """Start a release ``aigov_audit`` against ``database_url``. The process is stopped by ``stop()``."""
    t0 = time.time()
    if not binary.exists():
        raise RuntimeError(f"binary not found: {binary}")
    prepare_state_dir(state_dir)
    built = generate(state_dir)
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
            raise RuntimeError(
                f"Core exited early with status {proc.returncode}; see {state_dir / 'core.log'}"
            )
        return _health(url)

    try:
        _wait(ready, timeout_s, "Core /health")
    except BaseException:
        proc.kill()
        stop(state_dir, prefix=prefix)
        raise
    state_file = _write_state(
        state_dir, built, url, "binary", {"pid": proc.pid, "prefix": prefix}
    )
    return Running(
        "binary", url, state_file, time.time() - t0, prefix, {"pid": proc.pid}
    )


def stop(state_dir: Path, *, prefix: str) -> list[str]:
    """Remove this prefix's containers, network, and volume, the Core process it started, and the marked state dir."""
    removed: list[str] = []
    for name in (f"{prefix}-core", f"{prefix}-pg"):
        if _docker_ok("container", "inspect", name):
            _docker("rm", "-f", name, check=False)
            removed.append(f"container {name}")
    if _docker_ok("network", "inspect", f"{prefix}-net"):
        _docker("network", "rm", f"{prefix}-net", check=False)
        removed.append(f"network {prefix}-net")
    if _docker_ok("volume", "inspect", f"{prefix}-ledger"):
        _docker("volume", "rm", f"{prefix}-ledger", check=False)
        removed.append(f"volume {prefix}-ledger")
    state_file = state_dir / "state.json"
    if state_file.exists():
        try:
            data = json.loads(state_file.read_text())
        except (OSError, ValueError):
            data = {}
        pid = data.get("pid")
        if isinstance(pid, int) and data.get("prefix") == prefix:
            try:
                os.kill(pid, 15)
                removed.append(f"process {pid}")
            except OSError:
                pass
    if state_dir.exists() and (state_dir / MARKER).exists():
        shutil.rmtree(state_dir)
        removed.append(f"state directory {state_dir}")
    return removed
