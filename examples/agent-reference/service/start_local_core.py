#!/usr/bin/env python3
"""Start a local AIGov Core container with PostgreSQL and the trusted-execution reference configuration.

Everything runs on this machine: a private Docker network, a PostgreSQL 18 container, and the Core image built
from this repository. Identities, API keys, the policy signing key, and the authorization signing key are generated
per run (see ``trust_setup.py``) and written only to a state directory outside the repository, with owner-only
permissions. Nothing is deployed, and no external service is contacted.

Usage (from the repository root):
    python examples/agent-reference/service/start_local_core.py start
    python examples/agent-reference/service/start_local_core.py stop

``start`` prints the state-file path and the Core URL. The demo and the tests read the identities from the state
file. ``stop`` removes the containers, the network, the ledger volume, and the state file.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO_ROOT / "examples" / "agent-reference"))

from trust_setup import build

IMAGE = os.environ.get("GOVAI_REF_IMAGE", "aigov-core:agent-reference")
PG_IMAGE = "postgres:18-alpine"
NETWORK = "aigov-agent-ref-net"
PG_NAME = "aigov-agent-ref-pg"
CORE_NAME = "aigov-agent-ref-core"
LEDGER_VOLUME = "aigov-agent-ref-ledger"
HOST_PORT = 18088
STATE_DIR = Path.home() / ".cache" / "aigov-agent-reference"
DB_NAME = "govai"
DB_USER = "govai"
CONTAINER_POLICY_DIR = "/app/policies"


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], check=check, capture_output=True, text=True
    )


def docker_ok(*args: str) -> bool:
    return (
        subprocess.run(
            ["docker", *args], capture_output=True, text=True, check=False
        ).returncode
        == 0
    )


def wait_until(predicate, timeout_s: float, what: str) -> None:
    last_error: Exception | None = None
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:  # noqa: BLE001 - retry until the deadline; the last error is shown below
            last_error = exc
        time.sleep(1)
    raise SystemExit(f"timed out waiting for {what}: {last_error}")


def start() -> None:
    if not docker_ok("info"):
        raise SystemExit("Docker is not running. Start Docker, then run this again.")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state_file = STATE_DIR / "state.json"
    if state_file.exists():
        raise SystemExit(f"already started (state in {state_file}). Run `stop` first.")

    if not docker_ok("image", "inspect", IMAGE):
        print(f"building {IMAGE} from {REPO_ROOT} ...", flush=True)
        subprocess.run(["docker", "build", "-t", IMAGE, str(REPO_ROOT)], check=True)

    built = build(STATE_DIR)
    env = dict(built["env"])
    # Inside the container the policy lives at a fixed mount point.
    env["AIGOV_POLICY_DIR"] = CONTAINER_POLICY_DIR
    env["AIGOV_POLICY_BUNDLE_FILE"] = (
        f"{CONTAINER_POLICY_DIR}/policy.bundle.staging.json"
    )
    pg_password = secrets.token_urlsafe(24)
    bundle_dir = STATE_DIR / "policies"

    docker("network", "create", NETWORK, check=False)
    docker("volume", "create", LEDGER_VOLUME, check=False)
    docker(
        "run",
        "-d",
        "--name",
        PG_NAME,
        "--network",
        NETWORK,
        "-e",
        f"POSTGRES_DB={DB_NAME}",
        "-e",
        f"POSTGRES_USER={DB_USER}",
        "-e",
        f"POSTGRES_PASSWORD={pg_password}",
        PG_IMAGE,
    )
    wait_until(
        lambda: docker_ok("exec", PG_NAME, "pg_isready", "-U", DB_USER, "-d", DB_NAME),
        90,
        "PostgreSQL",
    )

    env["DATABASE_URL"] = f"postgres://{DB_USER}:{pg_password}@{PG_NAME}:5432/{DB_NAME}"
    run_args = [
        "run",
        "-d",
        "--name",
        CORE_NAME,
        "--network",
        NETWORK,
        "-p",
        f"127.0.0.1:{HOST_PORT}:8088",
        "-v",
        f"{bundle_dir}:{CONTAINER_POLICY_DIR}:ro",
        "-v",
        f"{LEDGER_VOLUME}:/var/lib/govai/ledger",
    ]
    for key, value in env.items():
        run_args += ["-e", f"{key}={value}"]
    run_args.append(IMAGE)
    docker(*run_args)

    url = f"http://127.0.0.1:{HOST_PORT}"
    wait_until(
        lambda: urllib.request.urlopen(url + "/health", timeout=3).status == 200,
        120,
        "Core /health",
    )

    state_file.write_text(json.dumps({**built["state"], "core_url": url}, indent=2))
    state_file.chmod(0o600)
    print("Core is up.")
    print(f"  Identities and keys: {state_file} (owner-only). Not printed.")
    print(f"  Core URL: {url}")
    print("Then run: python examples/agent-reference/run_core_demo.py")


def stop() -> None:
    for name in (CORE_NAME, PG_NAME):
        docker("rm", "-f", name, check=False)
    docker("network", "rm", NETWORK, check=False)
    docker("volume", "rm", LEDGER_VOLUME, check=False)
    state_file = STATE_DIR / "state.json"
    if state_file.exists():
        state_file.unlink()
    print("Stopped. Containers, network, ledger volume, and state file removed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=["start", "stop"])
    args = parser.parse_args()
    start() if args.command == "start" else stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
