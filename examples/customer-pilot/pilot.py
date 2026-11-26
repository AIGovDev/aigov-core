"""AIGov Core customer pilot: one command to run the whole evaluation on synthetic data.

    python examples/customer-pilot/pilot.py run            # start, run the workflow, verify, report, clean up
    python examples/customer-pilot/pilot.py run --keep     # same, but leave Core running for inspection
    python examples/customer-pilot/pilot.py down           # remove everything a kept run created

Each run generates its own identities, keys, and signed policy. Nothing is read from an existing configuration.
Output goes to ``--out`` (default: ``pilot-output/<timestamp>`` under the scratch area you choose).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from pilot_config import (
    AGENT_IDENTITY,
    APPROVER_IDENTITIES,
    EXECUTOR_IDENTITY,
    POLICY_ID,
    TENANT,
)
from pilot_launch import DEFAULT_IMAGE, DEFAULT_PORT, start_binary, start_docker, stop
from pilot_report import write_report
from pilot_workflow import run_pilot

DEFAULT_STATE = Path.home() / ".cache" / "aigov-customer-pilot"


def _out_dir(arg: str | None) -> Path:
    if arg:
        return Path(arg).resolve()
    return (Path.cwd() / "pilot-output" / time.strftime("%Y%m%d-%H%M%S")).resolve()


def cmd_run(args: argparse.Namespace) -> int:
    state_dir = DEFAULT_STATE / "run"
    out = _out_dir(args.out)
    out.mkdir(parents=True, exist_ok=True)
    timings: dict[str, float] = {}
    try:
        t0 = time.perf_counter()
        if args.binary:
            running = start_binary(
                state_dir, args.port, Path(args.binary), args.database_url
            )
        else:
            running = start_docker(state_dir, args.port, args.image)
        timings["start_seconds"] = round(time.perf_counter() - t0, 2)
        print(
            f"Core ready at {running.core_url} ({running.mode}) in {timings['start_seconds']} s",
            flush=True,
        )

        state = json.loads(running.state_file.read_text())
        run = run_pilot(running.core_url, state, out)
        report = write_report(out, run, running, timings)
        print(f"workflow complete: {run.run_id}", flush=True)
        print(f"report: {report}", flush=True)
        failed = [c for s in run.steps for c in s.checks if not c["ok"]]
        failed += [c for c in run.evidence_checks if not c["ok"]]
        if failed:
            for c in failed:
                print(f"FAILED: {c['name']}: {c['detail']}", flush=True)
            return 1
        print("all checks passed", flush=True)
        return 0
    finally:
        if args.keep:
            print(
                "Core is still running at the URL above. Remove it with: pilot.py down",
                flush=True,
            )
        else:
            removed = stop(state_dir)
            print(
                "cleaned up: "
                + ("; ".join(removed) if removed else "nothing to remove"),
                flush=True,
            )


def cmd_down(_: argparse.Namespace) -> int:
    removed = stop(DEFAULT_STATE / "run")
    print("removed: " + ("; ".join(removed) if removed else "nothing"))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the pilot end to end")
    run.add_argument(
        "--keep", action="store_true", help="leave Core running after the run"
    )
    run.add_argument(
        "--out", help="output directory (default: ./pilot-output/<timestamp>)"
    )
    run.add_argument("--port", type=int, default=DEFAULT_PORT)
    run.add_argument(
        "--image", default=DEFAULT_IMAGE, help="Core image for Docker mode"
    )
    run.add_argument("--binary", help="run a release aigov_audit instead of Docker")
    run.add_argument("--database-url", help="PostgreSQL URL, required with --binary")
    run.set_defaults(func=cmd_run)
    down = sub.add_parser("down", help="remove a kept run")
    down.set_defaults(func=cmd_down)
    args = parser.parse_args(argv)
    if getattr(args, "binary", None) and not args.database_url:
        parser.error("--binary needs --database-url")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

__all__ = [
    "AGENT_IDENTITY",
    "APPROVER_IDENTITIES",
    "EXECUTOR_IDENTITY",
    "POLICY_ID",
    "TENANT",
    "main",
]
