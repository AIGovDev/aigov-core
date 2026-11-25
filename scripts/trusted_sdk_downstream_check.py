"""Downstream consumption check for the installed ``aigov-py`` wheel.

This is what a customer's application looks like. It imports only ``aigov_py.trusted``, and it must run from any working
directory, with the repository absent from ``sys.path``. It refuses to run if it finds the repository on the path, so a
passing result means the installed package works on its own.

Offline checks (no Core needed):

    python trusted_sdk_downstream_check.py offline

Live check, which starts a Core for this run only, with its own prefix and database, and removes it afterwards:

    python trusted_sdk_downstream_check.py live --mode docker --image aigov-core:integration
    python trusted_sdk_downstream_check.py live --mode binary --binary <aigov_audit> --database-url <postgres url>
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
import uuid
from pathlib import Path


def _refuse_repo_on_path() -> None:
    import aigov_py

    location = Path(aigov_py.__file__).resolve()
    if (
        "verdict-scratch" in str(location)
        or "/agentref/" in str(location)
        or "/examples/" in str(location)
    ):
        raise SystemExit(
            f"this check must run against the installed wheel, not the repository: {location}"
        )
    if any("examples" in p for p in sys.path):
        raise SystemExit(
            "an examples/ directory is on sys.path; the check must not depend on it"
        )


def _open_store(path: Path):  # type: ignore[no-untyped-def]
    """Apply the executor store migration once, then open the store, as an operator does before first use."""

    from aigov_py.trusted import ExecutionStore, migrate

    path.parent.mkdir(parents=True, exist_ok=True)
    migrate(path, backup_dir=None)
    return ExecutionStore(path)


def offline() -> int:
    from aigov_py.canonical_json import canonical_bytes
    from aigov_py.trusted import (
        Executor,
        Refused,
        ToolSpec,
        args_binding_hash,
        build_policy_document,
        provision,
        tool_registry,
        verify_authorization_signature,
    )
    from aigov_py.trusted.authorization import AUTH_DOMAIN, AUTH_SCHEMA
    from nacl.signing import SigningKey

    spec = ToolSpec("refund_order", "order:refund", "write", "order_id")
    digest = args_binding_hash(spec, {"order_id": "ORD-1", "amount": 10})
    assert len(digest) == 64

    key = SigningKey.generate()
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    payload = {
        "schema": AUTH_SCHEMA,
        "tool_name": "refund_order",
        "args_binding_hash": digest,
    }
    signed = {
        "payload": payload,
        "signature": base64.b64encode(
            key.sign(AUTH_DOMAIN + canonical_bytes(payload)).signature
        ).decode("ascii"),
    }
    verify_authorization_signature(signed, pub)  # valid: passes
    signed["payload"]["tool_name"] = "delete_everything"
    try:
        verify_authorization_signature(signed, pub)
    except Refused as exc:
        assert exc.reason == "authorization_signature_invalid", exc.reason
    else:
        raise AssertionError("a tampered authorization was accepted")

    with tempfile.TemporaryDirectory() as tmp:
        doc = build_policy_document(
            policy_id="downstream",
            issuer_id="downstream-issuer",
            issuer_display_name="downstream",
            created_at_utc="2026-01-01T00:00:00Z",
            read_tools=[],
            write_tools=["refund_order"],
            approvers=["lead@example.test"],
        )
        built = provision(
            Path(tmp),
            tenant="downstream",
            approvers={"lead": "lead@example.test"},
            agent_identity="agent:downstream",
            executor_identity="executor:downstream",
            policy_document=doc,
            policy_issuer_id="downstream-issuer",
            policy_signer="downstream",
            policy_created_at_utc="2026-01-01T00:00:00Z",
            policy_expires_at_utc="2999-01-01T00:00:00Z",
        )
        assert "GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX" not in json.dumps(built["state"])
        performed: list = []

        class NoCore:
            actor = system = "downstream"

            def status(self, *a, **k):
                raise AssertionError("contacted Core before a local refusal")

        executor = Executor(
            core=NoCore(),
            public_key_b64=built["state"]["authorization_public_key"],
            audience="executor:downstream",
            store=_open_store(Path(tmp) / "store.sqlite"),
            tools=tool_registry([spec]),
            performer=lambda t, a, e: (
                performed.append(t) or {"success": True, "data": {}}
            ),
        )
        out = executor.execute(
            run_id="r",
            tool="refund_order",
            arguments={"order_id": "ORD-1"},
            signed=signed,
        )
        assert not out.executed and out.reason == "authorization_signature_invalid", (
            out.reason
        )
        assert performed == []
    print("offline: all checks passed")
    return 0


def live(args: argparse.Namespace) -> int:
    from aigov_py.trusted import (
        Integration,
        IntegrationConfig,
        Tool,
        start_core,
        stop_core,
    )

    config = IntegrationConfig(
        tenant="downstream-live",
        policy_id="downstream-live-policy",
        tools=(
            Tool("read_order", "order:read", "read", resource_key="order_id"),
            Tool("refund_order", "order:refund", "write", resource_key="order_id"),
        ),
        approvers={"lead": "lead@downstream.example"},
        agent_identity="agent:downstream",
        executor_identity="executor:downstream",
    )
    orders = {"ORD-1": {"total": 80.0, "refunded": False}}

    def perform(tool: str, arguments: dict, execution_id: str) -> dict:
        order = orders[arguments["order_id"]]
        if tool == "refund_order":
            order["refunded"] = True
        return {"success": True, "data": dict(order)}

    # Under the home cache, not a temporary directory: Docker Desktop shares the home directory with its VM, not /var/folders.
    state_dir = (
        Path.home() / ".cache" / "aigov-downstream" / f"run-{uuid.uuid4().hex[:8]}"
    )
    running, prefix = start_core(
        config,
        state_dir,
        port=args.port,
        mode=args.mode,
        image=args.image,
        binary=Path(args.binary) if args.binary else None,
        database_url=args.database_url,
    )
    try:
        state = json.loads(running.state_file.read_text())
        out_dir = state_dir / "run"
        _open_store(
            out_dir / "executor.sqlite"
        )  # the migration, applied before the run
        integ = Integration(config, running.core_url, state, out_dir, perform)
        call_args = {"order_id": "ORD-1"}

        read = integ.call("read_order", call_args, "call-read")
        assert integ.execute("read_order", call_args, read).executed

        request = integ.request_approval("refund_order", call_args, "call-refund")
        approval = integ.approve(
            "lead", request, "refund_order", call_args, "call-refund"
        )
        assert approval.decision.value == "ALLOW", approval.reason
        call = integ.call(
            "refund_order", call_args, "call-refund", approval.event_id or ""
        )
        outcome = integ.execute("refund_order", call_args, call)
        assert outcome.executed and orders["ORD-1"]["refunded"], outcome.reason

        issued = [d.authorization for d in (read, call) if d.authorization]
        checks = integ.verify(issued)
        failed = [c["name"] for c in checks if not c["ok"]]
        assert not failed, failed
        print(
            f"live ({running.mode}): refund executed once, {len(checks)} evidence checks passed"
        )
        return 0
    finally:
        removed = stop_core(state_dir, prefix)
        print("cleaned up:", "; ".join(removed) or "nothing")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("offline")
    live_p = sub.add_parser("live")
    live_p.add_argument("--mode", choices=["docker", "binary"], default="docker")
    live_p.add_argument("--image", default="aigov-core:integration")
    live_p.add_argument("--binary")
    live_p.add_argument("--database-url")
    live_p.add_argument("--port", type=int, default=18377)
    args = parser.parse_args(argv)
    _refuse_repo_on_path()
    if args.cmd == "offline":
        return offline()
    if args.mode == "binary" and not (args.binary and args.database_url):
        parser.error("binary mode needs --binary and --database-url")
    return live(args)


if __name__ == "__main__":
    raise SystemExit(main())
