"""Validate the Acme integration against a real AIGov Core.

Runs each required case on a fresh run with its own ledger and executor store, then checks authorization, rejection,
approval, revocation, replay, modified arguments, Core unavailability, and independent evidence verification. Writes
``validation.json`` and ``validation.md`` to ``--out``. Exits 1 if any case fails.

    python examples/customer-integration/acme/validate.py run            # starts Docker Core, validates, cleans up
    python examples/customer-integration/acme/validate.py run --binary <aigov_audit> --database-url <postgres url>
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from aigov_py.trusted import (
    ApproverActor,
    CoreClient,
    Integration,
    migrate,
    start_core,
    stop_core,
    verify_authorization_signature,
)
from app import CONFIG, AcmeAssistant, AcmeLedger

DEFAULT_STATE = Path.home() / ".cache" / "aigov-customer-integration"


class Case:
    def __init__(self, name: str, claim: str) -> None:
        self.name = name
        self.claim = claim
        self.checks: list[dict[str, Any]] = []
        self.notes: list[str] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(c["ok"] for c in self.checks)

    def as_dict(self) -> dict[str, Any]:
        return {
            "case": self.name,
            "claim": self.claim,
            "passed": self.passed,
            "checks": self.checks,
            "notes": self.notes,
        }


def new_run(
    core_url: str, state: dict[str, Any], out: Path
) -> tuple[Integration, AcmeLedger, AcmeAssistant]:
    ledger = AcmeLedger()
    run_dir = out / f"run-{uuid.uuid4().hex[:8]}"
    _apply_migration(run_dir / "executor.sqlite")
    integ = Integration(CONFIG, core_url, state, run_dir, ledger.perform)
    return integ, ledger, AcmeAssistant(integ, ledger)


def _apply_migration(path: Path) -> None:
    """The executor store's migration, applied once to each run's store file before the run starts."""
    path.parent.mkdir(parents=True, exist_ok=True)
    migrate(path, backup_dir=None)


def pay_args(ledger: AcmeLedger, invoice: str = "INV-2001") -> dict[str, Any]:
    return {"invoice_id": invoice, "vendor_id": ledger.invoices[invoice]["vendor_id"]}


def case_authorization(core_url: str, state: dict, out: Path) -> Case:
    c = Case(
        "authorization",
        "A consequential call runs only with an approval and Core's authorization; the executor "
        "performs it once and records a receipt.",
    )
    _, ledger, app = new_run(core_url, state, out)
    read = app.read_invoice("INV-2001", "tc-read")
    c.check("governed_read_executes", read["status"] == "read", read["reason"])
    result = app.pay_vendor("INV-2001", "tc-pay")
    c.check("approved_payment_executes", result.get("status") == "paid", str(result))
    c.check(
        "payment_recorded_once", len(ledger.payments) == 1, str(len(ledger.payments))
    )
    return c


def case_rejection(core_url: str, state: dict, out: Path) -> Case:
    c = Case("rejection", "A rejected request is refused by Core and nothing runs.")
    integ, ledger, _ = new_run(core_url, state, out)
    args = pay_args(ledger)
    req = integ.request_approval("pay_vendor", args, "tc-rej")
    rej = integ.approve("controller", req, "pay_vendor", args, "tc-rej", approve=False)
    c.check("controller_rejection_recorded", rej.decision.value == "ALLOW", rej.reason)
    write = integ.call("pay_vendor", args, "tc-rej", rej.event_id or "")
    c.check(
        "call_after_rejection_refused",
        write.decision.value == "DENY" and write.reason == "approval_not_approved",
        write.reason,
    )
    c.check("no_payment", not ledger.payments)
    return c


def case_approval(core_url: str, state: dict, out: Path) -> Case:
    c = Case(
        "approval",
        "An approval is bound to one call and authenticated to its approver's credential.",
    )
    integ, ledger, _ = new_run(core_url, state, out)
    args = pay_args(ledger)
    req = integ.request_approval("pay_vendor", args, "tc-appr")
    claimed = integ.approve(
        "controller",
        req,
        "pay_vendor",
        args,
        "tc-appr",
        claimed_approver="cfo@acme-finance.example",
    )
    c.check(
        "claimed_identity_refused",
        claimed.decision.value == "DENY"
        and claimed.reason == "approver_identity_mismatch",
        claimed.reason,
    )
    agent_key = state["keys"]["agent"]
    as_agent = ApproverActor(
        CoreClient(core_url, agent_key), CONFIG.agent_identity, CONFIG.registry
    ).decide(
        run_id=integ.run_id,
        request=req,
        tool="pay_vendor",
        args=args,
        tool_call_id="tc-appr",
        approve=True,
    )
    c.check(
        "agent_credential_cannot_approve",
        as_agent.decision.value == "DENY" and as_agent.reason == "role_not_permitted",
        as_agent.reason,
    )
    ok = integ.approve("controller", req, "pay_vendor", args, "tc-appr")
    c.check("authenticated_approval_recorded", ok.decision.value == "ALLOW", ok.reason)
    return c


def case_revocation(core_url: str, state: dict, out: Path) -> Case:
    c = Case(
        "revocation",
        "Only the approver who gave an approval can revoke it, and a revoked approval cannot authorize "
        "a call. Revocation after issuance stops execution if it is recorded before the executor checks.",
    )
    integ, ledger, _ = new_run(core_url, state, out)
    args = pay_args(ledger)
    req = integ.request_approval("pay_vendor", args, "tc-rev")
    ap = integ.approve("controller", req, "pay_vendor", args, "tc-rev")
    other = integ.revoke("cfo", ap.event_id or "", "not mine")
    c.check(
        "other_approver_cannot_revoke", other.decision.value == "DENY", other.reason
    )
    integ2, ledger2, _ = new_run(core_url, state, out)
    args2 = pay_args(ledger2, "INV-2002")
    req2 = integ2.request_approval("pay_vendor", args2, "tc-rev2")
    ap2 = integ2.approve("controller", req2, "pay_vendor", args2, "tc-rev2")
    rv = integ2.revoke("controller", ap2.event_id or "", "withdrawn")
    c.check("approver_can_revoke", rv.decision.value == "ALLOW", rv.reason)
    write = integ2.call("pay_vendor", args2, "tc-rev2", ap2.event_id or "")
    c.check(
        "call_after_revocation_refused",
        write.decision.value == "DENY" and write.reason == "approval_revoked",
        write.reason,
    )
    c.check("no_payment_after_revocation", not ledger2.payments)
    integ3, ledger3, _ = new_run(core_url, state, out)
    args3 = pay_args(ledger3, "INV-2002")
    req3 = integ3.request_approval("pay_vendor", args3, "tc-rev3")
    ap3 = integ3.approve("controller", req3, "pay_vendor", args3, "tc-rev3")
    issued = integ3.call("pay_vendor", args3, "tc-rev3", ap3.event_id or "")
    c.check(
        "authorization_issued_before_revocation",
        issued.authorization is not None,
        issued.reason,
    )
    integ3.revoke("controller", ap3.event_id or "", "changed mind before execution")
    late = integ3.execute("pay_vendor", args3, issued)
    c.check(
        "executor_refuses_after_revocation",
        not late.executed and late.reason == "authorization_revoked",
        late.reason,
    )
    c.check("no_payment_after_late_revocation", not ledger3.payments)
    c.notes.append(
        "Not covered here: a revocation recorded between the executor's status check and its side effect is not "
        "stopped. This is a stated limit of the design; see the limitations."
    )
    return c


def case_replay(core_url: str, state: dict, out: Path) -> Case:
    c = Case("replay", "The same authorization and the same approval cannot run twice.")
    integ, ledger, _ = new_run(core_url, state, out)
    args = pay_args(ledger)
    req = integ.request_approval("pay_vendor", args, "tc-rep")
    ap = integ.approve("controller", req, "pay_vendor", args, "tc-rep")
    d = integ.call("pay_vendor", args, "tc-rep", ap.event_id or "")
    first = integ.execute("pay_vendor", args, d)
    c.check("first_execution_runs", first.executed, first.reason)
    again = integ.execute("pay_vendor", args, d)
    c.check(
        "replayed_authorization_refused",
        not again.executed and again.reason == "authorization_receipt_recorded",
        again.reason,
    )
    second_call = integ.call("pay_vendor", args, "tc-rep", ap.event_id or "")
    c.check(
        "approval_cannot_authorize_twice",
        second_call.decision.value == "DENY"
        and second_call.reason == "approval_already_consumed",
        second_call.reason,
    )
    c.check("one_payment_only", len(ledger.payments) == 1, str(len(ledger.payments)))
    return c


def case_modified_arguments(core_url: str, state: dict, out: Path) -> Case:
    c = Case(
        "modified_arguments",
        "Changed arguments are refused by Core and by the executor. The approved arguments "
        "still run.",
    )
    integ, ledger, _ = new_run(core_url, state, out)
    args = pay_args(ledger)
    req = integ.request_approval("pay_vendor", args, "tc-mod")
    ap = integ.approve("controller", req, "pay_vendor", args, "tc-mod")
    changed_call = integ.call(
        "pay_vendor", {**args, "vendor_id": "VEND-EVIL"}, "tc-mod", ap.event_id or ""
    )
    c.check(
        "core_refuses_changed_call",
        changed_call.decision.value == "DENY"
        and changed_call.reason == "approval_linkage_mismatch",
        changed_call.reason,
    )
    d = integ.call("pay_vendor", args, "tc-mod", ap.event_id or "")
    bad = integ.execute_with(
        "pay_vendor", {**args, "vendor_id": "VEND-EVIL"}, d.authorization or {}
    )
    c.check(
        "executor_refuses_changed_arguments",
        not bad.executed and bad.reason == "authorization_arguments_mismatch",
        bad.reason,
    )
    c.check("no_payment_with_changed_arguments", not ledger.payments)
    good = integ.execute("pay_vendor", args, d)
    c.check("approved_arguments_run", good.executed, good.reason)
    return c


def case_core_unavailable(core_url: str, state: dict, out: Path) -> Case:
    c = Case(
        "core_unavailable",
        "With Core unreachable, the agent gets no authorization and the executor refuses. Nothing "
        "runs, and the same authorization runs once Core returns.",
    )
    integ, ledger, _ = new_run(core_url, state, out)
    args = pay_args(ledger)
    req = integ.request_approval("pay_vendor", args, "tc-down")
    ap = integ.approve("controller", req, "pay_vendor", args, "tc-down")
    down = integ.unreachable_view()
    d_down = down.call("pay_vendor", args, "tc-down", ap.event_id or "")
    c.check(
        "agent_fails_closed",
        d_down.decision.value == "INDETERMINATE" and d_down.authorization is None,
        d_down.reason,
    )
    d = integ.call("pay_vendor", args, "tc-down", ap.event_id or "")
    c.check("recovered_call_authorized", d.authorization is not None, d.reason)
    refused = down.execute("pay_vendor", args, d)
    c.check(
        "executor_fails_closed",
        not refused.executed and refused.reason == "core_unavailable",
        refused.reason,
    )
    c.check("no_payment_while_down", not ledger.payments)
    ran = integ.execute("pay_vendor", args, d)
    c.check(
        "runs_once_after_recovery",
        ran.executed and len(ledger.payments) == 1,
        ran.reason,
    )
    return c


def case_independent_verification(core_url: str, state: dict, out: Path) -> Case:
    c = Case(
        "independent_verification",
        "The evidence verifies without Core's keys or database, and a changed "
        "authorization is detected.",
    )
    integ, ledger, _ = new_run(core_url, state, out)
    args = pay_args(ledger)
    req = integ.request_approval("pay_vendor", args, "tc-ver")
    ap = integ.approve("controller", req, "pay_vendor", args, "tc-ver")
    d = integ.call("pay_vendor", args, "tc-ver", ap.event_id or "")
    outcome = integ.execute("pay_vendor", args, d)
    c.check("run_executed", outcome.executed, outcome.reason)
    auths = [d.authorization] if d.authorization else []
    checks = integ.verify(auths)
    for ch in checks:
        c.check(ch["name"], ch["ok"], ch["detail"])
    if auths:
        tampered = copy.deepcopy(auths[0])
        tampered["payload"]["tool_name"] = "adjust_budget"
        try:
            verify_authorization_signature(tampered, state["authorization_public_key"])
            detected = False
        except Exception:  # noqa: BLE001 - any refusal counts as detection
            detected = True
        c.check(
            "tampered_authorization_detected",
            detected,
            "tool name changed after signing",
        )
    return c


CASES: list[Callable[[str, dict, Path], Case]] = [
    case_authorization,
    case_rejection,
    case_approval,
    case_revocation,
    case_replay,
    case_modified_arguments,
    case_core_unavailable,
    case_independent_verification,
]


def write_outputs(out: Path, cases: list[Case], meta: dict[str, Any]) -> bool:
    all_ok = all(x.passed for x in cases)
    (out / "validation.json").write_text(
        json.dumps(
            {"meta": meta, "passed": all_ok, "cases": [x.as_dict() for x in cases]},
            indent=2,
        )
    )
    lines = [
        "# Acme integration validation",
        "",
        (
            f"Core: {meta['mode']}. Run completed in {meta['seconds']} s. Result: "
            f"**{'all cases passed' if all_ok else 'FAILURES'}**."
        ),
        "",
        "| Case | Result | What it shows |",
        "|---|---|---|",
    ]
    for x in cases:
        lines.append(f"| {x.name} | {'pass' if x.passed else 'FAIL'} | {x.claim} |")
    lines += ["", "## Checks", ""]
    for x in cases:
        lines.append(f"### {x.name}")
        for ch in x.checks:
            lines.append(
                f"- {'pass' if ch['ok'] else 'FAIL'}: {ch['name']} ({ch['detail'] or '-'})"
            )
        for n in x.notes:
            lines.append(f"- note: {n}")
        lines.append("")
    (out / "validation.md").write_text("\n".join(lines), encoding="utf-8")
    return all_ok


def cmd_run(args: argparse.Namespace) -> int:
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    state_dir = DEFAULT_STATE / f"run-{uuid.uuid4().hex[:8]}"
    t0 = time.time()
    running, prefix = start_core(
        CONFIG,
        state_dir,
        port=args.port,
        mode=args.mode,
        image=args.image,
        binary=Path(args.binary) if args.binary else None,
        database_url=args.database_url,
    )
    try:
        state = json.loads(running.state_file.read_text())
        cases = [fn(running.core_url, state, out) for fn in CASES]
        meta = {
            "mode": running.mode,
            "core_url": running.core_url,
            "seconds": round(time.time() - t0, 2),
            "core_ready_seconds": round(running.started_seconds, 2),
        }
        ok = write_outputs(out, cases, meta)
        for x in cases:
            print(f"{'pass' if x.passed else 'FAIL'}  {x.name}")
        print(f"report: {out / 'validation.md'}")
        return 0 if ok else 1
    finally:
        removed = stop_core(state_dir, prefix)
        print("cleaned up: " + ("; ".join(removed) if removed else "nothing"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--out", default="integration-validation")
    run.add_argument("--mode", choices=["docker", "binary"], default="docker")
    run.add_argument("--port", type=int, default=18288)
    run.add_argument("--image", default="aigov-core:integration")
    run.add_argument("--binary")
    run.add_argument("--database-url")
    run.set_defaults(func=cmd_run)
    args = parser.parse_args(argv)
    if args.mode == "binary" and not (args.binary and args.database_url):
        parser.error("binary mode needs --binary and --database-url")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
