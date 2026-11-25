"""Independent evidence checks for an exported run.

These checks need only the export, the authorizations, and the pinned authorization public key. A reviewer can run them
without Core's database or keys.
"""

from __future__ import annotations

from typing import Any

from .authorization import verify_authorization_signature


def offline_evidence_checks(
    export: dict[str, Any],
    authorizations: list[dict[str, Any]],
    pub: str,
    audience: str,
    run_id: str,
) -> list[dict[str, Any]]:
    """Checks that need only the export and the pinned public key: no access to Core's database or keys."""
    checks: list[dict[str, Any]] = []
    chain = export.get("evidence_hashes", {}).get("log_chain", [])
    continuous = all(
        chain[i]["prev_hash"] == chain[i - 1]["record_hash"]
        for i in range(1, len(chain))
    )
    checks.append(
        {
            "name": "log_chain_links_are_continuous",
            "ok": continuous,
            "detail": f"{len(chain)} records",
        }
    )
    recorded = {entry["event_id"]: entry["record_hash"] for entry in chain}
    for signed in authorizations:
        payload = signed.get("payload", {})
        auth_id = payload.get("authorization_id", "")
        try:
            verify_authorization_signature(signed, pub)
            sig_ok, sig_detail = True, "valid for the pinned key and domain"
        except Exception as exc:  # noqa: BLE001 - report, do not raise, in an evidence check
            sig_ok, sig_detail = False, str(exc)
        checks.append(
            {
                "name": f"authorization_signature {auth_id}",
                "ok": sig_ok,
                "detail": sig_detail,
            }
        )
        bound = payload.get("consequential_record_hash") in recorded.values()
        checks.append(
            {
                "name": f"authorization_bound_to_ledger {auth_id}",
                "ok": bound,
                "detail": "consequential_record_hash is a record in the ledger export",
            }
        )
        checks.append(
            {
                "name": f"authorization_scope {auth_id}",
                "ok": payload.get("run_id") == run_id
                and payload.get("executor_audience") == audience,
                "detail": f"run and audience match ({audience})",
            }
        )
    receipts = [
        e
        for e in export.get("evidence_events", [])
        if e.get("event_type") == "execution_receipt"
    ]
    issued = {a.get("payload", {}).get("authorization_id") for a in authorizations}
    checks.append(
        {
            "name": "every_receipt_matches_an_issued_authorization",
            "ok": all(
                r["payload"].get("execution_authorization_id") in issued
                for r in receipts
            ),
            "detail": f"{len(receipts)} receipt(s)",
        }
    )
    checks.append(
        {
            "name": "one_receipt_per_authorization",
            "ok": len(
                {r["payload"].get("execution_authorization_id") for r in receipts}
            )
            == len(receipts),
            "detail": "no authorization has two receipts",
        }
    )
    return checks
