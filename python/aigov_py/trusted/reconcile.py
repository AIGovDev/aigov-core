"""Reconciliation of an execution whose outcome is unknown, by signed evidence from an authorized reconciler.

An outcome_unknown execution is never retried. A human (or a process they run) checks the external system and records
what it found. That record is a reconciliation evidence envelope, signed with the reconciler's Ed25519 key. The
executor applies it only if all of these hold:

- the signer is listed in the reconciler registry (authorization: a key the operator pinned, not one the signer claims);
- the signature verifies under that key and this domain (authentication: possession of the key);
- every binding field matches the stored execution: authorization id, run, tool, argument digest, executor identity;
- the execution is in reconciliation_required (it cannot be reconciled twice, and an evidence envelope cannot be replayed);
- the outcome is one of ``succeeded``, ``failed``, or ``not_executed``;
- the observation time is after the reservation and not in the future.

Reconciliation appends. The original outcome_unknown and reconciliation_required entries stay in the history, and the
evidence is stored with the reconciled event. A reconciled ``not_executed`` closes the authorization without repeating
the action. Running the action again needs a new authorization, which needs a new human approval.

There is no force-execute and no force-success. Evidence can only say what the external system showed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from aigov_py.canonical_json import canonical_bytes

from .lifecycle import State
from .store import ExecutionStore

RECON_SCHEMA = "govai.reconciliation.v1"
RECON_DOMAIN = b"govai.reconciliation.v1\x00"
OUTCOMES = ("succeeded", "failed", "not_executed")
MAX_FUTURE_SKEW = timedelta(seconds=30)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ReconciliationRefused(Exception):
    """The evidence is not accepted. ``reason`` is a stable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ReconcilerRegistry:
    """Pinned reconciler identities and their public keys. The operator maintains it."""

    keys: Mapping[str, str]  # identity -> public key, base64

    @classmethod
    def from_json(cls, text: str) -> ReconcilerRegistry:
        data = json.loads(text)
        keys = data.get("reconcilers")
        if not isinstance(keys, dict) or not keys:
            raise ValueError("registry must contain a non-empty 'reconcilers' object")
        return cls(keys=dict(keys))

    def public_key(self, identity: str) -> str | None:
        return self.keys.get(identity)


def sign_evidence(payload: dict[str, Any], seed_b64: str) -> dict[str, Any]:
    """Sign an evidence payload. The seed is the reconciler's own key, held by that reconciler."""
    seed = base64.b64decode(seed_b64, validate=True)
    key = SigningKey(seed)
    sig = key.sign(RECON_DOMAIN + canonical_bytes(payload)).signature
    return {"payload": payload, "signature": base64.b64encode(sig).decode("ascii")}


def make_payload(
    row: dict[str, Any],
    *,
    outcome: str,
    external_reference: str,
    external_evidence: bytes,
    reconciler: str,
    observed_at_utc: str,
) -> dict[str, Any]:
    """The payload a reconciler signs, with the binding fields taken from the stored execution."""
    return {
        "schema": RECON_SCHEMA,
        "authorization_id": row["authorization_id"],
        "run_id": row["run_id"],
        "tool_name": row["tool_name"],
        "args_binding_hash": row["args_digest"],
        "executor_identity": row["executor_identity"],
        "outcome": outcome,
        "external_reference": external_reference,
        "external_evidence_sha256": hashlib.sha256(external_evidence).hexdigest(),
        "observed_at_utc": observed_at_utc,
        "reconciler": reconciler,
    }


def verify_reconciliation(
    signed: dict[str, Any],
    registry: ReconcilerRegistry,
    row: dict[str, Any] | None,
    *,
    now: datetime,
) -> dict[str, Any]:
    """Return the accepted evidence (the payload, the signature, and the envelope digest), or raise."""
    if row is None:
        raise ReconciliationRefused("authorization_not_found")
    payload = signed.get("payload") if isinstance(signed, dict) else None
    if not isinstance(payload, dict) or payload.get("schema") != RECON_SCHEMA:
        raise ReconciliationRefused("reconciliation_schema_mismatch")

    reconciler = payload.get("reconciler")
    pub = registry.public_key(reconciler) if isinstance(reconciler, str) else None
    if pub is None:
        raise ReconciliationRefused("reconciler_not_authorized")
    try:
        sig = base64.b64decode(signed["signature"], validate=True)
        VerifyKey(base64.b64decode(pub, validate=True)).verify(
            RECON_DOMAIN + canonical_bytes(payload), sig
        )
    except (BadSignatureError, KeyError, ValueError, TypeError) as exc:
        raise ReconciliationRefused("reconciliation_signature_invalid") from exc

    bindings = {
        "authorization_id": row["authorization_id"],
        "run_id": row["run_id"],
        "tool_name": row["tool_name"],
        "args_binding_hash": row["args_digest"],
        "executor_identity": row["executor_identity"],
    }
    for key, expected in bindings.items():
        if payload.get(key) != expected:
            raise ReconciliationRefused("reconciliation_binding_mismatch")

    if State(row["state"]) != State.RECONCILIATION_REQUIRED:
        raise ReconciliationRefused("reconciliation_not_required")
    if payload.get("outcome") not in OUTCOMES:
        raise ReconciliationRefused("reconciliation_outcome_invalid")
    evidence_digest = payload.get("external_evidence_sha256")
    if not isinstance(evidence_digest, str) or not _HEX64.match(evidence_digest):
        raise ReconciliationRefused("reconciliation_evidence_invalid")

    try:
        observed = datetime.fromisoformat(payload["observed_at_utc"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ReconciliationRefused("reconciliation_timestamp_invalid") from exc
    reserved = datetime.fromisoformat(row["reserved_at_utc"])
    if observed < reserved or observed > now + MAX_FUTURE_SKEW:
        raise ReconciliationRefused("reconciliation_timestamp_invalid")

    envelope = hashlib.sha256(canonical_bytes(signed)).hexdigest()
    return {**payload, "signature": signed["signature"], "evidence_sha256": envelope}


def apply_reconciliation(
    store: ExecutionStore,
    signed: dict[str, Any],
    registry: ReconcilerRegistry,
    *,
    receipt_event_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify, then append. Raises ``ReconciliationRefused`` or the store's error. Returns the recorded evidence."""
    now = now or datetime.now(UTC)
    auth_id = (
        signed.get("payload", {}).get("authorization_id")
        if isinstance(signed, dict)
        else None
    )
    row = store.row(auth_id) if isinstance(auth_id, str) else None
    evidence = verify_reconciliation(signed, registry, row, now=now)
    store.reconcile(
        authorization_id=auth_id,
        outcome=evidence["outcome"],
        evidence=evidence,
        now=now.isoformat(),
        actor=evidence["reconciler"],
        receipt_event_id=receipt_event_id,
    )
    return evidence


def sign_escalation(payload: dict[str, Any], seed_b64: str) -> dict[str, Any]:
    """Escalation uses the same signature scheme under its own schema."""
    return sign_evidence(payload, seed_b64)


def escalation_payload(
    row: dict[str, Any], *, reason: str, reconciler: str, observed_at_utc: str
) -> dict[str, Any]:
    return {
        "schema": "govai.escalation.v1",
        "authorization_id": row["authorization_id"],
        "run_id": row["run_id"],
        "reason": reason,
        "reconciler": reconciler,
        "observed_at_utc": observed_at_utc,
    }


def apply_escalation(
    store: ExecutionStore,
    signed: dict[str, Any],
    registry: ReconcilerRegistry,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Record a signed escalation for manual investigation. Changes no state. Raises ``ReconciliationRefused``."""
    now = now or datetime.now(UTC)
    payload = signed.get("payload") if isinstance(signed, dict) else None
    if not isinstance(payload, dict) or payload.get("schema") != "govai.escalation.v1":
        raise ReconciliationRefused("escalation_schema_mismatch")
    reconciler = payload.get("reconciler")
    pub = registry.public_key(reconciler) if isinstance(reconciler, str) else None
    if pub is None:
        raise ReconciliationRefused("reconciler_not_authorized")
    try:
        sig = base64.b64decode(signed["signature"], validate=True)
        VerifyKey(base64.b64decode(pub, validate=True)).verify(
            RECON_DOMAIN + canonical_bytes(payload), sig
        )
    except (BadSignatureError, KeyError, ValueError, TypeError) as exc:
        raise ReconciliationRefused("escalation_signature_invalid") from exc
    row = store.row(payload.get("authorization_id", ""))
    if row is None:
        raise ReconciliationRefused("authorization_not_found")
    if row["run_id"] != payload.get("run_id"):
        raise ReconciliationRefused("reconciliation_binding_mismatch")
    store.escalate(
        authorization_id=row["authorization_id"],
        actor=reconciler,
        now=now.isoformat(),
        reason=str(payload.get("reason", "")),
        evidence={"signature": signed["signature"], "escalation": payload},
    )
    return payload
