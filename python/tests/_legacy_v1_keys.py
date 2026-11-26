# TEST-ONLY copy of the v1 registry writer (commit eaab53f). Builds realistic v1 registries for the migration tests.
# Production code never imports this module; the v2 migration reads v1 logs with aigov_py.trusted.legacy_v1 only.
"""Trusted verification-key registry: key ownership, purposes, lifecycle, and historical trust.

What this module is:

- A registry of Ed25519 public keys. Each key has a stable identifier (``kid``), exactly one purpose, an owner, and a
  status. The registry is the source of truth for which key may verify which signature, and when.
- An append-only event log, hash-chained, that records every change. The registry snapshot is a view. On every load the
  state is rebuilt from the log; a snapshot that disagrees with the log is reported, and the log wins.
- Operator actions as signed requests. A change needs an operator in the registry with the right role, a signature by that
  operator's key over a domain-separated request, the current registry version (compare-and-swap), and a nonce that has not
  been used. Two processes racing for the same version cannot both succeed.
- A trust assessment that separates four things: the signature's cryptographic validity, whether the key was trusted at
  the time the signature claims, the key's current status, and whether a compromise leaves the result uncertain.

What this module is not:

- It does not hold private keys. Signing keys live with the signer (``signers.py``) or with Core. The registry holds
  public keys only.
- It does not provide a trusted timestamp. Every ``signed_at`` is a claim made by the signer. Historical verdicts are
  therefore only as good as those claims. The assessment says so in ``timestamp_trust``.
- It is not an identity provider. Operators are identities with keys pinned in the registry, not federated users.

Lifecycle of a key:

    pending -> active -> retired          (ordinary rotation: retired after its successor is active)
    pending | active | retired -> revoked (compromise; terminal)

Exactly one key per purpose is active at a time. Rotation moves the old key to retired and the new key to active in one
operation, recorded as one group of events. A retired key still verifies signatures that were made while it was active,
which is what keeps historical evidence verifiable after ordinary rotation.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import secrets
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from aigov_py.canonical_json import canonical_bytes

REGISTRY_SCHEMA = "govai.key_registry.v1"
OP_SCHEMA = "govai.key_op.v1"
OP_DOMAIN = b"govai.key_op.v1\x00"
EVENT_SCHEMA = "govai.key_event.v1"
MAX_CLOCK_SKEW = timedelta(minutes=5)

# One domain prefix per purpose. A signer for one purpose only signs messages that begin with that purpose's domain, and a
# verifier only accepts a signature under a key whose purpose matches. The policy-bundle format predates this module and has
# no prefix; its keys are still separated by purpose in the registry (see docs/operations/key-management-runbook.md).
DOMAINS: dict[str, bytes] = {
    "execution_authorization": b"govai.execution_authorization.v1\x00",
    "reconciliation_evidence": b"govai.reconciliation.v1\x00",
    "policy_bundle": b"govai.policy_bundle.v1\x00",
    "audit_export": b"govai.audit_export.v1\x00",
}
PURPOSES: tuple[str, ...] = tuple(DOMAINS)
STATUSES = ("pending", "active", "retired", "revoked")
OPERATOR_ROLES = ("keyadmin", "revoker", "reconciler")
OPS = ("register", "activate", "retire", "rotate", "revoke")
_KID_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")


class KeyRegistryError(Exception):
    """A refused operation or an invalid registry. ``code`` is a stable reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class RegistryIntegrityError(KeyRegistryError):
    """The event log does not verify, or a transition in it is not permitted. Nothing is trusted from such a registry."""


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat()


def _parse(ts: str) -> datetime:
    parsed = datetime.fromisoformat(ts)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def valid_kid(kid: str) -> bool:
    return 0 < len(kid) <= 64 and all(c in _KID_OK for c in kid)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(raw: str) -> bytes:
    return base64.b64decode(raw, validate=True)


def _event_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


@dataclass
class KeyRecord:
    kid: str
    purpose: str
    public_key_b64: str
    owner: str
    status: str = "pending"
    registered_at_utc: str = ""
    activated_at_utc: str | None = None
    retired_at_utc: str | None = None
    revoked_at_utc: str | None = None
    compromised_from_utc: str | None = None
    revocation_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "purpose": self.purpose,
            "algorithm": "Ed25519",
            "public_key_b64": self.public_key_b64,
            "owner": self.owner,
            "status": self.status,
            "registered_at_utc": self.registered_at_utc,
            "activated_at_utc": self.activated_at_utc,
            "retired_at_utc": self.retired_at_utc,
            "revoked_at_utc": self.revoked_at_utc,
            "compromised_from_utc": self.compromised_from_utc,
            "revocation_reason": self.revocation_reason,
        }


@dataclass
class State:
    version: int = 0
    keys: dict[str, KeyRecord] = field(default_factory=dict)
    operators: dict[str, dict[str, Any]] = field(default_factory=dict)
    nonces: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Assessment:
    """What is known about one signature. Each field answers a different question; none implies another."""

    kid: str
    purpose: str
    signature_valid: bool
    key_known: bool
    key_trusted_at_signing: bool
    current_status: str | None
    compromise_uncertainty: bool
    verdict: str  # trusted | untrusted | uncertain
    reasons: tuple[str, ...]
    timestamp_trust: str = "self_asserted"

    def accepted(self, *, accept_uncertain: bool = False) -> bool:
        return self.signature_valid and (self.verdict == "trusted" or (accept_uncertain and self.verdict == "uncertain"))


def _apply_event(state: State, ev: dict[str, Any]) -> None:
    """Replay one event into the state. Raises RegistryIntegrityError for any transition the lifecycle does not permit."""
    op, kid, ts = ev["op"], ev.get("kid"), ev["ts_utc"]
    detail = ev.get("detail", {})
    if ev.get("nonce"):
        if ev["nonce"] in state.nonces:
            raise RegistryIntegrityError("replayed_nonce", ev["nonce"])
        state.nonces.add(ev["nonce"])
    if op == "operator_register":
        state.operators[detail["identity"]] = {"public_key_b64": detail["public_key_b64"], "roles": list(detail["roles"])}
    elif op == "register":
        if kid in state.keys:
            raise RegistryIntegrityError("kid_already_registered", kid)
        state.keys[kid] = KeyRecord(
            kid=kid,
            purpose=detail["purpose"],
            public_key_b64=detail["public_key_b64"],
            owner=detail["owner"],
            registered_at_utc=ts,
        )
    elif op == "activate":
        rec = state.keys.get(kid)
        if rec is None or rec.status != "pending":
            raise RegistryIntegrityError("illegal_transition", f"activate {kid} from {rec.status if rec else 'unknown'}")
        if any(k.status == "active" and k.purpose == rec.purpose for k in state.keys.values()):
            raise RegistryIntegrityError("second_active_key", f"activate {kid} while another {rec.purpose} key is active")
        rec.status, rec.activated_at_utc = "active", ts
    elif op == "retire":
        rec = state.keys.get(kid)
        if rec is None or rec.status != "active":
            raise RegistryIntegrityError("illegal_transition", f"retire {kid} from {rec.status if rec else 'unknown'}")
        rec.status, rec.retired_at_utc = "retired", ts
    elif op == "revoke":
        rec = state.keys.get(kid)
        if rec is None or rec.status not in ("pending", "active", "retired"):
            raise RegistryIntegrityError("illegal_transition", f"revoke {kid} from {rec.status if rec else 'unknown'}")
        rec.status = "revoked"
        rec.revoked_at_utc = ts
        rec.compromised_from_utc = detail.get("compromised_from_utc") or ts
        rec.revocation_reason = detail.get("reason", "")
    else:
        raise RegistryIntegrityError("unknown_event", op)
    state.version = ev["version"]


class KeyRegistry:
    """A registry at ``path`` (snapshot) and ``path + '.events.jsonl'`` (authoritative log)."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._events_path = self._path.with_name(self._path.name + ".events.jsonl")
        self._lock_path = self._path.with_name(self._path.name + ".lock")
        self.state, self.events, self.snapshot_matches = self._replay()

    # --- loading and integrity --------------------------------------------------------------------------------

    def _read_events(self) -> list[dict[str, Any]]:
        if not self._events_path.exists():
            return []
        out = []
        for line in self._events_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def _replay(self) -> tuple[State, list[dict[str, Any]], bool]:
        events = self._read_events()
        prev: str | None = None
        state = State()
        for expected_seq, ev in enumerate(events, start=1):
            body = {k: v for k, v in ev.items() if k != "hash"}
            if ev.get("seq") != expected_seq:
                raise RegistryIntegrityError("event_sequence_broken", f"event {expected_seq}")
            if ev.get("prev_hash") != prev:
                raise RegistryIntegrityError("event_chain_broken", f"event {expected_seq}")
            if _event_hash(body) != ev.get("hash"):
                raise RegistryIntegrityError("event_altered", f"event {expected_seq}")
            _apply_event(state, ev)
            prev = ev["hash"]
        snapshot_matches = True
        if self._path.exists():
            snap = json.loads(self._path.read_text(encoding="utf-8"))
            snapshot_matches = snap.get("version") == state.version and snap.get("keys") == {
                kid: rec.as_dict() for kid, rec in state.keys.items()
            }
        return state, events, snapshot_matches

    @classmethod
    def load(cls, path: Path) -> KeyRegistry:
        return cls(path)

    def refresh(self) -> None:
        """Re-read and re-verify the log. Call before any decision that must see the latest revocation or rotation."""
        self.state, self.events, self.snapshot_matches = self._replay()

    @property
    def version(self) -> int:
        return self.state.version

    def get(self, kid: str) -> KeyRecord | None:
        return self.state.keys.get(kid)

    def active_for(self, purpose: str) -> KeyRecord | None:
        return next((k for k in self.state.keys.values() if k.status == "active" and k.purpose == purpose), None)

    def operator_key(self, identity: str) -> bytes | None:
        op = self.state.operators.get(identity)
        return _unb64(op["public_key_b64"]) if op else None

    # --- bootstrap (the first operator is installed by the operator, once) -------------------------------------

    def install_operator(self, identity: str, public_key_b64: str, roles: tuple[str, ...]) -> None:
        """Install an operator. Allowed only while the registry has no operators yet: the first keyadmin is trusted by
        the person who created the file. Later operators are added only by a keyadmin's signed request."""
        if self.state.operators:
            raise KeyRegistryError("operators_already_installed", "add operators with a signed keyadmin request")
        for r in roles:
            if r not in OPERATOR_ROLES:
                raise KeyRegistryError("unknown_role", r)
        _unb64(public_key_b64)
        with self._locked():
            self._append(
                "operator_register",
                None,
                None,
                actor="bootstrap",
                detail={"identity": identity, "public_key_b64": public_key_b64, "roles": list(roles)},
                version=self.state.version + 1,
                nonce=None,
                request_sha256=None,
            )

    # --- signed operator requests ------------------------------------------------------------------------------

    @staticmethod
    def sign_request(payload: dict[str, Any], seed_b64: str) -> dict[str, Any]:
        sk = SigningKey(_unb64(seed_b64))
        sig = sk.sign(OP_DOMAIN + canonical_bytes(payload)).signature
        return {"payload": payload, "signature": _b64(sig)}

    @staticmethod
    def new_request(*, op: str, actor: str, expected_version: int, **fields: Any) -> dict[str, Any]:
        """A request payload. The nonce makes each request usable once; issued_at bounds how long it stays usable."""
        return {
            "schema": OP_SCHEMA,
            "op": op,
            "actor": actor,
            "expected_version": expected_version,
            "nonce": secrets.token_hex(16),
            "issued_at_utc": _iso(_now()),
            **fields,
        }

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._lock_path, "a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _reload_locked(self) -> None:
        self.state, self.events, self.snapshot_matches = self._replay()

    def _append(
        self,
        op: str,
        kid: str | None,
        purpose: str | None,
        *,
        actor: str,
        detail: dict[str, Any],
        version: int,
        nonce: str | None,
        request_sha256: str | None,
        group: str | None = None,
    ) -> None:
        prev = self.events[-1]["hash"] if self.events else None
        body = {
            "schema": EVENT_SCHEMA,
            "seq": len(self.events) + 1,
            "version": version,
            "ts_utc": _iso(_now()),
            "op": op,
            "kid": kid,
            "purpose": purpose,
            "actor": actor,
            "group": group,
            "nonce": nonce,
            "request_sha256": request_sha256,
            "detail": detail,
            "prev_hash": prev,
        }
        ev = {**body, "hash": _event_hash(body)}
        with open(self._events_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        _apply_event(self.state, ev)
        self.events.append(ev)
        self._write_snapshot()

    def _write_snapshot(self) -> None:
        snap = {
            "schema": REGISTRY_SCHEMA,
            "version": self.state.version,
            "operators": {k: {"public_key_b64": v["public_key_b64"], "roles": v["roles"]} for k, v in self.state.operators.items()},
            "keys": {kid: rec.as_dict() for kid, rec in self.state.keys.items()},
            "note": "A view of the event log. The log is authoritative; this file is checked against it on load.",
        }
        tmp = self._path.with_name(self._path.name + f".tmp-{os.getpid()}")
        tmp.write_text(json.dumps(snap, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self._path)
        self.snapshot_matches = True

    def _authorize(self, request: dict[str, Any], *, needed_role: str, op: str) -> bytes:
        payload = request.get("payload")
        if not isinstance(payload, dict) or payload.get("schema") != OP_SCHEMA:
            raise KeyRegistryError("request_schema_mismatch")
        if payload.get("op") != op:
            raise KeyRegistryError("request_op_mismatch", f"expected {op}")
        actor = payload.get("actor")
        pub = self.operator_key(actor) if isinstance(actor, str) else None
        if pub is None:
            raise KeyRegistryError("operator_not_authorized", "unknown operator")
        roles = self.state.operators[actor]["roles"]
        if needed_role not in roles:
            raise KeyRegistryError("operator_not_authorized", f"{actor} lacks role {needed_role}")
        try:
            VerifyKey(pub).verify(OP_DOMAIN + canonical_bytes(payload), _unb64(request["signature"]))
        except (BadSignatureError, KeyError, ValueError, TypeError) as exc:
            raise KeyRegistryError("request_signature_invalid") from exc
        issued = _parse(payload["issued_at_utc"])
        if abs(_now() - issued) > MAX_CLOCK_SKEW:
            raise KeyRegistryError("request_not_fresh", "issued_at_utc is outside the allowed window")
        if payload.get("expected_version") != self.state.version:
            raise KeyRegistryError("version_conflict", f"registry is at version {self.state.version}")
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or len(nonce) < 16 or nonce in self.state.nonces:
            raise KeyRegistryError("nonce_rejected")
        return canonical_bytes(payload)

    def _request_hash(self, request: dict[str, Any]) -> str:
        return hashlib.sha256(canonical_bytes(request["payload"])).hexdigest()

    # --- operations -------------------------------------------------------------------------------------------

    def register(self, request: dict[str, Any]) -> KeyRecord:
        p = request["payload"]
        self._authorize(request, needed_role="keyadmin", op="register")
        kid, purpose, pub = p["kid"], p["purpose"], p["public_key_b64"]
        if not valid_kid(kid):
            raise KeyRegistryError("kid_invalid")
        if purpose not in PURPOSES:
            raise KeyRegistryError("purpose_unknown", purpose)
        try:
            if len(_unb64(pub)) != 32:
                raise ValueError
        except (ValueError, TypeError) as exc:
            raise KeyRegistryError("public_key_invalid") from exc
        with self._locked():
            self._reload_locked()
            self._authorize(request, needed_role="keyadmin", op="register")
            if kid in self.state.keys:
                raise KeyRegistryError("kid_already_registered", "a key id cannot be reused, with any key")
            self._append(
                "register", kid, purpose, actor=p["actor"],
                detail={"purpose": purpose, "public_key_b64": pub, "owner": p.get("owner", p["actor"])},
                version=self.state.version + 1, nonce=p["nonce"], request_sha256=self._request_hash(request),
            )
        return self.state.keys[kid]

    def activate(self, request: dict[str, Any]) -> KeyRecord:
        p = request["payload"]
        with self._locked():
            self._reload_locked()
            self._authorize(request, needed_role="keyadmin", op="activate")
            rec = self.state.keys.get(p["kid"])
            if rec is None:
                raise KeyRegistryError("kid_unknown")
            if rec.status != "pending":
                raise KeyRegistryError("illegal_transition", f"activate from {rec.status}")
            if self.active_for(rec.purpose) is not None:
                raise KeyRegistryError("second_active_key", "retire or rotate the current key first")
            self._append(
                "activate", rec.kid, rec.purpose, actor=p["actor"], detail={},
                version=self.state.version + 1, nonce=p["nonce"], request_sha256=self._request_hash(request),
            )
        return self.state.keys[p["kid"]]

    def retire(self, request: dict[str, Any]) -> KeyRecord:
        p = request["payload"]
        with self._locked():
            self._reload_locked()
            self._authorize(request, needed_role="keyadmin", op="retire")
            rec = self.state.keys.get(p["kid"])
            if rec is None:
                raise KeyRegistryError("kid_unknown")
            if rec.status != "active":
                raise KeyRegistryError("illegal_transition", f"retire from {rec.status}")
            self._append(
                "retire", rec.kid, rec.purpose, actor=p["actor"], detail={},
                version=self.state.version + 1, nonce=p["nonce"], request_sha256=self._request_hash(request),
            )
        return self.state.keys[p["kid"]]

    def rotate(self, request: dict[str, Any]) -> tuple[KeyRecord, KeyRecord]:
        """Retire the active key and activate its successor, as one group of two events."""
        p = request["payload"]
        with self._locked():
            self._reload_locked()
            self._authorize(request, needed_role="keyadmin", op="rotate")
            old = self.active_for(p["purpose"]) if p.get("purpose") else None
            new = self.state.keys.get(p["successor_kid"])
            if old is None or old.kid != p["kid"]:
                raise KeyRegistryError("rotation_mismatch", "kid is not the active key for this purpose")
            if new is None or new.status != "pending" or new.purpose != old.purpose:
                raise KeyRegistryError("rotation_mismatch", "successor must be a pending key of the same purpose")
            group = secrets.token_hex(8)
            rhash = self._request_hash(request)
            self._append("retire", old.kid, old.purpose, actor=p["actor"], detail={"rotation_group": group},
                         version=self.state.version + 1, nonce=p["nonce"], request_sha256=rhash, group=group)
            self._append("activate", new.kid, new.purpose, actor=p["actor"], detail={"rotation_group": group},
                         version=self.state.version + 1, nonce=None, request_sha256=rhash, group=group)
        return self.state.keys[old.kid], self.state.keys[new.kid]

    def revoke(self, request: dict[str, Any]) -> KeyRecord:
        p = request["payload"]
        with self._locked():
            self._reload_locked()
            self._authorize(request, needed_role="revoker", op="revoke")
            rec = self.state.keys.get(p["kid"])
            if rec is None:
                raise KeyRegistryError("kid_unknown")
            if rec.status == "revoked":
                raise KeyRegistryError("illegal_transition", "already revoked")
            reason = str(p.get("reason", ""))[:200]
            if not reason:
                raise KeyRegistryError("reason_required")
            self._append(
                "revoke", rec.kid, rec.purpose, actor=p["actor"],
                detail={"reason": reason, "compromised_from_utc": p.get("compromised_from_utc")},
                version=self.state.version + 1, nonce=p["nonce"], request_sha256=self._request_hash(request),
            )
        return self.state.keys[p["kid"]]

    # --- verification and assessment ---------------------------------------------------------------------------

    def assess(
        self,
        *,
        purpose: str,
        kid: str,
        payload: bytes,
        signature_b64: str,
        signed_at_utc: str,
        now: datetime | None = None,
    ) -> Assessment:
        """Assess one signature. ``payload`` is the signed bytes without the domain prefix; the domain is added here."""
        now = now or _now()
        reasons: list[str] = []
        rec = self.get(kid)
        if rec is None:
            return Assessment(kid, purpose, False, False, False, None, False, "untrusted", ("key_unknown",))
        if rec.purpose != purpose:
            return Assessment(kid, purpose, False, True, False, rec.status, False, "untrusted", ("purpose_mismatch",))
        signature_valid = False
        try:
            VerifyKey(_unb64(rec.public_key_b64)).verify(DOMAINS[purpose] + payload, _unb64(signature_b64))
            signature_valid = True
        except (BadSignatureError, ValueError, TypeError):
            reasons.append("signature_invalid")
        try:
            signed_at = _parse(signed_at_utc)
        except (TypeError, ValueError):
            return Assessment(kid, purpose, signature_valid, True, False, rec.status, False, "untrusted",
                              tuple(reasons + ["signed_at_invalid"]))

        trusted_at = False
        uncertain = False
        if rec.activated_at_utc is None or signed_at < _parse(rec.activated_at_utc):
            reasons.append("not_yet_active_at_signing")
        elif rec.status == "revoked":
            compromised_from = _parse(rec.compromised_from_utc or rec.revoked_at_utc)
            if signed_at >= compromised_from:
                reasons.append("signed_after_compromise")
            else:
                uncertain = True
                reasons.append("signed_before_compromise_uncertain")
                trusted_at = True
        elif rec.status == "retired":
            if rec.retired_at_utc and signed_at >= _parse(rec.retired_at_utc):
                reasons.append("signed_after_retirement")
            else:
                trusted_at = True
                reasons.append("ordinary_rotation_key_trusted_at_signing")
        elif rec.status == "active":
            trusted_at = True
        else:
            reasons.append("key_not_active")
        if signed_at > now + MAX_CLOCK_SKEW:
            reasons.append("signed_in_future")
            trusted_at = False

        if not signature_valid:
            verdict = "untrusted"
        elif trusted_at and not uncertain:
            verdict = "trusted"
        elif uncertain:
            verdict = "uncertain"
        else:
            verdict = "untrusted"
        return Assessment(
            kid=kid,
            purpose=purpose,
            signature_valid=signature_valid,
            key_known=True,
            key_trusted_at_signing=trusted_at,
            current_status=rec.status,
            compromise_uncertainty=uncertain,
            verdict=verdict,
            reasons=tuple(reasons),
        )

    def verify_integrity(self) -> dict[str, Any]:
        """Re-check the log end to end and the snapshot against it. Used by the operator tool and the tests."""
        state, events, snap_ok = self._replay()
        return {"events": len(events), "version": state.version, "snapshot_matches_log": snap_ok,
                "chain_verified": True}


def new_signing_seed() -> tuple[str, str]:
    """A new Ed25519 key pair for a purpose. Returns (seed_b64, public_key_b64). The seed belongs to its signer."""
    sk = SigningKey.generate()
    return _b64(bytes(sk)), _b64(bytes(sk.verify_key))


def key_status_now(registry: KeyRegistry, kid: str) -> str | None:
    rec = registry.get(kid)
    return rec.status if rec else None


def time_sleep_for_tests(seconds: float) -> None:  # pragma: no cover - convenience for live tests
    time.sleep(seconds)
