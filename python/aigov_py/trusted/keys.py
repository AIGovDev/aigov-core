"""Trusted verification-key registry (format v2): key ownership, purposes, lifecycle, and historical trust.

What this module is:

- A registry of Ed25519 public keys. Each key has a stable identifier (``kid``), one purpose, an owner, and a status.
- An append-only event log in which every event carries the signed request that produced it. Replay verifies every
  signature, the sequence, the hash chain, the authorization of the signer, and every state transition. Nothing in the
  registry's files is trusted by itself.
- A root of trust outside the registry. The root operator public keys are pinned in a trusted configuration file (the
  trust file, see ``TrustConfig``). The registry cannot supply or replace a root key. Only roots install and remove
  operators and import legacy history. Operators (identities with roles) sign lifecycle changes.
- An independent anchor (``registry_anchor``): the sequence number and head hash of the last committed event, kept in
  PostgreSQL. Readers require the log to match the anchor exactly. A rolled-back log is shorter than the anchor; a
  substituted log has a different head; an unreconciled write is longer. All three are refused.
- A trust assessment that separates the signature's validity, trust at the time it claims, the current status, and
  compromise uncertainty. Keys imported from a v1 registry carry an explicit provenance flag, and their history is
  never more than ``uncertain``.

What this module is not:

- It holds public keys only. Private keys belong to their signers. Core and the executor never receive a root seed.
- It provides no trusted timestamp. ``issued_at_utc`` in a signed request is a claim by the signer.
- It does not defend against a party that can change the trust file and the anchor at the same time. That residual is
  documented in ``docs/operations/key-management-runbook.md``.

Lifecycle of a key:

    pending -> active -> retired          (ordinary rotation: retired when its successor becomes active)
    pending | active | retired -> revoked (compromise; terminal)

Exactly one key per purpose is active at a time. Rotation is one ``rotate`` event that retires the old key and activates
its successor.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
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
from aigov_py.trusted.registry_anchor import GENESIS, AnchorError, AnchorState

REGISTRY_SCHEMA = "govai.key_registry.v2"
EVENT_SCHEMA = "govai.key_event.v2"
OP_SCHEMA = "govai.key_op.v2"
OP_DOMAIN = b"govai.key_op.v2\x00"
TRUST_SCHEMA = "govai.key_registry_trust.v1"
LEGACY_V1_EVENT_SCHEMA = "govai.key_event.v1"
MAX_CLOCK_SKEW = timedelta(minutes=5)
NONCE_MIN_LENGTH = 16
READ_ATTEMPTS = 5
READ_RETRY_SECONDS = 0.05
PROVENANCE_SIGNED = "signed"
PROVENANCE_LEGACY_V1 = "legacy_v1_unsigned"

# One domain prefix per purpose. A signer for one purpose signs only messages that begin with that purpose's domain, and a
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
ROOT_OPS = ("legacy_import", "operator_install", "operator_revoke")
OPERATOR_OP_ROLE = {"register": "keyadmin", "activate": "keyadmin", "retire": "keyadmin", "rotate": "keyadmin", "revoke": "revoker"}
OPS = ROOT_OPS + tuple(OPERATOR_OP_ROLE)
_KID_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
_IDENTITY = re.compile(r"^[A-Za-z0-9._@:-]{1,128}$")


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


def _public_key_ok(pub_b64: str) -> bool:
    try:
        return len(_unb64(pub_b64)) == 32
    except (ValueError, TypeError):
        return False


def _event_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


# --- trusted configuration -------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RootKey:
    kid: str
    public_key_b64: str
    status: str  # "current" | "retired"
    retired_after_seq: int | None  # a retired root may sign events up to and including this sequence number


@dataclass(frozen=True)
class TrustConfig:
    """The pinned roots of trust for one registry. Loaded from a file the registry cannot change."""

    registry_id: str
    roots: tuple[RootKey, ...]

    @classmethod
    def load(cls, path: Path | str) -> TrustConfig:
        p = Path(path)
        try:
            st = p.stat()
        except OSError as exc:
            raise KeyRegistryError("trust_config_missing", str(p)) from exc
        if st.st_mode & 0o077:
            raise KeyRegistryError("trust_config_permissions", "the trust file must be readable only by its owner")
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise KeyRegistryError("trust_config_invalid", "not JSON") from exc
        return cls.from_dict(doc)

    @classmethod
    def from_dict(cls, doc: Any) -> TrustConfig:
        if not isinstance(doc, dict) or doc.get("schema") != TRUST_SCHEMA:
            raise KeyRegistryError("trust_config_invalid", "schema")
        rid = doc.get("registry_id")
        if not isinstance(rid, str) or not rid.strip():
            raise KeyRegistryError("trust_config_invalid", "registry_id")
        raw_roots = doc.get("roots")
        if not isinstance(raw_roots, list) or not raw_roots:
            raise KeyRegistryError("trust_config_invalid", "roots")
        roots: list[RootKey] = []
        seen: set[str] = set()
        for r in raw_roots:
            if not isinstance(r, dict):
                raise KeyRegistryError("trust_config_invalid", "root entry")
            kid, pub, status = r.get("kid"), r.get("public_key_b64"), r.get("status")
            if not isinstance(kid, str) or not valid_kid(kid) or kid in seen:
                raise KeyRegistryError("trust_config_invalid", f"root kid {kid!r}")
            seen.add(kid)
            if not isinstance(pub, str) or not _public_key_ok(pub):
                raise KeyRegistryError("trust_config_invalid", f"root {kid} public key")
            if status == "current":
                if "retired_after_seq" in r:
                    raise KeyRegistryError("trust_config_invalid", f"current root {kid} has retired_after_seq")
                roots.append(RootKey(kid, pub, "current", None))
            elif status == "retired":
                after = r.get("retired_after_seq")
                if not isinstance(after, int) or isinstance(after, bool) or after < 0:
                    raise KeyRegistryError("trust_config_invalid", f"retired root {kid} needs retired_after_seq")
                roots.append(RootKey(kid, pub, "retired", after))
            else:
                raise KeyRegistryError("trust_config_invalid", f"root {kid} status")
        if not any(r.status == "current" for r in roots):
            raise KeyRegistryError("trust_config_invalid", "at least one current root is required")
        return cls(registry_id=rid, roots=tuple(roots))

    def root(self, kid: str) -> RootKey | None:
        return next((r for r in self.roots if r.kid == kid), None)

    def root_may_sign(self, kid: str, seq: int) -> RootKey | None:
        r = self.root(kid)
        if r is None:
            return None
        if r.status == "current":
            return r
        if r.retired_after_seq is not None and seq <= r.retired_after_seq:
            return r
        return None


# --- state and records -------------------------------------------------------------------------------------------------


@dataclass
class KeyRecord:
    kid: str
    purpose: str
    public_key_b64: str
    owner: str
    status: str = "pending"
    provenance: str = PROVENANCE_SIGNED
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
            "provenance": self.provenance,
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
    legacy_imported: bool = False


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


# --- verification of the log (pure: used by readers, writers, and reconcile) -------------------------------------------


def head_hash(events: list[dict[str, Any]]) -> str:
    return events[-1]["hash"] if events else GENESIS


def _verify_request_signature(state: State, trust: TrustConfig, seq: int, request: dict[str, Any]) -> None:
    """Check the signer and the signature of one request. Raises RegistryIntegrityError."""
    payload = request.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != OP_SCHEMA:
        raise RegistryIntegrityError("request_schema_mismatch", f"event {seq}")
    op, actor = payload.get("op"), payload.get("actor")
    if op not in OPS:
        raise RegistryIntegrityError("unknown_event", f"event {seq}: {op!r}")
    if payload.get("expected_version") != seq - 1:
        raise RegistryIntegrityError("expected_version_mismatch", f"event {seq}")
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or len(nonce) < NONCE_MIN_LENGTH or nonce in state.nonces:
        raise RegistryIntegrityError("replayed_nonce", f"event {seq}")
    try:
        _parse(payload["issued_at_utc"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RegistryIntegrityError("request_time_invalid", f"event {seq}") from exc
    if not isinstance(actor, str):
        raise RegistryIntegrityError("signer_missing", f"event {seq}")
    if op in ROOT_OPS:
        if op == "legacy_import" and seq != 1:
            raise RegistryIntegrityError("legacy_import_not_first", f"event {seq}")
        root = trust.root_may_sign(actor, seq)
        if root is None:
            raise RegistryIntegrityError("root_not_authorized", f"event {seq}: {actor} is not a root for this sequence")
        pub = _unb64(root.public_key_b64)
    else:
        op_rec = state.operators.get(actor)
        if op_rec is None or op_rec["status"] != "active":
            raise RegistryIntegrityError("operator_not_authorized", f"event {seq}: unknown or inactive operator")
        need = OPERATOR_OP_ROLE[op]
        if need not in op_rec["roles"]:
            raise RegistryIntegrityError("operator_not_authorized", f"event {seq}: {actor} lacks role {need}")
        pub = _unb64(op_rec["public_key_b64"])
    try:
        VerifyKey(pub).verify(OP_DOMAIN + canonical_bytes(payload), _unb64(request["signature"]))
    except (BadSignatureError, KeyError, ValueError, TypeError) as exc:
        raise RegistryIntegrityError("request_signature_invalid", f"event {seq}") from exc


def _transition(state: State, seq: int, payload: dict[str, Any]) -> None:
    """Apply one verified request to the state. Raises RegistryIntegrityError for a transition the lifecycle forbids."""
    op = payload["op"]
    ts = payload["issued_at_utc"]
    state.nonces.add(payload["nonce"])
    if op == "legacy_import":
        if state.keys or state.operators or state.legacy_imported:
            raise RegistryIntegrityError("legacy_import_not_empty", f"event {seq}")
        for identity, rec in payload.get("operators", {}).items():
            state.operators[identity] = {"public_key_b64": rec["public_key_b64"], "roles": list(rec["roles"]), "status": "active"}
        for kid, rec in payload.get("keys", {}).items():
            state.keys[kid] = KeyRecord(
                kid=kid, purpose=rec["purpose"], public_key_b64=rec["public_key_b64"], owner=rec["owner"],
                status=rec["status"], provenance=PROVENANCE_LEGACY_V1, registered_at_utc=rec.get("registered_at_utc") or ts,
                activated_at_utc=rec.get("activated_at_utc"), retired_at_utc=rec.get("retired_at_utc"),
                revoked_at_utc=rec.get("revoked_at_utc"), compromised_from_utc=rec.get("compromised_from_utc"),
                revocation_reason=rec.get("revocation_reason"),
            )
        state.legacy_imported = True
    elif op == "operator_install":
        identity = payload["identity"]
        if not isinstance(identity, str) or not _IDENTITY.match(identity):
            raise RegistryIntegrityError("operator_identity_invalid", f"event {seq}")
        if identity in state.operators:
            raise RegistryIntegrityError("operator_exists", f"event {seq}: {identity}")
        roles = payload["roles"]
        if not isinstance(roles, list) or not roles or any(r not in OPERATOR_ROLES for r in roles):
            raise RegistryIntegrityError("operator_roles_invalid", f"event {seq}")
        if not _public_key_ok(payload["public_key_b64"]):
            raise RegistryIntegrityError("operator_key_invalid", f"event {seq}")
        state.operators[identity] = {"public_key_b64": payload["public_key_b64"], "roles": list(roles), "status": "active"}
    elif op == "operator_revoke":
        identity = payload["identity"]
        rec = state.operators.get(identity)
        if rec is None or rec["status"] != "active":
            raise RegistryIntegrityError("illegal_transition", f"event {seq}: operator {identity} is not active")
        rec["status"] = "revoked"
    elif op == "register":
        kid = payload["kid"]
        if not valid_kid(kid):
            raise RegistryIntegrityError("kid_invalid", f"event {seq}")
        if kid in state.keys:
            raise RegistryIntegrityError("kid_already_registered", f"event {seq}: {kid}")
        if payload["purpose"] not in PURPOSES or not _public_key_ok(payload["public_key_b64"]):
            raise RegistryIntegrityError("register_invalid", f"event {seq}")
        state.keys[kid] = KeyRecord(
            kid=kid, purpose=payload["purpose"], public_key_b64=payload["public_key_b64"],
            owner=payload.get("owner") or payload["actor"], registered_at_utc=ts,
        )
    elif op == "activate":
        rec = state.keys.get(payload["kid"])
        if rec is None or rec.status != "pending":
            raise RegistryIntegrityError("illegal_transition", f"event {seq}: activate from {rec.status if rec else 'unknown'}")
        if any(k.status == "active" and k.purpose == rec.purpose for k in state.keys.values()):
            raise RegistryIntegrityError("second_active_key", f"event {seq}")
        rec.status, rec.activated_at_utc = "active", ts
    elif op == "retire":
        rec = state.keys.get(payload["kid"])
        if rec is None or rec.status != "active":
            raise RegistryIntegrityError("illegal_transition", f"event {seq}: retire from {rec.status if rec else 'unknown'}")
        rec.status, rec.retired_at_utc = "retired", ts
    elif op == "rotate":
        old = state.keys.get(payload["kid"])
        new = state.keys.get(payload["successor_kid"])
        if old is None or old.status != "active":
            raise RegistryIntegrityError("rotation_mismatch", f"event {seq}: {payload['kid']} is not the active key")
        if new is None or new.status != "pending" or new.purpose != old.purpose:
            raise RegistryIntegrityError("rotation_mismatch", f"event {seq}: successor must be pending and of the same purpose")
        old.status, old.retired_at_utc = "retired", ts
        new.status, new.activated_at_utc = "active", ts
    elif op == "revoke":
        rec = state.keys.get(payload["kid"])
        if rec is None or rec.status not in ("pending", "active", "retired"):
            raise RegistryIntegrityError("illegal_transition", f"event {seq}: revoke from {rec.status if rec else 'unknown'}")
        reason = str(payload.get("reason", ""))[:200]
        if not reason:
            raise RegistryIntegrityError("reason_required", f"event {seq}")
        rec.status = "revoked"
        rec.revoked_at_utc = ts
        rec.compromised_from_utc = payload.get("compromised_from_utc") or ts
        rec.revocation_reason = reason
    state.version = seq


def verify_log(events: list[dict[str, Any]], trust: TrustConfig) -> State:
    """Verify the whole log from genesis: every hash, sequence number, signature, authorization, and transition."""
    state = State()
    prev: str | None = None
    for seq, ev in enumerate(events, start=1):
        if not isinstance(ev, dict) or ev.get("schema") != EVENT_SCHEMA:
            raise RegistryIntegrityError("event_schema", f"event {seq}")
        if ev.get("seq") != seq:
            raise RegistryIntegrityError("event_sequence_broken", f"event {seq}")
        if ev.get("prev_hash") != prev:
            raise RegistryIntegrityError("event_chain_broken", f"event {seq}")
        body = {k: v for k, v in ev.items() if k != "hash"}
        if _event_hash(body) != ev.get("hash"):
            raise RegistryIntegrityError("event_altered", f"event {seq}")
        request = ev.get("request")
        _verify_request_signature(state, trust, seq, request)
        if seq == 1 and request["payload"]["op"] not in ("legacy_import", "operator_install"):
            # A registry starts either with a root-signed v1 import or with a root-signed first operator.
            raise RegistryIntegrityError("genesis_invalid", f"event {seq}")
        _transition(state, seq, request["payload"])
        prev = ev["hash"]
    return state


def check_anchor(events: list[dict[str, Any]], anchor: AnchorState | None) -> None:
    """Refuse unless the log is exactly the state the anchor records."""
    if anchor is None:
        raise KeyRegistryError("anchor_missing", "the registry anchor is not initialized")
    if len(events) < anchor.seq:
        raise KeyRegistryError("anchor_log_behind", "the log has fewer events than the anchor: rollback or truncation")
    if len(events) > anchor.seq:
        raise KeyRegistryError("anchor_log_ahead", "the log has events the anchor does not record: reconcile or investigate")
    if head_hash(events) != anchor.head_hash:
        raise KeyRegistryError("anchor_head_mismatch", "the log head is not the anchored head: substitution")


# --- the registry ------------------------------------------------------------------------------------------------------


class KeyRegistry:
    """A registry at ``path`` (log: ``path + '.events.jsonl'``), anchored by ``anchor`` and rooted by ``trust``.

    Reading verifies the whole log and checks it against the anchor. Writing takes the anchor's exclusive transaction for
    the whole append and commit. ``path`` (the snapshot) is a view for people and is never read for decisions.
    """

    def __init__(self, path: Path | str, *, trust: TrustConfig, anchor: Any) -> None:
        self._path = Path(path)
        self._events_path = self._path.with_name(self._path.name + ".events.jsonl")
        self._lock_path = self._path.with_name(self._path.name + ".lock")
        self._trust = trust
        self._anchor = anchor
        self.events: list[dict[str, Any]] = []
        self.state = State()
        self.refresh()

    @classmethod
    def load(cls, path: Path | str, *, trust: TrustConfig, anchor: Any) -> KeyRegistry:
        return cls(path, trust=trust, anchor=anchor)

    # --- reading ---------------------------------------------------------------------------------------------------

    def _read_events(self) -> list[dict[str, Any]]:
        if not self._events_path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self._events_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except ValueError as exc:
                raise RegistryIntegrityError("event_unparseable", f"event {len(out) + 1}") from exc
        return out

    def refresh(self) -> None:
        """Re-read the log, verify it, and check it against the anchor. Call before any decision.

        The log and the anchor are read without a lock, so a commit that lands between the two reads looks like a mismatch.
        Mismatches are therefore retried a few times. The view is accepted only when one attempt sees the log and the anchor
        agree. If the last attempt still disagrees, the read is refused: the retry hides timing, never a real mismatch.
        """
        for attempt in range(READ_ATTEMPTS):
            try:
                events = self._read_events()
                state = verify_log(events, self._trust)
            except RegistryIntegrityError as exc:
                if exc.code == "event_unparseable" and attempt < READ_ATTEMPTS - 1:
                    time.sleep(READ_RETRY_SECONDS)
                    continue
                raise
            try:
                anchored = self._anchor.current()
            except AnchorError as exc:
                raise KeyRegistryError(exc.code, exc.detail) from exc
            try:
                check_anchor(events, anchored)
            except KeyRegistryError as exc:
                if exc.code in ("anchor_log_behind", "anchor_log_ahead") and attempt < READ_ATTEMPTS - 1:
                    time.sleep(READ_RETRY_SECONDS)
                    continue
                raise
            self.events, self.state = events, state
            return

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

    def verify_integrity(self) -> dict[str, Any]:
        self.refresh()
        return {"events": len(self.events), "version": self.version, "anchored": True, "chain_verified": True}

    # --- requests ----------------------------------------------------------------------------------------------------

    @staticmethod
    def sign_request(payload: dict[str, Any], seed_b64: str) -> dict[str, Any]:
        sk = SigningKey(_unb64(seed_b64))
        sig = sk.sign(OP_DOMAIN + canonical_bytes(payload)).signature
        return {"payload": payload, "signature": _b64(sig)}

    @staticmethod
    def new_request(*, op: str, actor: str, expected_version: int, **fields: Any) -> dict[str, Any]:
        """A request payload. ``expected_version`` is the version the request was made against; a nonce makes it single-use."""
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
    def _file_lock(self) -> Iterator[None]:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._lock_path, "a+") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    # --- writing -----------------------------------------------------------------------------------------------------

    def _submit(self, request: dict[str, Any], *, now: datetime | None = None, hook: Any = None) -> dict[str, Any]:
        """Verify and commit one signed request. ``hook`` runs after the append and before the anchor commit (tests)."""
        now = now or _now()
        with self._file_lock(), self._anchor.exclusive() as tx:
            anchored = tx.current()
            events = self._read_events()
            state = verify_log(events, self._trust)
            check_anchor(events, anchored)
            payload = request["payload"]
            if abs(now - _parse(payload["issued_at_utc"])) > MAX_CLOCK_SKEW:
                raise KeyRegistryError("request_not_fresh", "issued_at_utc is outside the allowed window")
            seq = len(events) + 1
            if payload.get("expected_version") != len(events):
                raise KeyRegistryError("version_conflict", f"registry is at version {len(events)}")
            try:
                _verify_request_signature(state, self._trust, seq, request)
            except RegistryIntegrityError as exc:
                raise KeyRegistryError(exc.code, exc.detail) from exc
            prev = events[-1]["hash"] if events else None
            body = {"schema": EVENT_SCHEMA, "seq": seq, "prev_hash": prev, "request": request}
            ev = {**body, "hash": _event_hash(body)}
            try:
                _transition(state, seq, payload)
            except RegistryIntegrityError as exc:
                raise KeyRegistryError(exc.code, exc.detail) from exc
            with open(self._events_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            if hook is not None:
                hook()
            tx.set(AnchorState(seq, ev["hash"]), expected=anchored)
        self.events = events + [ev]
        self.state = state
        self._write_snapshot()
        return ev

    def reconcile(self) -> AnchorState:
        """Anchor one event that was appended but not committed (a crash between append and commit).

        Only the single event beyond the anchor can be reconciled, and only if the whole log verifies. Anything else is
        refused and must be investigated.
        """
        with self._file_lock(), self._anchor.exclusive() as tx:
            anchored = tx.current()
            if anchored is None:
                raise KeyRegistryError("anchor_missing", "the registry anchor is not initialized")
            events = self._read_events()
            if len(events) != anchored.seq + 1:
                raise KeyRegistryError("nothing_to_reconcile", f"log has {len(events)} events, anchor {anchored.seq}")
            verify_log(events, self._trust)
            before = head_hash(events[: anchored.seq])
            if before != anchored.head_hash:
                raise KeyRegistryError("anchor_head_mismatch", "the event before the extra one is not the anchored head")
            new = AnchorState(len(events), events[-1]["hash"])
            tx.set(new, expected=anchored)
        self.refresh()
        return new

    def _write_snapshot(self) -> None:
        snap = {
            "schema": REGISTRY_SCHEMA,
            "version": self.state.version,
            "operators": {k: {"public_key_b64": v["public_key_b64"], "roles": v["roles"], "status": v["status"]}
                          for k, v in self.state.operators.items()},
            "keys": {kid: rec.as_dict() for kid, rec in self.state.keys.items()},
            "note": "A view of the event log. The log and the anchor are authoritative; this file is never read for decisions.",
        }
        tmp = self._path.with_name(self._path.name + f".tmp-{os.getpid()}")
        tmp.write_text(json.dumps(snap, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self._path)

    # --- operations (each takes a signed request; the signer is verified against the log and the trust file) ----------

    def install_operator_request(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._submit(request)

    def register(self, request: dict[str, Any]) -> KeyRecord:
        self._submit(request)
        return self.state.keys[request["payload"]["kid"]]

    def activate(self, request: dict[str, Any]) -> KeyRecord:
        self._submit(request)
        return self.state.keys[request["payload"]["kid"]]

    def retire(self, request: dict[str, Any]) -> KeyRecord:
        self._submit(request)
        return self.state.keys[request["payload"]["kid"]]

    def rotate(self, request: dict[str, Any]) -> tuple[KeyRecord, KeyRecord]:
        self._submit(request)
        return self.state.keys[request["payload"]["kid"]], self.state.keys[request["payload"]["successor_kid"]]

    def revoke(self, request: dict[str, Any]) -> KeyRecord:
        self._submit(request)
        return self.state.keys[request["payload"]["kid"]]

    def apply(self, request: dict[str, Any]) -> dict[str, Any]:
        """Apply any signed request by its ``op``. Returns the committed event."""
        op = request["payload"]["op"]
        if op not in OPS:
            raise KeyRegistryError("unsupported_op", op)
        return self._submit(request)

    # --- assessment --------------------------------------------------------------------------------------------------

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
        if rec.provenance == PROVENANCE_LEGACY_V1 and trusted_at:
            # Imported from an unsigned v1 registry: the times are the v1 log's claims, never more than uncertain.
            uncertain = True
            reasons.append("legacy_unsigned_history")
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


# --- migration of a v1 registry ----------------------------------------------------------------------------------------


def read_v1_registry(v1_snapshot: Path | str) -> dict[str, Any]:
    """Verify a v1 log's hash chain and transitions, and return its state as a plain dict. v1 history is not signed, so
    this checks integrity only; the result is never trusted by itself (see ``migrate_v1``)."""
    from aigov_py.trusted import legacy_v1  # local import: the v1 code is kept only for migration

    events_path = Path(v1_snapshot).with_name(Path(v1_snapshot).name + ".events.jsonl")
    if not events_path.exists():
        raise KeyRegistryError("v1_log_missing", str(events_path))
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    try:
        state = legacy_v1.replay(events)
    except legacy_v1.V1IntegrityError as exc:
        raise KeyRegistryError(exc.code, str(exc)) from exc
    return {
        "head_hash": events[-1]["hash"] if events else GENESIS,
        "events": len(events),
        "operators": {k: {"public_key_b64": v["public_key_b64"], "roles": list(v["roles"])} for k, v in state.operators.items()},
        "keys": {kid: rec.as_dict() for kid, rec in state.keys.items()},
    }


def migrate_v1(
    v1_snapshot: Path | str,
    new_snapshot: Path | str,
    *,
    trust: TrustConfig,
    anchor: Any,
    root_kid: str,
    root_seed_b64: str,
) -> dict[str, Any]:
    """Import a v1 registry into a new v2 registry as one root-signed ``legacy_import`` event.

    The import is an explicit attestation by the root holder that the v1 state is what they accept. The v1 history is not
    carried over as signed history: its keys are marked ``legacy_v1_unsigned``, and their verdicts are at most uncertain.
    The v1 log is left in place. The new registry must not exist, and its anchor must be at genesis.
    """
    new_path = Path(new_snapshot)
    if new_path.with_name(new_path.name + ".events.jsonl").exists():
        raise KeyRegistryError("migration_target_exists", "a v2 log already exists at the target")
    root = trust.root_may_sign(root_kid, 1)
    if root is None or root.status != "current":
        raise KeyRegistryError("root_not_authorized", "the migration must be signed by a current root")
    v1 = read_v1_registry(v1_snapshot)
    try:
        anchor.init()
    except AnchorError as exc:
        raise KeyRegistryError(exc.code, exc.detail) from exc
    reg = KeyRegistry(new_path, trust=trust, anchor=anchor)
    request = KeyRegistry.sign_request(
        KeyRegistry.new_request(
            op="legacy_import", actor=root_kid, expected_version=0,
            v1_head_hash=v1["head_hash"], v1_events=v1["events"], operators=v1["operators"], keys=v1["keys"],
        ),
        root_seed_b64,
    )
    reg._submit(request)
    return {"imported_keys": len(v1["keys"]), "imported_operators": len(v1["operators"]), "v1_events": v1["events"]}


def new_signing_seed() -> tuple[str, str]:
    """A new Ed25519 key pair for a purpose. Returns (seed_b64, public_key_b64). The seed belongs to its signer."""
    sk = SigningKey.generate()
    return _b64(bytes(sk)), _b64(bytes(sk.verify_key))


def key_status_now(registry: KeyRegistry, kid: str) -> str | None:
    rec = registry.get(kid)
    return rec.status if rec else None
