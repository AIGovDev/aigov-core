"""Verification of Core's execution authorizations, and the refusal type the executor raises.

Core signs an authorization with Ed25519 under a domain prefix, so a signature made for another purpose never verifies
here. The executor pins Core's public key, and checks the signature itself. Nothing in this module signs.
"""

from __future__ import annotations

import base64
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from aigov_py.canonical_json import canonical_bytes

AUTH_SCHEMA = "govai.execution_authorization.v1"
AUTH_DOMAIN = b"govai.execution_authorization.v1\x00"
CLOCK_SKEW_SECONDS = 5


class Refused(Exception):
    """The executor refuses to act. ``reason`` is a stable, machine-readable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def verify_authorization_signature(signed: dict[str, Any], public_key_b64: str) -> None:
    """Raise ``Refused`` unless the signature is valid for this public key and this domain."""
    payload = signed.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != AUTH_SCHEMA:
        raise Refused("authorization_schema_mismatch")
    try:
        sig = base64.b64decode(signed["signature"], validate=True)
        key = VerifyKey(base64.b64decode(public_key_b64, validate=True))
        key.verify(AUTH_DOMAIN + canonical_bytes(payload), sig)
    except (BadSignatureError, KeyError, ValueError, TypeError) as exc:
        raise Refused("authorization_signature_invalid") from exc


def verify_authorization_with_registry(signed: dict[str, Any], registry: Any, *, now: Any = None) -> str:
    """Verify an authorization against the trusted key registry and return its key id.

    The payload must name its signing key (``signing_key_id``). The key must be trusted at the time the authorization
    claims it was issued: a trusted verdict is required, and an uncertain verdict (signed before a compromise) is refused.
    Rotation does not change which authorizations are accepted; replay is refused by Core and the executor store, keyed by
    authorization id, and neither depends on the key.
    """
    payload = signed.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != AUTH_SCHEMA:
        raise Refused("authorization_schema_mismatch")
    kid = payload.get("signing_key_id")
    if not isinstance(kid, str) or not kid:
        raise Refused("authorization_key_id_missing")
    try:
        signed_at = payload["issued_at_utc"]
        sig = signed["signature"]
    except KeyError as exc:
        raise Refused("authorization_signature_invalid") from exc
    # Re-read the log: a revocation or rotation written by another process must apply to this decision at once.
    refresh = getattr(registry, "refresh", None)
    if refresh is not None:
        refresh()
    kwargs = {"purpose": "execution_authorization", "kid": kid, "payload": canonical_bytes(payload),
              "signature_b64": sig, "signed_at_utc": signed_at}
    if now is not None:
        kwargs["now"] = now
    assessment = registry.assess(**kwargs)
    if "purpose_mismatch" in assessment.reasons:
        raise Refused("authorization_key_purpose_mismatch")
    if not assessment.signature_valid:
        raise Refused("authorization_signature_invalid")
    if not assessment.accepted():
        raise Refused("authorization_key_untrusted")
    return kid

