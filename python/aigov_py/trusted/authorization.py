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
