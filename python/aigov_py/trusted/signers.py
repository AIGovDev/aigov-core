"""Signing-provider interface: one signer, one key id, one purpose.

A signer produces Ed25519 signatures over messages that are domain-separated by purpose. The signer adds the domain itself, so
a caller cannot choose the domain, and a signature made for one purpose does not verify under another (see ``keys.py``).

Two providers are included:

- ``LocalEd25519Signer`` holds a seed in process memory. The seed is never returned or repr'd.
- ``ExternalSigner`` delegates to a provider callable (for example an HTTP client to a signing service). Every call has a
  bounded timeout, and a failure of any kind is raised as ``SignerError``. Nothing is signed by a fallback.

``ExternalSigner`` is an interface only. The test provider in ``tests`` is a local, in-process signer that behaves like an
external one. No compatibility with any external key-management service is claimed or tested here.
"""

from __future__ import annotations

import base64
import concurrent.futures
from collections.abc import Callable
from dataclasses import dataclass

from nacl.signing import SigningKey

from aigov_py.trusted.keys import DOMAINS, valid_kid

DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_TIMEOUT_SECONDS = 30.0


class SignerError(Exception):
    """A signing request failed. ``code`` is stable; the message never includes key material."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _check_identity(key_id: str, purpose: str) -> None:
    if not valid_kid(key_id):
        raise SignerError("key_id_invalid")
    if purpose not in DOMAINS:
        raise SignerError("purpose_unknown", purpose)


@dataclass(frozen=True)
class SignResult:
    key_id: str
    purpose: str
    signature_b64: str


class LocalEd25519Signer:
    """Signs with a local Ed25519 seed. The seed stays inside the object."""

    __slots__ = ("_key", "key_id", "purpose")

    def __init__(self, seed_b64: str, *, key_id: str, purpose: str) -> None:
        _check_identity(key_id, purpose)
        raw = base64.b64decode(seed_b64, validate=True)
        if len(raw) != 32:
            raise SignerError("seed_invalid", "expected a 32-byte Ed25519 seed")
        self._key = SigningKey(raw)
        self.key_id = key_id
        self.purpose = purpose

    def __repr__(self) -> str:  # never reveal material
        return f"LocalEd25519Signer(key_id={self.key_id!r}, purpose={self.purpose!r})"

    def public_key_b64(self) -> str:
        return base64.b64encode(bytes(self._key.verify_key)).decode("ascii")

    def sign(self, payload: bytes) -> SignResult:
        sig = self._key.sign(DOMAINS[self.purpose] + payload).signature
        return SignResult(self.key_id, self.purpose, base64.b64encode(sig).decode("ascii"))


class ExternalSigner:
    """Delegates signing to ``provider(key_id, purpose, message) -> signature_b64`` with a bounded timeout.

    The provider receives the domain-prefixed message, so a provider cannot sign a message for another purpose without the
    caller having chosen that purpose. Any exception, timeout, or malformed reply raises ``SignerError``.
    """

    def __init__(
        self,
        provider: Callable[[str, str, bytes], str],
        *,
        key_id: str,
        purpose: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        _check_identity(key_id, purpose)
        if not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise SignerError("timeout_invalid", f"must be in (0, {MAX_TIMEOUT_SECONDS}] seconds")
        self._provider = provider
        self.key_id = key_id
        self.purpose = purpose
        self._timeout = timeout_seconds

    def sign(self, payload: bytes) -> SignResult:
        message = DOMAINS[self.purpose] + payload
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="signer")
        try:
            future = pool.submit(self._provider, self.key_id, self.purpose, message)
            try:
                reply = future.result(timeout=self._timeout)
            except concurrent.futures.TimeoutError as exc:
                raise SignerError("signer_timeout", f"no reply within {self._timeout}s") from exc
            except SignerError:
                raise
            except Exception as exc:  # provider failure: report the class, never the content
                raise SignerError("signer_failed", type(exc).__name__) from exc
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        if not isinstance(reply, str):
            raise SignerError("signer_reply_invalid", "provider returned a non-string signature")
        try:
            if len(base64.b64decode(reply, validate=True)) != 64:
                raise ValueError
        except ValueError as exc:
            raise SignerError("signer_reply_invalid", "signature is not 64 bytes") from exc
        return SignResult(self.key_id, self.purpose, reply)
