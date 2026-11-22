"""
Signing key providers for ExecutionAuthorizationToken (EAT).

Abstracts key material so production deployments can use a managed KMS
(Vercel KMS, AWS KMS, HashiCorp Vault) instead of raw in-memory bytes.

Implementations:
  InMemoryKeyProvider   — Single key, random 32 bytes at instantiation.
                          is_managed=False. For local tests only.
  RotatingKeyProvider   — Supports multiple keys by ID. One key is current
                          for signing; all added keys remain valid for
                          verification. Enables zero-downtime key rotation:
                          issue new tokens under key v2 while still verifying
                          tokens issued under v1, then retire v1 when drained.

Production deployment note:
  For production, implement a provider that fetches the signing key from a
  KMS at verification time (never hardcoding the bytes). The key_id lets the
  verifier locate the right key without exposing key material in the token.
  Example sketch:

      class VercelKMSKeyProvider:
          is_managed = True

          def __init__(self, current_key_id: str):
              self._current_key_id = current_key_id

          @property
          def key_id(self) -> str:
              return self._current_key_id

          @property
          def signing_key(self) -> bytes:
              return fetch_key_from_kms(self._current_key_id)

          def get_verification_key(self, key_id: str) -> bytes | None:
              return fetch_key_from_kms(key_id)  # returns None if unknown

Security invariants:
  - key_id is PART of the signed payload. Changing key_id on an issued token
    invalidates its signature; a verifier cannot be tricked into verifying with
    the wrong key.
  - Retiring a key (removing it from the provider) immediately invalidates all
    tokens issued under it. Drain in-flight requests before retiring.
  - InMemoryKeyProvider must never be used in production: is_managed=False
    triggers a warning in ToolGateway's __init__.
"""

from __future__ import annotations

import os
import threading
import warnings


class SigningKeyError(Exception):
    """Raised when a key operation fails (e.g., key_id not found)."""


class InMemoryKeyProvider:
    """
    Single in-memory signing key. NOT for production.

    A fresh 32-byte random key is generated at instantiation. is_managed=False
    triggers a ToolGateway warning when used outside of tests.
    """

    is_managed: bool = False

    def __init__(
        self,
        key_id: str = "default",
        key_bytes: bytes | None = None,
    ) -> None:
        self._key_id = key_id
        self._key_bytes = key_bytes if key_bytes is not None else os.urandom(32)
        if len(self._key_bytes) < 32:
            raise ValueError("Signing key must be at least 32 bytes")

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def signing_key(self) -> bytes:
        return self._key_bytes

    def get_verification_key(self, key_id: str) -> bytes | None:
        """Return key bytes if key_id matches, None otherwise."""
        return self._key_bytes if key_id == self._key_id else None


class RotatingKeyProvider:
    """
    Multi-key provider supporting key rotation.

    One key is current (used for signing new tokens). All keys that have been
    added and not yet retired remain valid for signature verification. This
    allows zero-downtime rotation:

      1. Add the new key (make_current=True).
      2. Deploy the new key to all instances (they sign with new key,
         verify with both old and new).
      3. Wait for all in-flight tokens issued under the old key to expire (≤500ms).
      4. Retire the old key with remove_key().

    Thread-safe. All key management operations hold the internal lock.
    """

    is_managed: bool = False  # set to True if backed by a real KMS

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}
        self._current_key_id: str | None = None
        self._lock = threading.RLock()

    def add_key(
        self,
        key_id: str,
        key_bytes: bytes,
        make_current: bool = False,
    ) -> None:
        """
        Add a key to the provider.

        make_current=True makes this the key used for signing new tokens.
        If no current key exists, the first key added is always made current.
        """
        if len(key_bytes) < 32:
            raise ValueError(f"Key {key_id!r} must be at least 32 bytes")
        with self._lock:
            self._keys[key_id] = key_bytes
            if make_current or self._current_key_id is None:
                self._current_key_id = key_id

    def remove_key(self, key_id: str) -> None:
        """
        Retire a key. All tokens signed with this key will fail verification.

        Drain in-flight requests before retiring to avoid false rejections.
        Cannot retire the current signing key; rotate first.
        """
        with self._lock:
            if key_id == self._current_key_id:
                raise SigningKeyError(
                    f"Cannot retire current signing key {key_id!r}. "
                    "Rotate to a new key first."
                )
            self._keys.pop(key_id, None)

    def set_current(self, key_id: str) -> None:
        """Make key_id the current signing key. It must already be in the provider."""
        with self._lock:
            if key_id not in self._keys:
                raise SigningKeyError(f"Key {key_id!r} not in provider")
            self._current_key_id = key_id

    @property
    def key_id(self) -> str:
        """The key ID currently used for signing new tokens."""
        with self._lock:
            if self._current_key_id is None:
                raise SigningKeyError("No signing key configured")
            return self._current_key_id

    @property
    def signing_key(self) -> bytes:
        """The key bytes currently used for signing new tokens."""
        with self._lock:
            if self._current_key_id is None:
                raise SigningKeyError("No signing key configured")
            return self._keys[self._current_key_id]

    def get_verification_key(self, key_id: str) -> bytes | None:
        """Return key bytes for key_id, or None if unknown / retired."""
        with self._lock:
            return self._keys.get(key_id)

    @property
    def active_key_ids(self) -> list[str]:
        """All key IDs currently available for verification."""
        with self._lock:
            return list(self._keys.keys())


def warn_if_unmanaged(provider: "InMemoryKeyProvider | RotatingKeyProvider") -> None:
    """
    Issue a RuntimeWarning if the provider is not managed (is_managed=False).

    Called by ToolGateway during __init__ to flag test-only key configurations.
    """
    if not getattr(provider, "is_managed", False):
        warnings.warn(
            "ExecutionTokenAuthority is using an unmanaged in-memory signing key. "
            "This is acceptable for tests but MUST be replaced with a managed key "
            "provider (KMS, HSM) in production. Set provider.is_managed = True "
            "or implement a production KeyProvider.",
            RuntimeWarning,
            stacklevel=3,
        )
