"""
ExecutionAuthorizationToken (EAT): cryptographic single-use capability token.

Issued by ExecutionTokenAuthority immediately after a PolicyDecision.ALLOW.
Verified by SandboxedGitHubTools.execute() independently of the caller's
claimed authorization status.

Security properties:
  1. Unforgeable: HMAC-SHA256 keyed with a provider-managed secret. The key
     is never exposed; the authority holds only a KeyProvider reference.
  2. Bound: covers (key_id, execution_id, tool_name, args_binding_hash,
     action_type, resource_id, tenant_id, issued_at_ns, max_age_ns) — a
     token for one operation cannot authorize a different one.
  3. Time-limited: verified against issued_at_ns + max_age_ns (default 500ms).
     Expired tokens are rejected even if the signature is valid.
  4. Key-identified: each token carries a key_id. On verification the authority
     asks the KeyProvider for that key; a retired key returns None → rejected.
     This enables zero-downtime key rotation.

Rotation protocol:
  1. Add new key to provider (make_current=True) → new tokens use new key.
  2. Wait max_age_ms for all in-flight tokens under the old key to expire.
  3. Remove old key from provider → old tokens now rejected.

Distributed-safety note:
  ExecutionTokenAuthority is per-process. After a process restart, a new
  InMemoryKeyProvider generates a new random key and all previously issued
  tokens are invalid (signature key mismatch). This is correct security
  behavior. For distributed deployments, use a shared KMS-backed KeyProvider
  so all workers share the same verification keys.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass

_DEFAULT_MAX_AGE_MS: float = 500.0  # 500ms max between authorization and execution


def _build_signable(
    key_id: str,
    execution_id: str,
    tool_name: str,
    args_binding_hash: str,
    action_type: str,
    resource_id: str,
    tenant_id: str,
    issued_at_ns: int,
    max_age_ns: int,
) -> bytes:
    """
    Deterministic bytes representation of the token's protected fields.
    key_id is included so it cannot be changed without invalidating the signature.
    """
    payload = json.dumps({
        "key_id": key_id,
        "execution_id": execution_id,
        "tool_name": tool_name,
        "args_binding_hash": args_binding_hash,
        "action_type": action_type,
        "resource_id": resource_id,
        "tenant_id": tenant_id,
        "issued_at_ns": issued_at_ns,
        "max_age_ns": max_age_ns,
    }, sort_keys=True, separators=(",", ":"))
    return payload.encode()


@dataclass(frozen=True)
class ExecutionToken:
    """
    Cryptographic capability token issued after PolicyDecision.ALLOW.

    Frozen: all fields are immutable after construction. Do not construct
    directly; use ExecutionTokenAuthority.issue().

    key_id identifies which signing key was used. The verifier uses it to
    look up the key bytes from the KeyProvider; an unknown or retired key_id
    causes immediate rejection without attempting signature verification.
    """
    key_id: str
    execution_id: str
    tool_name: str
    args_binding_hash: str
    action_type: str
    resource_id: str
    tenant_id: str
    issued_at_ns: int
    max_age_ns: int
    signature: str  # HMAC-SHA256 hex over all other fields

    def is_expired(self) -> bool:
        """True if more than max_age_ns nanoseconds have elapsed since issuance."""
        return time.monotonic_ns() - self.issued_at_ns > self.max_age_ns

    def signable(self) -> bytes:
        """The bytes this token's signature was computed over."""
        return _build_signable(
            key_id=self.key_id,
            execution_id=self.execution_id,
            tool_name=self.tool_name,
            args_binding_hash=self.args_binding_hash,
            action_type=self.action_type,
            resource_id=self.resource_id,
            tenant_id=self.tenant_id,
            issued_at_ns=self.issued_at_ns,
            max_age_ns=self.max_age_ns,
        )


class ExecutionTokenAuthority:
    """
    Issues and verifies ExecutionTokens via a KeyProvider.

    One authority per ToolGateway instance. By default an InMemoryKeyProvider
    is created (fresh random key, not for production). Pass a RotatingKeyProvider
    or a managed KMS provider for production deployments.

    SandboxedGitHubTools holds the same authority instance and calls
    verify_for_execution() before every execution.
    """

    def __init__(
        self,
        key_provider=None,  # SigningKeyProvider | None
        max_age_ms: float = _DEFAULT_MAX_AGE_MS,
    ) -> None:
        if key_provider is None:
            from key_provider import InMemoryKeyProvider
            key_provider = InMemoryKeyProvider()
        self._key_provider = key_provider
        self._max_age_ns: int = int(max_age_ms * 1_000_000)

    @property
    def key_provider(self):
        """Expose the provider so ToolGateway can inspect is_managed."""
        return self._key_provider

    def issue(
        self,
        execution_id: str,
        tool_name: str,
        args_binding_hash: str,
        action_type: str,
        resource_id: str,
        tenant_id: str,
    ) -> "ExecutionToken":
        """Issue a token binding authorization to this exact execution context."""
        key_id = self._key_provider.key_id
        signing_key = self._key_provider.signing_key
        issued_at_ns = time.monotonic_ns()
        signable = _build_signable(
            key_id=key_id,
            execution_id=execution_id,
            tool_name=tool_name,
            args_binding_hash=args_binding_hash,
            action_type=action_type,
            resource_id=resource_id,
            tenant_id=tenant_id,
            issued_at_ns=issued_at_ns,
            max_age_ns=self._max_age_ns,
        )
        signature = hmac.new(signing_key, signable, hashlib.sha256).hexdigest()
        return ExecutionToken(
            key_id=key_id,
            execution_id=execution_id,
            tool_name=tool_name,
            args_binding_hash=args_binding_hash,
            action_type=action_type,
            resource_id=resource_id,
            tenant_id=tenant_id,
            issued_at_ns=issued_at_ns,
            max_age_ns=self._max_age_ns,
            signature=signature,
        )

    def _verify_signature(self, token: "ExecutionToken") -> tuple[bool, str]:
        """
        Verify HMAC using the key identified by token.key_id.

        Returns (ok, reason). reason is "" on success.
        Returns "token_key_id_unknown" if the key_id is not in the provider
        (the key was retired or the token was forged with an unknown key_id).
        """
        verification_key = self._key_provider.get_verification_key(token.key_id)
        if verification_key is None:
            return False, "token_key_id_unknown"
        expected = hmac.new(verification_key, token.signable(), hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(expected, token.signature)
        return ok, ("" if ok else "token_signature_invalid")

    def verify_for_execution(
        self,
        token: "ExecutionToken",
        expected_tool_name: str,
        expected_args_binding_hash: str,
        expected_action_type: str,
        expected_resource_id: str,
        expected_tenant_id: str,
    ) -> tuple[bool, str]:
        """
        Full verification: key_id lookup + signature + field binding + not expired.

        Returns (ok, reason). reason is empty on success, a short slug on failure.
        Checks run in order that leaks least timing information about which field
        was wrong (key_id and signature checked first; field-binding after).
        """
        sig_ok, sig_reason = self._verify_signature(token)
        expired = token.is_expired()
        tool_match   = token.tool_name         == expected_tool_name
        hash_match   = token.args_binding_hash == expected_args_binding_hash
        action_match = token.action_type       == expected_action_type
        res_match    = token.resource_id       == expected_resource_id
        tenant_match = token.tenant_id         == expected_tenant_id

        if not sig_ok:
            return False, sig_reason
        if expired:
            return False, "token_expired"
        if not tool_match:
            return False, "token_tool_name_mismatch"
        if not hash_match:
            return False, "token_args_hash_mismatch"
        if not action_match:
            return False, "token_action_type_mismatch"
        if not res_match:
            return False, "token_resource_id_mismatch"
        if not tenant_match:
            return False, "token_tenant_id_mismatch"
        return True, ""
