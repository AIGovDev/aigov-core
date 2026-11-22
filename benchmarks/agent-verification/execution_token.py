"""
ExecutionAuthorizationToken (EAT): cryptographic single-use capability token.

Issued by ExecutionTokenAuthority immediately after a PolicyDecision.ALLOW.
Verified by SandboxedGitHubTools.execute() independently of the caller's
claimed authorization status.

Security properties:
  1. Unforgeable: HMAC-SHA256 keyed with a per-authority random 32-byte key.
  2. Bound: covers (execution_id, tool_name, args_binding_hash, action_type,
     resource_id, tenant_id, issued_at_ns, max_age_ns) — a token for one
     operation cannot authorize a different one.
  3. Time-limited: verified against issued_at_ns + max_age_ns (default 500ms).
     Expired tokens are rejected even if the signature is valid.
  4. Per-instance: each ExecutionTokenAuthority holds its own random key.
     Tokens from one authority are not valid under another.

Distributed-safety note:
  ExecutionTokenAuthority is per-process. After a process restart, a new key
  is generated and all previously issued tokens are invalid. This is correct
  security behavior, NOT a limitation: stale tokens cannot be replayed. However,
  the ReplayRegistry (nonce store) is also per-process — see replay_protection.py
  for that cross-process limitation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass

_DEFAULT_MAX_AGE_MS: float = 500.0  # 500ms max between authorization and execution


def _build_signable(
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
    The `signature` field is NOT included (it's what we're computing over these).
    """
    payload = json.dumps({
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
    """
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
    Issues and verifies ExecutionTokens.

    One authority per ToolGateway instance. The signing key is a fresh
    random 32-byte secret generated at instantiation; it is never persisted
    or exposed outside this object.

    SandboxedGitHubTools holds the same authority instance and calls
    verify_for_execution() before every execution.
    """

    def __init__(self, max_age_ms: float = _DEFAULT_MAX_AGE_MS) -> None:
        self._key: bytes = os.urandom(32)
        self._max_age_ns: int = int(max_age_ms * 1_000_000)

    def issue(
        self,
        execution_id: str,
        tool_name: str,
        args_binding_hash: str,
        action_type: str,
        resource_id: str,
        tenant_id: str,
    ) -> ExecutionToken:
        """Issue a token binding authorization to this exact execution context."""
        issued_at_ns = time.monotonic_ns()
        signable = _build_signable(
            execution_id=execution_id,
            tool_name=tool_name,
            args_binding_hash=args_binding_hash,
            action_type=action_type,
            resource_id=resource_id,
            tenant_id=tenant_id,
            issued_at_ns=issued_at_ns,
            max_age_ns=self._max_age_ns,
        )
        signature = hmac.new(self._key, signable, hashlib.sha256).hexdigest()
        return ExecutionToken(
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

    def _verify_signature(self, token: ExecutionToken) -> bool:
        """Verify HMAC. Does NOT check expiry or field binding."""
        expected = hmac.new(self._key, token.signable(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, token.signature)

    def verify_for_execution(
        self,
        token: ExecutionToken,
        expected_tool_name: str,
        expected_args_binding_hash: str,
        expected_action_type: str,
        expected_resource_id: str,
        expected_tenant_id: str,
    ) -> tuple[bool, str]:
        """
        Full verification: signature + field binding + not expired.

        Returns (ok, reason). reason is empty on success, a short slug on failure.
        All checks run regardless of which failed first (no short-circuit that
        leaks timing information about which field was wrong).
        """
        sig_ok = self._verify_signature(token)
        expired = token.is_expired()
        tool_match   = token.tool_name         == expected_tool_name
        hash_match   = token.args_binding_hash == expected_args_binding_hash
        action_match = token.action_type       == expected_action_type
        res_match    = token.resource_id       == expected_resource_id
        tenant_match = token.tenant_id         == expected_tenant_id

        if not sig_ok:
            return False, "token_signature_invalid"
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
