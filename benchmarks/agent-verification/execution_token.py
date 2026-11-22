"""
ExecutionAuthorizationToken (EAT): cryptographic single-use capability token.

Issued by ExecutionTokenAuthority immediately after a PolicyDecision.ALLOW.
Verified by SandboxedGitHubTools.execute() independently of the caller's
claimed authorization status.

Security properties:
  1. Unforgeable: HMAC-SHA256 keyed with a provider-managed secret. The key
     is never exposed; the authority holds only a KeyProvider reference.
  2. Bound: covers (key_id, execution_id, tool_name, args_binding_hash,
     action_type, resource_id, tenant_id, issued_at_ns, not_before_ns,
     max_age_ns) — a token for one operation cannot authorize a different one.
  3. Time-limited: verified against issued_at_ns + max_age_ns (default 500ms)
     using UTC wall-clock time (time.time_ns()). Expired tokens are rejected
     even if the signature is valid.
  4. Not-before enforced: tokens are invalid before not_before_ns UTC.
  5. Clock-skew tolerant: ExecutionTokenAuthority accepts a clock_skew_ns
     argument (default 0) that widens the valid window symmetrically. This
     allows cross-host verification when clocks are synchronized within a
     known bound (e.g. NTP ±50ms → clock_skew_ns=50_000_000).
  6. Key-identified: each token carries a key_id. On verification the authority
     asks the KeyProvider for that key; a retired key returns None → rejected.
     This enables zero-downtime key rotation.

Timestamps:
  issued_at_ns and not_before_ns are UTC nanoseconds from time.time_ns().
  time.time_ns() is portable across processes and machines (unlike
  time.monotonic_ns(), which is per-process). Cross-process verification
  requires that clocks be synchronized; use NTP or equivalent.

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
    not_before_ns: int,
    max_age_ns: int,
) -> bytes:
    """
    Deterministic bytes representation of the token's protected fields.
    key_id is included so it cannot be changed without invalidating the signature.
    not_before_ns is included so it cannot be zeroed without invalidating the
    signature (prevents stripping the not-before constraint).
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
        "not_before_ns": not_before_ns,
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
    issued_at_ns: int         # UTC nanoseconds (time.time_ns()) at issuance
    not_before_ns: int        # UTC nanoseconds; token invalid before this time
    max_age_ns: int           # maximum lifetime in nanoseconds from issued_at_ns
    signature: str            # HMAC-SHA256 hex over all other fields

    def is_expired(self, clock_skew_ns: int = 0) -> bool:
        """
        True if more than max_age_ns nanoseconds have elapsed since issuance.

        clock_skew_ns widens the valid window: a token expires only after
        (max_age_ns + clock_skew_ns) nanoseconds, accommodating small clock
        differences between issuer and verifier (e.g. NTP drift).
        """
        return time.time_ns() - self.issued_at_ns > self.max_age_ns + clock_skew_ns

    def is_not_yet_valid(self, clock_skew_ns: int = 0) -> bool:
        """
        True if the current UTC time is before not_before_ns (minus clock skew).

        A token is considered valid from (not_before_ns - clock_skew_ns) onward,
        allowing for small clock differences between issuer and verifier.
        """
        return time.time_ns() < self.not_before_ns - clock_skew_ns

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
            not_before_ns=self.not_before_ns,
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
        clock_skew_ns: int = 0,
    ) -> None:
        if key_provider is None:
            from key_provider import InMemoryKeyProvider
            key_provider = InMemoryKeyProvider()
        self._key_provider = key_provider
        self._max_age_ns: int = int(max_age_ms * 1_000_000)
        self._clock_skew_ns: int = clock_skew_ns

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
        not_before_ns: int | None = None,
    ) -> "ExecutionToken":
        """
        Issue a token binding authorization to this exact execution context.

        issued_at_ns and not_before_ns are set to the current UTC wall-clock
        time (time.time_ns()). The token is immediately valid unless
        not_before_ns is supplied explicitly.

        Using time.time_ns() (UTC wall clock) instead of time.monotonic_ns()
        makes expiry portable across processes and machines: a token issued on
        worker A can be verified on worker B provided clocks are synchronized
        within clock_skew_ns nanoseconds.
        """
        key_id = self._key_provider.key_id
        signing_key = self._key_provider.signing_key
        issued_at_ns = time.time_ns()
        if not_before_ns is None:
            not_before_ns = issued_at_ns
        signable = _build_signable(
            key_id=key_id,
            execution_id=execution_id,
            tool_name=tool_name,
            args_binding_hash=args_binding_hash,
            action_type=action_type,
            resource_id=resource_id,
            tenant_id=tenant_id,
            issued_at_ns=issued_at_ns,
            not_before_ns=not_before_ns,
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
            not_before_ns=not_before_ns,
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
        expected_execution_id: str | None = None,
    ) -> tuple[bool, str]:
        """
        Full verification: key_id lookup + signature + field binding + time checks.

        Returns (ok, reason). reason is empty on success, a short slug on failure.
        Checks run in order that leaks least timing information about which field
        was wrong (key_id and signature checked first; field-binding after).

        Time checks use self._clock_skew_ns to tolerate synchronized-clock drift:
          - not_before: token must not be from the future (minus clock_skew_ns)
          - expiry:     token must not be older than max_age_ns (plus clock_skew_ns)

        expected_execution_id: when provided, the token's execution_id must match
        exactly.  Pass the calling context's execution_id (not token.execution_id)
        to prevent cross-request token reuse in distributed deployments.

        expected_action_type / expected_resource_id: pass independently from the
        calling context (not from the token) to enforce that the token authorizes
        this specific operation, not just that it is internally self-consistent.
        """
        sig_ok, sig_reason = self._verify_signature(token)
        not_yet_valid = token.is_not_yet_valid(self._clock_skew_ns)
        expired       = token.is_expired(self._clock_skew_ns)
        tool_match    = token.tool_name         == expected_tool_name
        hash_match    = token.args_binding_hash == expected_args_binding_hash
        action_match  = token.action_type       == expected_action_type
        res_match     = token.resource_id       == expected_resource_id
        tenant_match  = token.tenant_id         == expected_tenant_id
        eid_match     = (
            expected_execution_id is None
            or token.execution_id == expected_execution_id
        )

        if not sig_ok:
            return False, sig_reason
        if not_yet_valid:
            return False, "token_not_yet_valid"
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
        if not eid_match:
            return False, "token_execution_id_mismatch"
        return True, ""
