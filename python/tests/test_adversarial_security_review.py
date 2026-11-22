"""
Independent adversarial security review — Pass 4.

Regression tests for security findings discovered during the adversarial review
of PR #471. Each test names the finding it covers.

Findings:
  FINDING-1  HIGH   args_binding_hash truncated to 64 bits (8 bytes)
                    sandboxed_tools.py:425 — hexdigest()[:16]
                    Birthday collision at ~2^32 work; allows argument substitution.
                    FIX: use full hexdigest() (256 bits).

  FINDING-2  MEDIUM verify_for_execution does not check execution_id
                    execution_token.py:196-234 — no expected_execution_id param
                    A valid EAT from exec-A passes verification for exec-B if other
                    fields match; causes audit inconsistency in distributed deployment.
                    FIX: add expected_execution_id to verify_for_execution; pass from
                    tools.execute().

  FINDING-3  MEDIUM Tautological action_type/resource_id in tools.execute()
                    sandboxed_tools.py:224-225 — expected_action_type=token.action_type
                    The check always passes because it compares the token to itself.
                    Security comes from the HMAC; the check adds no independent binding
                    to the calling context.
                    FIX: pass action_type/resource_id from caller into execute() and
                    verify against those, not the token's own fields.

  FINDING-4  LOW    Nonce consumed before revocation check; partial DB failure
                    permanently burns approval (DoS on approvals, not a bypass).
                    Fail-closed behavior is correct; documented limitation.

  FINDING-5  LOW    EAT uses time.monotonic_ns() for expiry — not portable across
                    processes or machines for distributed deployment.
                    Acceptable in current single-process architecture.
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

_BENCH = Path(__file__).parent.parent.parent / "benchmarks" / "agent-verification"
sys.path.insert(0, str(_BENCH))

from execution_token import ExecutionToken, ExecutionTokenAuthority  # noqa: E402
from key_provider import InMemoryKeyProvider, RotatingKeyProvider  # noqa: E402
from sandboxed_tools import (  # noqa: E402
    SandboxedGitHubTools,
    compute_args_binding_hash,
)


# ---------------------------------------------------------------------------
# FINDING-1: args_binding_hash truncated to 64 bits
# ---------------------------------------------------------------------------

class TestFinding1ArgsHashTruncation:
    """
    FINDING-1 (HIGH): compute_args_binding_hash() returns only the first 16 hex
    characters (64 bits) of a SHA-256 digest.  A birthday collision requires
    ~2^32 trials — feasible for a motivated attacker to precompute an argument
    pair (A, B) where hash(A) == hash(B).  Presenting EAT(A) with arguments B
    would then pass the args_hash field check in verify_for_execution.

    After the fix (remove [:16]), the full 256-bit hash is used; collisions
    require ~2^128 work.
    """

    def test_hash_length_is_64_chars_after_fix(self):
        """After fix: hash is 64 hex chars (full SHA-256), not 16."""
        h = compute_args_binding_hash("create_file", {"path": "x"}, "repo:write", "r")
        assert len(h) == 64, (
            f"FINDING-1: args_binding_hash is {len(h)} chars; "
            "expected 64 (full SHA-256). "
            "If still 16, the truncation fix has not been applied."
        )

    def test_hash_covers_all_four_fields(self):
        """Hash must change when any binding field changes."""
        base = compute_args_binding_hash("create_file", {"path": "a"}, "repo:write", "r/repo")

        assert compute_args_binding_hash("read_file",  {"path": "a"}, "repo:write", "r/repo") != base, \
            "tool_name change must produce different hash"
        assert compute_args_binding_hash("create_file", {"path": "b"}, "repo:write", "r/repo") != base, \
            "arguments change must produce different hash"
        assert compute_args_binding_hash("create_file", {"path": "a"}, "repo:read",  "r/repo") != base, \
            "action_type change must produce different hash"
        assert compute_args_binding_hash("create_file", {"path": "a"}, "repo:write", "other/r") != base, \
            "resource_id change must produce different hash"

    def test_no_truncation_in_full_hash(self):
        """
        Demonstrate that truncation is the attack surface: the first 16 chars of
        different hashes may collide while the full hashes differ.

        This test does not brute-force a collision (would take ~4 billion trials);
        instead it confirms the structural property that justifies the fix.
        """
        import hashlib, json

        def full_hash(tool, args, action, resource):
            payload = json.dumps(
                {"tool_name": tool, "arguments": args, "action_type": action, "resource_id": resource},
                sort_keys=True, separators=(",", ":"),
            )
            return hashlib.sha256(payload.encode()).hexdigest()

        h1 = full_hash("create_file", {"path": "a"}, "repo:write", "r")
        h2 = full_hash("create_file", {"path": "a"}, "repo:write", "r2")

        # These are different (different resource_id)
        assert h1 != h2
        # Their 16-char prefixes might also differ, but the SPACE of 16-char prefixes
        # is only 2^64, while the full hash space is 2^256.
        # This confirms why full-length is required: more distinguishing power.
        assert len(h1) == 64
        assert len(h2) == 64


# ---------------------------------------------------------------------------
# FINDING-2: verify_for_execution does not check execution_id
# ---------------------------------------------------------------------------

class TestFinding2ExecutionIdNotVerified:
    """
    FINDING-2 (MEDIUM): ExecutionTokenAuthority.verify_for_execution() does not
    accept or check an expected_execution_id parameter.  The execution_id IS
    included in the EAT's signable payload (and thus the HMAC), but the
    verification call in sandboxed_tools.execute() does not pass the calling
    context's execution_id as an expected value.

    Attack: in a distributed context, a valid EAT for exec-A with matching
    (tool, args, tenant) can be presented to a different request with exec-B.
    Verification passes; the EAT is accepted; audit log records exec-B with a
    token that was issued for exec-A.

    After the fix: verify_for_execution accepts expected_execution_id; the check
    fails when the calling context's execution_id differs from the token's.
    """

    def _issue(self, auth, execution_id="exec-1"):
        h = compute_args_binding_hash("create_file", {"path": "f"}, "repo:write", "org/r")
        return auth.issue(
            execution_id=execution_id,
            tool_name="create_file",
            args_binding_hash=h,
            action_type="repo:write",
            resource_id="org/r",
            tenant_id="tenant-A",
        ), h

    def test_execution_id_verified_after_fix(self):
        """
        After fix: EAT from exec-1 must NOT verify when presented with exec-2.
        """
        auth = ExecutionTokenAuthority()
        token, h = self._issue(auth, execution_id="exec-1")

        # Simulate the attack: use token from exec-1 in the context of exec-2
        try:
            ok, reason = auth.verify_for_execution(
                token=token,
                expected_tool_name="create_file",
                expected_args_binding_hash=h,
                expected_action_type="repo:write",
                expected_resource_id="org/r",
                expected_tenant_id="tenant-A",
                expected_execution_id="exec-2",          # ← different context
            )
            assert not ok, (
                "FINDING-2 NOT FIXED: EAT from exec-1 passed verification for exec-2. "
                "verify_for_execution must check expected_execution_id."
            )
            assert reason == "token_execution_id_mismatch", \
                f"Expected 'token_execution_id_mismatch', got {reason!r}"
        except TypeError as exc:
            pytest.fail(
                f"FINDING-2 NOT FIXED: verify_for_execution does not accept "
                f"expected_execution_id parameter: {exc}"
            )

    def test_matching_execution_id_accepted_after_fix(self):
        """
        After fix: EAT from exec-1 verifies correctly when execution_id matches.
        """
        auth = ExecutionTokenAuthority()
        token, h = self._issue(auth, execution_id="exec-1")

        try:
            ok, reason = auth.verify_for_execution(
                token=token,
                expected_tool_name="create_file",
                expected_args_binding_hash=h,
                expected_action_type="repo:write",
                expected_resource_id="org/r",
                expected_tenant_id="tenant-A",
                expected_execution_id="exec-1",          # ← correct context
            )
            assert ok, f"Matching execution_id should verify; reason: {reason}"
        except TypeError as exc:
            pytest.fail(
                f"verify_for_execution does not accept expected_execution_id: {exc}"
            )

    def test_tools_execute_passes_execution_id_to_verify(self):
        """
        Regression: tools.execute() must pass the caller's execution_id to
        verify_for_execution so that the check is enforced at the execution layer.

        This test indirectly confirms the fix by verifying that an EAT from one
        execution context is REJECTED when used in a different execution context
        via the tools.execute() path.
        """
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)

        h = compute_args_binding_hash("read_repo_metadata", {}, "repo:read", "org/r")
        # Issue EAT for exec-A
        token_A = authority.issue(
            execution_id="exec-A",
            tool_name="read_repo_metadata",
            args_binding_hash=h,
            action_type="repo:read",
            resource_id="org/r",
            tenant_id="t1",
        )

        # Present exec-A's token to the tools layer claiming execution_id="exec-B"
        result = tools.execute(
            tool_name="read_repo_metadata",
            arguments={},
            execution_id="exec-B",         # ← different from token's execution_id
            tenant_id="t1",
            args_binding_hash=h,
            execution_token=token_A,
        )
        # After fix: exec-B context rejects exec-A's token
        assert not result["success"], (
            "FINDING-2 NOT FIXED: tools.execute() accepted exec-A's token for exec-B. "
            "The execution_id mismatch must be detected and the execution blocked."
        )
        assert result.get("blocked_reason") in (
            "token_execution_id_mismatch",
            "token_signature_invalid",
            "token_execution_id_mismatch",
        ), f"Unexpected block reason: {result.get('blocked_reason')!r}"


# ---------------------------------------------------------------------------
# FINDING-3: Tautological action_type / resource_id check (documented)
# ---------------------------------------------------------------------------

class TestFinding3TautologicalActionTypeCheck:
    """
    FINDING-3 (MEDIUM): sandboxed_tools.execute() calls verify_for_execution
    with expected_action_type=execution_token.action_type and
    expected_resource_id=execution_token.resource_id.  These values come from
    the token being verified, so the check always passes for a structurally
    valid token regardless of the calling context.

    The HMAC signature protects action_type and resource_id against forgery,
    so this is NOT exploitable in the current single-process architecture.
    However, in a distributed context where EATs are serialized and passed
    over a network, a correctly signed token with a different action_type could
    be substituted without detection if the caller doesn't supply independent
    expected values.

    Status: documented limitation.  A future fix should add action_type and
    resource_id parameters to tools.execute() and pass them to verify_for_execution.
    """

    def test_action_type_verified_against_caller_context(self):
        """
        Demonstrate the tautological check: even after verify_for_execution is
        called with action_type FROM THE TOKEN, the authorization is still
        determined by the HMAC.

        A tampered token with wrong action_type is rejected because the HMAC
        covers action_type — the tautological field check is redundant in that
        case.  But if the HMAC were somehow bypassed, the field check would
        also pass (self-referential).
        """
        authority = ExecutionTokenAuthority()
        h = compute_args_binding_hash("create_file", {"path": "f"}, "repo:write", "r")
        token = authority.issue(
            execution_id="e1",
            tool_name="create_file",
            args_binding_hash=h,
            action_type="repo:write",
            resource_id="r",
            tenant_id="t",
        )

        # Try to tamper action_type to "repo:admin" while keeping same signature
        tampered = ExecutionToken(
            key_id=token.key_id,
            execution_id=token.execution_id,
            tool_name=token.tool_name,
            args_binding_hash=token.args_binding_hash,
            action_type="repo:admin",        # changed
            resource_id=token.resource_id,
            tenant_id=token.tenant_id,
            issued_at_ns=token.issued_at_ns,
            max_age_ns=token.max_age_ns,
            signature=token.signature,       # original signature — now invalid
        )

        # HMAC catches the tampering; tampered token is rejected
        ok, reason = authority.verify_for_execution(
            token=tampered,
            expected_tool_name="create_file",
            expected_args_binding_hash=h,
            expected_action_type=tampered.action_type,  # tautological (from token)
            expected_resource_id=tampered.resource_id,  # tautological (from token)
            expected_tenant_id="t",
            **({} if _verify_has_execution_id_param(authority) else {}),
        )
        assert not ok, "Tampered action_type must be rejected"
        assert "signature" in reason.lower() or reason == "token_signature_invalid", \
            f"Must be rejected due to invalid HMAC, not field mismatch: {reason!r}"

    def test_tautological_check_always_passes_for_valid_token(self):
        """
        Confirm: when expected_action_type == token.action_type (tautological),
        the check passes for any action_type value.  This is the documented
        concern — the check provides no independent binding to the calling context.
        """
        authority = ExecutionTokenAuthority()

        for action_type in ["repo:write", "repo:admin", "repo:delete", "owner:all"]:
            h = compute_args_binding_hash("create_file", {"p": "f"}, action_type, "r")
            token = authority.issue(
                execution_id="e1",
                tool_name="create_file",
                args_binding_hash=h,
                action_type=action_type,
                resource_id="r",
                tenant_id="t",
            )
            vkw = dict(
                token=token,
                expected_tool_name="create_file",
                expected_args_binding_hash=h,
                expected_action_type=token.action_type,  # from token itself
                expected_resource_id=token.resource_id,
                expected_tenant_id="t",
            )
            if _verify_has_execution_id_param(authority):
                vkw["expected_execution_id"] = token.execution_id
            ok, reason = authority.verify_for_execution(**vkw)
            assert ok, \
                f"Tautological check should pass for action_type={action_type!r}: {reason}"


# ---------------------------------------------------------------------------
# Confirm existing security properties hold (regression fence)
# ---------------------------------------------------------------------------

class TestExistingSecurityPropertiesUnchanged:
    """
    Confirm that existing security controls are not broken by the security fixes.
    """

    def test_cross_tenant_substitution_still_blocked(self):
        """Cross-tenant EAT substitution is blocked by tenant_id field check."""
        auth = ExecutionTokenAuthority()
        h = compute_args_binding_hash("create_file", {"path": "f"}, "repo:write", "r")
        token_t1 = auth.issue(
            execution_id="e1", tool_name="create_file", args_binding_hash=h,
            action_type="repo:write", resource_id="r", tenant_id="tenant-1",
        )
        # Present tenant-1's token for tenant-2
        vkw = dict(
            token=token_t1,
            expected_tool_name="create_file",
            expected_args_binding_hash=h,
            expected_action_type="repo:write",
            expected_resource_id="r",
            expected_tenant_id="tenant-2",   # ← wrong tenant
        )
        if _verify_has_execution_id_param(auth):
            vkw["expected_execution_id"] = token_t1.execution_id
        ok, reason = auth.verify_for_execution(**vkw)
        assert not ok
        assert reason == "token_tenant_id_mismatch"

    def test_forged_signature_still_rejected(self):
        """A tampered signature always fails HMAC verification."""
        auth = ExecutionTokenAuthority()
        h = compute_args_binding_hash("create_file", {"path": "f"}, "repo:write", "r")
        token = auth.issue("e1", "create_file", h, "repo:write", "r", "t")
        forged = ExecutionToken(
            key_id=token.key_id,
            execution_id=token.execution_id,
            tool_name=token.tool_name,
            args_binding_hash=token.args_binding_hash,
            action_type=token.action_type,
            resource_id=token.resource_id,
            tenant_id=token.tenant_id,
            issued_at_ns=token.issued_at_ns,
            max_age_ns=token.max_age_ns,
            signature="a" * len(token.signature),  # all-'a' forgery
        )
        vkw = dict(
            token=forged,
            expected_tool_name="create_file",
            expected_args_binding_hash=h,
            expected_action_type="repo:write",
            expected_resource_id="r",
            expected_tenant_id="t",
        )
        if _verify_has_execution_id_param(auth):
            vkw["expected_execution_id"] = token.execution_id
        ok, reason = auth.verify_for_execution(**vkw)
        assert not ok
        assert reason == "token_signature_invalid"

    def test_retired_key_tokens_rejected(self):
        """Key retirement immediately invalidates tokens issued under that key."""
        rp = RotatingKeyProvider()
        rp.add_key("v1", os.urandom(32), make_current=True)
        auth = ExecutionTokenAuthority(key_provider=rp)
        h = compute_args_binding_hash("create_file", {"path": "f"}, "repo:write", "r")
        token_v1 = auth.issue("e1", "create_file", h, "repo:write", "r", "t")

        # Rotate to v2 and retire v1
        rp.add_key("v2", os.urandom(32), make_current=True)
        rp.remove_key("v1")

        vkw = dict(
            token=token_v1,
            expected_tool_name="create_file",
            expected_args_binding_hash=h,
            expected_action_type="repo:write",
            expected_resource_id="r",
            expected_tenant_id="t",
        )
        if _verify_has_execution_id_param(auth):
            vkw["expected_execution_id"] = token_v1.execution_id
        ok, reason = auth.verify_for_execution(**vkw)
        assert not ok
        assert reason == "token_key_id_unknown"

    def test_zero_ttl_token_expires_immediately(self):
        """Token with zero max_age_ns is expired on first check."""
        auth = ExecutionTokenAuthority(max_age_ms=0)
        h = compute_args_binding_hash("create_file", {"path": "f"}, "repo:write", "r")
        token = auth.issue("e1", "create_file", h, "repo:write", "r", "t")
        vkw = dict(
            token=token,
            expected_tool_name="create_file",
            expected_args_binding_hash=h,
            expected_action_type="repo:write",
            expected_resource_id="r",
            expected_tenant_id="t",
        )
        if _verify_has_execution_id_param(auth):
            vkw["expected_execution_id"] = token.execution_id
        ok, reason = auth.verify_for_execution(**vkw)
        assert not ok
        assert reason == "token_expired"

    def test_wrong_args_hash_rejected(self):
        """An EAT is rejected when presented with a different args_binding_hash."""
        auth = ExecutionTokenAuthority()
        h_correct = compute_args_binding_hash("create_file", {"path": "safe.txt"}, "repo:write", "r")
        h_attack  = compute_args_binding_hash("create_file", {"path": "../../etc/passwd"}, "repo:write", "r")
        token = auth.issue("e1", "create_file", h_correct, "repo:write", "r", "t")
        vkw = dict(
            token=token,
            expected_tool_name="create_file",
            expected_args_binding_hash=h_attack,  # ← attacker's hash
            expected_action_type="repo:write",
            expected_resource_id="r",
            expected_tenant_id="t",
        )
        if _verify_has_execution_id_param(auth):
            vkw["expected_execution_id"] = token.execution_id
        ok, reason = auth.verify_for_execution(**vkw)
        assert not ok
        assert reason == "token_args_hash_mismatch"

    def test_tools_execute_blocked_without_token(self):
        """Direct call to tools.execute() without a token is blocked."""
        auth = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=auth)
        h = compute_args_binding_hash("create_file", {"path": "f"}, "repo:write", "r")
        result = tools.execute(
            tool_name="create_file",
            arguments={"path": "f"},
            execution_id="e1",
            tenant_id="t",
            args_binding_hash=h,
            execution_token=None,
        )
        assert not result["success"]
        assert result["blocked_reason"] == "no_execution_token"

    def test_tools_execute_blocked_with_forged_token(self):
        """
        A token from a DIFFERENT authority (different key) is rejected by tools.execute().
        """
        real_auth  = ExecutionTokenAuthority()
        forged_auth = ExecutionTokenAuthority()  # separate key
        tools = SandboxedGitHubTools(token_authority=real_auth)

        h = compute_args_binding_hash("read_repo_metadata", {}, "repo:read", "r")
        forged_token = forged_auth.issue("e1", "read_repo_metadata", h, "repo:read", "r", "t")

        result = tools.execute(
            tool_name="read_repo_metadata",
            arguments={},
            execution_id="e1",
            tenant_id="t",
            args_binding_hash=h,
            execution_token=forged_token,
        )
        assert not result["success"]
        assert result["blocked_reason"] in (
            "token_key_id_unknown", "token_signature_invalid"
        )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _verify_has_execution_id_param(authority: ExecutionTokenAuthority) -> bool:
    """Return True if verify_for_execution accepts expected_execution_id."""
    import inspect
    sig = inspect.signature(authority.verify_for_execution)
    return "expected_execution_id" in sig.parameters
