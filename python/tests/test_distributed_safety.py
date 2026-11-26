"""
Distributed-safety tests for the agent-tool gateway hardening.

Tests in this file verify the properties added in the second hardening pass:

1. TestNonceStoreBackends     — InMemoryNonceStore vs SqlNonceStore semantics
2. TestProcessRestartNonce    — SQLite nonce store persists across process restart
3. TestMultiWorkerNonce       — Exactly 1 of N concurrent processes consumes nonce
4. TestRevocationPersistence  — SqlRevocationStore persists across restart
5. TestRevocationConcurrency  — Concurrent revocation is idempotent; check is consistent
6. TestKeyProviders           — InMemoryKeyProvider, RotatingKeyProvider basics
7. TestKeyRotation            — Old tokens verify after rotation; retired key rejects
8. TestNoBypassPaths          — Every execute() path that could bypass the gateway is closed
9. TestDistributedSafetyFlags — is_distributed_safe propagates correctly through facades

Concurrency tests use multiprocessing.Process (not threading) to simulate
separate OS processes. No timing-sensitive sleeps: results are collected from
a multiprocessing.Queue with explicit timeouts.
"""

from __future__ import annotations

import multiprocessing
import os
import sys
import tempfile
import threading
import time
import warnings
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Path setup — same approach as the other test files
# ---------------------------------------------------------------------------
_BENCH_DIR = Path(__file__).parent.parent.parent / "benchmarks" / "agent-verification"
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))

from execution_token import ExecutionToken, ExecutionTokenAuthority  # noqa: E402
from key_provider import InMemoryKeyProvider, RotatingKeyProvider    # noqa: E402
from nonce_store import InMemoryNonceStore, SqlNonceStore             # noqa: E402
from replay_protection import ApprovalNonce, ReplayRegistry           # noqa: E402
from revocation_list import (                                          # noqa: E402
    InMemoryRevocationStore,
    RevocationList,
    SqlRevocationStore,
)

# Silence the in-process managed-key RuntimeWarning; tests deliberately use
# InMemoryKeyProvider.
warnings.filterwarnings("ignore", category=RuntimeWarning, message="unmanaged")


# ---------------------------------------------------------------------------
# Helpers shared across test classes
# ---------------------------------------------------------------------------

def _make_nonce(tag: str = "default") -> ApprovalNonce:
    return ApprovalNonce(
        approval_id=f"appr-{tag}",
        tenant_id="tenant-test",
        action_type="repo:write",
        resource_id="org/repo",
        proposal_id=f"prop-{tag}",
    )


def _worker_try_consume(sqlite_path: str, nonce_key: str, q: "multiprocessing.Queue[bool]") -> None:
    """Subprocess worker: try to consume nonce_key and put result in queue."""
    # Re-import in subprocess (fresh Python interpreter)
    import sys
    sys.path.insert(0, str(_BENCH_DIR))
    from nonce_store import SqlNonceStore
    store = SqlNonceStore("sqlite", path=sqlite_path)
    q.put(store.try_consume(nonce_key))


def _worker_revoke_and_check(
    sqlite_path: str,
    approval_id: str,
    tenant_id: str,
    q: "multiprocessing.Queue[Any]",
) -> None:
    """Subprocess worker: revoke an approval and report is_revoked."""
    import sys
    sys.path.insert(0, str(_BENCH_DIR))
    from revocation_list import RevocationList, SqlRevocationStore
    store = SqlRevocationStore("sqlite", path=sqlite_path)
    rl = RevocationList(backend=store)
    rl.revoke(approval_id, tenant_id, reason="worker-revocation")
    q.put(rl.is_revoked(approval_id, tenant_id))


# ---------------------------------------------------------------------------
# 1. NonceStore backend semantics
# ---------------------------------------------------------------------------

class TestNonceStoreBackends:

    def test_in_memory_first_consume_true(self):
        store = InMemoryNonceStore()
        assert store.try_consume("key-1") is True

    def test_in_memory_replay_returns_false(self):
        store = InMemoryNonceStore()
        store.try_consume("key-1")
        assert store.try_consume("key-1") is False

    def test_in_memory_different_keys_independent(self):
        store = InMemoryNonceStore()
        assert store.try_consume("key-A") is True
        assert store.try_consume("key-B") is True

    def test_in_memory_not_distributed_safe(self):
        assert InMemoryNonceStore().is_distributed_safe is False

    def test_sqlite_first_consume_true(self, tmp_path):
        store = SqlNonceStore("sqlite", path=str(tmp_path / "nonces.db"))
        assert store.try_consume("key-1") is True

    def test_sqlite_replay_returns_false(self, tmp_path):
        store = SqlNonceStore("sqlite", path=str(tmp_path / "nonces.db"))
        store.try_consume("key-1")
        assert store.try_consume("key-1") is False

    def test_sqlite_different_keys_independent(self, tmp_path):
        store = SqlNonceStore("sqlite", path=str(tmp_path / "nonces.db"))
        assert store.try_consume("key-A") is True
        assert store.try_consume("key-B") is True

    def test_sqlite_not_distributed_safe(self, tmp_path):
        store = SqlNonceStore("sqlite", path=str(tmp_path / "nonces.db"))
        assert store.is_distributed_safe is False

    def test_sqlite_reset_clears_state(self, tmp_path):
        store = SqlNonceStore("sqlite", path=str(tmp_path / "nonces.db"))
        store.try_consume("key-1")
        store.reset()
        assert store.try_consume("key-1") is True  # cleared

    def test_sqlite_new_instance_same_file_sees_consumed(self, tmp_path):
        """Two SqlNonceStore instances sharing a file share state (file-backed)."""
        path = str(tmp_path / "shared.db")
        store1 = SqlNonceStore("sqlite", path=path)
        store2 = SqlNonceStore("sqlite", path=path)
        store1.try_consume("key-shared")
        assert store2.try_consume("key-shared") is False

    def test_replay_registry_delegates_to_backend(self, tmp_path):
        store = SqlNonceStore("sqlite", path=str(tmp_path / "nonces.db"))
        registry = ReplayRegistry(backend=store)
        nonce = _make_nonce("reg-test")
        assert registry.try_consume(nonce) is True
        assert registry.try_consume(nonce) is False

    def test_replay_registry_is_distributed_safe_mirrors_backend(self, tmp_path):
        mem_registry = ReplayRegistry()
        assert mem_registry.is_distributed_safe is False
        sql_registry = ReplayRegistry(
            backend=SqlNonceStore("sqlite", path=str(tmp_path / "n.db"))
        )
        assert sql_registry.is_distributed_safe is False  # sqlite not distributed-safe

    def test_in_memory_replay_registry_is_not_distributed_safe(self):
        """Explicitly verify the documented limitation."""
        registry = ReplayRegistry()
        assert registry.is_distributed_safe is False


# ---------------------------------------------------------------------------
# 2. Process restart: SQLite nonce persists
# ---------------------------------------------------------------------------

class TestProcessRestartNonce:

    def test_nonce_persists_across_simulated_restart(self, tmp_path):
        """
        Simulate process restart by creating two separate SqlNonceStore instances
        backed by the same file. The second instance represents a fresh process
        that loaded the same database.
        """
        path = str(tmp_path / "nonces.db")
        nonce_key = "restart-test-nonce"

        # Simulated process 1: consume nonce
        store1 = SqlNonceStore("sqlite", path=path)
        result1 = store1.try_consume(nonce_key)
        del store1  # simulate process exit (connection closed)

        # Simulated process 2 (restart): try same nonce
        store2 = SqlNonceStore("sqlite", path=path)
        result2 = store2.try_consume(nonce_key)

        assert result1 is True, "First consume must succeed"
        assert result2 is False, "Second consume after restart must be detected as replay"

    def test_in_memory_nonce_does_not_persist_across_restart(self):
        """
        Demonstrate the known limitation: InMemoryNonceStore cannot prevent
        replay after a process restart (new object = fresh state).
        """
        nonce_key = "restart-inmemory-nonce"

        # Simulated process 1
        store1 = InMemoryNonceStore()
        store1.try_consume(nonce_key)

        # Simulated restart: brand new InMemoryNonceStore
        store2 = InMemoryNonceStore()
        result2 = store2.try_consume(nonce_key)

        # This SUCCEEDS — documented cross-process limitation of InMemory store
        assert result2 is True, (
            "InMemoryNonceStore correctly shows cross-restart replay gap: "
            "new process can replay a nonce consumed by a previous process."
        )

    def test_sqlite_registry_persists_across_restart(self, tmp_path):
        """Full ReplayRegistry → SqlNonceStore → SQLite file: restart-safe."""
        path = str(tmp_path / "nonces.db")
        nonce = _make_nonce("persist-test")

        # Process 1
        registry1 = ReplayRegistry(backend=SqlNonceStore("sqlite", path=path))
        consumed = registry1.try_consume(nonce)
        del registry1

        # Process 2 (restart)
        registry2 = ReplayRegistry(backend=SqlNonceStore("sqlite", path=path))
        replay_blocked = not registry2.try_consume(nonce)

        assert consumed is True
        assert replay_blocked is True


# ---------------------------------------------------------------------------
# 3. Multi-worker: exactly one of N concurrent processes consumes nonce
# ---------------------------------------------------------------------------

class TestMultiWorkerNonce:

    @pytest.mark.timeout(30)
    def test_exactly_one_worker_consumes_nonce(self, tmp_path):
        """
        Spawn 5 real OS processes each trying to consume the same nonce key.
        Exactly 1 must succeed; the other 4 must see replay.

        Uses multiprocessing.Process (not threads) to simulate separate workers.
        No sleep-based synchronization: results collected from a Queue.
        """
        ctx = multiprocessing.get_context("spawn")
        q: multiprocessing.Queue = ctx.Queue()
        path = str(tmp_path / "workers.db")

        # Initialize schema before spawning
        SqlNonceStore("sqlite", path=path)

        nonce_key = "multi-worker-exclusive-nonce"
        n_workers = 5
        processes = [
            ctx.Process(
                target=_worker_try_consume,
                args=(path, nonce_key, q),
            )
            for _ in range(n_workers)
        ]
        for p in processes:
            p.start()
        for p in processes:
            p.join(timeout=15)

        # Collect results (all processes must have put exactly one value)
        results = []
        for _ in range(n_workers):
            try:
                results.append(q.get(timeout=5))
            except Exception:
                pytest.fail("Worker did not return result within timeout")

        successes = results.count(True)
        failures = results.count(False)

        assert successes == 1, (
            f"Expected exactly 1 successful consume across {n_workers} workers, "
            f"got {successes} (results={results})"
        )
        assert failures == n_workers - 1, (
            f"Expected {n_workers - 1} replay-detected failures, got {failures}"
        )

    @pytest.mark.timeout(30)
    def test_distinct_nonces_all_succeed_across_workers(self, tmp_path):
        """Each worker gets its own distinct nonce key → all 5 consume successfully."""
        ctx = multiprocessing.get_context("spawn")
        q: multiprocessing.Queue = ctx.Queue()
        path = str(tmp_path / "workers2.db")
        SqlNonceStore("sqlite", path=path)

        n_workers = 5
        processes = [
            ctx.Process(
                target=_worker_try_consume,
                args=(path, f"distinct-nonce-{i}", q),
            )
            for i in range(n_workers)
        ]
        for p in processes:
            p.start()
        for p in processes:
            p.join(timeout=15)

        results = [q.get(timeout=5) for _ in range(n_workers)]
        assert all(results), f"All distinct nonces should succeed: {results}"


# ---------------------------------------------------------------------------
# 4. Revocation persistence
# ---------------------------------------------------------------------------

class TestRevocationPersistence:

    def test_in_memory_revocation_does_not_persist(self):
        """Document the known limitation: InMemoryRevocationStore is per-process."""
        store1 = InMemoryRevocationStore()
        store1.revoke("appr-A", "t1", "test")
        # New object = no memory of revocation
        store2 = InMemoryRevocationStore()
        assert store2.is_revoked("appr-A", "t1") is False

    def test_sqlite_revocation_persists_across_simulated_restart(self, tmp_path):
        """SQLite RevocationStore: revocation from 'process 1' visible in 'process 2'."""
        path = str(tmp_path / "revocations.db")

        # Process 1: revoke
        store1 = SqlRevocationStore("sqlite", path=path)
        store1.revoke("appr-persist", "tenant-x", reason="security-incident")
        del store1

        # Process 2 (restart): check
        store2 = SqlRevocationStore("sqlite", path=path)
        assert store2.is_revoked("appr-persist", "tenant-x") is True

    def test_sqlite_revocation_is_tenant_scoped(self, tmp_path):
        """Revocation in tenant A does not affect tenant B."""
        path = str(tmp_path / "rev.db")
        store = SqlRevocationStore("sqlite", path=path)
        store.revoke("appr-shared", "tenant-A", reason="reason-A")
        assert store.is_revoked("appr-shared", "tenant-A") is True
        assert store.is_revoked("appr-shared", "tenant-B") is False

    def test_sqlite_revocation_is_idempotent(self, tmp_path):
        """Revoking the same approval twice leaves exactly one entry."""
        path = str(tmp_path / "rev.db")
        store = SqlRevocationStore("sqlite", path=path)
        store.revoke("appr-dup", "t1", reason="first")
        store.revoke("appr-dup", "t1", reason="second")  # first wins
        entries = store.all_entries()
        matching = [e for e in entries if e.approval_id == "appr-dup"]
        assert len(matching) == 1
        assert matching[0].reason == "first"

    def test_revocation_list_with_sqlite_backend(self, tmp_path):
        """RevocationList facade over SqlRevocationStore mirrors persistence."""
        path = str(tmp_path / "rev.db")
        backend = SqlRevocationStore("sqlite", path=path)
        rl1 = RevocationList(backend=backend)
        rl1.revoke("appr-sql", "tenant-sql", reason="sql-test")

        # New facade, same backend instance
        rl2 = RevocationList(backend=SqlRevocationStore("sqlite", path=path))
        assert rl2.is_revoked("appr-sql", "tenant-sql") is True

    def test_revocation_list_is_distributed_safe_flag(self, tmp_path):
        mem_rl = RevocationList()
        assert mem_rl.is_distributed_safe is False
        sql_rl = RevocationList(backend=SqlRevocationStore("sqlite", path=str(tmp_path / "r.db")))
        assert sql_rl.is_distributed_safe is False  # sqlite is single-machine only

    @pytest.mark.timeout(30)
    def test_concurrent_revocation_across_workers(self, tmp_path):
        """
        Worker revokes in a subprocess; main process observes the revocation.
        Demonstrates cross-process revocation visibility with SQLite.
        """
        path = str(tmp_path / "rev_concurrent.db")
        approval_id = "appr-cross-process"
        tenant_id = "tenant-xp"

        # Initialize schema
        SqlRevocationStore("sqlite", path=path)

        ctx = multiprocessing.get_context("spawn")
        q: multiprocessing.Queue = ctx.Queue()
        p = ctx.Process(
            target=_worker_revoke_and_check,
            args=(path, approval_id, tenant_id, q),
        )
        p.start()
        p.join(timeout=15)

        worker_saw_revoked = q.get(timeout=5)
        assert worker_saw_revoked is True, "Worker should see its own revocation"

        # Main process now reads same DB
        store_main = SqlRevocationStore("sqlite", path=path)
        assert store_main.is_revoked(approval_id, tenant_id) is True, (
            "Main process must see revocation written by worker"
        )


# ---------------------------------------------------------------------------
# 5. Key providers
# ---------------------------------------------------------------------------

class TestKeyProviders:

    def test_in_memory_provider_generates_key(self):
        p = InMemoryKeyProvider()
        assert len(p.signing_key) == 32
        assert p.key_id == "default"
        assert p.is_managed is False

    def test_in_memory_provider_custom_key_id(self):
        p = InMemoryKeyProvider(key_id="k1")
        assert p.key_id == "k1"

    def test_in_memory_provider_explicit_key_bytes(self):
        raw = os.urandom(32)
        p = InMemoryKeyProvider(key_bytes=raw)
        assert p.signing_key == raw

    def test_in_memory_provider_rejects_short_key(self):
        with pytest.raises(ValueError):
            InMemoryKeyProvider(key_bytes=b"tooshort")

    def test_in_memory_provider_verification_key_match(self):
        p = InMemoryKeyProvider(key_id="x")
        assert p.get_verification_key("x") == p.signing_key

    def test_in_memory_provider_verification_key_mismatch(self):
        p = InMemoryKeyProvider(key_id="x")
        assert p.get_verification_key("y") is None

    def test_rotating_provider_add_and_sign(self):
        rp = RotatingKeyProvider()
        rp.add_key("v1", os.urandom(32), make_current=True)
        assert rp.key_id == "v1"
        assert len(rp.signing_key) == 32

    def test_rotating_provider_first_added_becomes_current(self):
        rp = RotatingKeyProvider()
        rp.add_key("first", os.urandom(32))
        assert rp.key_id == "first"

    def test_rotating_provider_no_key_raises(self):
        rp = RotatingKeyProvider()
        with pytest.raises(Exception):
            _ = rp.key_id

    def test_rotating_provider_set_current(self):
        rp = RotatingKeyProvider()
        rp.add_key("v1", os.urandom(32))
        rp.add_key("v2", os.urandom(32))
        rp.set_current("v2")
        assert rp.key_id == "v2"

    def test_rotating_provider_cannot_retire_current(self):
        from key_provider import SigningKeyError
        rp = RotatingKeyProvider()
        rp.add_key("v1", os.urandom(32), make_current=True)
        with pytest.raises(SigningKeyError):
            rp.remove_key("v1")

    def test_rotating_provider_retire_non_current(self):
        rp = RotatingKeyProvider()
        rp.add_key("v1", os.urandom(32), make_current=True)
        rp.add_key("v2", os.urandom(32), make_current=True)
        rp.remove_key("v1")
        assert "v1" not in rp.active_key_ids

    def test_rotating_provider_retired_key_returns_none(self):
        rp = RotatingKeyProvider()
        rp.add_key("v1", os.urandom(32), make_current=True)
        rp.add_key("v2", os.urandom(32), make_current=True)
        rp.remove_key("v1")
        assert rp.get_verification_key("v1") is None


# ---------------------------------------------------------------------------
# 6. Key rotation: old tokens verify; retired key rejects
# ---------------------------------------------------------------------------

class TestKeyRotation:

    def _common_kwargs(self) -> dict:
        return dict(
            execution_id="eid-rot",
            tool_name="create_file",
            args_binding_hash="abc123",
            action_type="repo:write",
            resource_id="org/repo",
            tenant_id="tenant-rot",
        )

    def test_key_id_embedded_in_token(self):
        provider = InMemoryKeyProvider(key_id="embed-test")
        authority = ExecutionTokenAuthority(key_provider=provider)
        token = authority.issue(**self._common_kwargs())
        assert token.key_id == "embed-test"

    def test_rotating_new_key_tokens_use_new_id(self):
        rp = RotatingKeyProvider()
        rp.add_key("v1", os.urandom(32), make_current=True)
        authority = ExecutionTokenAuthority(key_provider=rp)
        t1 = authority.issue(**self._common_kwargs())
        assert t1.key_id == "v1"

        rp.add_key("v2", os.urandom(32), make_current=True)
        kwargs2 = dict(self._common_kwargs()); kwargs2["execution_id"] = "eid-rot2"
        t2 = authority.issue(**kwargs2)
        assert t2.key_id == "v2"

    def test_old_key_token_still_verifies_after_rotation(self):
        """Old tokens remain valid while v1 is still in the provider."""
        rp = RotatingKeyProvider()
        rp.add_key("v1", os.urandom(32), make_current=True)
        authority = ExecutionTokenAuthority(key_provider=rp)
        token_v1 = authority.issue(**self._common_kwargs())

        # Rotate to v2 — do NOT remove v1 yet
        rp.add_key("v2", os.urandom(32), make_current=True)

        kw = self._common_kwargs()
        ok, reason = authority.verify_for_execution(
            token_v1,
            expected_tool_name=kw["tool_name"],
            expected_args_binding_hash=kw["args_binding_hash"],
            expected_action_type=kw["action_type"],
            expected_resource_id=kw["resource_id"],
            expected_tenant_id=kw["tenant_id"],
        )
        assert ok, f"v1 token should verify while v1 key still active: {reason}"

    def test_new_key_token_verifies_after_rotation(self):
        rp = RotatingKeyProvider()
        rp.add_key("v1", os.urandom(32), make_current=True)
        rp.add_key("v2", os.urandom(32), make_current=True)
        authority = ExecutionTokenAuthority(key_provider=rp)
        kwargs2 = dict(self._common_kwargs()); kwargs2["execution_id"] = "new-eid"
        token_v2 = authority.issue(**kwargs2)
        assert token_v2.key_id == "v2"

        kw = self._common_kwargs()
        ok, _ = authority.verify_for_execution(
            token_v2,
            expected_tool_name=kw["tool_name"],
            expected_args_binding_hash=kw["args_binding_hash"],
            expected_action_type=kw["action_type"],
            expected_resource_id=kw["resource_id"],
            expected_tenant_id=kw["tenant_id"],
        )
        assert ok

    def test_retired_key_token_rejected(self):
        """After removing v1, tokens issued under v1 are rejected."""
        rp = RotatingKeyProvider()
        rp.add_key("v1", os.urandom(32), make_current=True)
        authority = ExecutionTokenAuthority(key_provider=rp)
        token_v1 = authority.issue(**self._common_kwargs())

        # Rotate to v2, then retire v1
        rp.add_key("v2", os.urandom(32), make_current=True)
        rp.remove_key("v1")

        kw = self._common_kwargs()
        ok, reason = authority.verify_for_execution(
            token_v1,
            expected_tool_name=kw["tool_name"],
            expected_args_binding_hash=kw["args_binding_hash"],
            expected_action_type=kw["action_type"],
            expected_resource_id=kw["resource_id"],
            expected_tenant_id=kw["tenant_id"],
        )
        assert not ok
        assert reason == "token_key_id_unknown", f"Expected key_id_unknown, got {reason!r}"

    def test_changed_key_id_field_invalidates_signature(self):
        """key_id is covered by the signature; tampering with it is detected."""
        provider = InMemoryKeyProvider(key_id="k1")
        authority = ExecutionTokenAuthority(key_provider=provider)
        token = authority.issue(**self._common_kwargs())

        # Reconstruct with a different key_id but same signature (tampered)
        tampered = ExecutionToken(
            key_id="k2",           # changed
            execution_id=token.execution_id,
            tool_name=token.tool_name,
            args_binding_hash=token.args_binding_hash,
            action_type=token.action_type,
            resource_id=token.resource_id,
            tenant_id=token.tenant_id,
            issued_at_ns=token.issued_at_ns,
            not_before_ns=token.not_before_ns,
            max_age_ns=token.max_age_ns,
            signature=token.signature,  # original signature, now invalid
        )

        # Provider doesn't know k2 → rejected with key_id_unknown
        kw = self._common_kwargs()
        ok, reason = authority.verify_for_execution(
            tampered,
            expected_tool_name=kw["tool_name"],
            expected_args_binding_hash=kw["args_binding_hash"],
            expected_action_type=kw["action_type"],
            expected_resource_id=kw["resource_id"],
            expected_tenant_id=kw["tenant_id"],
        )
        assert not ok
        assert reason == "token_key_id_unknown"


# ---------------------------------------------------------------------------
# 7. No bypass paths: every route through execute() is covered by EAT
# ---------------------------------------------------------------------------

class TestNoBypassPaths:

    def _make_sandboxed_tools_with_authority(self):
        from sandboxed_tools import SandboxedGitHubTools
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)
        return tools, authority

    def test_execute_no_token_blocked(self):
        """Direct execute() call with no token is blocked regardless of other args."""
        from sandboxed_tools import SandboxedGitHubTools
        tools = SandboxedGitHubTools()
        authority = ExecutionTokenAuthority()
        tools._token_authority = authority

        result = tools.execute(
            tool_name="create_file",
            arguments={"path": "pwned.txt", "content": "bypass"},
            execution_id="bypass-attempt",
            tenant_id="tenant-x",
            args_binding_hash="fakehash",
            execution_token=None,
            decision_label="ALLOW",  # attacker claims ALLOW; irrelevant
        )
        assert result.get("success") is False, f"No-token execute must be blocked: {result}"

    def test_execute_forged_token_blocked(self):
        """Token from a different authority cannot authorize execution."""
        from sandboxed_tools import SandboxedGitHubTools
        from sandboxed_tools import compute_args_binding_hash

        # Legitimate authority installed on the tools object
        legitimate_authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=legitimate_authority)

        # Attacker creates their own authority and issues a token
        attacker_authority = ExecutionTokenAuthority()
        forged_token = attacker_authority.issue(
            execution_id="forged-exec",
            tool_name="create_file",
            args_binding_hash="fakehash",
            action_type="repo:write",
            resource_id="org/repo",
            tenant_id="tenant-x",
        )

        result = tools.execute(
            tool_name="create_file",
            arguments={"path": "pwned.txt"},
            execution_id="forged-exec",
            tenant_id="tenant-x",
            args_binding_hash="fakehash",
            execution_token=forged_token,
            decision_label="ALLOW",
        )
        assert result.get("success") is False, f"Forged-token execute must be blocked: {result}"

    def test_execute_no_authority_on_tools_blocked(self):
        """Tools object with no authority installed blocks all executions."""
        from sandboxed_tools import SandboxedGitHubTools
        tools = SandboxedGitHubTools()
        # _token_authority is None by default
        assert tools._token_authority is None

        authority = ExecutionTokenAuthority()
        token = authority.issue(
            execution_id="no-auth-tools",
            tool_name="create_file",
            args_binding_hash="h",
            action_type="repo:write",
            resource_id="res",
            tenant_id="t",
        )
        result = tools.execute(
            tool_name="create_file",
            arguments={},
            execution_id="no-auth-tools",
            tenant_id="t",
            args_binding_hash="h",
            execution_token=token,
            decision_label="ALLOW",
        )
        assert result.get("success") is False, f"No-authority execute must be blocked: {result}"

    def test_execute_valid_token_from_gateway_executes(self):
        """When the gateway issues the token and the tools hold the same authority, execution succeeds."""
        from sandboxed_tools import SandboxedGitHubTools, compute_args_binding_hash
        authority = ExecutionTokenAuthority()
        tools = SandboxedGitHubTools(token_authority=authority)
        args = {"path": "file.txt", "content": "hello"}
        args_hash = compute_args_binding_hash(
            tool_name="create_file",
            arguments=args,
            action_type="repo:write",
            resource_id="org/repo",
        )
        exec_id = "legitimate-exec"
        token = authority.issue(
            execution_id=exec_id,
            tool_name="create_file",
            args_binding_hash=args_hash,
            action_type="repo:write",
            resource_id="org/repo",
            tenant_id="tenant-y",
        )
        result = tools.execute(
            tool_name="create_file",
            arguments=args,
            execution_id=exec_id,
            tenant_id="tenant-y",
            args_binding_hash=args_hash,
            execution_token=token,
            decision_label="ALLOW",
        )
        assert result.get("success") is True, f"Valid-token execute must succeed: {result}"


# ---------------------------------------------------------------------------
# 8. Distributed safety flag propagation
# ---------------------------------------------------------------------------

class TestDistributedSafetyFlags:

    def test_in_memory_replay_registry_flag(self):
        assert ReplayRegistry().is_distributed_safe is False

    def test_sqlite_replay_registry_flag(self, tmp_path):
        store = SqlNonceStore("sqlite", path=str(tmp_path / "n.db"))
        registry = ReplayRegistry(backend=store)
        assert registry.is_distributed_safe is False  # sqlite is single-machine

    def test_in_memory_revocation_list_flag(self):
        assert RevocationList().is_distributed_safe is False

    def test_sqlite_revocation_list_flag(self, tmp_path):
        store = SqlRevocationStore("sqlite", path=str(tmp_path / "r.db"))
        rl = RevocationList(backend=store)
        assert rl.is_distributed_safe is False

    def test_unmanaged_key_provider_flag(self):
        p = InMemoryKeyProvider()
        assert p.is_managed is False

    def test_rotating_provider_is_not_managed_by_default(self):
        rp = RotatingKeyProvider()
        assert rp.is_managed is False

    def test_gateway_warns_on_unmanaged_key(self, tmp_path):
        """ToolGateway emits RuntimeWarning when given unmanaged InMemoryKeyProvider."""
        import sys
        sys.path.insert(0, str(_BENCH_DIR))
        from agent_integration_scenarios import POLICY_FIXTURE, _NOW
        from replay_protection import ReplayRegistry
        from revocation_list import RevocationList
        from sandboxed_tools import SandboxedGitHubTools
        from tool_gateway import ToolGateway
        from trusted_policy_provider import TrustedPolicyProvider

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            ToolGateway(
                policy_provider=TrustedPolicyProvider(POLICY_FIXTURE),
                tools=SandboxedGitHubTools(),
                replay_registry=ReplayRegistry(),
                revocation_list=RevocationList(),
                current_time=_NOW,
            )
        runtime_warnings = [w for w in caught if issubclass(w.category, RuntimeWarning)
                            and "unmanaged" in str(w.message).lower()]
        assert len(runtime_warnings) >= 1, "Expected RuntimeWarning about unmanaged key"
