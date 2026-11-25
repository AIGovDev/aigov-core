"""The public trusted-execution SDK (``aigov_py.trusted``): checks that need no running Core.

They pin the security contract (the argument digest and the authorization domain), exercise each refusal the executor
makes before it contacts Core, check that a reservation is single-use under concurrency, and check the launcher's
safety rules. The package must not depend on ``examples/``; a subprocess test checks that.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from aigov_py.canonical_json import canonical_bytes
from aigov_py.trusted import (
    ExecutionStore,
    Executor,
    Refused,
    ToolSpec,
    args_binding_hash,
    build_policy_document,
    executor_store_migration,
    provision,
    tool_registry,
    verify_authorization_signature,
)
from aigov_py.trusted.authorization import AUTH_DOMAIN, AUTH_SCHEMA
from aigov_py.trusted.launch import prepare_state_dir
from nacl.signing import SigningKey

REPO_ROOT = Path(__file__).resolve().parents[2]

# Digests recorded from the reference implementation before the SDK existed. A change to the binding breaks these.
GOLDEN = [
    (
        ToolSpec("read_repo_metadata", "repo:read", "read", "repo_id"),
        {"repo_id": "acme/app"},
        "18277f1c6c82e640459f369b81e625f792ddbdd52bd32dda1813fcd951ba6b44",
    ),
    (
        ToolSpec("create_file", "repo:write", "write", "repo_id"),
        {"repo_id": "acme/app", "path": "docs/A.md", "content": "v1"},
        "90d72bec0a0584d5a769466091f5e0298c03a050a16d0e2c9baa211f08e91131",
    ),
    (
        ToolSpec("create_file", "repo:write", "write", "repo_id"),
        {"repo_id": "acme/app", "path": "docs/A.md", "content": "ünïcode ✓", "n": 2},
        "e1a59d17f4bc8d4fdd86f2b44af66ff4a87392bae93a6b797ce4dc0880feb0a0",
    ),
    (
        ToolSpec("deploy_pilot", "deploy:staging", "write", "environment"),
        {"environment": "staging", "version": 3},
        "0b060669db6bfc935d2fd9f49a5bade726e1f4777abb1ea8cd25de0292c52de9",
    ),
    (
        ToolSpec("create_file", "repo:write", "write", "repo_id"),
        {"path": "no-resource.md"},
        "ba8054153278c3c67b7d9588dd0a8b2739beb7334a630148b7b0d5ecc02476f0",
    ),
]


def _store(path: Path) -> ExecutionStore:
    """Apply the executor store migration to a fresh file, as an operator does before first use."""
    import sqlite3

    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.executescript(executor_store_migration())
    return ExecutionStore(path)


def test_a_store_without_the_migration_refuses_to_start():
    from aigov_py.trusted import ExecutionStoreSchemaError

    with (
        tempfile.TemporaryDirectory() as tmp,
        pytest.raises(ExecutionStoreSchemaError, match="executor_store_migration"),
    ):
        ExecutionStore(Path(tmp) / "fresh.sqlite")


def test_the_migration_creates_the_table_once_and_is_idempotent():
    import sqlite3

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "m.sqlite"
        with sqlite3.connect(path) as conn:
            conn.executescript(executor_store_migration())
            conn.executescript(executor_store_migration())  # re-running is safe
        ExecutionStore(path)  # now starts


@pytest.mark.parametrize("spec, args, expected", GOLDEN)
def test_argument_digest_matches_the_recorded_reference_value(spec, args, expected):
    assert args_binding_hash(spec, args) == expected


def test_digest_changes_with_any_bound_field():
    spec = ToolSpec("create_file", "repo:write", "write", "repo_id")
    base = {"repo_id": "r", "path": "a", "content": "x"}
    digest = args_binding_hash(spec, base)
    assert args_binding_hash(spec, {**base, "content": "y"}) != digest
    assert args_binding_hash(spec, {**base, "repo_id": "s"}) != digest
    assert (
        args_binding_hash(
            ToolSpec("create_file", "repo:admin", "write", "repo_id"), base
        )
        != digest
    )
    assert (
        args_binding_hash(ToolSpec("other", "repo:write", "write", "repo_id"), base)
        != digest
    )


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"name": "", "action": "a", "kind": "read"}, "name"),
        ({"name": "t", "action": "", "kind": "read"}, "action"),
        ({"name": "t", "action": "a", "kind": "delete"}, "kind"),
        (
            {"name": "t", "action": "a", "kind": "read", "resource_key": ""},
            "resource_key",
        ),
    ],
)
def test_tool_spec_rejects_invalid_definitions(kwargs, message):
    with pytest.raises(ValueError, match=message):
        ToolSpec(**kwargs)


def test_tool_registry_rejects_duplicates_and_non_specs():
    spec = ToolSpec("t", "a", "read")
    with pytest.raises(ValueError, match="duplicate"):
        tool_registry([spec, spec])
    with pytest.raises(TypeError):
        tool_registry(["t"])


def test_policy_allowlists_and_approval_gates_are_built_from_the_arguments():
    doc = build_policy_document(
        policy_id="p",
        issuer_id="i",
        issuer_display_name="I",
        created_at_utc="2026-01-01T00:00:00Z",
        read_tools=["r1"],
        write_tools=["w1"],
        approvers=["a@example.test"],
        approval_max_age_seconds=45,
    )
    events = doc["ingest_rules"]["event_types"]
    approved = {g["type"]: g for g in events["human_approved"]["gates"]}
    assert approved["requires_approver_allowlist"]["allowlist"] == ["a@example.test"]
    assert approved["requires_principal_relation"]["relation"] == "distinct"
    consequential = {g["type"]: g for g in events["consequential_tool_call"]["gates"]}
    assert consequential["requires_decision_enum"]["allowed"] == ["w1"]
    assert consequential["requires_unconsumed_approval"]["max_age_seconds"] == 45
    assert events["tool_call"]["gates"][0]["allowed"] == ["r1"]
    assert doc["ingest_rules"]["unknown_event_types"] == {"behavior": "reject"}


def _signed(payload: dict, seed: SigningKey, domain: bytes = AUTH_DOMAIN) -> dict:
    sig = seed.sign(domain + canonical_bytes(payload)).signature
    return {"payload": payload, "signature": base64.b64encode(sig).decode("ascii")}


def _payload(**overrides) -> dict:
    base = {
        "schema": AUTH_SCHEMA,
        "authorization_id": "auth_1",
        "run_id": "run-1",
        "tool_name": "create_file",
        "args_binding_hash": "0" * 64,
        "policy_revision": "1",
        "executor_audience": "executor:ref",
        "approval_event_id": "human_approved-1",
        "consequential_record_hash": "f" * 64,
        "issued_at_utc": "2026-01-01T00:00:00+00:00",
        "expires_at_utc": "2999-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return base


def test_a_correctly_signed_authorization_verifies():
    key = SigningKey.generate()
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    verify_authorization_signature(_signed(_payload(), key), pub)


def test_a_signature_without_the_domain_prefix_is_refused():
    key = SigningKey.generate()
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    with pytest.raises(Refused) as exc:
        verify_authorization_signature(_signed(_payload(), key, domain=b""), pub)
    assert exc.value.reason == "authorization_signature_invalid"


def test_a_signature_from_another_key_is_refused():
    key, other = SigningKey.generate(), SigningKey.generate()
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    with pytest.raises(Refused) as exc:
        verify_authorization_signature(_signed(_payload(), other), pub)
    assert exc.value.reason == "authorization_signature_invalid"


def test_a_tampered_payload_is_refused():
    key = SigningKey.generate()
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    signed = _signed(_payload(), key)
    signed["payload"]["tool_name"] = "delete_everything"
    with pytest.raises(Refused):
        verify_authorization_signature(signed, pub)


def test_a_wrong_schema_is_refused():
    key = SigningKey.generate()
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    with pytest.raises(Refused) as exc:
        verify_authorization_signature(_signed(_payload(schema="other.v1"), key), pub)
    assert exc.value.reason == "authorization_schema_mismatch"


class _NoCore:
    """A Core stand-in for refusals that happen before any Core call. Any call is a test failure."""

    actor = "test"
    system = "test"

    def status(self, *args, **kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("the executor contacted Core before refusing")

    def submit(self, *args, **kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("the executor submitted to Core before refusing")


def _executor(tmp: Path, key: SigningKey, performed: list) -> Executor:
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    tools = tool_registry([ToolSpec("create_file", "repo:write", "write", "repo_id")])

    def performer(tool, args, execution_id):
        performed.append((tool, args))
        return {"success": True, "data": {"ok": True}}

    return Executor(
        core=_NoCore(),
        public_key_b64=pub,
        audience="executor:ref",
        store=_store(tmp / "store.sqlite"),
        tools=tools,
        performer=performer,
    )


ARGS = {"repo_id": "acme/app", "path": "a.md", "content": "x"}


def _authorized(key: SigningKey, **overrides) -> dict:
    digest = args_binding_hash(
        ToolSpec("create_file", "repo:write", "write", "repo_id"), ARGS
    )
    return _signed(_payload(args_binding_hash=digest, **overrides), key)


def test_the_executor_refuses_before_acting_for_each_binding_mismatch():
    key = SigningKey.generate()
    cases = [
        ("tool_not_registered", {}, "unknown_tool", ARGS),
        (
            "authorization_audience_mismatch",
            {"executor_audience": "someone-else"},
            "create_file",
            ARGS,
        ),
        ("authorization_run_mismatch", {"run_id": "other-run"}, "create_file", ARGS),
        ("authorization_tool_mismatch", {"tool_name": "other"}, "create_file", ARGS),
        (
            "authorization_arguments_mismatch",
            {},
            "create_file",
            {**ARGS, "content": "changed"},
        ),
        (
            "authorization_expired",
            {"expires_at_utc": "2000-01-01T00:00:00+00:00"},
            "create_file",
            ARGS,
        ),
    ]
    for expected, overrides, tool, args in cases:
        performed: list = []
        with tempfile.TemporaryDirectory() as tmp:
            executor = _executor(Path(tmp), key, performed)
            outcome = executor.execute(
                run_id="run-1",
                tool=tool,
                arguments=args,
                signed=_authorized(key, **overrides),
            )
        assert not outcome.executed, expected
        assert outcome.reason == expected, (outcome.reason, expected)
        assert performed == [], f"{expected}: the side effect must not run"


def test_a_forged_authorization_is_refused_before_anything_else():
    key, forger = SigningKey.generate(), SigningKey.generate()
    performed: list = []
    with tempfile.TemporaryDirectory() as tmp:
        executor = _executor(Path(tmp), key, performed)
        outcome = executor.execute(
            run_id="run-1",
            tool="create_file",
            arguments=ARGS,
            signed=_authorized(forger),
        )
    assert outcome.reason == "authorization_signature_invalid"
    assert performed == []


def test_the_executor_requires_a_performer():
    key = SigningKey.generate()
    pub = base64.b64encode(bytes(key.verify_key)).decode("ascii")
    with (
        tempfile.TemporaryDirectory() as tmp,
        pytest.raises(TypeError, match="performer"),
    ):
        Executor(
            core=_NoCore(),
            public_key_b64=pub,
            audience="executor:ref",
            store=_store(Path(tmp) / "s.sqlite"),
            tools={},
            performer=None,
        )


def test_a_reservation_is_single_use_under_concurrent_attempts():
    with tempfile.TemporaryDirectory() as tmp:
        store = _store(Path(tmp) / "s.sqlite")
        wins: list[bool] = []
        lock = threading.Lock()

        def attempt():
            ok = store.reserve(
                authorization_id="auth_race",
                run_id="r",
                tool="create_file",
                digest="d",
                signed_json="{}",
                now=datetime.now(UTC).isoformat(),
            )
            with lock:
                wins.append(ok)

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert wins.count(True) == 1
        assert store.row("auth_race")["state"] == "reserved"


def test_provisioning_gives_each_principal_its_own_key_and_role():
    doc = build_policy_document(
        policy_id="p",
        issuer_id="i",
        issuer_display_name="I",
        created_at_utc="2026-01-01T00:00:00Z",
        read_tools=[],
        write_tools=["create_file"],
        approvers=["a@example.test"],
    )
    with tempfile.TemporaryDirectory() as tmp:
        built = provision(
            Path(tmp),
            tenant="t",
            approvers={"a": "a@example.test"},
            agent_identity="agent:one",
            executor_identity="executor:one",
            policy_document=doc,
            policy_issuer_id="i",
            policy_signer="s",
            policy_created_at_utc="2026-01-01T00:00:00Z",
            policy_expires_at_utc="2999-01-01T00:00:00Z",
        )
        assert "GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX" in built["env"]
        assert "GOVAI_EXECUTION_AUTH_SIGNING_SEED_HEX" not in json.dumps(built["state"])
    keys = built["state"]["keys"]
    assert len(set(keys.values())) == len(keys)
    principals = json.loads(built["env"]["GOVAI_PRINCIPALS_JSON"])
    assert sorted(p["role"] for p in principals.values()) == [
        "agent",
        "approver",
        "executor",
    ]


def test_provisioning_refuses_shared_identities_and_bad_ttl():
    doc = {"schema": "govai.policy.v1"}
    with tempfile.TemporaryDirectory() as tmp:
        base = {
            "tenant": "t",
            "approvers": {"a": "a@example.test"},
            "policy_document": doc,
            "policy_issuer_id": "i",
            "policy_signer": "s",
            "policy_created_at_utc": "2026-01-01T00:00:00Z",
            "policy_expires_at_utc": "2999-01-01T00:00:00Z",
        }
        with pytest.raises(ValueError, match="different"):
            provision(
                Path(tmp) / "x", agent_identity="same", executor_identity="same", **base
            )
        with pytest.raises(ValueError, match="different"):
            provision(
                Path(tmp) / "y",
                agent_identity="a@example.test",
                executor_identity="executor:one",
                **base,
            )
        with pytest.raises(ValueError, match="auth_ttl"):
            provision(
                Path(tmp) / "z",
                agent_identity="agent:one",
                executor_identity="executor:one",
                auth_ttl_seconds=0,
                **base,
            )


def test_a_state_directory_without_the_marker_is_never_removed():
    with tempfile.TemporaryDirectory() as tmp:
        foreign = Path(tmp) / "not-ours"
        foreign.mkdir()
        (foreign / "precious.txt").write_text("keep me")
        with pytest.raises(RuntimeError, match="not created by AIGov"):
            prepare_state_dir(foreign)
        assert (foreign / "precious.txt").read_text() == "keep me"
        assert (foreign / "precious.txt").exists()


def test_the_public_package_does_not_import_examples():
    code = (
        "import sys\n"
        "import aigov_py.trusted\n"
        "bad = [m for m in sys.modules if m.startswith(('aigov_agent_reference', 'sandboxed_tools', "
        "'tool_gateway', 'execution_token', 'examples'))]\n"
        "print('BAD' if bad else 'CLEAN', bad)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tempfile.gettempdir(),
        capture_output=True,
        text=True,
        check=True,
        env={"PYTHONPATH": str(REPO_ROOT / "python")},
    )
    assert out.stdout.strip().startswith("CLEAN"), out.stdout + out.stderr
