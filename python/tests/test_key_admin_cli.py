"""Operator CLI tests (format v2): the lifecycle through the command interface, refusal of forged and unauthorized requests,
the trust file and the anchor, and secret handling. Each test runs in its own temporary directory with a SQLite anchor;
the PostgreSQL anchor is covered by ``test_registry_postgres.py``.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from _sqlite_anchor import SqliteAnchor

from aigov_py.trusted import key_admin as A
from aigov_py.trusted import keys as K


@pytest.fixture
def work():
    with tempfile.TemporaryDirectory(prefix="key-admin-cli-") as d:
        w = Path(d)
        root_out = w / "root.seed"
        _, out, _ = _run(["--registry", str(w / "x.json"), "--trust", str(w / "none.json"), "new-key", str(root_out)])
        root_pub = _json(out)["public_key_b64"]
        trust = {"schema": K.TRUST_SCHEMA, "registry_id": "cli-registry",
                 "roots": [{"kid": "root-a", "public_key_b64": root_pub, "status": "current"}]}
        (w / "trust.json").write_text(json.dumps(trust))
        os.chmod(w / "trust.json", 0o600)
        w.joinpath("root.kid").write_text("root-a")
        yield w


def _common(w: Path) -> list[str]:
    return ["--registry", str(w / "registry.json"), "--trust", str(w / "trust.json"),
            "--anchor-sqlite", str(w / "anchor.sqlite")]


def _run(argv: list[str]) -> tuple[int, str, str]:
    """Run the tool. ``--anchor-sqlite PATH`` (tests only) injects the SQLite anchor with the same contract."""
    factory = None
    argv = list(argv)
    if "--anchor-sqlite" in argv:
        i = argv.index("--anchor-sqlite")
        path = Path(argv[i + 1])
        del argv[i:i + 2]
        factory = lambda registry_id: SqliteAnchor(path, registry_id)  # noqa: E731
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = A.main(argv, anchor_factory=factory)
    return code, out.getvalue(), err.getvalue()


def _json(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def _init(w: Path) -> tuple[str, str]:
    """Anchor the registry and install ops-admin under the root. Returns (root seed file, operator seed file)."""
    assert _run(_common(w) + ["anchor-init"])[0] == 0
    root_seed = str(w / "root.seed")
    op_seed = str(w / "ops.seed")
    _, out, _ = _run(["--registry", "x", "--trust", "x", "new-key", op_seed])
    op_pub = _json(out)["public_key_b64"]
    _, out, _ = _run(_common(w) + ["request", "operator_install", root_seed, "--actor", "root-a",
                                   "--identity", "ops-admin", "--public-key-b64", op_pub, "--roles", "keyadmin", "revoker"])
    (w / "req-install.json").write_text(out)
    assert _run(_common(w) + ["apply", str(w / "req-install.json")])[0] == 0
    return root_seed, op_seed


def test_full_lifecycle_through_the_operator_tool(work):
    _, op_seed = _init(work)
    _, out, _ = _run(["--registry", "x", "--trust", "x", "new-key", str(work / "exe-a.seed")])
    exe_pub = _json(out)["public_key_b64"]
    for name, argv in [
        ("register", ["request", "register", op_seed, "--actor", "ops-admin", "--kid", "exe-a",
                      "--purpose", "execution_authorization", "--public-key-b64", exe_pub]),
        ("activate", ["request", "activate", op_seed, "--actor", "ops-admin", "--kid", "exe-a"]),
    ]:
        _, out, _ = _run(_common(work) + argv)
        (work / f"req-{name}.json").write_text(out)
        code, _, err = _run(_common(work) + ["apply", str(work / f"req-{name}.json")])
        assert code == 0, err
    code, out, _ = _run(_common(work) + ["inspect"])
    state = json.loads(out)
    assert state["keys"]["exe-a"]["status"] == "active"
    assert state["integrity"]["chain_verified"] is True
    assert state["integrity"]["anchored"] is True


def test_a_request_cannot_be_applied_twice(work):
    _, op_seed = _init(work)
    _, out, _ = _run(["--registry", "x", "--trust", "x", "new-key", str(work / "k.seed")])
    _, out, _ = _run(_common(work) + ["request", "register", op_seed, "--actor", "ops-admin", "--kid", "k1",
                                      "--purpose", "policy_bundle", "--public-key-b64", _json(out)["public_key_b64"]])
    (work / "req.json").write_text(out)
    assert _run(_common(work) + ["apply", str(work / "req.json")])[0] == 0
    code, _, err = _run(_common(work) + ["apply", str(work / "req.json")])
    assert code == 3
    assert json.loads(err)["error"] == "version_conflict"


def test_an_operator_cannot_sign_a_root_operation(work):
    _, op_seed = _init(work)
    _, out, _ = _run(["--registry", "x", "--trust", "x", "new-key", str(work / "evil.seed")])
    evil_pub = _json(out)["public_key_b64"]
    _, out, _ = _run(_common(work) + ["request", "operator_install", op_seed, "--actor", "root-a",
                                      "--identity", "ops-evil", "--public-key-b64", evil_pub, "--roles", "keyadmin"])
    (work / "req.json").write_text(out)
    code, _, err = _run(_common(work) + ["apply", str(work / "req.json")])
    assert code == 3
    assert json.loads(err)["error"] == "request_signature_invalid"


def test_an_operator_without_the_role_cannot_register(work):
    _, op_seed = _init(work)
    _, out, _ = _run(["--registry", "x", "--trust", "x", "new-key", str(work / "viewer.seed")])
    viewer_pub = _json(out)["public_key_b64"]
    _, out, _ = _run(_common(work) + ["request", "register", str(work / "viewer.seed"), "--actor", "viewer", "--kid", "k2",
                                      "--purpose", "policy_bundle", "--public-key-b64", viewer_pub])
    (work / "req.json").write_text(out)
    code, _, err = _run(_common(work) + ["apply", str(work / "req.json")])
    assert code == 3
    assert json.loads(err)["error"] == "operator_not_authorized"


def test_a_trust_file_readable_by_others_is_refused_by_the_tool(work):
    os.chmod(work / "trust.json", 0o644)
    code, _, err = _run(_common(work) + ["inspect"])
    assert code == 3
    assert json.loads(err)["error"] == "trust_config_permissions"


def test_reconcile_with_nothing_pending_is_refused(work):
    _init(work)
    code, _, err = _run(_common(work) + ["reconcile"])
    assert code == 3
    assert json.loads(err)["error"] == "nothing_to_reconcile"


def test_apply_refuses_when_the_anchor_is_not_initialized(work):
    code, _, err = _run(_common(work) + ["inspect"])
    assert code == 3
    assert json.loads(err)["error"] == "anchor_missing"


def test_seed_files_are_created_owner_only_and_never_printed(work):
    seed_path = work / "secret.seed"
    code, out, err = _run(["--registry", "x", "--trust", "x", "new-key", str(seed_path)])
    assert code == 0
    seed = seed_path.read_text().strip()
    assert seed not in out and seed not in err
    assert seed_path.stat().st_mode & 0o777 == 0o600


def test_new_key_refuses_to_overwrite_an_existing_seed(work):
    seed_path = work / "exists.seed"
    seed_path.write_text("keep-me\n")
    with pytest.raises(FileExistsError):
        _run(["--registry", "x", "--trust", "x", "new-key", str(seed_path)])
    assert seed_path.read_text() == "keep-me\n"
