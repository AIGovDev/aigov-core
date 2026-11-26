"""Operator CLI tests: the full lifecycle through the command interface, refusal of forged and unauthorized requests, and
secret handling. Each test runs in its own temporary directory.
"""

from __future__ import annotations

import io
import json
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from aigov_py.trusted import key_admin as A


@pytest.fixture
def work():
    with tempfile.TemporaryDirectory(prefix="key-admin-cli-") as d:
        yield Path(d)


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = A.main(argv)
    return code, out.getvalue(), err.getvalue()


def _json(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_full_lifecycle_through_the_operator_tool(work):
    reg = str(work / "registry.json")
    admin_seed = str(work / "admin.seed")
    code, out, _ = _run(["--registry", reg, "new-operator-key", admin_seed])
    assert code == 0
    admin_pub = _json(out)["public_key_b64"]
    code, _, _ = _run(["--registry", reg, "install-operator", "ops-admin", admin_pub, "keyadmin", "revoker"])
    assert code == 0

    key_seed = str(work / "exe-a.seed")
    _, out, _ = _run(["--registry", reg, "new-operator-key", key_seed])
    exe_pub = _json(out)["public_key_b64"]

    _, out, _ = _run(["--registry", reg, "request", "register", admin_seed, "--actor", "ops-admin",
                      "--kid", "exe-a", "--purpose", "execution_authorization", "--public-key-b64", exe_pub])
    req = work / "req-register.json"
    req.write_text(out)
    code, out, err = _run(["--registry", reg, "apply", str(req)])
    assert code == 0, err

    _, out, _ = _run(["--registry", reg, "request", "activate", admin_seed, "--actor", "ops-admin", "--kid", "exe-a"])
    (work / "req-activate.json").write_text(out)
    assert _run(["--registry", reg, "apply", str(work / "req-activate.json")])[0] == 0

    code, out, _ = _run(["--registry", reg, "inspect"])
    state = json.loads(out)
    assert state["keys"]["exe-a"]["status"] == "active"
    assert state["integrity"]["chain_verified"] is True
    assert state["snapshot_matches_log"] is True


def test_a_request_cannot_be_applied_twice(work):
    reg = str(work / "registry.json")
    admin_seed = str(work / "admin.seed")
    _, out, _ = _run(["--registry", reg, "new-operator-key", admin_seed])
    _run(["--registry", reg, "install-operator", "ops-admin", _json(out)["public_key_b64"], "keyadmin"])
    _, out, _ = _run(["--registry", reg, "new-operator-key", str(work / "k.seed")])
    req = work / "req.json"
    _, out, _ = _run(["--registry", reg, "request", "register", admin_seed, "--actor", "ops-admin", "--kid", "k1",
                      "--purpose", "policy_bundle", "--public-key-b64", _json(out)["public_key_b64"]])
    req.write_text(out)
    assert _run(["--registry", reg, "apply", str(req)])[0] == 0
    code, _, err = _run(["--registry", reg, "apply", str(req)])
    assert code == 3
    assert json.loads(err)["error"] in ("version_conflict", "kid_already_registered")


def test_operator_without_the_role_cannot_register(work):
    reg = str(work / "registry.json")
    admin_seed = str(work / "admin.seed")
    _, out, _ = _run(["--registry", reg, "new-operator-key", admin_seed])
    _run(["--registry", reg, "install-operator", "ops-admin", _json(out)["public_key_b64"], "keyadmin"])
    viewer_seed = str(work / "viewer.seed")
    _, out, _ = _run(["--registry", reg, "new-operator-key", viewer_seed])
    viewer_pub = _json(out)["public_key_b64"]
    # The viewer is not installed as an operator, so its request must be refused.
    _, out, _ = _run(["--registry", reg, "request", "register", viewer_seed, "--actor", "viewer", "--kid", "k2",
                      "--purpose", "policy_bundle", "--public-key-b64", viewer_pub])
    (work / "req.json").write_text(out)
    code, _, err = _run(["--registry", reg, "apply", str(work / "req.json")])
    assert code == 3
    assert json.loads(err)["error"] == "operator_not_authorized"


def test_seed_files_are_created_owner_only_and_never_printed(work):
    seed_path = work / "secret.seed"
    code, out, err = _run(["--registry", str(work / "r.json"), "new-operator-key", str(seed_path)])
    assert code == 0
    seed = seed_path.read_text().strip()
    assert seed not in out and seed not in err
    assert seed_path.stat().st_mode & 0o777 == 0o600


def test_new_operator_key_refuses_to_overwrite_an_existing_seed(work):
    seed_path = work / "exists.seed"
    seed_path.write_text("keep-me\n")
    with pytest.raises(FileExistsError):
        _run(["--registry", str(work / "r.json"), "new-operator-key", str(seed_path)])
    assert seed_path.read_text() == "keep-me\n"
