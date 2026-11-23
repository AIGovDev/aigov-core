"""Regression: signing keys reach the CLI from a protected file, not only from the command line.

The seed below is a fixed TEST-ONLY value. It signs nothing outside these tests.
"""

import base64
import json
import os
import stat

import pytest
from nacl.signing import SigningKey, VerifyKey

from aigov_py.cli import main
from aigov_py.policy_bundle_signing import policy_payload_digest_sha256_hex

TEST_SEED = bytes(range(32))
TEST_SEED_B64 = base64.b64encode(TEST_SEED).decode("ascii")
ISSUER = "test-issuer"


def _policy(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"schema": "govai.policy.v1", "issuer": {"issuer_id": ISSUER}}), encoding="utf-8")
    return p


def _argv(tmp_path, *key_args):
    return [
        "policy", "sign-bundle",
        "--in", str(_policy(tmp_path)),
        "--out", str(tmp_path / "signed.json"),
        "--issuer-id", ISSUER,
        "--signer", "ci-test",
        "--created-at-utc", "2026-11-23T00:00:00Z",
        *key_args,
    ]


def _key_file(tmp_path, mode=0o600, content=TEST_SEED_B64):
    f = tmp_path / "signing.key"
    f.write_text(content + "\n", encoding="utf-8")
    os.chmod(f, mode)
    return f


def test_key_file_with_owner_only_mode_signs_and_verifies(tmp_path):
    rc = main(_argv(tmp_path, "--private-key-file", str(_key_file(tmp_path))))
    assert rc == 0
    doc = json.loads((tmp_path / "signed.json").read_text(encoding="utf-8"))
    rec = doc["signatures"][0]
    digest = policy_payload_digest_sha256_hex({"schema": "govai.policy.v1", "issuer": {"issuer_id": ISSUER}})
    assert rec["payload_digest_sha256"] == digest
    VerifyKey(SigningKey(TEST_SEED).verify_key.encode()).verify(
        digest.encode("utf-8"), base64.b64decode(rec["signature"]["value"])
    )


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_key_file_readable_by_group_or_others_is_refused(tmp_path, mode):
    key = _key_file(tmp_path, mode=mode)
    assert stat.S_IMODE(os.stat(key).st_mode) == mode
    rc = main(_argv(tmp_path, "--private-key-file", str(key)))
    assert rc != 0
    assert not (tmp_path / "signed.json").exists()


def test_missing_key_file_is_refused(tmp_path):
    rc = main(_argv(tmp_path, "--private-key-file", str(tmp_path / "absent.key")))
    assert rc != 0
    assert not (tmp_path / "signed.json").exists()


def test_empty_key_file_is_refused(tmp_path):
    rc = main(_argv(tmp_path, "--private-key-file", str(_key_file(tmp_path, content="  "))))
    assert rc != 0


def test_both_key_sources_are_refused(tmp_path):
    rc = main(_argv(tmp_path, "--private-key-file", str(_key_file(tmp_path)), "--private-key-base64", TEST_SEED_B64))
    assert rc != 0
    assert not (tmp_path / "signed.json").exists()


def test_no_key_source_is_refused(tmp_path):
    rc = main(_argv(tmp_path))
    assert rc != 0
    assert not (tmp_path / "signed.json").exists()


def test_legacy_command_line_key_still_works_with_warning(tmp_path, capsys):
    rc = main(_argv(tmp_path, "--private-key-base64", TEST_SEED_B64))
    assert rc == 0
    assert (tmp_path / "signed.json").exists()
    assert "exposes the signing key" in capsys.readouterr().err
