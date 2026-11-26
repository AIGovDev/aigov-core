"""Sigstore/DSSE verification must fail closed on malformed input and missing identity.

Offline by design: these cases are rejected before any trust-root fetch. They do NOT prove that a
real Sigstore bundle verifies. That needs a live bundle and identity (see test_sigstore_verify_api_smoke).
"""

import pytest

from aigov_py.cli import main
from aigov_py.sigstore_verify import SigstoreIdentity, verify_dsse_bundle


def test_malformed_bundle_is_rejected_before_any_trust_decision():
    # Fail-closed: any exception type is acceptable, but nothing may be returned as verified.
    with pytest.raises(Exception):  # noqa: B017
        verify_dsse_bundle(
            bundle_json_bytes=b"{not a sigstore bundle",
            identity=SigstoreIdentity(identity="ci@example.invalid", issuer="https://issuer.invalid"),
        )


def test_empty_bundle_object_is_rejected():
    # Fail-closed: any exception type is acceptable, but nothing may be returned as verified.
    with pytest.raises(Exception):  # noqa: B017
        verify_dsse_bundle(
            bundle_json_bytes=b"{}",
            identity=SigstoreIdentity(identity="ci@example.invalid", issuer="https://issuer.invalid"),
        )


def test_cli_verify_evidence_pack_fails_on_garbage_bundle(tmp_path, capsys):
    bundle = tmp_path / "bundle.json"
    bundle.write_text("garbage", encoding="utf-8")
    rc = main([
        "crypto", "verify-evidence-pack",
        "--run-id", "run-1",
        "--attestation-bundle", str(bundle),
        "--identity", "ci@example.invalid",
        "--issuer", "https://issuer.invalid",
        "--expected-events-content-sha256", "a" * 64,
    ])
    assert rc != 0
    assert "ok" not in capsys.readouterr().out.split()


def test_cli_verify_evidence_pack_requires_identity_and_issuer(tmp_path):
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}", encoding="utf-8")
    rc = main([
        "crypto", "verify-evidence-pack",
        "--run-id", "run-1",
        "--attestation-bundle", str(bundle),
        "--identity", "",
        "--issuer", "",
        "--expected-events-content-sha256", "a" * 64,
    ])
    assert rc != 0
