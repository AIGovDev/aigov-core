"""Key registry and signer tests: lifecycle, purpose separation, historical verdicts, operator authorization, and tampering.

Every test runs in its own ``tempfile.TemporaryDirectory`` so nothing is shared between tests or sessions.
"""

from __future__ import annotations

import base64
import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from aigov_py.trusted import keys as K
from aigov_py.trusted.signers import ExternalSigner, LocalEd25519Signer, SignerError

_PUB = K.new_signing_seed()[1]


@pytest.fixture
def tmpdir_path():
    with tempfile.TemporaryDirectory(prefix="keyreg-test-") as d:
        yield Path(d)


def _bootstrap(path: Path):
    reg = K.KeyRegistry(path / "registry.json")
    admin_seed, admin_pub = K.new_signing_seed()
    reg.install_operator("ops-admin", admin_pub, ("keyadmin", "revoker"))
    return reg, admin_seed


def _register(reg, admin_seed, kid, purpose, pub, owner="team"):
    req = K.KeyRegistry.new_request(
        op="register", actor="ops-admin", expected_version=reg.version,
        kid=kid, purpose=purpose, public_key_b64=pub, owner=owner,
    )
    return reg.register(K.KeyRegistry.sign_request(req, admin_seed))


def _activate(reg, admin_seed, kid):
    req = K.KeyRegistry.new_request(op="activate", actor="ops-admin", expected_version=reg.version, kid=kid)
    return reg.activate(K.KeyRegistry.sign_request(req, admin_seed))


def _sign(seed_b64, purpose, payload: bytes) -> str:
    sk = SigningKey(base64.b64decode(seed_b64))
    return base64.b64encode(sk.sign(K.DOMAINS[purpose] + payload).signature).decode()


# --- lifecycle and purpose separation -----------------------------------------------------------------------------


def test_register_activate_and_only_one_active_key_per_purpose(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    _, pub1 = K.new_signing_seed()
    _, pub2 = K.new_signing_seed()
    _register(reg, admin, "auth-a", "execution_authorization", pub1)
    _register(reg, admin, "auth-b", "execution_authorization", pub2)
    _activate(reg, admin, "auth-a")
    req = K.KeyRegistry.new_request(op="activate", actor="ops-admin", expected_version=reg.version, kid="auth-b")
    with pytest.raises(K.KeyRegistryError) as exc:
        reg.activate(K.KeyRegistry.sign_request(req, admin))
    assert exc.value.code == "second_active_key"


def test_a_kid_cannot_be_reused(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    _, pub = K.new_signing_seed()
    _register(reg, admin, "auth-a", "execution_authorization", pub)
    req = K.KeyRegistry.new_request(
        op="register", actor="ops-admin", expected_version=reg.version,
        kid="auth-a", purpose="policy_bundle", public_key_b64=pub, owner="x",
    )
    with pytest.raises(K.KeyRegistryError) as exc:
        reg.register(K.KeyRegistry.sign_request(req, admin))
    assert exc.value.code in ("kid_already_registered", "version_conflict")


def test_unknown_purpose_and_bad_public_key_are_refused(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    _, pub = K.new_signing_seed()
    req = K.KeyRegistry.new_request(
        op="register", actor="ops-admin", expected_version=reg.version,
        kid="k-x", purpose="made_up", public_key_b64=pub, owner="x",
    )
    with pytest.raises(K.KeyRegistryError) as exc:
        reg.register(K.KeyRegistry.sign_request(req, admin))
    assert exc.value.code == "purpose_unknown"
    req = K.KeyRegistry.new_request(
        op="register", actor="ops-admin", expected_version=reg.version,
        kid="k-y", purpose="policy_bundle", public_key_b64=base64.b64encode(b"short").decode(), owner="x",
    )
    with pytest.raises(K.KeyRegistryError) as exc:
        reg.register(K.KeyRegistry.sign_request(req, admin))
    assert exc.value.code == "public_key_invalid"


def test_cross_purpose_signature_is_refused(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    seed, pub = K.new_signing_seed()
    _register(reg, admin, "pol-1", "policy_bundle", pub)
    _activate(reg, admin, "pol-1")
    payload = b"same bytes"
    sig = _sign(seed, "policy_bundle", payload)
    now = datetime.now(UTC).isoformat()
    ok = reg.assess(purpose="policy_bundle", kid="pol-1", payload=payload, signature_b64=sig, signed_at_utc=now)
    assert ok.verdict == "trusted"
    cross = reg.assess(purpose="execution_authorization", kid="pol-1", payload=payload, signature_b64=sig, signed_at_utc=now)
    assert cross.verdict == "untrusted"
    assert "purpose_mismatch" in cross.reasons


def test_signature_by_a_different_key_with_the_same_kid_fails(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    _, pub = K.new_signing_seed()
    forger_seed, _ = K.new_signing_seed()
    _register(reg, admin, "exe-1", "execution_authorization", pub)
    _activate(reg, admin, "exe-1")
    sig = _sign(forger_seed, "execution_authorization", b"x")
    a = reg.assess(purpose="execution_authorization", kid="exe-1", payload=b"x", signature_b64=sig,
                   signed_at_utc=datetime.now(UTC).isoformat())
    assert not a.signature_valid
    assert a.verdict == "untrusted"


# --- rotation and historical evidence ---------------------------------------------------------------------------------


def test_ordinary_rotation_keeps_historical_evidence_trusted(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    seed_a, pub_a = K.new_signing_seed()
    _, pub_b = K.new_signing_seed()
    _register(reg, admin, "exe-a", "execution_authorization", pub_a)
    _activate(reg, admin, "exe-a")
    payload = b"authorization-1"
    sig = _sign(seed_a, "execution_authorization", payload)
    signed_at = datetime.now(UTC).isoformat()
    _register(reg, admin, "exe-b", "execution_authorization", pub_b)
    req = K.KeyRegistry.new_request(
        op="rotate", actor="ops-admin", expected_version=reg.version,
        kid="exe-a", purpose="execution_authorization", successor_kid="exe-b",
    )
    reg.rotate(K.KeyRegistry.sign_request(req, admin))
    a = reg.assess(purpose="execution_authorization", kid="exe-a", payload=payload, signature_b64=sig,
                   signed_at_utc=signed_at)
    assert a.verdict == "trusted"
    assert a.current_status == "retired"
    assert a.accepted()


def test_retired_key_does_not_vouch_for_a_signature_made_after_retirement(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    seed_a, pub_a = K.new_signing_seed()
    _, pub_b = K.new_signing_seed()
    _register(reg, admin, "exe-a", "execution_authorization", pub_a)
    _activate(reg, admin, "exe-a")
    _register(reg, admin, "exe-b", "execution_authorization", pub_b)
    req = K.KeyRegistry.new_request(
        op="rotate", actor="ops-admin", expected_version=reg.version,
        kid="exe-a", purpose="execution_authorization", successor_kid="exe-b",
    )
    reg.rotate(K.KeyRegistry.sign_request(req, admin))
    later = (datetime.now(UTC) + timedelta(minutes=30)).isoformat()
    sig = _sign(seed_a, "execution_authorization", b"late")
    a = reg.assess(purpose="execution_authorization", kid="exe-a", payload=b"late", signature_b64=sig,
                   signed_at_utc=later)
    assert a.verdict == "untrusted"
    assert "signed_after_retirement" in a.reasons


def test_signature_before_activation_is_not_trusted(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    seed, pub = K.new_signing_seed()
    _register(reg, admin, "exe-a", "execution_authorization", pub)
    before = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    _activate(reg, admin, "exe-a")
    sig = _sign(seed, "execution_authorization", b"p")
    a = reg.assess(purpose="execution_authorization", kid="exe-a", payload=b"p", signature_b64=sig, signed_at_utc=before)
    assert a.verdict == "untrusted"
    assert "not_yet_active_at_signing" in a.reasons


def test_compromise_makes_pre_compromise_signatures_uncertain_not_trusted(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    seed, pub = K.new_signing_seed()
    _register(reg, admin, "pol-1", "policy_bundle", pub)
    _activate(reg, admin, "pol-1")
    t0 = datetime.now(UTC)
    sig = _sign(seed, "policy_bundle", b"bundle")
    req = K.KeyRegistry.new_request(
        op="revoke", actor="ops-admin", expected_version=reg.version, kid="pol-1",
        reason="key material exposed", compromised_from_utc=(t0 + timedelta(minutes=10)).isoformat(),
    )
    reg.revoke(K.KeyRegistry.sign_request(req, admin))
    a = reg.assess(purpose="policy_bundle", kid="pol-1", payload=b"bundle", signature_b64=sig,
                   signed_at_utc=(t0 + timedelta(seconds=1)).isoformat())
    assert a.verdict == "uncertain"
    assert a.compromise_uncertainty
    assert not a.accepted()
    assert a.accepted(accept_uncertain=True)


def test_signature_after_compromise_is_untrusted(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    seed, pub = K.new_signing_seed()
    _register(reg, admin, "pol-1", "policy_bundle", pub)
    _activate(reg, admin, "pol-1")
    t0 = datetime.now(UTC)
    req = K.KeyRegistry.new_request(
        op="revoke", actor="ops-admin", expected_version=reg.version, kid="pol-1",
        reason="exposed", compromised_from_utc=(t0 - timedelta(minutes=1)).isoformat(),
    )
    reg.revoke(K.KeyRegistry.sign_request(req, admin))
    sig = _sign(seed, "policy_bundle", b"b")
    a = reg.assess(purpose="policy_bundle", kid="pol-1", payload=b"b", signature_b64=sig,
                   signed_at_utc=t0.isoformat())
    assert a.verdict == "untrusted"
    assert "signed_after_compromise" in a.reasons


# --- operator authorization and replay ------------------------------------------------------------------------------


def test_operator_without_the_role_is_refused(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    viewer_seed, viewer_pub = K.new_signing_seed()
    reg.state.operators["viewer"] = {"public_key_b64": viewer_pub, "roles": []}
    _, pub = K.new_signing_seed()
    req = K.KeyRegistry.new_request(
        op="register", actor="viewer", expected_version=reg.version,
        kid="k-v", purpose="policy_bundle", public_key_b64=pub, owner="x",
    )
    with pytest.raises(K.KeyRegistryError) as exc:
        reg.register(K.KeyRegistry.sign_request(req, viewer_seed))
    assert exc.value.code == "operator_not_authorized"


def test_forged_operator_request_is_refused(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    impostor_seed, _ = K.new_signing_seed()
    _, pub = K.new_signing_seed()
    req = K.KeyRegistry.new_request(
        op="register", actor="ops-admin", expected_version=reg.version,
        kid="k-f", purpose="policy_bundle", public_key_b64=pub, owner="x",
    )
    with pytest.raises(K.KeyRegistryError) as exc:
        reg.register(K.KeyRegistry.sign_request(req, impostor_seed))
    assert exc.value.code == "request_signature_invalid"


def test_replayed_request_is_refused(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    _, pub = K.new_signing_seed()
    req = K.KeyRegistry.new_request(
        op="register", actor="ops-admin", expected_version=reg.version,
        kid="k-r", purpose="policy_bundle", public_key_b64=pub, owner="x",
    )
    signed = K.KeyRegistry.sign_request(req, admin)
    reg.register(signed)
    with pytest.raises(K.KeyRegistryError):
        reg.register(signed)


def test_stale_version_is_a_conflict_so_racing_changes_do_not_both_apply(tmpdir_path):
    reg_a, admin = _bootstrap(tmpdir_path)
    reg_b = K.KeyRegistry(tmpdir_path / "registry.json")
    _, pub1 = K.new_signing_seed()
    _, pub2 = K.new_signing_seed()
    req1 = K.KeyRegistry.new_request(
        op="register", actor="ops-admin", expected_version=reg_a.version,
        kid="k-1", purpose="policy_bundle", public_key_b64=pub1, owner="x",
    )
    req2 = K.KeyRegistry.new_request(
        op="register", actor="ops-admin", expected_version=reg_b.version,
        kid="k-2", purpose="policy_bundle", public_key_b64=pub2, owner="x",
    )
    reg_a.register(K.KeyRegistry.sign_request(req1, admin))
    with pytest.raises(K.KeyRegistryError) as exc:
        reg_b.register(K.KeyRegistry.sign_request(req2, admin))
    assert exc.value.code == "version_conflict"
    fresh = K.KeyRegistry(tmpdir_path / "registry.json")
    assert fresh.get("k-2") is None


def test_revoke_requires_a_reason(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    _, pub = K.new_signing_seed()
    _register(reg, admin, "pol-1", "policy_bundle", pub)
    _activate(reg, admin, "pol-1")
    req = K.KeyRegistry.new_request(op="revoke", actor="ops-admin", expected_version=reg.version, kid="pol-1", reason="")
    with pytest.raises(K.KeyRegistryError) as exc:
        reg.revoke(K.KeyRegistry.sign_request(req, admin))
    assert exc.value.code == "reason_required"


def test_rotation_does_not_reset_the_registry_version(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    _, pub_a = K.new_signing_seed()
    _, pub_b = K.new_signing_seed()
    _register(reg, admin, "exe-a", "execution_authorization", pub_a)
    _activate(reg, admin, "exe-a")
    _register(reg, admin, "exe-b", "execution_authorization", pub_b)
    before = reg.version
    req = K.KeyRegistry.new_request(
        op="rotate", actor="ops-admin", expected_version=before,
        kid="exe-a", purpose="execution_authorization", successor_kid="exe-b",
    )
    reg.rotate(K.KeyRegistry.sign_request(req, admin))
    assert reg.version > before
    assert reg.version == len(reg.events)


# --- integrity ---------------------------------------------------------------------------------------------------


def test_altered_event_is_detected_on_load(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    _, pub = K.new_signing_seed()
    _register(reg, admin, "k-t", "policy_bundle", pub)
    log = tmpdir_path / "registry.json.events.jsonl"
    lines = log.read_text().splitlines()
    ev = json.loads(lines[1])
    ev["detail"]["public_key_b64"] = K.new_signing_seed()[1]
    lines[1] = json.dumps(ev, sort_keys=True)
    log.write_text("\n".join(lines) + "\n")
    with pytest.raises(K.KeyRegistryError) as exc:
        K.KeyRegistry(tmpdir_path / "registry.json")
    assert exc.value.code == "event_altered"


def test_removed_middle_event_breaks_the_chain(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    _, pub = K.new_signing_seed()
    _register(reg, admin, "k-t", "policy_bundle", pub)
    _, pub2 = K.new_signing_seed()
    _register(reg, admin, "k-u", "policy_bundle", pub2)
    log = tmpdir_path / "registry.json.events.jsonl"
    lines = log.read_text().splitlines()
    assert len(lines) == 3
    log.write_text("\n".join([lines[0], lines[2]]) + "\n")
    with pytest.raises(K.KeyRegistryError) as exc:
        K.KeyRegistry(tmpdir_path / "registry.json")
    assert exc.value.code in ("event_sequence_broken", "event_chain_broken")


def test_truncated_tail_is_reported_through_the_snapshot_not_silently_accepted(tmpdir_path):
    # A tail truncation leaves a valid, shorter chain, so the chain alone cannot detect it. The snapshot records the
    # newer version, so the mismatch is reported. Full protection needs an external anchor (see the runbook).
    reg, admin = _bootstrap(tmpdir_path)
    _, pub = K.new_signing_seed()
    _register(reg, admin, "k-t", "policy_bundle", pub)
    log = tmpdir_path / "registry.json.events.jsonl"
    lines = log.read_text().splitlines()
    log.write_text("\n".join(lines[:-1]) + "\n")
    loaded = K.KeyRegistry(tmpdir_path / "registry.json")
    assert loaded.version == 1
    assert loaded.snapshot_matches is False


def test_snapshot_disagreement_is_reported_and_the_log_wins(tmpdir_path):
    reg, admin = _bootstrap(tmpdir_path)
    _, pub = K.new_signing_seed()
    _register(reg, admin, "k-t", "policy_bundle", pub)
    snap = tmpdir_path / "registry.json"
    data = json.loads(snap.read_text())
    data["keys"]["k-t"]["status"] = "active"
    snap.write_text(json.dumps(data))
    loaded = K.KeyRegistry(snap)
    assert loaded.snapshot_matches is False
    assert loaded.get("k-t").status == "pending"


# --- signers -----------------------------------------------------------------------------------------------------


def test_local_signer_signs_under_its_purpose_and_hides_the_seed(tmpdir_path):
    seed, pub = K.new_signing_seed()
    signer = LocalEd25519Signer(seed, key_id="pol-1", purpose="policy_bundle")
    assert seed not in repr(signer)
    assert not hasattr(signer, "seed")
    result = signer.sign(b"m")
    sig = base64.b64decode(result.signature_b64)
    from nacl.signing import VerifyKey

    VerifyKey(base64.b64decode(pub)).verify(K.DOMAINS["policy_bundle"] + b"m", sig)


def test_external_signer_timeout_fails_closed():
    import time

    def slow(kid, purpose, msg):
        time.sleep(2)
        return base64.b64encode(b"\x00" * 64).decode()

    signer = ExternalSigner(slow, key_id="pol-1", purpose="policy_bundle", public_key_b64=_PUB, timeout_seconds=0.2)
    with pytest.raises(SignerError) as exc:
        signer.sign(b"m")
    assert exc.value.code == "signer_timeout"


def test_external_signer_exception_fails_closed_without_leaking_content():
    def boom(kid, purpose, msg):
        raise RuntimeError("secret detail that must not surface")

    signer = ExternalSigner(boom, key_id="pol-1", purpose="policy_bundle", public_key_b64=_PUB)
    with pytest.raises(SignerError) as exc:
        signer.sign(b"m")
    assert exc.value.code == "signer_failed"
    assert "secret detail" not in str(exc.value)


def test_external_signer_rejects_malformed_reply():
    signer = ExternalSigner(lambda k, p, m: "not-a-signature", key_id="pol-1", purpose="policy_bundle", public_key_b64=_PUB)
    with pytest.raises(SignerError) as exc:
        signer.sign(b"m")
    assert exc.value.code == "signer_reply_invalid"


def test_external_signer_refuses_an_unknown_purpose_and_bad_timeouts():
    with pytest.raises(SignerError):
        ExternalSigner(lambda k, p, m: "", key_id="x", purpose="made_up", public_key_b64=_PUB)
    with pytest.raises(SignerError):
        ExternalSigner(lambda k, p, m: "", key_id="x", purpose="policy_bundle", public_key_b64=_PUB, timeout_seconds=0)


def test_external_signer_accepts_a_reply_that_verifies_under_its_key():
    seed, pub = K.new_signing_seed()
    key = SigningKey(base64.b64decode(seed))

    def provider(kid, purpose, msg):
        return base64.b64encode(key.sign(msg).signature).decode()

    signer = ExternalSigner(provider, key_id="pol-1", purpose="policy_bundle", public_key_b64=pub)
    result = signer.sign(b"m")
    assert result.key_id == "pol-1"


def test_external_signer_refuses_a_reply_signed_by_another_key():
    _, pub = K.new_signing_seed()
    other = SigningKey(base64.b64decode(K.new_signing_seed()[0]))

    def provider(kid, purpose, msg):
        return base64.b64encode(other.sign(msg).signature).decode()

    signer = ExternalSigner(provider, key_id="pol-1", purpose="policy_bundle", public_key_b64=pub)
    with pytest.raises(SignerError) as exc:
        signer.sign(b"m")
    assert exc.value.code == "signer_reply_invalid"
