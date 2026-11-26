"""Key registry (format v2) and signer tests: lifecycle, purpose separation, historical verdicts, operator authorization,
anchor checks, and the signers.

Every test runs in its own temporary directory. The registry world is in ``_registry_world``: a trust file, a SQLite anchor,
a root, and operators. The attack tests are in ``test_registry_attacks.py``.
"""

from __future__ import annotations

import base64
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from _registry_world import World
from nacl.signing import SigningKey

from aigov_py.trusted import keys as K
from aigov_py.trusted.signers import ExternalSigner, LocalEd25519Signer, SignerError

_PUB = K.new_signing_seed()[1]


@pytest.fixture
def tmpdir_path():
    with tempfile.TemporaryDirectory(prefix="keyreg-test-") as d:
        yield Path(d)


@pytest.fixture
def world():
    with tempfile.TemporaryDirectory(prefix="keyreg-test-") as d:
        w = World(Path(d))
        w.install_operator("ops-admin")
        yield w


def _sign(seed_b64, purpose, payload: bytes) -> str:
    sk = SigningKey(base64.b64decode(seed_b64))
    return base64.b64encode(sk.sign(K.DOMAINS[purpose] + payload).signature).decode()


def _code(fn) -> str:
    with pytest.raises(K.KeyRegistryError) as exc:
        fn()
    return exc.value.code


# --- lifecycle and purpose separation -----------------------------------------------------------------------------


def test_register_activate_and_only_one_active_key_per_purpose(world):
    world.register_active("exe-a")
    world.register_pending("exe-b")
    assert world.reader().active_for("execution_authorization").kid == "exe-a"
    assert _code(lambda: world.op("ops-admin", "activate", kid="exe-b")) == "second_active_key"


def test_a_kid_cannot_be_reused_even_after_revocation(world):
    world.register_active("exe-a")
    world.revoke("exe-a")
    assert _code(lambda: world.op("ops-admin", "register", kid="exe-a", purpose="execution_authorization",
                                  public_key_b64=_PUB, owner="x")) == "kid_already_registered"


def test_unknown_purpose_and_bad_public_key_are_refused(world):
    assert _code(lambda: world.op("ops-admin", "register", kid="exe-a", purpose="made_up",
                                  public_key_b64=_PUB, owner="x")) == "register_invalid"
    assert _code(lambda: world.op("ops-admin", "register", kid="exe-b", purpose="execution_authorization",
                                  public_key_b64="AAAA", owner="x")) == "register_invalid"


def test_cross_purpose_signature_is_refused(world):
    world.register_active("exe-a")
    reg = world.reader()
    sig = _sign(world.keys["exe-a"][0], "policy_bundle", b"m")  # signed for another purpose
    a = reg.assess(purpose="policy_bundle", kid="exe-a", payload=b"m", signature_b64=sig,
                   signed_at_utc=datetime.now(UTC).isoformat())
    assert a.verdict == "untrusted" and "purpose_mismatch" in a.reasons


def test_signature_by_a_different_key_with_the_same_kid_fails(world):
    world.register_active("exe-a")
    reg = world.reader()
    sig = _sign(K.new_signing_seed()[0], "execution_authorization", b"m")
    a = reg.assess(purpose="execution_authorization", kid="exe-a", payload=b"m", signature_b64=sig,
                   signed_at_utc=datetime.now(UTC).isoformat())
    assert not a.signature_valid and a.verdict == "untrusted"


# --- historical verdicts -------------------------------------------------------------------------------------------------


def test_ordinary_rotation_keeps_historical_evidence_trusted(world):
    world.register_active("exe-a")
    t_active = datetime.now(UTC)
    seed_a = world.keys["exe-a"][0]
    world.rotate("exe-a", "exe-b")
    reg = world.reader()
    sig = _sign(seed_a, "execution_authorization", b"evidence")
    a = reg.assess(purpose="execution_authorization", kid="exe-a", payload=b"evidence", signature_b64=sig,
                   signed_at_utc=t_active.isoformat())
    assert a.verdict == "trusted", a.reasons


def test_retired_key_does_not_vouch_for_a_signature_made_after_retirement(world):
    world.register_active("exe-a")
    seed_a = world.keys["exe-a"][0]
    world.rotate("exe-a", "exe-b")
    later = datetime.now(UTC) + timedelta(seconds=1)
    sig = _sign(seed_a, "execution_authorization", b"late")
    a = world.reader().assess(purpose="execution_authorization", kid="exe-a", payload=b"late", signature_b64=sig,
                              signed_at_utc=later.isoformat(), now=later + timedelta(seconds=1))
    assert a.verdict == "untrusted" and "signed_after_retirement" in a.reasons


def test_signature_before_activation_is_not_trusted(world):
    before = datetime.now(UTC)
    world.register_active("exe-a")
    sig = _sign(world.keys["exe-a"][0], "execution_authorization", b"early")
    a = world.reader().assess(purpose="execution_authorization", kid="exe-a", payload=b"early", signature_b64=sig,
                              signed_at_utc=(before - timedelta(seconds=5)).isoformat())
    assert a.verdict == "untrusted" and "not_yet_active_at_signing" in a.reasons


def test_compromise_makes_pre_compromise_signatures_uncertain_not_trusted(world):
    world.register_active("exe-a")
    t_sign = datetime.now(UTC)
    sig = _sign(world.keys["exe-a"][0], "execution_authorization", b"pre")
    world.revoke("exe-a", compromised_from=(t_sign + timedelta(hours=1)).isoformat())
    a = world.reader().assess(purpose="execution_authorization", kid="exe-a", payload=b"pre", signature_b64=sig,
                              signed_at_utc=t_sign.isoformat())
    assert a.verdict == "uncertain" and not a.accepted()
    assert a.accepted(accept_uncertain=True)


def test_signature_after_compromise_is_untrusted(world):
    world.register_active("exe-a")
    compromised = datetime.now(UTC) - timedelta(minutes=1)
    world.revoke("exe-a", compromised_from=compromised.isoformat())
    sig = _sign(world.keys["exe-a"][0], "execution_authorization", b"post")
    a = world.reader().assess(purpose="execution_authorization", kid="exe-a", payload=b"post", signature_b64=sig,
                              signed_at_utc=datetime.now(UTC).isoformat())
    assert a.verdict == "untrusted" and "signed_after_compromise" in a.reasons


# --- operators and requests ----------------------------------------------------------------------------------------------


def test_operator_without_the_role_is_refused(world):
    world.install_operator("auditor", roles=("reconciler",))
    world.register_active("exe-a")
    assert _code(lambda: world.op("auditor", "revoke", kid="exe-a", reason="x",
                                  compromised_from_utc="2026-11-26T00:00:00+00:00")) == "operator_not_authorized"


def test_forged_operator_request_is_refused(world):
    world.register_active("exe-a")
    other_seed, _ = K.new_signing_seed()
    req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="revoke", actor="ops-admin", expected_version=world.reg.version, kid="exe-a", reason="x",
        compromised_from_utc="2026-11-26T00:00:00+00:00"), other_seed)
    assert _code(lambda: world.reg.apply(req)) == "request_signature_invalid"


def test_replayed_request_is_refused(world):
    world.register_pending("exe-a")
    world.reg.refresh()
    req = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="activate", actor="ops-admin", expected_version=world.reg.version, kid="exe-a"), world.operators["ops-admin"])
    world.reg.apply(req)
    assert _code(lambda: world.reg.apply(req)) == "version_conflict"


def test_stale_version_is_a_conflict_so_racing_changes_do_not_both_apply(world):
    world.register_pending("exe-a")
    world.register_pending("exe-b")
    world.reg.refresh()
    stale = K.KeyRegistry.sign_request(K.KeyRegistry.new_request(
        op="activate", actor="ops-admin", expected_version=world.reg.version, kid="exe-a"), world.operators["ops-admin"])
    world.op("ops-admin", "activate", kid="exe-b")
    assert _code(lambda: world.reg.apply(stale)) == "version_conflict"


def test_revoke_requires_a_reason(world):
    world.register_active("exe-a")
    assert _code(lambda: world.op("ops-admin", "revoke", kid="exe-a", reason="",
                                  compromised_from_utc="2026-11-26T00:00:00+00:00")) == "reason_required"


def test_a_revoked_key_cannot_be_activated_again(world):
    world.register_active("exe-a")
    world.revoke("exe-a")
    assert _code(lambda: world.op("ops-admin", "activate", kid="exe-a")) == "illegal_transition"


# --- the snapshot is a view, never a source of decisions ------------------------------------------------------------------


def test_the_snapshot_file_is_never_read_for_decisions(world):
    world.register_active("exe-a")
    world.registry_path.write_text('{"version": 999, "keys": {}}', encoding="utf-8")
    reg = world.reader()
    assert reg.active_for("execution_authorization").kid == "exe-a"
    assert reg.version == len(world.events())


def test_verify_integrity_reports_the_anchored_head(world):
    world.register_active("exe-a")
    report = world.reader().verify_integrity()
    assert report["anchored"] is True and report["events"] == len(world.events())


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
