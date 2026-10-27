from __future__ import annotations

import pytest

from aigov_py.runtime import (captured_artifact, decision_reasoning_event, model_invocation_event,
                              decision_trace_links_event, invoke_and_record, verify_captured_artifact,
                              ProviderInvocationError)


def test_capture_profiles_and_digest_only_is_not_reconstruction() -> None:
    content = {"messages": [{"role": "user", "content": "classify"}]}
    full = captured_artifact(profile="full", content=content)
    redacted = captured_artifact(profile="redacted", content={"messages": []}, redacted=True)
    digest = captured_artifact(profile="digest_only", content=content)
    assert "content" in full and "content" not in digest and "artifact_ref" not in digest
    assert len(digest["sha256"]) == 64
    assert captured_artifact(profile="digest_only", sha256=digest["sha256"]) == digest
    assert captured_artifact(profile="digest_only", sha256=digest["sha256"], availability="expired")["availability"] == "expired"
    with pytest.raises(ValueError, match="cannot reconstruct"):
        captured_artifact(profile="digest_only", artifact_ref="s3://bucket/object", sha256=digest["sha256"])
    assert redacted["redacted"] is True


def test_invocation_and_reasoning_helpers_emit_events_and_reject_credentials() -> None:
    artifact = captured_artifact(profile="digest_only", content={"body": "x"})
    event = model_invocation_event(
        event_id="e1", ts_utc="2026-01-01T00:00:00Z", actor="agent", system="test", run_id="r1",
        invocation_id="i1", provider={"name": "unknown", "endpoint": "unknown", "requested_model": "m",
        "reported_model": "unknown", "api_version": "unknown", "determinism": {"status": "unknown"}},
        capture_profile="digest_only", request=artifact, response=artifact,
    )
    assert event.event_type == "model_invocation_recorded"
    assert event.payload["capture"]["profile"] == "digest_only"
    with pytest.raises(ValueError, match="credential-like"):
        captured_artifact(profile="full", content={"api_key": "do-not-store"})
    with pytest.raises(ValueError, match="credential-like"):
        captured_artifact(profile="full", content={"note": "Bearer sk-example"})
    with pytest.raises(ValueError, match="userinfo"):
        captured_artifact(profile="full", content={"endpoint": "https://user:password@provider.test/v1"})
    with pytest.raises(ValueError, match="query parameter"):
        captured_artifact(profile="full", content={"artifact_ref": "s3://bucket/item?token=do-not-store"})

    reasoning = decision_reasoning_event(
        event_id="e2", ts_utc="2026-01-01T00:00:01Z", actor="agent", system="test", run_id="r1",
        decision_id="d1", step_id="s1", reasoning_type="action_selection", source="runtime",
        rationale="Require a human approval gate.", evidence_refs=[], source_event_ids=["e1"], claims=[], reliance=[],
    )
    assert reasoning.event_type == "decision_reasoning_recorded"
    assert reasoning.payload["representation"] == "concise_rationale"


def test_provider_wrapper_and_artifact_resolution_verify_observed_bytes() -> None:
    request = {"input": "classify", "temperature": 0}
    response = {"id": "req-1", "output": "allow"}
    provider = {"name": "hosted", "endpoint": "https://provider.test/api", "requested_model": "m",
                "reported_model": "m-r7", "api_version": "v1", "backend_fingerprint": "r7",
                "provider_request_id": "req-1", "determinism": {"status": "unknown", "source": "unknown"}}
    actual, event = invoke_and_record(
        call=lambda req: response if req == request else None, request=request,
        response_to_json=lambda value: value, provider_observation=lambda _: provider,
        capture_profile="full", invocation_id="i1",
        event_context={"event_id": "e1", "ts_utc": "2026-01-01T00:00:00Z", "actor": "a", "system": "s", "run_id": "r1"},
        decision_context={"prompt_template": {"version": "v1", "sha256": "a" * 64}, "policy_version": "policy-v1", "application_revision": "abc123"},
    )
    assert actual is response
    assert event.payload["capture"]["request"]["content"] == request
    assert event.payload["decision_context"]["application_revision"] == "abc123"
    artifact = event.payload["capture"]["response"]
    assert verify_captured_artifact(artifact)["status"] == "verified"

    raw = b'{"output":"allow"}'
    import hashlib
    external = {"sha256": hashlib.sha256(raw).hexdigest(), "availability": "retained", "artifact_ref": "s3://bucket/item"}
    assert verify_captured_artifact(external, fetcher=lambda _: raw)["status"] == "verified"
    assert verify_captured_artifact(external, fetcher=lambda _: b"tampered")["status"] == "tampered"
    assert verify_captured_artifact(external, fetcher=lambda _: (_ for _ in ()).throw(FileNotFoundError()))["status"] == "unavailable"
    digest_only = captured_artifact(profile="digest_only", content=request)
    assert verify_captured_artifact(digest_only)["content_available"] is False


def test_late_action_and_human_links_are_separate_append_only_event() -> None:
    event = decision_trace_links_event(event_id="links", ts_utc="2026-01-01T00:00:02Z", actor="a", system="s",
        run_id="r1", decision_id="d1", reasoning_event_id="reasoning", action_event_ids=["action"],
        human_endorsement_event_ids=["approval"])
    assert event.event_type == "decision_trace_links_recorded"
    assert event.payload["human_endorsement_event_ids"] == ["approval"]


def test_failed_provider_call_carries_failure_event_without_exception_message() -> None:
    def fail(_):
        raise RuntimeError("sensitive prompt text")
    with pytest.raises(ProviderInvocationError) as caught:
        invoke_and_record(
            call=fail, request={"input": "private"}, response_to_json=lambda value: value,
            provider_observation=lambda _: {"name": "unknown", "endpoint": "unknown", "requested_model": "unknown",
                "reported_model": "unknown", "api_version": "unknown", "backend_fingerprint": "unknown",
                "provider_request_id": "unknown", "determinism": {"status": "unknown", "source": "unknown"}},
            capture_profile="digest_only", invocation_id="failed-1",
            event_context={"event_id": "failed-event", "ts_utc": "2026-01-01T00:00:00Z", "actor": "a", "system": "s", "run_id": "r1"},
        )
    assert caught.value.evidence_event.payload["outcome"] == "failed"
    assert "sensitive prompt text" not in str(caught.value)

