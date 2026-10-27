"""Builders for provider-neutral decision-time evidence events.

Capture is explicit. Artifact bytes should be stored in an operator-controlled,
access-controlled store; digest-only events prove integrity only, never content.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from aigov_py.runtime.models import EvidenceEvent

_CREDENTIAL_KEYS = ("api_key", "apikey", "authorization", "access_token", "refresh_token", "password", "secret", "credential", "bearer_token", "private_key", "cookie")
_CREDENTIAL_MARKERS = ("bearer ", "sk-", "ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-", "akia", "-----begin private key")
_CREDENTIAL_QUERY_MARKERS = ("?api_key=", "&api_key=", "?api-key=", "&api-key=", "?access_token=", "&access_token=", "?token=", "&token=", "?secret=", "&secret=", "?password=", "&password=", "?key=", "&key=")


def _check_no_credentials(value: Any, path: str = "payload") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(part in normalized for part in _CREDENTIAL_KEYS):
                raise ValueError(f"credential-like field prohibited at {path}.{key}")
            _check_no_credentials(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for i, child in enumerate(value):
            _check_no_credentials(child, f"{path}[{i}]")
    elif isinstance(value, str):
        if any(marker in value.lower() for marker in _CREDENTIAL_MARKERS):
            raise ValueError(f"credential-like value detected at {path}; remove it before evidence capture")
        if any(marker in value.lower() for marker in _CREDENTIAL_QUERY_MARKERS):
            raise ValueError(f"credential-like query parameter detected at {path}; remove it before evidence capture")
        try:
            if urlsplit(value).username is not None or urlsplit(value).password is not None:
                raise ValueError(f"credential-like URI userinfo detected at {path}; remove it before evidence capture")
        except ValueError as exc:
            if "userinfo" in str(exc):
                raise


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def captured_artifact(*, profile: str, content: Any | None = None, artifact_ref: str | None = None, sha256: str | None = None, redacted: bool = False, availability: str = "retained") -> dict[str, Any]:
    """Describe bytes in full/redacted capture or a digest-only commitment.

    For full/redacted capture, either provide the actual JSON content or its
    external artifact reference. In digest_only mode pass content solely to hash
    it; it is intentionally omitted from the returned event.
    """
    if profile not in {"full", "redacted", "digest_only"}:
        raise ValueError("profile must be full, redacted, or digest_only")
    if content is None and not sha256:
        raise ValueError("content or sha256 is required")
    if content is None and profile != "digest_only" and not artifact_ref:
        raise ValueError("full/redacted capture needs content or an artifact_ref")
    if content is not None:
        _check_no_credentials(content)
        digest = hashlib.sha256(_canonical(content)).hexdigest()
    else:
        digest = str(sha256 or "").lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("sha256 must be 64 hexadecimal characters")
    out: dict[str, Any] = {"sha256": digest, "availability": availability}
    if profile == "digest_only":
        if artifact_ref:
            raise ValueError("digest_only must not include an artifact_ref; a digest alone cannot reconstruct content")
    else:
        if content is not None:
            out["content"] = content
        else:
            out["artifact_ref"] = artifact_ref
        if profile == "redacted":
            if not redacted:
                raise ValueError("redacted profile requires redacted=True")
            out["redacted"] = True
    if availability != "retained" and profile != "digest_only":
        if not artifact_ref:
            raise ValueError("expired/inaccessible artifacts must keep an artifact_ref")
        out["artifact_ref"] = artifact_ref
    return out


def model_invocation_event(*, event_id: str, ts_utc: str, actor: str, system: str, run_id: str, invocation_id: str, provider: Mapping[str, Any], capture_profile: str, request: Mapping[str, Any], response: Mapping[str, Any], generation: Mapping[str, Any] | None = None, decision_context: Mapping[str, Any] | None = None) -> EvidenceEvent:
    """Create a valid ``model_invocation_recorded`` event for POST /evidence."""
    payload = {"schema_version": "aigov.model_invocation.v1", "invocation_id": invocation_id, "provider": dict(provider), "generation": dict(generation or {}), "capture": {"profile": capture_profile, "request": dict(request), "response": dict(response)}}
    if decision_context is not None:
        payload["decision_context"] = dict(decision_context)
    _check_no_credentials(payload)
    return EvidenceEvent(event_id, "model_invocation_recorded", ts_utc, actor, system, run_id, payload)


class ProviderInvocationError(RuntimeError):
    """Provider call failure carrying the trace event that must still be submitted."""
    def __init__(self, cause: Exception, evidence_event: EvidenceEvent):
        super().__init__(f"provider invocation failed ({type(cause).__name__}); evidence_event={evidence_event.event_id}")
        self.cause = cause
        self.evidence_event = evidence_event


def decision_reasoning_event(*, event_id: str, ts_utc: str, actor: str, system: str, run_id: str, decision_id: str, step_id: str, reasoning_type: str, source: str, rationale: str | None, evidence_refs: list[Mapping[str, Any]], source_event_ids: list[str], claims: list[Mapping[str, Any]], reliance: list[Mapping[str, Any]], action_event_ids: list[str] | None = None, human_endorsement_event_ids: list[str] | None = None) -> EvidenceEvent:
    """Record a concise rationale, never a claim to hidden chain-of-thought."""
    payload = {"schema_version": "aigov.decision_reasoning.v1", "run_id": run_id, "decision_id": decision_id, "step_id": step_id, "reasoning_type": reasoning_type, "source": source, "rationale_status": "available" if rationale else "unknown", "rationale": rationale or "", "representation": "concise_rationale", "evidence_refs": list(evidence_refs), "source_event_ids": list(source_event_ids), "claims": list(claims), "reliance": list(reliance), "action_event_ids": list(action_event_ids or []), "human_endorsement_event_ids": list(human_endorsement_event_ids or [])}
    _check_no_credentials(payload)
    return EvidenceEvent(event_id, "decision_reasoning_recorded", ts_utc, actor, system, run_id, payload)


def decision_trace_links_event(*, event_id: str, ts_utc: str, actor: str, system: str, run_id: str, decision_id: str, reasoning_event_id: str, action_event_ids: list[str] | None = None, human_endorsement_event_ids: list[str] | None = None) -> EvidenceEvent:
    """Append links after their action/endorsement events exist in the ledger."""
    payload = {"schema_version": "aigov.decision_trace_links.v1", "run_id": run_id,
               "decision_id": decision_id, "reasoning_event_id": reasoning_event_id,
               "action_event_ids": list(action_event_ids or []),
               "human_endorsement_event_ids": list(human_endorsement_event_ids or [])}
    return EvidenceEvent(event_id, "decision_trace_links_recorded", ts_utc, actor, system, run_id, payload)


def verify_captured_artifact(artifact: Mapping[str, Any], *, fetcher: Callable[[str], bytes] | None = None) -> dict[str, Any]:
    """Verify inline canonical JSON or fetched artifact bytes; never treats a hash as content."""
    expected = str(artifact.get("sha256", "")).lower()
    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        return {"status": "invalid_digest", "content_available": False}
    if "content" in artifact:
        actual = hashlib.sha256(_canonical(artifact["content"])).hexdigest()
        return {"status": "verified" if actual == expected else "tampered", "content_available": True}
    ref = artifact.get("artifact_ref")
    if not ref or fetcher is None:
        return {"status": str(artifact.get("availability", "unknown")), "content_available": False,
                "detail": "artifact bytes were not resolved; a digest alone cannot reconstruct content"}
    try:
        data = fetcher(str(ref))
    except Exception as exc:
        return {"status": "unavailable", "content_available": False, "detail": type(exc).__name__}
    actual = hashlib.sha256(data).hexdigest()
    return {"status": "verified" if actual == expected else "tampered", "content_available": actual == expected}


def invoke_and_record(*, call: Callable[[Any], Any], request: Any, response_to_json: Callable[[Any], Any],
                      provider_observation: Callable[[Any], Mapping[str, Any]], capture_profile: str,
                      event_context: Mapping[str, str], invocation_id: str,
                      generation: Mapping[str, Any] | None = None,
                      decision_context: Mapping[str, Any] | None = None,
                      redact: Callable[[Any], Any] | None = None,
                      artifact_writer: Callable[[str, bytes], str] | None = None) -> tuple[Any, EvidenceEvent]:
    """Invoke a provider callable and return its real response plus an evidence event.

    The caller owns the provider SDK adapter: ``request`` is the JSON-safe request
    actually passed to it, ``response_to_json`` extracts the observed response, and
    ``provider_observation`` extracts only metadata actually exposed by the provider.
    Secrets must be removed before the call representation reaches this helper.
    """
    if capture_profile not in {"full", "redacted", "digest_only"}:
        raise ValueError("capture_profile must be full, redacted, or digest_only")
    if capture_profile == "redacted" and redact is None:
        raise ValueError("redacted profile requires a redaction callback")
    observed_request = redact(request) if redact else request
    # Digest-only computes commitments from observed values but omits them from the event.
    def capture(direction: str, content: Any) -> dict[str, Any]:
        if artifact_writer and capture_profile in {"full", "redacted"}:
            data = _canonical(content)
            ref = artifact_writer(direction, data)
            return captured_artifact(profile=capture_profile, sha256=hashlib.sha256(data).hexdigest(),
                                     artifact_ref=ref, redacted=capture_profile == "redacted")
        return captured_artifact(profile=capture_profile, content=content,
                                 redacted=capture_profile == "redacted")

    request_capture = capture("request", observed_request)
    try:
        response = call(request)
    except Exception as exc:
        try:
            provider = dict(provider_observation(None))
        except Exception:
            provider = {"name": "unknown", "endpoint": "unknown", "requested_model": "unknown",
                        "reported_model": "unknown", "api_version": "unknown", "backend_fingerprint": "unknown",
                        "provider_request_id": "unknown", "determinism": {"status": "unknown", "source": "unknown"}}
        failed_response = {"invocation_outcome": "failed", "error_type": type(exc).__name__}
        response_capture = capture("response", redact(failed_response) if redact else failed_response)
        event = model_invocation_event(**dict(event_context), invocation_id=invocation_id,
                                       provider=provider, capture_profile=capture_profile,
                                       request=request_capture, response=response_capture, generation=generation,
                                       decision_context=decision_context)
        event.payload["outcome"] = "failed"
        raise ProviderInvocationError(exc, event) from exc
    observed_response = response_to_json(response)
    if redact:
        observed_response = redact(observed_response)
    response_capture = capture("response", observed_response)
    event = model_invocation_event(**dict(event_context), invocation_id=invocation_id,
                                   provider=provider_observation(response), capture_profile=capture_profile,
                                   request=request_capture, response=response_capture, generation=generation,
                                   decision_context=decision_context)
    event.payload["outcome"] = "succeeded"
    return response, event


__all__ = ["captured_artifact", "model_invocation_event", "decision_reasoning_event",
           "decision_trace_links_event", "verify_captured_artifact", "invoke_and_record",
           "ProviderInvocationError"]
