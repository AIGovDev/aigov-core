# Python runtime SDK

The package **`aigov_py.runtime`** exposes a small, typed surface for:

- **`POST /evidence`** via [`RuntimeGovernanceClient.submit_evidence`](../../python/aigov_py/runtime/client.py)
- **`GET /compliance-summary`** via [`RuntimeGovernanceClient.get_compliance_summary`](../../python/aigov_py/runtime/client.py)
- Provider-neutral evidence builders and helpers: `invoke_and_record`,
  `model_invocation_event`, `decision_reasoning_event`,
  `decision_trace_links_event`, `captured_artifact`, and `verify_captured_artifact`.

For the event fields, capture profiles, reference handling, and limits, see
[Decision-time traces](decision-time-traces.md). These helpers do not intercept
provider traffic automatically. `invoke_and_record` wraps the actual callable and
returns its real response plus a trace event; the integration supplies serializers
and a metadata extractor. Optional `decision_context` pins prompt/tool versions,
retrieval references, policy, application revision, and runtime version. Artifact
bytes can be sent to an operator-owned store via
an `artifact_writer` callback and checked later through `verify_captured_artifact`.
Use `decision_trace_links_event` after action and endorsement events are appended.
If the provider call fails, `ProviderInvocationError.evidence_event` carries a
failure invocation record for submission; its error message is intentionally omitted.

## Design principles

1. **No extra runtime dependencies** — HTTP uses **`urllib`** only (separate from the `requests`-based `GovaiClient` under `aigov_py.client`).
2. **Deterministic request bodies** — evidence JSON is serialized with sorted keys via [`canonical_bytes`](../../python/aigov_py/canonical_json.py).
3. **Explicit timeouts** — every call accepts optional `timeout_sec`; the client default is **`30.0`** seconds and must be **positive**.
4. **Transport vs domain** — [`JsonHttpTransport`](../../python/aigov_py/runtime/client.py) returns raw JSON objects; [`EvidenceEvent`](../../python/aigov_py/runtime/models.py) / [`ComplianceSummary`](../../python/aigov_py/runtime/models.py) model the contract.

## Quick usage

```python
from aigov_py.runtime import EvidenceEvent, RuntimeGovernanceClient

client = RuntimeGovernanceClient(
    "https://audit.example.com",
    api_key="…",
    project="my-service",
    timeout_sec=15.0,
)

event = EvidenceEvent(
    event_id="e1",
    event_type="model_trained",
    ts_utc="2026-05-12T10:00:00Z",
    actor="pipeline",
    system="training",
    run_id="00000000-0000-0000-0000-000000000001",
    payload={"note": "example"},
)
ingest = client.submit_evidence(event)
summary = client.get_compliance_summary(event.run_id)
```

## Compliance summary semantics

[`ComplianceSummary`](../../python/aigov_py/runtime/models.py) mirrors the JSON body. It **does not** re-score or reinterpret verdicts; consumers must continue to treat the hosted response as authoritative (see [overview](overview.md)).

## Validation

From the repository root:

```bash
make runtime-sdk-check
```
