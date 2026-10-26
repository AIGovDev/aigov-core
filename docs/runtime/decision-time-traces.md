# Decision-time reasoning and hosted-model invocation evidence

AIGov records what the application actually observed and relied on at decision time.
It does not promise that a hosted model can reproduce the same generation later: a
provider may route the same model label to changed weights, hardware, safety layers,
or other backend behavior. Requested and reported identities, API version, provider
request ID, backend fingerprint/revision, parameters, seed, and determinism guarantee
are recorded when available. Unavailable values must be represented as `unknown`;
never infer a provider's hidden backend state.

Optionally pin decision context without retaining extra prompt text: prompt-template
version and SHA-256, tool-schema names/versions/digests, retrieval snapshot event or
artifact references, policy version, application revision, and runtime version. These
pins help explain changes around a call; they do not reveal hidden provider state or
guarantee regeneration. Referenced retrieval events must already be in the ledger.

## Event types

Submit these through the existing `POST /evidence` endpoint:

- `model_invocation_recorded` (`aigov.model_invocation.v1`) captures each invocation,
  request/response capture profile, generation parameters, and provider metadata.
- `decision_reasoning_recorded` (`aigov.decision_reasoning.v1`) ties a concise
  rationale to `run_id`, `decision_id`, and `step_id`, with source attribution,
  evidence/source event IDs, claims, reliance, actions, and human endorsements.
- `decision_trace_links_recorded` (`aigov.decision_trace_links.v1`) appends links
  to resulting actions and human endorsements after those events exist. This keeps
  append-only ordering honest instead of requiring future event IDs in advance.

The events remain ordinary append-only `EvidenceEvent` records. They are included in
the existing audit export and hash-chain verification. They do not alter governance
verdict rules. Offline governance replay reconstructs the recorded governance
decision from the retained ledger; it does not call a model. Any provider re-execution
is a separate diagnostic comparison and must never replace the historical response.

`source` is `runtime`, `model_provided`, or `human`. `rationale_status` is
`available`, `unavailable`, or `unknown`. When inaccessible, omit rationale text and
use unavailable/unknown. A concise explanation or provider-supplied summary is not a
verbatim record of hidden chain-of-thought; the schema labels it `concise_rationale`.

## Capture profiles

| Profile | Ledger event | Artifact store | Reconstruction |
|---|---|---|---|
| `full` | SHA-256 and inline JSON or a reference | Keep original request and response | Possible while artifact and decryption keys remain available |
| `redacted` | SHA-256 of the redacted JSON, `redacted: true`, and inline JSON or a reference | Keep only the redacted copy as configured | Reconstructs only the redacted request/response |
| `digest_only` | SHA-256 only | No artifact reference or content is required | Cannot reconstruct content; proves equality only if candidate bytes are supplied |

Hashes cover canonical UTF-8 JSON (object keys sorted, compact separators) for inline
JSON. For externally stored bytes, hash the exact stored byte sequence using the same
SHA-256 algorithm and record the reference. References should be opaque, tenant-scoped
URIs in an operator-controlled artifact store. Core does not fetch, retain, or verify
external objects during ingest. A syntactically valid but broken reference is reported
as unavailable during an external artifact check; `availability` can be `expired`,
`inaccessible`, or `unknown`. Do not describe such evidence as reconstructable.

## Retention and security operations

1. Set a capture profile per workload based on data classification, legal basis,
   purpose, and retention schedule. Prefer redacted/digest-only capture for sensitive
   inputs unless full retention is demonstrably necessary.
2. Redact before evidence submission. Core rejects credential-like payload keys
   (API keys, authorization, tokens, passwords, secrets, credentials, cookies) and
   common bearer/API-key markers in string values; never copy bearer headers, provider
   keys, or secret-bearing endpoint query strings into events. This guard is a
   fail-closed tripwire, not a general purpose secret scanner.
3. Store large/full artifacts outside the ledger with tenant isolation, encryption,
   least-privilege access, access logging, backup, expiry, and legal-hold controls.
   The ledger retains the digest and opaque reference; that reference does not grant
   access by itself.
4. Apply a written retention schedule to both ledger and artifact store. If bytes are
   deleted or access is revoked, append a new evidence event or update an external
   retention register to report the status; never rewrite an old ledger event.
5. Restrict export access: exports can contain captured prompts and outputs. Treat
   full/redacted exports with the same classification as the underlying data.

This is an event contract and reference helper, not an artifact-storage service,
or secret scanner for free text. `invoke_and_record` is a provider-neutral callable
wrapper: the integration supplies the actual call, request serialization, response
serialization, and a metadata extractor. It records only values those callbacks
actually observe. It does not hook arbitrary SDK traffic automatically; callers must
wrap every relevant call and persist/submit the returned event even when provider
metadata is sparse. On success the helper returns the provider response unchanged
alongside the event. On failure it raises `ProviderInvocationError` with the original
exception in `.cause` and a failure invocation event in `.evidence_event`; submit
that event before re-raising or handling the provider error. Only the exception class
is captured, never its message, which can contain sensitive input.

`verify_captured_artifact` checks inline canonical JSON or bytes returned by an
operator-supplied fetcher against the stored digest. It does not access cloud storage
itself. Readiness reports invocation counts, capture profiles, unknown metadata,
backend fingerprint changes under a stable provider/model label, and unavailable
artifacts as advisory trace diagnostics; these observations never alter a governance
verdict. Offline readiness cannot fetch external artifacts. Retention and access
decisions remain the operator's responsibility.
