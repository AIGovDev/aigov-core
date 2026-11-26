---
title: Runtime governance roadmap
audience: maintainers, operators, integration partners
scope: evidence-based implementation roadmap
status: prioritized
---

# Runtime governance roadmap

## Repository baseline

This assessment uses `main` at `099e764` and the repository-required feature integration base `staging` at `bbb0efb` (PR #520 merged there). The CI workflow `enforce-branch-policy.yml` requires feature branches to target `staging`; do not open a feature PR directly to `main`.

Evidence in the current tree:

- `rust/src/govai_api.rs`, `rust/src/execution_authorization.rs` and `rust/src/principals.rs` implement evidence-ingest authorization, role checks and signed, expiring execution authorizations.
- `python/aigov_py/trusted/` supplies agent/approver actors, signature verification, Core status checks, a replay-resistant executor, durable receipts, local SQLite and shared PostgreSQL executor stores.
- `rust/src/audit_store.rs` serializes ledger appends with an in-process mutex and host-local `flock`; this is not cross-host ledger coordination. `docs/architecture/distributed-execution.md` documents supported and unsupported topologies.
- `rust/src/policy_store.rs` currently selects a deployment-global policy. Tenant identity and tenant-scoped evidence exist, but tenant-specific policy selection is not implemented.
- `mcp/aigov_mcp_server.py` is a local stdio bridge. Before this branch its file-writing tool called the writer directly; this branch connects that tool to the existing trusted execution protocol. Arbitrary upstream MCP servers remain outside the boundary.
- `python/aigov_py/huggingface_provenance.py` and `python/tests/test_huggingface_provenance.py` capture selected Hub files at immutable commits and verify local bytes against an externally trusted manifest digest. The API is opt-in; it does not authenticate publisher truth or submit evidence to Core automatically.
- CI includes Rust/Python tests, `supply-chain-audit`, release validation and security scans. No bit-for-bit independent rebuild or builder provenance verification is established by those workflows alone.

## Priority summary

| Priority | Capability | Current status | Next implementation slice |
|---|---|---|---|
| P0 | Agent runtime enforcement and tool authorization | Signed Core authorization, human approval binding and trusted executor exist; local MCP adapter added in this branch for one writer | Add supported framework adapters and isolate executor credentials/process from the agent |
| P1 | MCP governance gateway | One local MCP writer now uses trusted Core/Executor path; no general upstream proxy | Inventory and mediate configured upstream MCP tools |
| P1 | Tenant isolation, replay and idempotency | Core principals, tenant ledgers, consumed approvals and executor replay protection exist; policies remain deployment-global | Tenant policy resolution and cross-tenant adversarial contract tests |
| P1 | Multi-host consistency and durable state | PostgreSQL executor store and policy/key anchors exist; Core ledger is host-local | Move authoritative ledger coordination to a supported shared transactional store or constrain Core to one host |
| P1 | Concurrent policy, approvals and key rotation | Approval consumption and key/policy anchor concurrency controls exist | Complete online policy activation lifecycle and end-to-end rotation/approval race verification |
| P2 | Model/dataset provenance | Hugging Face immutable-revision capture exists on staging | Complete manifest and metadata validation, typed evidence submission and authenticated Hub integration tests |
| P2 | External attestation and offline verification | Signed authorizations, offline verification and portable evidence checks exist | Publish a versioned, independently consumable attestation/export profile with trust/revocation bundle guidance |
| P2 | OpenTelemetry GenAI ingestion | No versioned GenAI semantic-convention normalizer | Add versioned OTLP adapter preserving source and normalization provenance |
| P3 | Reproducible builds and supply-chain security | Locked dependencies, CI and scans exist | Pin builders/toolchains and verify independent rebuilds plus signed provenance/SBOM |
| P3 | Enterprise/brand governance integration | Stable API, policy, export and Acme example are reusable foundations; no GentlyAI-specific contract | Agree partner schema, tenant lifecycle, data retention and labeled acceptance set before adapter work |

## Capability details

### P0 — Agent runtime enforcement and authorization

- **Existing / gap:** Core refuses unauthorized evidence events and issues signed execution authorizations. The Python `Executor` checks signature, audience, run, tool, expiry, argument digest, current Core status and durable reservation before calling the performer. This branch wires one MCP report-template writer through `AgentActor` and `Executor`; other agent frameworks and shell paths are not intercepted.
- **Invariants:** No side effect without a verified authorization and successful durable reservation; approval and authorization bind exact tool, run and normalized arguments; errors fail closed; a receipt is separate evidence and does not prove external truth.
- **API / storage:** Reuses `/evidence`, authorization status, receipts and existing executor stores; this branch adds no Core endpoint or policy schema. MCP config requires separate agent/executor keys, pinned public key, audience and pre-migrated executor store.
- **Compatibility:** Existing Core API and policy contracts remain unchanged. Real MCP writes now require trusted-execution configuration and a separately approved call; dry-run remains local.
- **Threats:** Agent/executor credential compromise, forged/mismatched arguments, replay, revocation TOCTOU, local-store tampering, direct shell bypass and filesystem race.
- **Tests / benchmarks:** Mocked MCP denial, malformed config, signature handoff, replay/no-dispatch and binding tests plus existing trusted SDK/Rust adversarial suites. Add real Core MCP E2E and measure authorization/executor overhead at p50/p95/p99.
- **Commercial value:** Brings existing preventive controls to a widely used agent tool protocol and produces reviewable approval/authorization/receipt evidence.
- **Dependencies / risks:** Requires Core trusted-execution principals and signing configuration, an independent approver workflow and a migrated executor store. The current MCP process performs the file write locally; it is not a hardened sandbox.

### P1 — MCP governance gateway

- **Existing / gap:** A local stdio bridge exposes read-only validators and one governed writer. It is not a reverse proxy and cannot enforce policy on arbitrary MCP servers.
- **Invariants:** Inventory tool identity/schema; evaluate before dispatch; preserve exact bound arguments; isolate upstream secrets; denial and timeout never dispatch.
- **API / storage:** Add configured upstream registry, schema digest/version, routing, credential references and decision/receipt linkage. Reuse trusted execution tokens rather than creating another decision endpoint.
- **Compatibility:** Keep stdio as an adapter; proxy mode should be opt-in and preserve MCP protocol/error semantics.
- **Threats:** Malicious descriptions, schema drift, prompt injection, SSRF, credential exfiltration, confused deputy and bypass.
- **Tests / benchmarks:** MCP conformance, malicious fake upstream, cancellation/timeout/no-dispatch tests, schema drift tests, fuzzing, throughput and p95 latency.
- **Commercial value:** Provides a control point for enterprise tool catalogs and vendor/brand-safety policy.
- **Dependencies / risks:** Depends on P0 credential separation and executor isolation; network proxying expands attack surface.

### P1 — Tenant isolation, replay protection and idempotency

- **Existing / gap:** API keys map to principals and tenants; evidence ledgers are tenant-scoped; approvals are consumed under ledger serialization; executor reservations prevent reuse of an authorization. Policy selection still ignores tenant and uses a deployment-global policy.
- **Invariants:** No cross-tenant read/write/authorization; every decision uses the authenticated tenant; repeated event/authorization cannot create another effect; policy selector overlap is rejected as ambiguous.
- **API / storage:** Add tenant-keyed active policy selection and versioned tenant policy state. Preserve unique event IDs and authorization IDs; add explicit request idempotency semantics for external adapters.
- **Compatibility:** Existing global bundle becomes an explicit default scope during migration. No silent policy-selection change.
- **Threats:** Cross-tenant IDOR, stale or reused keys, replayed webhooks, identifier collision and policy bleed.
- **Tests / benchmarks:** Cross-tenant API tests, concurrent duplicate event and approval races, replay across Core instances, tenant deletion/retention, and uniqueness-contention benchmarks.
- **Commercial value:** Required for multi-customer SaaS and brand monitoring providers.
- **Dependencies / risks:** Needs transactional policy state and a migration strategy for existing global deployments.

### P1 — Multi-host consistency and durable state

- **Existing / gap:** Shared PostgreSQL executor store uses row locks, fencing, database leases and append-only history. Policy/key anchors use PostgreSQL locks. Core ledger still relies on host-local `flock`; different-host Core instances cannot safely share its directory.
- **Invariants:** One committed decision per authorization; globally ordered ledger append; no allow if authoritative state is unavailable; no cross-host replay; recovery never repeats an action with unknown outcome.
- **API / storage:** Either move authoritative ledger, duplicate-event checks and approval consumption into a transactional shared backend, or formally limit Core ledger to one host. Add health/readiness reporting for the selected supported topology.
- **Compatibility:** Keep current file-ledger single-host deployment supported; distributed ledger requires migration and explicit topology selection.
- **Threats:** Split brain, stale state, duplicate appends, partial commit, NFS lock failure and rollback.
- **Tests / benchmarks:** Multi-host PostgreSQL integration, process crash injection, partition and recovery tests, concurrent approval/appends, and p95/p99 append latency under load.
- **Commercial value:** Enables highly available and horizontally scaled enterprise deployments.
- **Dependencies / risks:** Major storage and migration decision; current docs explicitly do not claim multi-host ledger safety.

### P1 — Concurrent policy updates, approvals and key rotation

- **Existing / gap:** Signed policy and key registries, anti-rollback anchors, approval consumption locking, and prepare/re-check signing logic exist. Online policy activation, operator UX and combined policy/approval/key lifecycle acceptance remain incomplete.
- **Invariants:** Approval names an immutable policy revision and exact call; one approval authorizes at most one call; rotations/revocations serialize with issuance; trust uncertainty fails closed.
- **API / storage:** Versioned staged/active/revoked policy state with compare-and-swap; key IDs, overlap, expiry and revocation metadata; audit events for activation and rotation.
- **Compatibility:** Continue verifying offline policy bundles; online activation is additive and must not mutate signed content.
- **Threats:** Stale cache, rollback, race bypass, key substitution, premature revocation and compromised signer.
- **Tests / benchmarks:** Competing activations, revoke-vs-issue, approval-vs-call, key rotation between prepare/sign/status, restart recovery and activation latency.
- **Commercial value:** Supports enterprise change control, delegated approvers and managed key lifecycle.
- **Dependencies / risks:** Builds on policy/key anchors; recovery and expiry semantics need an operator runbook.

### P2 — Model and dataset provenance, including Hugging Face

- **Existing / gap:** `huggingface_provenance.py` resolves immutable revisions and hashes explicitly selected model/dataset files; it captures constrained source-reported metadata and verifies local files against an external manifest digest. It does not prove publisher authenticity or automatically bind the manifest into a Core run.
- **Invariants:** Resolve mutable references to a commit; hash downloaded bytes independently; label source metadata as source-reported; credentials never enter evidence or errors; never execute repository code.
- **API / storage:** Add a stable provenance evidence contract and submission helper carrying repo ID/type, commit, file manifest, source metadata, capture time and resolver version. Support private repositories via credential providers.
- **Compatibility:** Additive evidence schema; retain existing manifest format and digest behavior.
- **Threats:** Moved refs, malicious files, path traversal, poisoned cache, private repo disclosure and false source metadata.
- **Tests / benchmarks:** Mocked public/private repositories, revision movement, digest mismatch, invalid paths, credential redaction, offline verification and manifest-size performance. Live Hub compatibility remains a separate integration check.
- **Commercial value:** Binds approved models and datasets to evaluations and procurement decisions.
- **Dependencies / risks:** Hub client version compatibility, licensing and potentially large artifact manifests.

### P2 — External evidence attestation and offline verification

- **Existing / gap:** Hash-linked records, signed execution authorizations, offline SDK verification and portable evidence checks exist. Trust roots and exported evidence still need a portable independent-verifier profile.
- **Invariants:** Verifier works without Core; algorithms and trust roots are explicit; signatures establish integrity/attribution under key assumptions, not factual truth or completeness; unknown/revoked keys fail closed.
- **API / storage:** Define versioned attestation/export envelope binding subject, policy, ledger records, signer/key ID, validity and evidence digests; publish trust/revocation bundle and standalone verifier.
- **Compatibility:** New envelope version; existing exports and hashes remain unchanged.
- **Threats:** Key compromise, stale roots, equivocation, incomplete evidence and overstated attestations.
- **Tests / benchmarks:** Independent cross-language vectors, tamper/truncation/unknown-key cases, offline verification, revocation updates and large-pack throughput.
- **Commercial value:** Lets auditors and customers verify a delivered package without privileged service access.
- **Dependencies / risks:** Key lifecycle and revocation distribution; trusted time is separate from signature validity.

### P2 — OpenTelemetry GenAI evidence ingestion

- **Existing / gap:** Generic evidence ingestion exists; no versioned OpenTelemetry GenAI semantic-convention normalizer is present.
- **Invariants:** Preserve source fields and timestamps; identify mapping version; redact before persistence; ingestion is evidence capture, never preventive enforcement.
- **API / storage:** Add an authenticated OTLP collector/adapter and versioned mapping registry, with source resource attributes and normalization provenance.
- **Compatibility:** Keep `/evidence` stable; version new normalized event types and preserve unknown-event policy behavior.
- **Threats:** Prompt/PII leakage, forged resource attributes, cardinality exhaustion and convention drift.
- **Tests / benchmarks:** Golden fixtures per convention, malformed/oversize/fuzz cases, privacy checks, throughput and storage growth.
- **Commercial value:** Connects existing observability stacks and reduces custom integration work.
- **Dependencies / risks:** Semantic conventions evolve; retain source provenance and avoid presenting telemetry as independently verified facts.

### P3 — Reproducible builds and supply-chain security

- **Existing / gap:** Lockfiles, CI, dependency audits, security scans and release validation exist. Bit-for-bit independent rebuilds and signed builder provenance are not demonstrated.
- **Invariants:** Pin source/toolchain/build inputs; sign release checksums and provenance; independently verify artifacts; time-bound dependency exceptions.
- **API / storage:** Pin Rust/Python toolchains and build images; emit SBOM/provenance; publish signature and rebuild instructions.
- **Compatibility:** No runtime API changes; release artifacts gain metadata.
- **Threats:** Compromised dependency, mutable CI action, runner/cache compromise and signing-key theft.
- **Tests / benchmarks:** Two clean independent builds and byte comparison, provenance/SBOM verification, dependency audit and installed-artifact smoke tests.
- **Commercial value:** Supports self-hosted procurement and regulated supply-chain review.
- **Dependencies / risks:** First inventory timestamps, host paths and non-hermetic steps before claiming reproducibility.

### P3 — Enterprise and brand-governance integration

- **Existing / gap:** Stable evidence, policy and export APIs plus `examples/customer-integration/acme` provide reusable foundations. No GentlyAI-specific schema or accepted integration contract is present.
- **Invariants:** Tenant isolation; preserve source attribution and confidence; human review for ambiguous brand claims; idempotent delivery and defined retention.
- **API / storage:** Agree partner identity, taxonomy version, finding/evidence links, risk labels, reviewer outcome, webhook authentication and retention fields before coding an adapter.
- **Compatibility:** Partner adapter should map to generic evidence and policy concepts; do not add vendor-specific core fields without a reusable contract.
- **Threats:** Cross-customer leakage, attribution error, manipulated sources, webhook replay, PII retention and partner-key compromise.
- **Tests / benchmarks:** Partner contract tests, tenant/replay controls, taxonomy drift, adversarial brand spoofing and precision/recall on partner-labeled data.
- **Commercial value:** Connects governance decisions to brand protection operations and makes dispositions independently reviewable.
- **Dependencies / risks:** Needs a partner-owned data model, retention/legal basis and labeled evaluation set; no partnership is implied by this roadmap.

## Implemented slice in this branch

The branch adds a local MCP adapter for the existing trusted execution design. It provides a request-for-approval tool, requires separate agent/executor identities, binds the normalized report path and overwrite flag in the SDK's argument digest, and invokes the existing verifier/replay-resistant executor before a real write. It adds no second authorization endpoint or policy format. It remains a single local writer integration; it is not a general MCP proxy or filesystem sandbox.
