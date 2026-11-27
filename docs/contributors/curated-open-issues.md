# Curated open issues for contributors

This index points to 20 existing open GitHub issues with concrete repository work and acceptance criteria. It does **not** create duplicate issues. Read the live issue before starting; scope and ownership can change.

## Developer launch and evaluation

| Issue | Gap and contribution scope | Suggested background |
| --- | --- | --- |
| [#427 — Reproducible demo and external feedback](https://github.com/AIGovDev/aigov-core/issues/427) | The public launch still needs a clean-clone walkthrough that demonstrates ingest, `BLOCKED`, export, and offline verification with claims limited to what the evidence proves. | Docs, Python CLI, demo verification |
| [#446 — Deterministic verification orchestrator](https://github.com/AIGovDev/aigov-core/issues/446) | Existing agent benchmark results show the need to execute and validate required evidence checks independently of model tool selection. The issue freezes the baseline and defines adversarial acceptance criteria. | Agent runtimes, ML evaluation, security |
| [#400 — Ledger snapshot restore rehearsal](https://github.com/AIGovDev/aigov-core/issues/400) | A snapshot is not useful for recovery until restore and chain verification have been rehearsed, including altered and incompatible inputs. | Operations, Rust, storage |
| [#399 — Concurrent append benchmark](https://github.com/AIGovDev/aigov-core/issues/399) | Measure multi-tenant writer contention with reproducible workloads and verify that performance tests do not hide lost, duplicated, or cross-tenant events. | Rust, databases, performance testing |
| [#398 — Long-ledger verification benchmark](https://github.com/AIGovDev/aigov-core/issues/398) | Establish reproducible time and resource baselines for verifying ledgers of increasing size and for corrupted chains. | Rust, benchmarking |

## Security and trust

| Issue | Gap and contribution scope | Suggested background |
| --- | --- | --- |
| [#501 — Policy revision anti-rollback design review](https://github.com/AIGovDev/aigov-core/issues/501) | The current watermark is protected on one persistent filesystem, but the issue records unauthenticated state, empty-ledger reset, and multi-host gaps. It requires design decisions before implementation. | Security architecture, policy lifecycle |
| [#380 — Audit-artifact key-compromise response](https://github.com/AIGovDev/aigov-core/issues/380) | Define how operators identify affected signatures, revoke compromised trust, and re-verify historical artifacts. | Cryptography operations, incident response |
| [#379 — Verifier trust-root bootstrap and rotation](https://github.com/AIGovDev/aigov-core/issues/379) | Specify bootstrap, overlap, revocation, and historical validation for verifier keys, with explicit tests for unknown and replaced roots. | Cryptography, supply-chain security |

## Testing and conformance

| Issue | Gap and contribution scope | Suggested background |
| --- | --- | --- |
| [#406 — Storage fault injection](https://github.com/AIGovDev/aigov-core/issues/406) | Inject failures around writes and durable commits; verify chain integrity and distinguish retry-safe from indeterminate outcomes. | Rust, transactional storage |
| [#405 — Tenant-isolation property tests](https://github.com/AIGovDev/aigov-core/issues/405) | Exercise list, cursor, filter, and export paths with generated tenant identities, including cross-tenant identifier substitution. | Rust, SQL, security testing |
| [#404 — Rust/Python decision conformance](https://github.com/AIGovDev/aigov-core/issues/404) | Run shared versioned vectors through both implementations and report reproducible mismatches in decisions and reason codes. | Rust, Python, contract testing |
| [#403 — Evidence-bundle parser fuzzing](https://github.com/AIGovDev/aigov-core/issues/403) | Fuzz malformed, truncated, duplicate-field, unsupported-version, and oversized verifier inputs with bounded resource use. | Rust, fuzzing, security testing |
| [#402 — Policy-evaluation property tests](https://github.com/AIGovDev/aigov-core/issues/402) | Encode determinism, precedence, unknown-value, and trace-consistency invariants with reproducible seeds. | Rust, property-based testing |
| [#401 — Policy-expression parser fuzzing](https://github.com/AIGovDev/aigov-core/issues/401) | Test parser safety and deterministic normalization across malformed, nested, and equivalent expressions. | Rust, parsers, fuzzing |

## Runtime reliability

| Issue | Gap and contribution scope | Suggested background |
| --- | --- | --- |
| [#397 — Query budgets for audit history](https://github.com/AIGovDev/aigov-core/issues/397) | Bound range, page size, and work for audit-history queries, with stable over-budget responses and tenant-safe tests. | Rust APIs, databases |
| [#396 — Bounded evidence-export jobs](https://github.com/AIGovDev/aigov-core/issues/396) | Move large exports off synchronous request workers while keeping job state and artifacts tenant-scoped, bounded, cancellable, and expiring. | Rust APIs, background jobs |
| [#384 — Liveness versus ledger readiness](https://github.com/AIGovDev/aigov-core/issues/384) | Distinguish a running process from one safe to accept governed operations, including corrupted and recovering storage. | Rust services, operations |
| [#383 — Flush accepted writes on graceful shutdown](https://github.com/AIGovDev/aigov-core/issues/383) | Define the acknowledgment boundary and shutdown deadline; test graceful stop, timeout, and interruption. | Rust, Tokio, durability |
| [#382 — Backpressure for saturated ledger writers](https://github.com/AIGovDev/aigov-core/issues/382) | Bound writer queues and define caller behavior under sustained storage pressure without sacrificing tenant isolation. | Rust, concurrency, operations |
| [#381 — Bound event size and ingest resources](https://github.com/AIGovDev/aigov-core/issues/381) | Set configurable byte and nesting limits and test oversized inputs with bounded memory. | Rust, API security |

## Maintainer triage before assigning

The open issue list contains same-title pairs for the storage and reliability proposals above: **#385–#395** duplicate the corresponding themes in **#396–#406**. This index links one issue per theme and does not declare either record canonical. Maintainers should close or cross-link duplicates before assigning work.

The repository also has older issues labeled `good first issue`. Check the live issue and current code before suggesting one; several older acceptance criteria may already be covered by current quickstarts, examples, badges, or glossary documentation. Do not treat the advanced issues above as newcomer tasks just because they appear in this index.
