# Threat model (foundation)

This document frames security assumptions for self-hosted AIGov Core. It does **not** claim formal certification or complete mitigation of all AI governance risks.

## Trust boundaries

```
[Agent / CI] --API key--> [aigov_audit runtime] --> [append-only ledger volume]
                              |
                              v
                        [Postgres (optional)]
                              |
                              v
                        [Operators / auditors] --exports--> [archive + verify]
```

**Inside trust boundary (operator responsibility):**

- Runtime process, ledger volume, policy directory, API keys, signing keys, network policy to port 8088.

**Outside trust boundary:**

- Upstream LLM providers, agent frameworks, and any system that fabricates evidence before ingest.

## Tampering threats

| Threat | Impact | Mitigations (today) |
|--------|--------|---------------------|
| Modify ledger files on disk | False history | Filesystem permissions, immutable snapshots, WORM storage (operator) |
| MITM on HTTP API | Inject/spoof evidence | TLS termination at ingress, private networking |
| Replace policy bundle | Change verdict rules | Mount integrity checks, signed policy (future), change control |

Core detects hash chain breaks via `/verify` and export integrity checks; it does not encrypt ledger at rest by default.

## Replay manipulation

Attackers may present forged **export JSON** without a matching ledger.

- Use `govai verify-audit-export` when signatures are enabled.
- Compare live `GET /api/export` to archived copies after restore.
- Deterministic replay validates internal consistency; it does not prove ingest authenticity without ledger + API auth logs.

## Missing evidence attacks

Agents can omit steps (e.g. skip `human_approved`) while still returning plausible text.

- Verdict projection marks runs **BLOCKED** or **INVALID** when required events are absent.
- Operators must require ingest of all governance lifecycle events, not rely on model self-reporting.

## Forged approvals

Submitting `human_approved` via API without organizational process is possible if API keys leak.

- Protect `GOVAI_API_KEYS` / JSON map in secrets managers.
- Rotate keys on departure; scope keys per tenant.
- Correlate approvals with external ticketing (operator process, not Core-enforced yet).

## Compromised signing keys

Attacker can sign false exports that verify cryptographically.

- Key rotation, hardware/security module storage (operator).
- Short-lived signing keys and dual-key verification windows.
- Monitor for exports signed after key retirement.

## Runtime isolation assumptions

- Container runs as non-root UID 1000.
- Single replica default — no distributed locking between writers.
- No built-in seccomp/AppArmor profiles in stock manifests (harden per cluster policy).

## Operator assumptions

Operators are expected to:

- Control who can reach the audit API and mount ledger volumes.
- Perform backups and restore drills.
- Maintain policy bundles and environment separation (`AIGOV_ENVIRONMENT`).
- Investigate INVALID/BLOCKED verdicts using exports and replay tooling.

## Lineage and delegation threats

| Threat | Impact | Mitigations (today) |
|--------|--------|---------------------|
| Forged delegation | False narrative of who delegated to whom | Signed exports; `agent_delegated` with `agent_id`; graph validation on replay |
| Orphaned lineage | Child run without parent evidence | `lineage-graph` orphan detection; warnings on export |
| Hidden sub-agents | Undisclosed workers bypassing approval | Require `parent_run_id` / `root_run_id`; cross-run export review |
| Replay desynchronization | Export verdict differs from replayed projection | `govai replay-audit-export`; hash chain verify |
| Lineage tampering | Edited `parent_run_id` without ledger change | Append-only ledger; chain integrity; signed export digests |
| Cyclic governance flows | Circular delegation obscures accountability | `lineage_validation` cycle detection; invalid graph status |

Core does **not** prove that `agent_id` maps to a real organizational principal without operator identity integrations.

## Explicit non-guarantees

- Protection against malicious insiders with root on the ledger host.
- Automated fraud detection on evidence payload content.
- Legal admissibility or regulatory certification by deploying Core alone.
- Strong tenant isolation beyond API key → tenant mapping (no per-tenant crypto boundaries).

See [runtime-operations.md](./runtime-operations.md) for operational guarantees and gaps.

## Identity and key management

Scope: caller identity (OIDC/JWT and API keys), the role and tenant each identity gets, and the keys that sign
authorizations, reconciliation evidence, policy bundles, and audit exports. Operational detail is in
`docs/operations/key-management-runbook.md` and `docs/authentication-guide.md`.

| Threat | Mitigation in this change | Residual risk |
|---|---|---|
| Unsigned token (`alg: none`) | Refused before any key lookup (`JWT_UNSIGNED`). | None known. |
| Algorithm confusion (HS256 keyed with the public key) | Only RS256 is accepted; the header is checked before the key is used. Tested with the public key as secret, live and in tests. | None known. |
| Token from an untrusted issuer or with a foreign audience | Issuer and audience must match configuration exactly. | Trust in the configured issuer is a deployment decision. |
| Unknown or substituted signing key | `kid` must be in the trusted set. A refresh runs at most once per interval, and refresh failure fails closed. | A key the identity provider publishes wrongly is trusted. |
| Workload impersonating a human approver | Workload tokens never match a human rule, through `sub`, `client_id`, or `azp`. Config refuses a workload rule with the approver role. Ingest role check still applies. | A compromised configuration that adds a human rule for a workload client would grant approval; config review is required. |
| Human identity forged through a workload token | A token issued to any configured workload client never maps as human, whatever `sub` says. | None known for tested shapes. |
| Privilege from token claims | Roles and tenants come only from configured rules; no claim sets them. | None. |
| Cross-tenant access | A principal's tenant must match the ledger tenant (existing check); OIDC principals carry their rule's tenant. | Tenant mapping correctness is a configuration responsibility. |
| API-key fallback after JWT failure | None: a JWT that fails is refused. | None. |
| Unauthorized key insertion (a writer of the log adds a key) | Every event carries the signed request. Readers verify the signature against the operator in the log with the needed role, from the pinned trust file. Test: `test_registry_attacks.py` (writer without an operator key; operator signing a root operation; role without authority); Rust: `key_registry::tests`. | A party holding an operator key can register keys within its role. Operator keys must be protected. |
| Key substitution (a whole log replaced) | The anchor records the head hash; a different log has a different head, and a log by another root fails the pinned root's signature. Tests: `test_a_whole_log_substituted...`, `test_a_substituted_log_under_the_same_root...`, Rust `a_registry_signed_by_a_different_root_is_refused`, PostgreSQL `anchor_head_mismatch`. | A party that can change the trust file and the anchor together is not stopped; see the residual threat in the runbook. |
| Purpose confusion (a signature from one purpose accepted as another) | Each purpose has its own domain prefix, the signer adds it, and the verifier requires the purpose to match. Tested. | Policy bundles predate the prefix; separation there is by registry purpose only. |
| Replay of an operator request | Expected version and nonce; the reader also refuses a duplicated event. Tests: `test_replayed_request_is_refused`, `test_a_valid_request_replayed_as_a_new_event_is_refused`, Rust `a_duplicated_event_is_refused_as_a_replay`. | None known. |
| Consequential call without a real approval (Core issues an authorization naming no approval) | With issuance enabled, Core checks under the ledger lock that the approval is a `human_approved` with decision `approve`, for the same tool call, not revoked and not already used; otherwise it refuses before append. Regression test: `tests/approval_before_authorization.rs`, which failed on the unfixed tree. | Under the built-in dev policy a tool approval cannot be recorded, so consequential calls are refused there while issuance is enabled. Non-consequential tool calls still receive authorizations without an approval. |
| Rollback of the registry log (an earlier valid prefix restored), including resurrection of a revoked key | The anchor records a later head; a shorter log is refused (`anchor_log_behind`). Tests: `test_a_rollback_to_before_a_revocation_is_refused_and_the_key_stays_revoked`, Rust `anchor_log_behind`, PostgreSQL rollback. The reproduction on the pre-fix commit (`eaab53f`) resurrected the key; see the audit report. | A party that can also move the anchor is not stopped; see the residual threat in the runbook. |
| Forged log built by a party that can recompute the hash chain | Not possible without an operator or root signature. The reproduction on `eaab53f` was accepted by the executor; it is refused now (`request_signature_invalid`, or `anchor_head_mismatch`). Tests: attack and fixture tests. | Same residual as substitution. |
| Racing registry changes | Writers hold the anchor's exclusive transaction (PostgreSQL row lock) for the whole append and commit, and compare-and-swap the anchor. Tests: `test_concurrent_revocations_apply_exactly_once` (6 processes, SQLite and PostgreSQL), and the rotation-versus-revocation race. | None known. Readers retry a mismatch that a concurrent commit causes, and still refuse a real one. |
| Registry log altered, deleted, reordered, or modified | Each event's hash covers its request; the chain and sequence are checked; each request's signature is checked. Anchor compares the count and head. Tests: deletion, modification (with a recomputed hash), reordering; cross-language fixture tests in Python and Rust. | None known for tested shapes. |
| Evidence signed by a compromised key | Verdicts separate signature validity, trust at signing time, current status, and compromise uncertainty; a signature after the compromise time is untrusted, one before it is uncertain and refused by default. Tested. | Timestamps are self-asserted; no trusted time source is used. |
| Key rotation or root rotation resetting replay state | Replay is keyed by authorization id in Core and the executor store, and rotation changes neither. Tests: `test_an_executed_authorization_cannot_run_again_after_its_key_is_rotated`, `test_replay_protection_survives_a_root_rotation`. | None known. |
| Crash between the registry append and the anchor commit | The transaction rolls back the anchor; the log is one event ahead; readers and writers refuse until `reconcile` anchors that single event after it verifies. Tests: `test_a_crash_between_the_append_and_the_anchor_commit...`, PostgreSQL crash test. | Reconcile trusts the operator's signature on the extra event, which the log already verified. |
| Root key compromise or root rotation | The trust file pins roots; a retired root signs only up to its bound; history stays verifiable. Tests: `test_root_rotation_keeps_history_verifiable...`, `test_a_retired_root_with_a_bound...`. | A compromised current root can sign within its bound; rotate promptly. |
| Migration of an unsigned v1 registry silently trusted | The migration is one root-signed `legacy_import` event; imported keys are `legacy_v1_unsigned`, and their verdicts are at most `uncertain`. Tests: `test_registry_migration.py`. | The root holder attests the imported state; that attestation is the trust decision. |
| Leaked seed in logs or chat | Operator seeds are written owner-only and never printed; signers hide their seed; tests check the repr and the CLI output. | Operators must still protect seed files on their own machines. |
| External signer failure or hang | Bounded timeout; every failure is an explicit error; no fallback signing. Tested. | Only the local test provider is exercised. No external KMS compatibility is claimed. |

Explicit non-guarantees: no trusted timestamps; no federated operator identity; no external key-management service
compatibility. Core signs with the registry's single active key, and its seed files live on the Core host. Simultaneous
compromise of PostgreSQL write access and the trust file is a residual threat that the registry code cannot detect (runbook,
"Residual threat").
