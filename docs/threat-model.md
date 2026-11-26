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
| Key substitution in the registry | Registry changes are operator-signed requests with the expected version and a fresh nonce; a kid is never reused. | An operator key compromise lets its holder change the registry; use revocation and keep the operator set small. |
| Purpose confusion (a signature from one purpose accepted as another) | Each purpose has its own domain prefix, the signer adds it, and the verifier requires the purpose to match. Tested. | Policy bundles predate the prefix; separation there is by registry purpose only. |
| Replay of an operator request | Nonce and expected-version check. Tested. | None known. |
| Racing registry changes | Compare-and-swap on the version, under a file lock. Tested with stale versions. | Single-host lock; multi-host registries are not supported. |
| Registry log altered | Hash chain; an altered event is detected on load. Tested. | A truncated tail is valid and shorter; detected only through the snapshot, or an off-host copy of the log. |
| Evidence signed by a compromised key | Verdicts separate signature validity, trust at signing time, current status, and compromise uncertainty; a signature after the compromise time is untrusted, one before it is uncertain and refused by default. Tested. | Timestamps are self-asserted; no trusted time source is used. |
| Key rotation resetting replay or anchor state | Rotation changes only key status. Authorization replay is keyed by authorization id in Core and the executor store; the policy anchor is keyed by revision. The existing lifecycle tests cover replay by authorization id; no test replays an authorization across a key rotation. | No replay test spans a rotation. The Core seed file for a retired or revoked key remains on disk; it is not used, but it is still a secret to remove. |
| Leaked seed in logs or chat | Operator seeds are written owner-only and never printed; signers hide their seed; tests check the repr and the CLI output. | Operators must still protect seed files on their own machines. |
| External signer failure or hang | Bounded timeout; every failure is an explicit error; no fallback signing. Tested. | Only the local test provider is exercised. No external KMS compatibility is claimed. |

Explicit non-guarantees for this change: no trusted timestamps; no federated operator identity; no external key-management
service compatibility. Core signs with the registry's single active key, and its seed files live on the Core host.
