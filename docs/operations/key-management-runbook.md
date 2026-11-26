# Key-management runbook (registry format v2)

Scope: the Ed25519 keys that GovAI signs and verifies with. Four purposes, each with its own domain prefix:

| Purpose | Domain prefix | Signer | Verified by |
|---|---|---|---|
| `execution_authorization` | `govai.execution_authorization.v1\0` | Core (the registry's active key; see [Core signing](#core-signing-execution-authorization)) | executor (`verify_authorization_with_registry`) |
| `reconciliation_evidence` | `govai.reconciliation.v1\0` | the reconciler's own signer | executor, reconciliation |
| `policy_bundle` | `govai.policy_bundle.v1\0` | the policy owner | Core policy trust store |
| `audit_export` | `govai.audit_export.v1\0` | Core export signer | external verifiers |

The registry holds **public keys only**. Private seeds belong to their signers and never go into the registry, the logs, or chat.

## What protects the registry

Three things, each independent of the others:

1. **Pinned roots (trust file).** The root operator public keys live in a *trust file* on each host that verifies or signs, owner-only (no group or other bits), outside the registry directory. The registry cannot supply, replace, or add a root. Only roots install and remove operators and import legacy history.
2. **Signed events (log).** Every event in `registry.json.events.jsonl` carries the signed request that produced it. Readers verify every signature, the sequence, the hash chain, the signer's authority, and every state transition, from genesis.
3. **Anchor (PostgreSQL).** The table `key_registry_anchor` holds the sequence number and head hash of the last committed event, per registry. Writers update it in the same transaction that appends the event. Readers require the log to match the anchor exactly.

A reader refuses unless all three agree. Refusal codes are stable; the common ones are listed at the end.

What is **not** protected: a party that can change the trust file and the anchor at the same time. See [Residual threat](#residual-threat).

## Files and configuration

| Setting | Where | Purpose |
|---|---|---|
| Trust file | `AIGOV_KEY_REGISTRY_TRUST_FILE` (Core), `--trust` (operator tool) | Pinned roots and the registry id. Owner-only. |
| Registry log | `<registry>.events.jsonl` (next to `registry.json`) | Authoritative signed log. |
| Snapshot | `registry.json` | A view for people. Never read for decisions. |
| Anchor URL | `AIGOV_KEY_REGISTRY_ANCHOR_URL`, else `GOVAI_DATABASE_URL` | PostgreSQL holding `key_registry_anchor`. |
| Seeds directory | `AIGOV_EXECUTION_AUTH_SIGNING_SEEDS_DIR` (Core) | `<kid>.seed` files, owner-only, base64 of the 32-byte seed. |

Trust file (`govai.key_registry_trust.v1`):

```json
{
  "schema": "govai.key_registry_trust.v1",
  "registry_id": "prod-authz",
  "roots": [
    {"kid": "root-2026-a", "public_key_b64": "...", "status": "retired", "retired_after_seq": 412},
    {"kid": "root-2026-b", "public_key_b64": "...", "status": "current"}
  ]
}
```

- A `current` root signs new events. A `retired` root signs only events up to and including `retired_after_seq`, so its history
  stays verifiable and it cannot sign after its bound.
- At least one `current` root is required.
- Keep retired roots in the file for as long as their history must verify.

The anchor table comes from migration `0004_key_registry_anchor` (`rust/migrations/`). Core applies it with the normal migration
step. Its readiness check counts that migration. The operator tool never creates tables. `anchor-init` refuses if the table is
missing.

## Core signing (execution authorization)

Core signs execution authorizations with the registry's single active `execution_authorization` key. Configure one mode:

- **Registry mode**: `AIGOV_KEY_REGISTRY_PATH` (the registry's `registry.json`), `AIGOV_KEY_REGISTRY_TRUST_FILE`, the anchor URL,
  and `AIGOV_EXECUTION_AUTH_SIGNING_SEEDS_DIR`. Core verifies the log from genesis, against the trust file and the anchor, on every
  issuance and again before signing. The trust file must load and validate at startup.
- **Single-key mode**: `AIGOV_EXECUTION_AUTH_SIGNING_SEED_HEX` with `AIGOV_EXECUTION_AUTH_KEY_ID`. No registry.

Setting both modes is refused at startup. Setting neither disables issuance, as before.

In registry mode:

- A consequential call is authorized only if its `approval_event_id` names a `human_approved` event with decision `approve`, in
  the same run, for the same `tool_call_id`, not revoked and not used by another call. Otherwise it is refused before anything is
  appended, with `policy_violation ... reason=approval_*`. This applies under every policy. With the built-in dev policy a tool
  approval cannot be recorded, so consequential calls are refused while issuance is enabled.
- If the registry does not verify, or the anchor is missing or unreachable, the call is refused with
  `503 AUTHORIZATION_KEY_UNAVAILABLE` before anything is appended.
- If the call is accepted but signing is refused, Core returns `503 AUTHORIZATION_SIGNING_REFUSED` with the record hash. The
  record stays in the ledger, no authorization is issued, and the call must not run.
- A seed file must be readable only by its owner, and must derive the public key the verified registry holds for its kid.

## Procedures

All changes are signed requests. Each carries the expected version and a fresh nonce, and applies once, to the version it names.
Commands below use `--registry R --trust T` and the anchor URL from the environment.

### 1. Create the trust file and the anchor (once per registry)

```
python -m aigov_py.trusted.key_admin --registry R --trust T new-key /secure/root-a.seed   # root key: keep it off Core and executor hosts
# put the public key in the trust file, owner-only (chmod 600), with registry_id and status "current"
python -m aigov_py.trusted.key_admin --registry R --trust T anchor-init   # requires migration 0004 applied
```

The root seed is needed only to sign root operations and migrations. Store it where the root holder works, not on Core.

### 2. Install an operator (root-signed)

```
python -m aigov_py.trusted.key_admin --registry R --trust T new-key /secure/ops-admin.seed
python -m aigov_py.trusted.key_admin --registry R --trust T request operator_install /secure/root-a.seed --actor root-a \
    --identity ops-admin --public-key-b64 <pub> --roles keyadmin revoker > req.json
python -m aigov_py.trusted.key_admin --registry R --trust T apply req.json
```

### 3. Register and activate a key

```
python -m aigov_py.trusted.key_admin --registry R --trust T new-key /secure/exe-a.seed
python -m aigov_py.trusted.key_admin --registry R --trust T request register /secure/ops-admin.seed --actor ops-admin \
    --kid exe-2026-01 --purpose execution_authorization --public-key-b64 <pub> > reg.json && ... apply reg.json
python -m aigov_py.trusted.key_admin --registry R --trust T request activate /secure/ops-admin.seed --actor ops-admin --kid exe-2026-01 > act.json && ... apply act.json
```

Activation is refused while another key of the same purpose is active. Use rotation for that. Place the key's seed in the Core
seeds directory as `<kid>.seed` (base64, owner-only) before its first use.

### 4. Ordinary rotation

Register the successor (pending), then `request rotate --kid exe-2026-01 --successor-kid exe-2026-02`. It is one event: the old key becomes `retired`, the successor `active`.
Historical evidence signed by the retired key stays trusted, and evidence signed after its retirement is untrusted. Core picks up
the change on its next decision, with no restart.

### 5. Emergency revocation (compromised key)

Revocation is terminal and needs a `revoker`. Set `--compromised-from` to the earliest time the key may have been used by an
attacker.

```
python -m aigov_py.trusted.key_admin --registry R --trust T request revoke /secure/ops-admin.seed --actor ops-admin \
    --kid exe-2026-01 --reason "suspected exposure" --compromised-from 2026-11-20T00:00:00+00:00 > rev.json && ... apply rev.json
```

- Core stops issuing with the revoked key at its next decision. Until a successor is registered and activated, consequential
  calls are refused with `AUTHORIZATION_KEY_UNAVAILABLE`.
- Authorizations signed by the key after `compromised-from` are `untrusted`. Those signed before it are `uncertain` and refused
  by default. Review them with a person; do not accept them automatically.

### 6. Operator rotation

```
python -m aigov_py.trusted.key_admin --registry R --trust T request operator_revoke /secure/root-a.seed --actor root-a --identity ops-admin --reason "left" > rev-op.json && ... apply rev-op.json
python -m aigov_py.trusted.key_admin --registry R --trust T request operator_install /secure/root-a.seed --actor root-a --identity ops-admin-2 --public-key-b64 <pub> --roles keyadmin revoker > inst.json && ... apply inst.json
```

A revoked operator's later requests are refused. Its earlier events stay verifiable. Identities are never reused.

### 7. Root key rotation

1. Create the new root and add it to the trust file as `current`.
2. Change the old root to `retired` with `retired_after_seq` set to the current registry version (`inspect` shows it).
3. Deploy the trust file to every host that verifies or signs. Until a host has the new file, it refuses events signed by the new root.

Old history stays verifiable because the old root stays in the file. The old root cannot sign past its bound. Keep the bound
as a record of the rotation.

### 8. Crash recovery

If a process dies between appending an event and committing the anchor, readers refuse with `anchor_log_ahead`, and writers refuse
too. Nothing is lost and nothing is accepted on top of an unreconciled event:

```
python -m aigov_py.trusted.key_admin --registry R --trust T reconcile
```

`reconcile` verifies the whole log, and anchors the single extra event only if it is the one directly after the anchored head. Two or more
extra events, or any mismatch, are refused and need an investigation.

### 9. Migrating a v1 registry

A v1 registry (the format before this runbook; commit `eaab53f`) has no signed history. Its events record only hashes of requests.
The migration is therefore an explicit attestation by the root holder:

```
python -m aigov_py.trusted.key_admin --registry R2 --trust T migrate-v1 --v1-registry R1 --root-kid root-a --root-seed-file /secure/root-a.seed
```

- The v1 chain and transitions are verified first; an altered v1 log is refused.
- The result is one root-signed `legacy_import` event. Its keys keep their statuses and times, with the provenance
  `legacy_v1_unsigned`.
- A signature made under an imported key is at most `uncertain`, with reason `legacy_unsigned_history`. It is refused by
  default. The migration does not make old history trusted.
- The target registry must not exist and the anchor must be uninitialized. The v1 log is left in place.

### 10. Inspect

```
python -m aigov_py.trusted.key_admin --registry R --trust T inspect
```

Shows the version, operators and roles, every key's purpose, status, and provenance, and whether the log verifies against the anchor.
An anchor mismatch is a signal to investigate, not a normal state.

## Refusal codes

| Code | Meaning |
|---|---|
| `anchor_missing` | The anchor row does not exist. Run `anchor-init` (after the migration). |
| `anchor_log_behind` | The log is shorter than the anchor: rollback or truncation. |
| `anchor_log_ahead` | The log is one or more events beyond the anchor: a crash (use `reconcile`) or an investigation. |
| `anchor_head_mismatch` | Same length, different head: substitution. |
| `anchor_unavailable` | The anchor database cannot be reached. Decisions are refused. |
| `request_signature_invalid` | A signature does not verify under the signer's key. |
| `root_not_authorized` | A root signed outside its bound, or is not in the trust file. |
| `operator_not_authorized` | The signer is unknown, inactive, or lacks the role. |
| `replayed_nonce`, `expected_version_mismatch`, `version_conflict` | A request was replayed, reordered, or made against a stale version. |
| `trust_config_permissions`, `trust_config_invalid`, `trust_config_missing` | The trust file is unsafe or invalid. |

## Residual threat

Simultaneous compromise of **PostgreSQL write access** and **the trust file** lets an attacker rewrite the anchor, replace the log,
and substitute the roots, so the reader accepts a forged registry. Nothing in the registry code detects that, because both
independent checks are then under the attacker's control. Defending against it needs separate controls, outside this code:

- Keep the trust file under change control, with its own audit trail, and compare its hash against a copy held elsewhere.
- Restrict write access to the anchor table to the migration role and to the operator's reconcile step, and audit it.
- Keep an off-host copy of the log and check the head hash against it periodically.

Other residual risks: a compromised root key can sign anything within its bound (rotate roots promptly); operator seeds and
execution seeds are protected only by their owners; timestamps are signer claims, with no trusted time source; single-host
anchors (`SqliteAnchor` in tests) are not production.
