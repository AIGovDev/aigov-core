# Key-management runbook

Scope: the Ed25519 keys that GovAI uses to sign and verify. Four purposes are defined, each with its own domain prefix:

| Purpose | Domain prefix | Signer | Verified by |
|---|---|---|---|
| `execution_authorization` | `govai.execution_authorization.v1\0` | Core (the registry's active key; see [Core signing](#core-signing-execution-authorization)) | executor (`verify_authorization_with_registry`) |
| `reconciliation_evidence` | `govai.reconciliation.v1\0` | the reconciler's own signer | executor, reconciliation |
| `policy_bundle` | `govai.policy_bundle.v1\0` | the policy owner | Core policy trust store |
| `audit_export` | `govai.audit_export.v1\0` | Core export signer | external verifiers |

The registry (`aigov_py.trusted.keys`) holds **public keys only**. Private seeds belong to their signers and are never
written to the registry, to logs, or to chat.

Implemented: the registry, the operator tool (`python -m aigov_py.trusted.key_admin`), the signer interface, registry-based
verification in the executor, and Core issuance from the registry. Verified locally: see the audit report
(`docs/reports/identity-key-management-2026-11-26.md`). Core reads the registry's event log on every issuance, so a rotation
or revocation takes effect without a restart.

## Concepts

- **Key id (`kid`).** 1 to 64 characters from `A-Z a-z 0-9 . _ -`. Never reused, even after revocation.
- **Status.** `pending` (registered, not signing) -> `active` (the one signing key for its purpose) -> `retired` (ordinary
  rotation) ; any non-revoked status -> `revoked` (terminal, for compromise).
- **One active key per purpose.** Activation is refused while another key of the same purpose is active.
- **Operators.** Identities with a public key and roles: `keyadmin` (register, activate, retire, rotate), `revoker`
  (revoke). The first operator is installed once, by the person who creates the registry file. Later operators are added by
  a `keyadmin` through a signed request.
- **Event log.** `registry.json.events.jsonl` is authoritative: every change is one hash-chained event. `registry.json` is
  a view and is checked against the log on load (`snapshot_matches`).
- **Signed requests.** Every change is an operator-signed request that carries the expected registry version and a nonce.
  A request applies once, to the version it names.

## Core signing (execution authorization)

Core signs execution authorizations with the registry's single active `execution_authorization` key. Configure one mode:

- **Registry mode**: `AIGOV_KEY_REGISTRY_PATH` (the registry's `registry.json`) and `AIGOV_EXECUTION_AUTH_SIGNING_SEEDS_DIR`.
  Core reads the active key from the event log `registry.json.events.jsonl` and loads its seed from
  `<seeds dir>/<kid>.seed`.
- **Legacy single-key mode**: `AIGOV_EXECUTION_AUTH_SIGNING_SEED_HEX` with `AIGOV_EXECUTION_AUTH_KEY_ID`. Unchanged.

Setting both modes is refused at startup. Neither is set: issuance is disabled, as before.

In registry mode:

- Core picks the active key when it prepares an authorization, and re-checks that the key is still active when it signs.
  A rotation or revocation in between refuses the signature.
- A seed file must be readable only by its owner (no group or other bits). It holds the base64 form of the 32-byte Ed25519
  seed, the format `new_signing_seed` returns. It must derive the public key registered for its kid, or Core refuses to sign.
  The key owner generates the seed and places the file on the Core host; the operator tool does not write it.
- With no active key, a consequential call is refused with `503 AUTHORIZATION_KEY_UNAVAILABLE` before anything is written to
  the ledger.
- If the call is accepted but signing is refused, Core returns `503 AUTHORIZATION_SIGNING_REFUSED` with the record hash. The
  record stays in the ledger, no authorization is issued, and the call must not run. Resolve the key state and resubmit under a
  new event id.
- Core decides from the event log only. It does not use the snapshot `registry.json`.

## Procedures

### Install the first operator (once per registry)

```
python -m aigov_py.trusted.key_admin --registry /secure/registry.json new-operator-key /secure/keys/ops-admin.seed
python -m aigov_py.trusted.key_admin --registry /secure/registry.json install-operator ops-admin <public_key_b64> keyadmin revoker
```

Store the seed file on the operator's machine with owner-only permissions (the tool creates it `0600`). Do not commit it.

### Register and activate a key

```
python -m aigov_py.trusted.key_admin --registry R request register ops-admin.seed --actor ops-admin \
    --kid exe-2026-01 --purpose execution_authorization --public-key-b64 <pub> > reg.json
python -m aigov_py.trusted.key_admin --registry R apply reg.json
python -m aigov_py.trusted.key_admin --registry R request activate ops-admin.seed --actor ops-admin --kid exe-2026-01 > act.json
python -m aigov_py.trusted.key_admin --registry R apply act.json
```

Activation is refused while another key of the same purpose is active. Use rotation for that.

### Ordinary rotation

Register the successor (pending), then rotate. The old key becomes `retired`, and the successor becomes `active` in one
group of two events.

```
python -m aigov_py.trusted.key_admin --registry R request rotate ops-admin.seed --actor ops-admin \
    --kid exe-2026-01 --purpose execution_authorization --successor-kid exe-2026-02 > rot.json
python -m aigov_py.trusted.key_admin --registry R apply rot.json
```

Historical evidence signed by the retired key stays trusted, because it was signed while the key was active. Evidence
signed after the retirement time is untrusted.

**Replay and rollback.** Rotation does not reset policy revision anchors or authorization replay protection. Those are
keyed by authorization id and policy revision (Core's authoritative anchor and the executor's store), not by key.

### Emergency revocation (compromised key)

Revocation is terminal and needs a `revoker`. Set `--compromised-from` to the earliest time you believe the key may have
been used by an attacker. When in doubt, use the earliest time that the key could have been exposed.

```
python -m aigov_py.trusted.key_admin --registry R request revoke revoker.seed --actor revoker \
    --kid exe-2026-01 --reason "suspected exposure" --compromised-from 2026-11-20T00:00:00+00:00 > rev.json
python -m aigov_py.trusted.key_admin --registry R apply rev.json
```

Immediately after revocation:

1. Core stops signing with the revoked key at once. Its next consequential call re-reads the log, finds no active key, and is
   refused with `503 AUTHORIZATION_KEY_UNAVAILABLE` until a successor is registered and activated. No restart is needed. In
   legacy single-key mode, replace `AIGOV_EXECUTION_AUTH_SIGNING_SEED_HEX` and `AIGOV_EXECUTION_AUTH_KEY_ID` and restart Core.
2. Treat authorizations issued by the revoked key between `compromised-from` and the revocation as suspect. The verdict
   for a signature made after `compromised-from` is `untrusted`. For a signature made before it, the verdict is
   `uncertain` and is refused by default. Review those authorizations with a person; do not accept them automatically.
3. Record the incident in the audit log of your operations.

### Inspect

```
python -m aigov_py.trusted.key_admin --registry R inspect
```

Shows the version, operators and roles, every key's purpose and status, and whether the log verifies and the snapshot
matches it. A snapshot mismatch is a signal to investigate, not a normal state.

## Recovery

- **Registry file lost.** Restore `registry.json.events.jsonl` from backup. Loading the log rebuilds the state; the snapshot
  `registry.json` is rewritten on the next change (or you can run `inspect` to confirm `snapshot_matches_log`). Without the
  log, the registry cannot be verified and nothing should be trusted from it.
- **Log altered or truncated.** The chain check refuses an altered or reordered log. A truncated tail is valid and shorter,
  so the chain alone cannot detect it; the snapshot mismatch reports it. Keep an off-host copy of the log to compare against.
- **Operator key lost.** An existing `keyadmin` installs a new operator through a signed request. If no `keyadmin` remains,
  the registry cannot be changed; restore from the last good backup and record the gap.

## Limits

- No trusted timestamps. `issued_at_utc` and `signed_at_utc` are claims by the signer. Historical verdicts depend on those
  claims. A signer that lies about time can move a signature into or out of a key's validity window. Use an independent
  timestamp source if that matters for your evidence.
- The registry is not a federated identity system. Operators are pinned keys.
- Core's seed files sit on the Core host. Whoever can read the active seed can sign until that key is revoked (see above).
- No compatibility with any external key-management service is claimed or tested.
