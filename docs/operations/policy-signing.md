# Policy trust: signed verdict configuration

Status: 2026-11-23.

## Trust boundary

In **production**, every security-sensitive decision (ingest gates, approver allowlist, verdict
configuration, export readiness) comes from one artifact: a **signed policy bundle** whose signature
is verified against an explicit trust store at startup. No policy file is read in production.

| Input | Production | Staging | Development |
|-------|------------|---------|-------------|
| Signed policy bundle (`AIGOV_POLICY_BUNDLE_FILE`, or `policy.bundle.prod.json` / `policy.bundle.json` in `AIGOV_POLICY_DIR`) | **Required**, verified, sole source | Verified, sole source when present | Verified when present |
| Unsigned policy file (`AIGOV_POLICY_FILE`, `policy.<env>.json`) | **Refused, not read** | Refused unless `AIGOV_ALLOW_UNSIGNED_POLICY_FILE=1` (unchanged) | Allowed (compatibility path) |
| `AIGOV_ALLOW_UNSIGNED_POLICY_FILE` | **Refused at startup** | Opt-in (unchanged) | Ignored |
| `AIGOV_APPROVER_ALLOWLIST` | **Refused at startup** | Overrides the file allowlist (unchanged) | Overrides (unchanged) |
| Built-in defaults | Used for export readiness only | Unchanged | Unchanged |

Production refuses to start, with a message naming the cause, when any of these hold: no bundle is
configured; `AIGOV_POLICY_FILE`, `AIGOV_ALLOW_UNSIGNED_POLICY_FILE`, or `AIGOV_APPROVER_ALLOWLIST` is
set; the trust store is missing or empty; the bundle is unsigned, malformed, expired, or signed by an
untrusted key; the bundle does not satisfy the production contract below.

Environment variables and command-line flags cannot bypass these checks in production.

## Signature format (v2)

A signature record with `"payload_version": 2` signs this canonical JSON (sorted keys, compact):

```
{ "payload_version": 2, "policy_digest_sha256": <document digest>, "issuer_id": ...,
  "signer": ..., "created_at_utc": ..., "expires_at_utc": <string or null> }
```

The document digest covers the whole bundle except the `signatures` array. The record's
`payload_digest_sha256` must equal the v2 digest computed from the record's own fields. Changing the
document, the issuer, the signer label, the creation time, or the expiry therefore invalidates the
signature. Expiry is enforced in staging and production.

Legacy records (no `payload_version`) sign the document digest only. They still verify, for
compatibility, but **an `expires_at_utc` on a legacy record is refused outside development**, because
the expiry is not covered by the signature. Re-sign to add an expiry.

Only `kind: "ed25519"` is accepted. Unknown `payload_version` values are refused. The verifier does
not negotiate algorithms or versions.

## Production contract for bundle contents

The verified bundle must satisfy these rules in staging and production. Each one exists because this
build does not enforce the corresponding control in a way a signature could vouch for:

- `policy_id` and `version` are non-empty.
- `inherits` is empty (inheritance is not resolved).
- `verdict_rules` has empty `required_evidence_codes` and `invalid_conditions` (they are parsed but
  not evaluated; a non-empty list would silently do nothing).
- `selectors.tenants` is `["*"]` and `selectors.environments` contains `"*"` or the deployment
  environment (selectors are not evaluated per request).
- Every `human_approved` rule contains a `requires_approver_allowlist` gate with a non-empty
  allowlist. The allowlist lives in the signed bundle, not in an environment variable.

## Trusted keys

`AIGOV_POLICY_TRUST_ED25519_JSON` is the trust store, set in the service environment:

```json
[{"issuer_id": "govai-policy-prod", "pubkeys_base64": ["<base64 32-byte public key>"]}]
```

- Each signature is checked only against keys listed for the `issuer_id` in the bundle's
  `policy.issuer.issuer_id`.
- Public keys only. The service never needs a private key.
- Store the trust store in the deployment's secret or configuration system, not in the repository.

## Operator signing procedure

Run offline, on a trusted machine. The private key stays in a file readable only by its owner
(mode `0600`); group- or world-readable key files are refused.

```sh
aigov policy sign-bundle \
  --in policy.json \
  --out policy.bundle.prod.json \
  --issuer-id govai-policy-prod \
  --signer "<your name or CI identity>" \
  --created-at-utc "2026-11-23T00:00:00Z" \
  --expires-at-utc "2027-02-21T00:00:00Z" \
  --private-key-file /secure/keys/govai-policy-prod.key
```

Then:

1. Verify before deploying. The service refuses an invalid bundle at startup, so run the service
   in staging with the same bundle and trust store first.
2. Deploy `policy.bundle.prod.json` and set `AIGOV_POLICY_BUNDLE_FILE` to its path.
3. Keep `--expires-at-utc` short enough that a forgotten re-sign fails closed. Re-sign before expiry.

`--private-key-base64` on the command line is a legacy opt-in and should not be used.

## Migrating an unsigned policy file

A policy file cannot be signed as-is for production, because it controls verdicts through legacy
flags that are not part of the bundle schema. Migrate each flag into the bundle explicitly:

| Legacy flag (`policy.prod.json`) | Bundle equivalent | Notes |
|----------------------------------|-------------------|-------|
| `enforce_approver_allowlist: true` with `approver_allowlist` | `requires_approver_allowlist` gate on `human_approved` | Required in production. The environment override is refused. |
| `require_risk_review_for_approval` | `requires_risk_reviewed_approved` gate on `human_approved` | Write the gate explicitly. |
| `block_if_missing_evidence`, `require_approval`, `require_passed_evaluation_for_promotion`, `require_risk_review_for_promotion` | Event-type `gates` in the bundle | Not automatic. Write each gate you need, then test it. |

After migration, verify each control with a test before deployment. A legacy flag with no bundle
equivalent has **no effect in production**, so an operator must not assume it still applies.

## Key rotation

1. Generate a new key. Add its public key to the trust store alongside the current one.
2. Sign a new bundle with the new key and a new `version`. Deploy it.
3. After every bundle that might still be in use is re-signed, remove the old public key.

For a suspected compromise, remove the public key from the trust store first, then re-sign with a new
key and deploy. Removing the key rejects all bundles signed with it at the next startup.

## Anti-rollback

In staging and production, each accepted bundle's version is recorded per `policy_id` in
`<GOVAI_LEDGER_DIR>/policy_watermark.json`. The record is written only after a bundle passes signature
verification and the production contract.

- A bundle with a **lower** version than the record is refused (`rollback refused`).
- A bundle with the **same** version and the **same** document digest is accepted. Re-signing the same
  content to extend the expiry keeps the digest, so it is allowed.
- A bundle with the **same** version and **different** content is refused. A content change needs a new version.
- A **higher** version is accepted, and the record advances.
- The version must be a plain non-negative integer (`1`, `2`, ...). Forms such as `1.0`, `v1`, or `01` are refused.
- A missing record on first start is created. A record that is unreadable, malformed, or has unknown fields
  refuses startup. Nothing is silently reset.

## Rollback

Rolling back the content of a policy means publishing it again under a **new, higher version**. The
service will not accept an older version number, even when the older bundle is still correctly signed.

1. Take the older content, set `version` to the next integer, and sign it with the production procedure.
2. Deploy it. Verify startup and the approval, evidence, and verdict checks.
3. Keep the previous bundles for audit. They cannot be redeployed.

Limits:

- The watermark lives on the ledger volume. Anyone who can write that volume can reset it, which is the
  same trust boundary as the ledger itself. An operator who deletes the record is recording a decision, and
  it must be logged.
- A single volume serves one instance. Several replicas sharing a volume would need a lock, which is not
  implemented.
- Development is unchanged: no watermark is kept there.

Verified by unit tests (`rust/src/policy_watermark.rs`) and by a cross-restart scenario in the local
harness (`scripts/staging_policy_verify.py`, `rollback.*` checks), which starts the real binary several times
against one ledger.

## Flags and settings that are invalid in production

| Setting | Production behavior |
|---------|---------------------|
| `AIGOV_POLICY_FILE` | Refused at startup |
| `AIGOV_ALLOW_UNSIGNED_POLICY_FILE` | Refused at startup |
| `AIGOV_APPROVER_ALLOWLIST` | Refused at startup |
| `policy.prod.json` in `AIGOV_POLICY_DIR` | Not read; a signed bundle is required |
| Legacy-only signature records (no `payload_version`) with `expires_at_utc` | Refused |
| Bundles with `verdict_rules`, `inherits`, non-global `selectors`, or a `human_approved` rule without an allowlist gate | Refused |

## Tests

- Rust: `rust/src/policy_watermark.rs` (anti-rollback), `rust/tests/tb_*.rs` (startup and verdict path, one binary per scenario, each asserting the
  refusal reason), `rust/tests/tb_http_verdict.rs` (router-level verdict through a signed bundle),
  and `policy_signing` unit tests (cross-language digest vector).
- Python: `python/tests/test_policy_bundle_v2.py` (tampering, expiry, legacy expiry, downgrade,
  unknown key) and `python/tests/test_cli_signing_key_input.py` (v2 record from the CLI).

## Residual gaps

- Replay of a valid, unexpired bundle is not prevented.
- No monotonic version enforcement (see Rollback).
- Staging still reads the unsigned policy file when the opt-in is set. That path is a risk
  acceptance for staging, not a production option.
- Key custody is file-based. KMS-backed signing is not part of this change.
