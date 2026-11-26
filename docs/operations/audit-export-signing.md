# Audit export signatures — format v2 and migration

Status: 2026-11-23. Applies to `aigov.audit_export.v1` documents signed with Ed25519.

## What the signature covers

| Record | Digest input | Expiry |
|--------|--------------|--------|
| v2 (`"payload_version": 2`, written by this release) | canonical JSON of: the content payload (schema, run id, policy version, environment, bundle hash, events hash, chain head, verdict), `issuer_id`, `signer`, `created_at_utc`, `expires_at_utc`, and `document_sha256` (SHA-256 of the whole export without its `signatures` array) | enforced: a signature at or after `expires_at_utc` is rejected |
| v1 (no `payload_version`, written before this release) | the content payload only | cannot carry an expiry; a record with `expires_at_utc` is rejected |

Any change to the signer label, creation time, expiry, or any field of the export (including `evidence_hashes.log_chain`) invalidates a v2 signature.

## Rules for signed exports

- Documents must not contain floating-point numbers. Both the Rust and the Python implementations refuse them, because their number formatting can differ.
- Only the `signatures` array is excluded from the document digest, so additional signatures can be appended without breaking existing ones.

## Migration

1. Existing v1 signatures keep verifying. They do not cover signer, time or expiry, so treat their metadata as informational.
2. To get expiry and full binding, re-sign the export with this release: `aigov sign-audit-export --private-key-file <file> ...` or `sign_audit_export_once --seed-file <file> ...`.
3. Do not strip `payload_version` from a v2 record to force v1 verification. The digests differ, so the signature will not verify.
4. Key handling: keep the seed in a file with mode 600 and use `--private-key-file` / `--seed-file`. Command-line seeds require an explicit opt-in (see the changelog for the CLI and the signing binaries).

## Not covered by this format

- Freshness and replay: a valid, unexpired export signed earlier is still accepted. Replay protection needs a verifier-side nonce or a freshness policy, which is not implemented.
- Key custody: the signing key's storage is outside this format. See the KMS architecture report for provider options.
