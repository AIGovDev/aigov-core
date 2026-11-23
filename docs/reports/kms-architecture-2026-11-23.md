# External KMS architecture — 2026-11-23

## Question

Which AIGov Core components sign, which only verify, whether any production workflow needs an external KMS, and which provider and algorithm would preserve the existing Ed25519 signature format.

## 1. Production signing and verification paths (verified in code)

| Component | Role | Evidence |
|-----------|------|----------|
| Rust service `aigov_audit` (the only binary the Dockerfile copies) | Verifies only | `rust/src/policy_store.rs` (`verify_policy_signatures`, trust from `policy_signing::load_trust_store_from_env`); `rust/src/audit_export_verification.rs` (`verify_audit_export_ed25519_signature`) |
| Rust policy trust | Public keys only | `rust/src/policy_signing.rs::load_trust_store_from_env` reads `AIGOV_POLICY_TRUST_ED25519_JSON` (public keys) |
| Rust export signing function | Signs, **no production caller** | `rust/src/audit_export_signing.rs::sign_audit_export_ed25519`. Non-test callers: only `rust/src/bin/sign_audit_export_once.rs` |
| Rust signing binaries | Offline operator tooling, not in the runtime image | `rust/src/bin/sign_audit_export_once.rs`, `rust/src/bin/signing_pubkey_from_seed_once.rs` |
| Python CLI `aigov` (shipped in `aigov_py`) | Offline operator tooling | `python/aigov_py/cli.py`: `sign-audit-export` (`sign_audit_export_ed25519`), `policy sign-bundle` (`sign_policy_bundle_ed25519`) |
| Python verification | Public keys | `python/aigov_py/audit_export_signing.py::verify_audit_export_ed25519_signature`, `policy_bundle_signing.py::verify_policy_bundle_ed25519` |
| `VercelKMSProvider` / `LocalEd25519KMSProvider` | Not in any shipped entry point | `benchmarks/agent-verification/asymmetric_kms_provider.py`; the only reference outside it is an unused import in `benchmarks/openai-agents-integration/tests/test_sdk_production.py` |

Callers in deployment: none. Nothing in `.github/`, `Dockerfile`, `rust/Dockerfile`, `Makefile`, or `scripts/` invokes a signing command or the KMS provider.

## 2. Where private signing keys originate and how they are passed

- **Origin:** not defined anywhere in the repository. An operator generates the Ed25519 seed outside the codebase.
- **Passing before this PR:** on the command line, in three places:
  - `aigov sign-audit-export --private-key-base64 …` and `aigov policy sign-bundle --private-key-base64 …` (`python/aigov_py/cli.py`);
  - `sign_audit_export_once <…> <seed-hex>` and `signing_pubkey_from_seed_once <seed-hex>` (Rust bins).
  A key in argv is visible to other users through the process list, and it is written to shell history.
- **Storage:** not defined. The repository stores no private keys. Public keys are stored in the trust configuration.

## 3. Is KMS required for an existing production workflow?

No. The running service never holds a private key and never signs. The only signing is offline operator tooling, and no deployment invokes it. An external KMS is therefore not required by any existing production workflow. Adding one to the runtime would add a dependency to a verification-only service with no current signer to serve.

KMS becomes relevant only when operators must produce signatures centrally, without holding seeds. That is a future workflow, not an existing one.

## 4. Vercel KMS (verified against official documentation)

Sources: [sign a message](https://vercel.com/docs/rest-api/kms/sign-a-message), [get an issuer](https://vercel.com/docs/rest-api/kms/get-an-issuer), [create a signing key](https://vercel.com/docs/rest-api/kms/create-a-signing-key), [authentication](https://vercel.com/docs/kms/concepts/authentication).

- Sign: `POST /v1/kms/issuers/{issuerId}/sign/message`, body `{"message": <standard base64>}`, response `signature` (standard base64).
- JWKS: `https://kms.vercel.com/<issuerId>/jwks.json`. The `GET /v1/kms/issuers/{issuerId}` response has **no `jwks` object** (its top-level properties are `algorithm`, `claimsSchema`, `createdAt`, `discoveryLayout`, `id`, `managedBy`, `name`, `origin`, `ownerId`, `policies`, `signingKeys`, `updatedAt`). PR #486 used that endpoint for JWKS and is wrong on this point.
- Algorithm: the issuer `algorithm` enum is `ES256, ES384, ES512, PS256, PS384, PS512, RS256, RS384, RS512`. **No EdDSA or Ed25519 value exists in the documented schema.** PR #486's prerequisite ("create a KMS issuer with algorithm=EdDSA") cannot be satisfied.
- Export: no export endpoint is documented.

**Conclusion:** Vercel KMS cannot produce the AIGov Ed25519 signature format, so it is not a candidate. `VercelKMSProvider` now refuses construction (see §7).

## 5. Provider comparison

Algorithms are listed only where the provider documentation states them. Where a claim comes from a search snippet and not a verified page, it is marked.

| Provider | Ed25519 / EdDSA | ECDSA | RSA | Private key stays in provider | Source |
|----------|-----------------|-------|-----|-------------------------------|--------|
| AWS KMS | Yes: key spec `ECC_NIST_EDWARDS25519`; signing algorithms `ED25519_SHA_512` (pure EdDSA, MessageType `RAW`) and `ED25519_PH_SHA_512` (prehash, MessageType `DIGEST`, which KMS hashes again). Message limit 4096 bytes. | Yes | Yes | Yes (no export of a KMS-generated key) | [key specs](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html), [Sign API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html) |
| Google Cloud KMS | Yes: `EC_SIGN_ED25519` (PureEdDSA on Curve25519, raw input), key purpose `ASYMMETRIC_SIGN` | Yes: P-256, P-384, secp256k1 | Yes | Yes | [algorithms](https://docs.cloud.google.com/kms/docs/algorithms) |
| HashiCorp Vault Transit | Yes: `ed25519`. Not certified in FIPS 140-3 mode. Prehashed `ed25519ph` requires Enterprise (from a search snippet, not a verified page). | Yes | Yes | Yes, when the key is created non-exportable (not verified here) | [transit](https://developer.hashicorp.com/vault/docs/secrets/transit) |
| Vercel KMS | **Not documented** (issuer algorithm enum has no EdDSA) | Yes (ES256/384/512) | Yes (RS/PS 256/384/512) | No export documented | Section 4 |

### Compatibility with the AIGov format

The AIGov format uses standard Ed25519 (RFC 8032, pure EdDSA) over these inputs:
- policy bundles: the 64-character hex SHA-256 digest of the canonical payload, as UTF-8 bytes;
- audit exports: the canonical signing payload.

Implications:
- AWS `ED25519_SHA_512` with MessageType `RAW` is pure EdDSA. For inputs up to 4096 bytes it should produce signatures verifiable by the existing verifier. The policy digest (64 bytes) fits. A large audit-export payload may not, and the caller would need a different path. **Not verified live.**
- AWS `ED25519_PH_SHA_512` signs a prehash. Signatures from it are **not** interchangeable with the AIGov format and must not be used.
- Google `EC_SIGN_ED25519` is pure EdDSA on raw data. It should be compatible with the existing verifier. Its input size limit was not checked in the documentation read here. **Not verified live.**
- Vault `ed25519` is pure EdDSA. It should be compatible. **Not verified live.**
- Any KMS-produced signature must still be checked by the existing verifier before it is trusted. A compatibility test needs a live key.

## 6. Recommendation

1. Keep the runtime verification-only. Do not add KMS to `aigov_audit`.
2. Remove the argv exposure for seeds (implemented, §8).
3. If operators need centralized signing, choose Google Cloud KMS `EC_SIGN_ED25519` or AWS KMS `ED25519_SHA_512` (RAW), after a live contract test that signs a real policy digest and an export payload and verifies both with the existing verifier. Vault Transit is the self-hosted alternative. Vercel KMS is excluded.
4. Do not wire any KMS into a shipped entry point until the live test has passed and the owner has approved the provider and the account.

## 7. Implemented in this PR

- **VercelKMSProvider fail-closed.** `benchmarks/agent-verification/asymmetric_kms_provider.py`: the constructor raises `AsymmetricKMSUnavailableError`. The documented API has no Ed25519 issuer algorithm, and the JWKS path was never verified. Test: `python/tests/test_vercel_kms_fail_closed.py`.
- **Rust seed input.** `rust/src/audit_export_signing.rs` adds `parse_seed_hex_strict` (exactly 64 hex characters, errors never echo input), `read_seed_hex_file` (refused on Unix unless mode excludes group and other), and `read_seed_hex_from_reader` (capped at 1 KiB, used for stdin).
- **Rust binaries.** `sign_audit_export_once` and `signing_pubkey_from_seed_once` accept `--seed-file <path>` or `--seed-stdin`. A seed on the command line requires `--allow-seed-argv` and prints a warning. Without any source the binary exits 2 and writes nothing. The old `expect` panics on malformed hex are replaced with clean errors. Tests: `rust/tests/signing_seed_sources.rs` (9 tests, including an end-to-end sign with a seed file whose signature verifies against the public key).
- **Python CLI.** `python/aigov_py/cli.py`: `--private-key-file` (refused unless mode excludes group and other, and non-empty). `--private-key-base64` is refused unless `--allow-private-key-argv` is given. Tests: `python/tests/test_cli_signing_key_input.py` (10 tests).

### Migration path for existing users

- Scripts that pass `--private-key-base64` or a seed argument now fail until they add `--allow-private-key-argv` or `--allow-seed-argv`. Better: write the key to a file with mode 600 and use `--private-key-file` or `--seed-file`.
- Signature format and verification are unchanged. The Rust round-trip test and the Python tests confirm this.

### Trade-offs (not solved by any of these)

- **Seed file:** protected only by file mode and the host's access controls. Backups, disk snapshots, and shared administrator accounts can expose it.
- **Stdin:** keeps the key out of argv, but whatever produces stdin (a secret manager, a pipe from another command) may log or expose it.
- **Environment variables:** not used. They are visible to the same user through `/proc/<pid>/environ` and to child processes. They do not solve argv exposure on their own.

## 8. Tests run

| Suite | Result |
|-------|--------|
| Rust `cargo test --locked` (no PostgreSQL) | 185 passed, 0 failed, 0 ignored |
| `rust/tests/signing_seed_sources.rs` | 9 passed |
| Python `test_cli_signing_key_input.py` | 10 passed |
| Python `test_vercel_kms_fail_closed.py` | 1 passed |
| Full Python suite, no database | 937 passed, 84 skipped |
| `make` gates (8 targets) | all exit 0 |
| CLA workflow security guard | PASS (CLA files not modified) |
| Report gate | PASS |
| `ruff` on changed files | no new findings versus the staging baseline |
| `mypy` on `cli.py` | no findings in the new code (file-level findings predate this work) |
| `clippy -D warnings` | fails crate-wide on pre-existing lints; none in changed code |

Not run: the PostgreSQL-backed suites (no database container in this session). The changed code does not touch PostgreSQL. Skipped tests are not counted as live evidence.

## 9. Not verified live (blocked)

- Any KMS signing call against AWS, Google Cloud, Vault, or Vercel. No credentials, no paid resources.
- Compatibility of a KMS-produced signature with the existing verifier. Requires a live key.
- Google Cloud input-size limit for `EC_SIGN_ED25519` and AWS limits for the export payload path.

## Evaluation gate

Passes when the Rust and Python suites, the signature compatibility round-trip, the seed-source regression tests, and the make gates pass on the PR head. Those results are recorded in section 8. The provider comparison rests on the documentation pages cited in sections 4 and 5. Live provider behavior is not claimed.

## Human approval gate

Not approved for production by this report.

- Requires your approval or credentials:
  - choosing the production KMS provider, and the account to use;
  - provisioning any paid KMS key, or any cloud account, for a live contract test;
  - moving signing into any shipped entry point;
  - whether to delete `VercelKMSProvider` from the repository (it is now disabled, not removed);
  - the migration timing for scripts that rely on the old command-line key flags.
- Production remains NO-GO until the owner selects a signing path, a live contract test passes for it, and the production configuration is verified (section 5 of the release-readiness report still applies).
