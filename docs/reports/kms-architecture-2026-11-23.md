# External KMS architecture — 2026-11-23

## Question

Does AIGov Core need an external KMS for asymmetric signing, which runtime needs it, and which provider and algorithm are supported?

## What the production runtime does (evidence)

- The shipped runtime is the Rust service `aigov_audit`. The Dockerfile copies only that binary.
- The service only **verifies** signatures. `rust/src/policy_store.rs` loads a trust store of public keys from `AIGOV_POLICY_TRUST_ED25519_JSON` and calls `verify_policy_signatures`. `rust/src/audit_export_verification.rs` verifies signed audit exports.
- No code path in the server signs anything. `sign_audit_export_ed25519` is called only from tests and from the offline binary `sign_audit_export_once`.
- No route, background task, or startup step holds a private key. The service needs public keys only.

## Where signing actually happens (evidence)

- **Offline operator tooling**, all taking the Ed25519 seed as input:
  - Python CLI `aigov` (shipped in `aigov_py`): `sign-audit-export` and `policy sign-bundle`.
  - Rust binaries `sign_audit_export_once` and `signing_pubkey_from_seed_once`, not in the runtime image.
- **Callers in deployment**: none. Nothing in `.github/`, `Dockerfile`, `rust/Dockerfile`, `Makefile`, or `scripts/` invokes the signing commands.
- **Real deployment of `VercelKMSProvider`**: none. The class is referenced only from `benchmarks/agent-verification`.

## Conclusion on requirement 2

The running service does not need KMS. Asymmetric signing exists in offline operator tooling only, and nothing deploys it. The real exposure is the tooling itself: the Python CLI required the private key on the command line (`--private-key-base64`), which places it in the process list and shell history. The Rust binary takes a hex seed as an argument, the same way.

## VercelKMSProvider against the official documentation (requirement 3)

Verified against https://vercel.com/docs/rest-api/kms/sign-a-message, https://vercel.com/docs/rest-api/kms/create-a-signing-key, and https://vercel.com/docs/kms/concepts/authentication.

| Aspect | Code assumes | Documentation says | Verdict |
|--------|--------------|--------------------|---------|
| Sign endpoint | `POST {base}/v1/sign` | `POST /v1/kms/issuers/{issuerId}/sign/message` | Wrong |
| Sign body | `{"keyId","data"}` (base64url) | `{"message"}` (standard base64) | Wrong |
| Sign response | `{"signature","keyId"}` | `algorithm`, `fingerprint`, `keyId`, `signature` (standard base64) | Partly wrong |
| Public keys | `GET /.well-known/jwks.json` | `https://kms.vercel.com/<issuerId>/jwks.json` | Wrong |
| Ed25519 | Assumed (`crv: Ed25519`) | Not stated; `algorithm` is a free string with no enum | **Unverified** |
| Private key export | Not claimed | No export endpoint documented; `importKey` only, on key creation | Not supported, not claimed |
| Auth | Vercel OIDC | Vercel OIDC bearer for signing | Consistent |

Conclusion: `VercelKMSProvider` cannot work against the documented API, and Ed25519 support is unverified. It must not be used.

## Provider comparison (requirement 4)

| Provider | Ed25519 | ECDSA | RSA | Private key stays in the service | Source |
|----------|---------|-------|-----|----------------------------------|--------|
| AWS KMS | Yes: `ECC_NIST_EDWARDS25519`, with `ED25519_SHA_512` (pure, `MessageType RAW`) and `ED25519_PH_SHA_512` (prehash, `DIGEST`). Message limit 4096 bytes, larger payloads need a caller digest. Verify must name the same algorithm. | Yes | Yes | Yes | https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html , https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html |
| Google Cloud KMS | Yes: `EC_SIGN_ED25519` (PureEdDSA on Curve25519, raw input). Requires key purpose `ASYMMETRIC_SIGN`. | Yes: P-256, P-384, secp256k1 | Yes | Yes | https://docs.cloud.google.com/kms/docs/algorithms |
| HashiCorp Vault Transit | Yes: `ed25519`. Not certified in FIPS 140-3 mode. `ed25519ph` needs Enterprise. | Yes | Yes | Yes, provided keys are not exported | https://developer.hashicorp.com/vault/docs/secrets/transit |

Ed25519 is available from all three. ECDSA and RSA are common to all three. None of the three requires a provider-specific workaround for Ed25519 at the algorithm level, but each has its own message-size and key-purpose rules that a verifier must match exactly.

## Recommendation (requirement 5)

1. **No KMS in the runtime now.** The service verifies with public keys only. Adding KMS there would add a dependency with no current signer to serve.
2. **Fix the real exposure now (implemented, below):** load the signing key from a protected file, not the command line.
3. **When operator signing must be centralized:** use a KMS through a documented, verified API. Google Cloud KMS `EC_SIGN_ED25519` or AWS KMS `ED25519_SHA_512` are the strongest candidates, because both document Ed25519 and no-export keys. Vault Transit is the option if the signer must stay self-hosted. Each needs live testing under an account the owner controls, which is a paid or credentialed step.
4. **Remove or quarantine `VercelKMSProvider`** before any real use, or rewrite it against the documented API after the provider is chosen.

## Implemented in this PR (requirement 6)

- `python/aigov_py/cli.py`: `sign-audit-export` and `policy sign-bundle` accept `--private-key-file`. The file must not be readable by group or others (refused otherwise), and it must be non-empty. Exactly one of `--private-key-file` or `--private-key-base64` must be given. The legacy flag still works, with a warning on stderr. This is backward compatible.
- `python/tests/test_cli_signing_key_input.py`: 9 tests. A key file with mode 600 signs and the signature verifies. Modes 644, 640, and 604 are refused. Missing and empty files are refused. Both sources and neither source are refused. The legacy path works and warns.

Not changed: the Rust binaries `sign_audit_export_once` and `signing_pubkey_from_seed_once`. They are outside the runtime image, and they take the seed as an argument. Recorded as a follow-up.

Not changed: `VercelKMSProvider`. Its docstring already states that its API shape is unverified (earlier PR). It is not wired into any runtime, so this PR does not add provider code.

## Tests run

| Suite | Result |
|-------|--------|
| `python/tests/test_cli_signing_key_input.py` | 9 passed |
| Full Python suite, no database | 935 passed, 84 skipped |
| `make` gates (8 targets) | all exit 0 |
| CLA workflow security guard | PASS |

The skip count differs from the earlier 972/38 because the release binary was removed during cleanup. The staging E2E tests need that binary and skip without it.

## Evaluation gate

The CLI change passes its tests and does not alter the runtime, the Rust service, or any CLA file. The architecture conclusions rest on the code paths listed above and on the three documentation pages linked, not on any live provider call.

## Human approval gate

Not approved for production by this report.

- Requires your approval or credentials:
  - choosing the production KMS provider (Google Cloud KMS, AWS KMS, or Vault);
  - provisioning any paid KMS key, or any account, for live testing;
  - any change that moves signing into the running service;
  - the decision on whether `VercelKMSProvider` stays in the repository.
- Production remains NO-GO until the owner confirms which signing path operators will use, and that path is tested live.
