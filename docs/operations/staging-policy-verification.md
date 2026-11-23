# Staging verification of signed policy bundles

Status: 2026-11-23.

This document describes how to verify signed Ed25519 v2 policy bundles and the verdict path, first
locally and then against a deployed staging service. It separates what is verified in simulation from
what requires a real deployment.

## Two scopes, never mixed

| Scope | What it proves | What it does not prove |
|-------|----------------|------------------------|
| `local_simulation` | The release binary, started by the harness with disposable keys and synthetic policies, refuses or admits startup and requests as specified. | Anything about a deployed environment, its trust store, its bundle, its database, or its network. |
| `live_staging` | A deployed staging service responds with the expected health, authentication, and authorization behavior. | Which policy bundle the service is running. The harness cannot see that, and reports nothing about it. |

Evidence records the scope on every check. A `live_staging` check reported as `blocked` means the
deployed service was not checked. It is never counted as passed.

## Local verification (no infrastructure)

Requirements: Rust stable, Python 3.11 or later.

```sh
cd rust && cargo build --release --locked && cd ..
python -m venv python/.venv && . python/.venv/bin/activate
pip install -e "python[dev]"
pytest -q python/tests/test_staging_policy_verify.py
python scripts/staging_policy_verify.py --skip-live --out artifacts/staging-verify/local-evidence.json
```

The harness generates a fresh Ed25519 key in memory for each run. The private key is never written to
disk or evidence; only the public-key fingerprint is recorded. Policies are synthetic. The harness uses
the production signer (`aigov_py.policy_bundle_signing`) and the release binary, so the signature and
startup checks exercise real code.

Exit status 0 means every local check passed. The evidence file lists each check with its expected and
observed value.

## Live verification against a deployed staging service

The live checks are infrastructure-level only: health, unauthenticated rejection, invalid-key rejection,
and an authorized verdict read. They do not depend on the bundle the service runs.

### Minimum infrastructure

1. A deployed AIGov Core service running with `AIGOV_ENVIRONMENT=staging`.
2. A hostname with an explicit `staging`, `stg`, or `test` token (for example `api.staging.example.com`
   or `govai-staging.example.com`). The harness refuses other hosts, so it cannot be pointed at
   production by mistake. This is a guard on operator input, not an authentication of the host.
3. The service's signed bundle configured through `AIGOV_POLICY_BUNDLE_FILE` or a `policy.bundle.staging.json`
   in `AIGOV_POLICY_DIR`, with `AIGOV_POLICY_TRUST_ED25519_JSON` containing only the staging public keys.
4. A staging API key in the `staging` GitHub environment as the secret `GOVAI_STAGING_API_KEY`.
5. The repository variable `GOVAI_STAGING_BASE_URL` set to the service's base URL.

Without items 1, 4, and 5, the live checks are recorded as `blocked`. The repository currently has
none of these configured, so live verification has not been run.

### Running

From the Actions tab, run the `staging-policy-verify` workflow manually (`workflow_dispatch`). The
`live-staging` job runs only when `GOVAI_STAGING_BASE_URL` is set, uses the `staging` environment, and
writes `live-evidence.json` as a workflow artifact.

Or locally:

```sh
GOVAI_STAGING_BASE_URL=https://api.staging.example.com \
GOVAI_STAGING_API_KEY="$(cat /secure/path/staging-key)" \
python scripts/staging_policy_verify.py --skip-local --require-live \
  --out artifacts/staging-verify/live-evidence.json
```

`--require-live` exits with status 2 when live checks are blocked, so a missing configuration cannot
look like success.

Pointing the live checks at `localhost` requires `--allow-local-for-self-test`. The result is then a
self-test of the harness, not staging evidence, and its scope must not be cited as staging evidence.

## What the harness verifies locally

Bundle loading and trust (staging):

- a valid signed v2 bundle with future expiry starts the service;
- an expired bundle is refused;
- a bundle edited after signing is refused (payload digest mismatch);
- a bundle signed by a key absent from the trust store is refused;
- an unsigned bundle is refused;
- a configured bundle path that does not exist is refused;
- a v1 record carrying an expiry is refused.

Unsigned and production overrides:

- an unsigned policy file is refused in staging without the explicit opt-in;
- `AIGOV_POLICY_FILE` is refused in production;
- `AIGOV_ALLOW_UNSIGNED_POLICY_FILE` is refused in production;
- `AIGOV_APPROVER_ALLOWLIST` is refused in production;
- production without a signed bundle is refused;
- development still starts with an unsigned file (compatibility control).

HTTP verdict behavior (against a service started with the valid bundle):

- health responds; evidence ingest without a key returns 401; verdict reads without a key return 401;
- verdict for a run with no evidence returns 404 `run_not_found`, not an invented verdict;
- an allowed event is admitted;
- promotion is refused without a passed evaluation, and remains refused after a failed evaluation;
- promotion is admitted after a passed evaluation;
- an approval by an approver outside the signed allowlist is refused;
- an approval by an allowlisted approver is admitted;
- the verdict summary is available after the flow.

Refusals are matched on the specific gate or startup message, not on any refusal.

## Changes that operators must know about

- **Staging with a configured signed bundle now uses the bundle as the only policy source.** Before
  this change, staging refused to start with a valid bundle, because it still required a legacy policy
  file. The verification harness found this defect. In staging, once a bundle is configured,
  `AIGOV_POLICY_FILE`, `AIGOV_ALLOW_UNSIGNED_POLICY_FILE`, and `AIGOV_APPROVER_ALLOWLIST` are refused.
  Staging without a bundle keeps its previous behavior.
- Production behavior is unchanged from the previous change: a signed bundle is required.
- Gate refusals return the gate's message in `error.message`. The gate code (for example
  `evaluation_not_passed`) is not returned to clients. Clients that match on it must match on the message.

## Residual risks and blockers

- Live staging has not been verified. No deployed staging service, staging API key, or staging
  hostname is configured for this repository.
- The harness does not check which bundle a deployed service runs, so bundle verification on a live
  service needs an operator to confirm the bundle hash out of band.
- Replay of a valid, unexpired bundle, and rollback to an older valid bundle, are not prevented.
- Key custody is file-based. KMS-backed signing is not implemented.
