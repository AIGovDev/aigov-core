# Staging verification of signed policy bundles

Status: 2026-11-23.

This document describes how to verify signed Ed25519 v2 policy bundles and the verdict path, first
locally and then against a deployed staging service. It separates what is verified in simulation from
what requires a real deployment.

## Two scopes, never mixed

| Scope | What it proves | What it does not prove |
|-------|----------------|------------------------|
| `local_simulation` | The release binary, started by the harness with disposable keys and synthetic policies, refuses or admits startup and requests as specified. | Anything about a deployed environment, its trust store, its bundle, its database, or its network. |
| `local_container` | A container of the built image, running on this machine with the staging overlay, has the expected identity and bundle hash, responds with the expected behavior, and refuses invalid bundles. | Any remote environment, network path, TLS, DNS, or secret management of a remote host. |
| `live_staging` | A remotely deployed staging service responds with the expected health and authentication behavior. Bundle-dependent checks run only when the deployed bundle hash is verified, which a remote host cannot be from this machine. | Which bundle a remote service runs, unless an operator confirms it out of band. |

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

## Local staging deployment (container on this machine)

This is the only staging target that can be deployed from this repository without external
infrastructure. It runs the real image with Postgres under docker compose, bound to loopback.

```sh
PYTHON=python/.venv/bin/python scripts/staging_local_deploy.sh up      # build if missing, prepare, start
PYTHON=python/.venv/bin/python scripts/staging_local_deploy.sh verify  # live checks against the container
scripts/staging_local_deploy.sh status
scripts/staging_local_deploy.sh down                                    # keeps data volumes
```

`PYTHON` must point at an interpreter where `aigov_py` is installed (`pip install -e python[dev]`),
because `prepare` uses its signer.

What the deploy does:

- Writes secrets to `~/.config/aigov-staging/staging.env` (mode 0600), outside the repository. The
  API key and database password are generated locally and never printed.
- Runs `prepare` to create a synthetic Ed25519 v2 bundle, a public-key trust store, negative
  fixtures, and `expected-manifest.json` in `~/.config/aigov-staging/bundle` (mode 0700). The signing
  seed is held in memory during `prepare` and is never written; `prepare` checks this before it
  returns.
- Mounts only the live bundle, read-only, at `/app/policies`. Compose refuses to start if a required
  secret or the bundle location is unset.
- Binds the API to `127.0.0.1:8088`. Postgres publishes no port.

What `verify` checks, all recorded with scope `local_container`:

- the container is running, and it runs the image that was built;
- the SHA-256 of the mounted bundle equals `expected-manifest.json`;
- the infrastructure behavior (health, readiness, authentication) and the bundle-dependent HTTP
  behavior (evaluation, approvals, verdict), which run only after the bundle hash matches;
- the same image refuses to start with a tampered, expired, untrusted-key, or unsigned bundle, and
  refuses an unsigned policy file override while a bundle is configured. Each refusal is matched on
  its specific message.

Evidence is written to `artifacts/staging-verify/deployed-evidence.json`. It is git-ignored and is
not committed. It records the commit (with a `-dirty` marker if the tree differs from HEAD), the host
release binary hash, and the check results. The image itself is identified by its ID in the
`deployment.*` checks.

## Known limitations of the local target

- It is a container on one machine, not a remote environment. It has no TLS and no external DNS.
- The container's root filesystem is writable. Read-only root with tmpfs is a recommended hardening step.
- The API does not expose the loaded bundle's identity. The hash check reads the mounted file, so it
  verifies what the container was given, not what the process has loaded.
