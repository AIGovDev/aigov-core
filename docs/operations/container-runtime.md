# AIGov Core container runtime

Status: 2026-11-24.

This describes how to build the runtime image reproducibly, what the image contains, how it runs, and
how migrations work. Operator instructions for the local staging stack are in
`docs/operations/staging-policy-verification.md`.

## Reproducible build

From the repository root, on a clean checkout:

```sh
docker build --no-cache -t aigov-core:local .
docker image inspect aigov-core:local --format '{{.Id}} {{.Config.User}}'
```

- `--no-cache` ensures no local layer is reused. The CI job `container-runtime` runs this on a fresh
  runner.
- Base images are pinned by digest in the `Dockerfile`: `rust:1-bookworm` for the build stage and
  `debian:bookworm-slim` for the runtime stage. Refresh them deliberately.
- The Rust build uses `cargo build --locked`, so `rust/Cargo.lock` must match `rust/Cargo.toml`.
- The image identity is its ID. Record it with the commit SHA when you report a build.

Checks:

```sh
docker buildx build --check -f Dockerfile .
trivy config --severity CRITICAL,HIGH --exit-code 1 Dockerfile deployments
trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 aigov-core:local
```

The image scan needs Trivy's vulnerability database. CI runs it with the pinned Trivy action.

## What the runtime image contains

- `/app/aigov_audit`, the release binary, owned by root and not writable by the service user.
- The runtime libraries it links against (`libssl3`, `libpq5`, `ca-certificates`), and `bash`, which
  the health check uses.
- `/app/policies`, an empty directory, owned by root and read-only to the service. Signed policy bundles
  are mounted here at runtime. Production refuses to start without one.
- `/var/lib/govai/ledger`, the writable ledger directory, owned by the service user.

It does not contain: source code, Cargo manifests, the migrations directory, compilers or build tools,
`curl`, unsigned policy files (`policy*.json`), private keys, API secrets, or production credentials.
The container tests check each of these.

## Runtime contract

| Property | Setting |
|----------|---------|
| User | `1000:1000` (`govai`), no login shell, home `/nonexistent` |
| Root filesystem | read-only (`read_only: true` in compose; `readOnlyRootFilesystem: true` in Kubernetes and Helm) |
| Writable paths | `/var/lib/govai/ledger` (volume) and `/tmp` (tmpfs or emptyDir, 64 MiB, `noexec,nosuid`) |
| Capabilities | all dropped (`cap_drop: ALL`) |
| Privilege escalation | disabled (`no-new-privileges`, `allowPrivilegeEscalation: false`) |
| Seccomp | `RuntimeDefault` in Kubernetes and Helm |
| Policy bundle and trust store | mounted read-only at `/app/policies` |
| Listening address | `0.0.0.0:8088` inside the container; publish to loopback only in compose |
| Health check | in the image: reads `/health` over TCP with bash; no `curl` |

Secrets and policy are supplied at deploy time, never in the image:

- `DATABASE_URL`, `GOVAI_API_KEYS`, `GOVAI_API_KEYS_JSON`: environment (from a secret store).
- `AIGOV_POLICY_BUNDLE_FILE` and `AIGOV_POLICY_TRUST_ED25519_JSON`: environment and the read-only mount.
  The trust store must contain public keys only.

## Migrations

The migrations in `rust/migrations/` are compiled into the binary with `sqlx::migrate!`. At runtime the
binary applies them from its own embedded copy, so the runtime image needs no source tree. Before this
change the binary read the migrations from a build-time path that the runtime image did not contain, so
an image with `GOVAI_AUTO_MIGRATE=true` could not start.

- `GOVAI_AUTO_MIGRATE=true`: apply pending migrations at startup. The image default is `false`.
- With `false`, readiness requires that every expected migration is recorded in `_sqlx_migrations`.
  Apply them out-of-band, or enable auto-migrate.
- The container tests check that the number of recorded successful migrations equals the number of
  `.sql` files in `rust/migrations/`, and that a restart keeps the recorded state.

## Fail-closed behavior

The image starts only when its configuration is valid. These refusals were checked against the built
image (see `python/tests/test_container_runtime.py`):

- production (`AIGOV_ENVIRONMENT=prod`, the image default) without a signed bundle: refused;
- staging with a tampered, expired, untrusted-key, or unsigned bundle: refused, each with its specific
  message;
- staging with a bundle configured and an unsigned policy-file override (`AIGOV_POLICY_FILE`): refused.

## Operator notes

- The image tag `latest` in the Kubernetes manifest and the Helm values is an operator decision. Pin an
  image digest or a release tag before deploying.
- The Helm chart was edited for the runtime contract but not rendered in this change, because `helm`
  is not installed on the development machine. Render it in CI or locally before deployment.
- `rust/Dockerfile` is a second image definition. It runs as the same non-root user and has no policy
  files, but it does not create `/app/policies` and nothing in the repository builds it in CI. Prefer the
  root `Dockerfile`.
