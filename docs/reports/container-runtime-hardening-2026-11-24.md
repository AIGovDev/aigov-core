# Container runtime hardening and reproducible builds — 2026-11-24

## Scope

Hardens the AIGov Core runtime image before remote staging deployment: fixes the migration startup
defect, runs as non-root with a read-only root filesystem, removes build tools, source, migrations, and
unsigned policy files from the image, mounts signed bundles read-only, and adds container tests and a
CI workflow. Builds on PR #495 (local staging deployment), merged as `79a6d8a`.

No production deployment, no production secrets, no changes to `main`, no CLA workflow changes, no
paid infrastructure, no change to external credentials, no weakening of fail-closed behavior or of the
Ed25519 verification and human approval gates.

## 1. Migration defect and fix

**Defect.** The binary applied migrations from `CARGO_MANIFEST_DIR/migrations`, a build-time path.
The runtime image did not contain it, so with `GOVAI_AUTO_MIGRATE=true` the container crash-looped with
`migration source error: ... /build/migrations`. The earlier fix copied the directory to that path in the
runtime image. That fix relied on a source-tree path and is replaced here.

**Fix.** `rust/src/db.rs` now embeds the migrations at compile time with `sqlx::migrate!("./migrations")`.
The sqlx `macros` feature is enabled in `rust/Cargo.toml`, and `rust/Cargo.lock` gains one dependency
edge (`sqlx-macros` for `sqlx`). The runtime image needs no migrations directory.

Verification:

- The container starts with `GOVAI_AUTO_MIGRATE=true` against a fresh Postgres, reports ready, and records
  the same number of successful migrations as there are `.sql` files in `rust/migrations/` (2).
- A restart keeps the recorded state and readiness.

## 2. Runtime image changes

| Change | Before | After |
|--------|--------|-------|
| User | root in the image's default | `1000:1000` (`govai`), no login shell |
| Policy files | `policy.json`, `policy.dev.json`, `policy.staging.json`, `policy.prod.json` copied into `/app/policies` | none; `/app/policies` is an empty read-only directory for mounted bundles |
| Migrations | copied to `/build/migrations` | none (embedded in the binary) |
| Source and build tools | builder stage only | builder stage only; runtime has no compiler or Cargo |
| `curl` | installed for health checks | removed; the health check uses bash over TCP |
| Binary | built in place | built, stripped, and copied to `/app` owned by root, not writable by the service |
| Read-only root | not set | set in compose (`read_only: true`), Kubernetes and Helm (`readOnlyRootFilesystem: true`) |
| Writable paths | everything | ledger volume and `/tmp` only (tmpfs or emptyDir, 64 MiB, `noexec,nosuid`) |
| Capabilities and escalation | not restricted | all capabilities dropped; `no-new-privileges`; `allowPrivilegeEscalation: false`; seccomp `RuntimeDefault` (Kubernetes and Helm) |

The second image definition, `rust/Dockerfile`, received the same user and policy-file changes and a
health check. Nothing in the repository builds it in CI.

Secrets and bundles are not in the image. Trust stores contain public keys only, mounted read-only.
The signing seed for the staging bundle is never written (checked by `prepare`).

## 3. Container tests

`python/tests/test_container_runtime.py` starts the real image. Fifteen tests:

| Area | Tests |
|------|-------|
| Image contents | non-root user (uid 1000); no source, Cargo files, migrations, or policy files; no compilers or build tools; binary links with no unresolved libraries; health check configured |
| Fail-closed startup | production without a bundle refused; staging refuses tampered, expired, untrusted-key, and unsigned bundles, each on its message; unsigned policy-file override refused when a bundle is configured |
| Read-only start | service starts with a read-only root and a signed bundle; `/health` and `/ready` return 200; writing to `/app` fails |
| Migrations | applied once, count equals the embedded `.sql` files; restart keeps migrations and readiness |

Test scratch material goes under the git-ignored `artifacts/container-tests/`. With Docker unavailable the
tests skip. In CI `AIGOV_REQUIRE_CONTAINER_TESTS=1` turns any skip into a failure.

**Defect found by the test run.** The restart test read the old published port after `docker restart`,
which assigned a new random host port. The service was healthy on the new port. The test now re-reads the
published port.

## 4. Build, scan, and deployment verification

| Check | Result |
|-------|--------|
| `docker build --no-cache` of the hardened image from the working tree | succeeds |
| Container tests (`test_container_runtime.py`), local | 15 passed, 0 failed |
| Local staging stack on the hardened image, read-only, non-root, all capabilities dropped | 28 of 28 deployed checks passed (`local_container`) |
| Trivy configuration scan, CRITICAL and HIGH, `Dockerfile`, `rust/Dockerfile`, `deployments` | no findings |
| `docker buildx build --check` on `Dockerfile` | no warnings |
| Trivy image vulnerability scan | **not run locally**: the scanner could not download its vulnerability database from this sandbox. CI runs it with the pinned Trivy action, with `ignore-unfixed` and a CRITICAL/HIGH gate. |

Clean build from the committed tree (the requirement to verify builds from the repository) is recorded in
section 7 with its commit SHA.

## 5. Test results

| Suite | Result |
|-------|--------|
| Rust `cargo test --locked` | 237 passed, 0 failed, 0 ignored |
| Python `pytest python/tests`, no database | 1071 passed, 41 skipped (database-gated); includes the 15 container tests and 20 harness tests |
| `make gate` | passes |
| `ruff`, `mypy` on the touched Python | clean |
| Skips | not counted as passing |

## 6. Security assessment

- The runtime process runs as an unprivileged user and cannot write outside `/var/lib/govai/ledger` and
  `/tmp`. Its binary is root-owned and read-only to it.
- No compiler, package manager use at runtime, shell utilities beyond bash, or network tools are needed for
  the service. `curl` is removed.
- The image contains no unsigned policy files. Production refuses to start without a signed bundle, and the
  container tests check this against the built image.
- Staging refuses each invalid bundle class and refuses the unsigned override on the built image.
- Residual risks: Trivy's image scan is pending in CI; the image tag `latest` in the Kubernetes manifest and
  Helm values is an operator decision; the Helm chart was not rendered in this change (no `helm` installed);
  the API does not expose the loaded bundle identity; replay and rollback of a valid bundle are unchanged.

## 7. Commit and clean build

Commit and clean-build SHA: recorded in the pull request description after the final commit, with the
container tests and the staging verification re-run on that clean build.

## Evaluation gate

Passes when the clean image build succeeds from the repository, the container tests pass against the built
image with no skips, the Rust and Python suites pass, the configuration scans pass, the deployed stack passes
its verification on the hardened image, and `make gate` passes. Sections 4 and 5 record these results for the
working tree; the CI run on the pull request is the authoritative record for the committed tree. The Trivy
image vulnerability scan is pending in CI.

## Human approval gate

Not approved for production by this report.

- **STAGING GO (container image, local stack):** the hardened image runs the staging contract on this machine.
- **STAGING GO (remote): NO-GO.** No remote environment has been deployed or verified in this change.
- **PRODUCTION GO: NO-GO.** The Trivy image scan has not run, the image tag used in production has not been
  chosen, no production signed bundle exists, and the production trust store is not configured.
- Requires your decision: which image tag or digest to deploy, and whether to accept the Trivy result as the
  release gate.
