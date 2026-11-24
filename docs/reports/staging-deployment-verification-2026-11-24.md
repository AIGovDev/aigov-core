# Staging deployment and live verification of signed policy bundles — 2026-11-24

## Scope

Deploys a minimal AIGov Core staging stack and verifies signed Ed25519 v2 policy bundles against
the running service. Builds on PR #492 (trust boundary), PR #493 (formatting), and PR #494 (staging
policy bundle governs startup and the verification harness), all merged into `staging`.

No production deployment, no production secrets, no changes to `main`, no CLA workflow changes, no
external infrastructure provisioned, no paid resources, no weakening of existing controls.

## 1. Infrastructure audit (Phase 1)

| Item | Finding |
|------|---------|
| `staging` head | `8d421dc`, PR #494 merged (`verify/staging-policy-bundles`) |
| Dockerfiles | Root `Dockerfile` (runtime image, digest-pinned base images) and `rust/Dockerfile` |
| Deployment manifests | `deployments/docker-compose` (complete), `deployments/helm/aigov-core`, `deployments/kubernetes` (manifests exist; not exercised here) |
| CI/CD | No deploy workflow exists. The `aigov-smoke` workflow is absent from the default branch. |
| Self-hosted runner | None registered (`gh api .../actions/runners` returns 0). `docs/operations/linux-self-hosted-runner.md` records the same blocker. |
| Repository variables / secrets / environments | 0 / 0 / 0. No staging URL, key, or environment is configured. |
| Local infrastructure | Docker 29.5.2 running; `docker compose` 5.3.1. Containers present belong to other test databases and to a `kind` lab, not to AIGov. |
| `kubectl` context | `kind-mlops-lab`, a local cluster that belongs to another project. **Not used.** |
| Vercel CLI | Installed; no identity (not authenticated). **Not used.** |
| AWS CLI | Installed but broken (`pyexpat` symbol error); no credentials visible. **Not used.** |

Minimum infrastructure for a remote staging deployment:

1. A host or platform account that the operator approves and pays for (none is connected).
2. A registered runner (self-hosted Linux, or a hosted runner with an approved target) and a `staging`
   GitHub environment with `GOVAI_STAGING_API_KEY` as a secret and `GOVAI_STAGING_BASE_URL` as a variable.
3. A DNS name with a `staging` token, and TLS in front of the service.
4. The staging trust store (public keys only) and a staging signed bundle, produced by an operator.

Items 1 to 4 need approval before anything is created. None was created.

## 2. What was deployed (Phase 2 and 3)

**Target: a local container stack on this machine.** This is the only staging target that could be
deployed without external approval. It is not a remote staging environment.

| Field | Value |
|-------|-------|
| Commit | `e6aac432dca98d5820f53a0f906d41b8f20f2cce` (clean tree; the evidence records no `-dirty` marker) |
| Image tag | `aigov-core:staging-local` |
| Image ID | `sha256:8b4d77ceb3a5b0787e93a3f35b11b4b98dde5886d9910ad4ddc63854d2ac7802` |
| Container | `aigov-staging-local-aigov-core-1` (ID `02d5c34c6620…`), status running |
| Postgres | `postgres:16-alpine`, healthy, no published port |
| Compose project | `aigov-staging-local` |
| Endpoint | `http://127.0.0.1:8088` (loopback only) |
| Runtime user | `govai` (uid 1000), not privileged |
| Bundle mount | `/app/policies`, read-only, contains only the live bundle |
| Environment | `AIGOV_ENVIRONMENT=staging`, `AIGOV_POLICY_BUNDLE_FILE=/app/policies/policy.bundle.staging.json` |

Secrets and signing material live in `~/.config/aigov-staging` (mode 0700), outside the repository:

- `staging.env` (0600): the staging API key, its key map, and the database password, all generated
  locally. The file is never printed.
- `bundle/` (0700): the signed bundle, trust store, negative fixtures, and `expected-manifest.json`.
  The Ed25519 signing seed is never written. `prepare` asserts that the seed string does not appear in
  any file it writes.
- `live/` (0700): a copy of the live bundle, which is the only file the container mounts.

Bundle identity: `bundle_sha256 = c930fbdab3c2b432f72a97977ed9e511af300df459d944d8de857258c6823f80`,
policy `staging-synthetic-policy` version 1, issuer `govai-staging-verify`, expires 30 days after
preparation, key fingerprint recorded in the manifest.

## 3. Defect found and fixed during deployment

**The runtime image could not start with auto-migrate enabled.** The binary resolves migrations at
compile time from `CARGO_MANIFEST_DIR` (`/build/migrations`). The runtime image did not contain that
path, so the container crash-looped with `migration source error: ... /build/migrations`.

Fix (`Dockerfile`): the runtime stage copies `/build/migrations` with `govai` ownership. The code is
unchanged. This affects every image built from the root `Dockerfile`, including any production image,
which has the same path problem with auto-migrate enabled. Image build and container start were
re-verified after the fix.

Also corrected: the first live run revealed that Docker Desktop does not share the system temporary
directory with containers. Refusal mounts are now created under the git-ignored
`artifacts/staging-verify/mounts`. The first attempt reported `No such file or directory` for four
refusals; those were a harness mount problem, not a service result, and were rerun after the fix.

## 4. Live verification (Phase 4)

Executed with `scripts/staging_local_deploy.sh verify`, which runs
`scripts/staging_policy_verify.py --target-kind local_container` against the running container.

Evidence file: `artifacts/staging-verify/deployed-evidence.json`
(sha256 `ad5eea40293fb2a68cdebf3e1335235375c0a25c6c7a0b7d20332c1ae7b8d9ab`). Git-ignored; not committed.
Started `2026-11-23T23:58:53Z`, finished `23:58:54Z`.

| Check group | Result |
|-------------|--------|
| Infrastructure: health, readiness (database, migrations, ledger), unauthenticated 401, invalid key 401, valid key authorized | 6 of 6 passed |
| Deployment identity: container running, container identity recorded, container runs the built image | 3 of 3 passed |
| Bundle consistency: deployed bundle hash equals `expected-manifest.json` | 1 of 1 passed |
| Bundle-dependent HTTP: promotion refused without evaluation, admitted after a passed evaluation, refused after only a failed evaluation; unauthorized approver refused, authorized approver admitted; verdict summary after the flow; unknown run 404 | 14 of 14 passed |
| Image refusals (same image, invalid bundles): tampered, expired, untrusted key, unsigned, unsigned policy file override | 5 of 5 passed, each on its specific message |
| **Total deployed** | **28 passed, 0 failed, 0 blocked** |

Specific refusal messages observed from the image:

- tampered: `policy signature payload_digest_sha256 mismatch`
- expired: `policy signature expired at 2020-01-01T00:00:00Z`
- untrusted key: `ed25519 signature verification failed for all trusted keys`
- unsigned: `policy is unsigned (no signatures)`
- override: `refusing to start: AIGOV_POLICY_FILE is not permitted in staging; use a signed policy bundle`

Negative control: before the migrations fix, the container crash-looped and the verification could not
run. The earlier local-simulation negative control on the pre-fix commit remains as recorded in
`docs/reports/staging-policy-verification-2026-11-23.md`.

Local simulation, same harness, same commit family: 27 passed, 0 failed.

Remote staging: **not verified.** No remote host is configured, so the `live_staging` checks are
recorded as blocked and are not counted.

## 5. Test results

| Suite | Result |
|-------|--------|
| Harness unit tests (`python/tests/test_staging_policy_verify.py`) | 20 passed |
| Python `pytest python/tests`, no database | 1056 passed, 41 skipped (database-gated) |
| Rust `cargo test --locked` | 237 passed, 0 failed, 0 ignored |
| `make gate` | passes ("Report gate passed.") |
| Dockerfile check (`docker buildx build --check`) | no warnings |
| `ruff`, `mypy` on the harness | clean |
| Release binary build | succeeds |

Skips are not counted as passing.

## 6. Security assessment

Verified on the running container:

- Runs as non-root (`govai`), not privileged.
- Published only on `127.0.0.1:8088`. Postgres publishes nothing.
- Bundle mount is read-only. The ledger volume is writable, as required.
- The trust store contains public keys only. No private key or seed exists in the container environment
  or filesystem (checked).
- No secret material in the repository, the evidence, or the image. The one match for a dev placeholder
  (`operator-dev-key`) is in pre-existing documentation for the development compose file. The staging
  overlay sets its own generated values.
- Compose refuses to start if a required secret or the bundle location is unset. It never falls back to
  the development credentials.

Residual risks and hardening gaps:

- **Writable root filesystem.** Recommend `read_only: true` with a tmpfs for scratch space. Not applied,
  because the process's writable paths were not confirmed.
- **Unsigned policy files are inside the image** at `/app/policies`. The mount shadows them in this
  deployment. A production image without a bundle mount still contains them. Startup refuses them
  (production requires a signed bundle), but they should be removed from the runtime image in a follow-up.
- **The API does not expose the loaded bundle identity.** The hash check verifies the mounted file, not the
  loaded policy. A readiness field for the bundle digest would close this.
- **No TLS**, and the endpoint is loopback-only. A remote deployment needs TLS.
- **Single machine, single container.** No replication, backups, or restart policy beyond `unless-stopped`.
- Replay of a valid, unexpired bundle is not prevented, and rollback to an older valid bundle is accepted
  (unchanged from earlier reports).
- Key custody is file-based. KMS signing is not implemented.

## 7. Infrastructure costs

**$0.** Everything ran on this machine with local Docker. No cloud resources, paid services, or credentials
were provisioned. Images pulled: `postgres:16-alpine` and the Rust and Debian base images used by the
Dockerfile. All are free to pull.

## 8. Unresolved blockers

1. **Remote staging is not deployed.** Needs an operator-approved host or platform, a registered runner or
   approved hosted target, a `staging` GitHub environment with `GOVAI_STAGING_API_KEY` and
   `GOVAI_STAGING_BASE_URL`, DNS with a staging token, and TLS. None was created without approval.
2. **No remote evidence exists.** The live remote checks are blocked, not passed.
3. **Bundle identity for a remote service cannot be confirmed from here.** Needs either an operator
   confirmation or a bundle-digest readiness field.
4. **Dockerfile fix affects every image built from it.** Reviewers should confirm the migrations path change
   before any production image is rebuilt.

## Evaluation gate

Passes for the local container target: the deployed stack is running on the built image, the bundle hash
matches the manifest, and all 28 deployed checks, including the five image refusals, pass on their specific
messages. The Python suite, harness unit tests, `make gate`, and the Dockerfile check pass. The remote staging
checks are blocked and are not counted. This gate passes for local evidence only.

## Human approval gate

Not approved for production by this report.

- **STAGING GO (local container on this machine):** the stack runs the built image with a signed staging bundle,
  and the verified behaviors above hold on that instance.
- **STAGING GO (remote): NO-GO.** Not deployed, not verified, no remote evidence.
- **PRODUCTION GO: NO-GO.** Remote staging is not verified, no production signed bundle exists, and the
  production trust store is not set up. Production stays at NO-GO until independently validated.

Requires your decision:

- Approve creating a remote staging target (host or platform, DNS, TLS, runner, GitHub environment), and
  name the account and cost ceiling.
- Decide whether to follow up the four hardening items in section 6 before a remote deployment.
- Decide whether to ship the Dockerfile migrations fix on its own ahead of the rest.
