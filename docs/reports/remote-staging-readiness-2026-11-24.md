# Remote staging readiness and live verification — 2026-11-24

## Scope

Prepares a remote staging deployment of AIGov Core on the hardened image with Ed25519-signed policy bundles,
and records what is verified against the real remote endpoint and what is blocked. Builds on PR #496
(hardened container runtime, merged as `0cf8617`) and the local staging work in PR #495.

No production change, no DNS change, no database or credential change, no paid resource, no GitHub environment
or secret created, no deployment performed. Remote probes were credential-free and read-only.

## 1. Infrastructure audit (Phase 1)

| Item | Finding |
|------|---------|
| `staging` head | `0cf8617` (PR #496 merged) |
| Repository's Railway link | project `daring-embrace`, environment `production`. Not used. Any `railway` command run from the repository would target production. |
| Railway project `aigov-staging` | exists; environments `staging` and `production`; services `Postgres` and `audit` |
| `audit` service in `staging` | deployed (latest `SUCCESS`); built from `rust/Dockerfile`; public domain `audit-staging-96c34140.up.railway.app`; volume `/data` |
| Configuration of the `audit` service | includes variables outside this repository's staging contract (billing enforcement, identity issuer, metrics token). Values withheld. |
| Commit and bundle of the running service | **unknown**; deployment metadata does not expose the commit, and no bundle identity is visible |
| Vercel | logged in; a scope exists; no staging project for AIGov Core identified. Not used. |
| GitHub | `staging` environment, its secrets, and its variables do not exist |
| Kubernetes and Helm | manifests exist from PR #496; no cluster for staging is connected |

The existing staging project is the nearest suitable resource. Whether to reuse it is a decision for you (section 8).

## 2. Deployment security (Phase 2)

| Requirement | State |
|-------------|-------|
| TLS-enabled HTTPS endpoint | **verified**: `https://audit-staging-96c34140.up.railway.app` (certificate verifies); HTTP redirects with 301 |
| Immutable image reference by digest | in the workflow (publish step records the digest); **not applied** to the running service |
| Non-root, read-only root, dropped capabilities, no-new-privileges | in the hardened image and compose, Kubernetes and Helm manifests; **the Railway service's own settings are not verified** |
| Private PostgreSQL connectivity | **not verified**; needs the Railway network configuration |
| Separate staging API credentials | **not verified**; the service's keys were not read or changed |
| Read-only signed bundle and Ed25519 trust store | in the local stack and compose overlay; **not set on the Railway service** |
| No signing private keys in the container or environment | verified locally (`prepare` never writes the seed; the container has none) |
| Health and readiness probes | **verified remotely**: `/health` 200, `/ready` 200 |
| Resource limits and restart behavior | Railway defaults; **not verified** |
| No unsigned production policy fallback | verified in the image; the remote service's `AIGOV_POLICY_DIR` is `/app`, not a bundle directory, so **not verified remotely** |
| No sensitive data in logs or committed artifacts | the workflow writes only commit and digest; probe evidence is sanitized and git-ignored |

Preserved: the fail-closed authorization behavior. The remote service rejects unauthenticated requests with 401.

## 3. Deployment workflow (Phase 3)

`.github/workflows/staging-deploy.yml` (manual `workflow_dispatch` only):

- **preflight:** the requested commit must be on `staging`, and every check run on it must be completed and green.
- **build:** `docker build --no-cache` from that commit, then the container tests against the image.
- **publish:** pushes `ghcr.io/aigovdev/aigov-core:<sha>` and records the immutable digest.
- **deploy:** runs only when `STAGING_DEPLOY_ENABLED` is `true`, in the protected `staging` environment, and uses the
  `staging` project IDs. **It currently fails closed by design:** the Railway image-source binding is not configured,
  so enabling the variable alone cannot push an unverified build.
- **record:** writes the commit and digest to the job summary and an artifact.
- **concurrency:** a single staging deployment at a time; a waiting run is never cancelled.

The workflow is validated as YAML. It has not been run, because it needs a configured environment and approval.

## 4. Live verification (Phase 4)

Remote, credential-free, read-only (recorded in `artifacts/remote-staging/probes.json`, not committed):

| Check | Result | Scope |
|-------|--------|-------|
| 1. Health and readiness | `/health` 200, `/ready` 200 | remote, verified |
| 2. Authentication (unauthenticated rejection) | `POST /evidence` 401, `GET /compliance-summary` 401 | remote, verified |
| 2. Authentication (valid key accepted) | **blocked**: needs the staging API key, which was not used | remote, blocked |
| 3. Valid signed bundle accepted | **blocked**: the remote bundle is not known | remote, blocked |
| 4. Tampered bundle rejected | **blocked** remotely; verified on the built image (local container) | local_container, passed |
| 5. Expired bundle rejected | **blocked** remotely; verified on the built image | local_container, passed |
| 6. Untrusted key rejected | **blocked** remotely; verified on the built image | local_container, passed |
| 7. Unsigned policy override rejected | **blocked** remotely; verified on the built image | local_container, passed |
| 8. Human approval gate | **blocked** remotely; verified locally and on the local stack | local_container, passed |
| 9. Evidence and verdict behavior | **blocked** remotely; verified on the local stack | local_container, passed |
| 10. Database persistence and migration compatibility | **blocked** remotely; the service reports ready, which requires migrations complete, but the persistence test needs writes with the staging key | remote, blocked |
| 11. Identity of the deployed bundle, commit, and image | **blocked**: not exposed by the service or the platform | remote, blocked |

Local simulations are reported separately and are not remote evidence:

- Local staging stack on the hardened image: 28 of 28 deployed checks passed (`local_container`), recorded in PR #495's
  verification and re-run on the hardened image.
- Container tests against the clean-built image: 15 of 15 passed.

Blocked checks are not counted as passed. Skipped tests are not counted as passed.

## 5. Tests and checks (Phase 5)

| Suite | Result |
|-------|--------|
| `make gate` | passes (run on this branch) |
| Python without a database | 1071 passed, 41 skipped (database-gated); included in the earlier run on the same code |
| Rust `cargo test --locked` | 237 passed, 0 failed (earlier run on the same code) |
| Workflow YAML (`staging-deploy.yml`) | parses; jobs and concurrency as specified |
| Security scans | Trivy configuration scan of the Dockerfiles and manifests passed earlier; the image vulnerability scan runs in CI (`container-runtime`) |

## 6. Threat model and runbook

See `docs/operations/remote-staging-runbook.md` for the architecture, the threat model with each control's
status, the deployment and rollback procedure, and the incident steps.

## 7. Infrastructure-as-code

No infrastructure-as-code was added to the repository for Railway. A `railway.toml` or `railway.json` at the
repository root would be read by the production link (`daring-embrace`) on its next build, so it would change
production. Any Railway configuration must be introduced only after the link is separated from production.

## Evaluation gate

Passes for repository-side work: the deployment workflow is validated, the runbook and threat model are written,
probe evidence is sanitized and recorded, and `make gate` passes. Passes for live verification only for the
infrastructure items in section 4 (checks 1 and the unauthenticated part of 2). The bundle, approval, evidence, and
identity checks against the remote endpoint are blocked and are not counted. The remote deployment itself has not
happened.

## Human approval gate

Not approved for production by this report.

- **LOCAL STAGING GO:** unchanged from PR #495 and PR #496. The hardened image runs the staging contract on this machine.
- **REMOTE STAGING GO: NO-GO.** The remote endpoint is reachable and rejects unauthenticated requests, but the
  deployed commit, image, and bundle are unknown. The signed-policy behavior has not been verified remotely. Remote
  deployment needs your approval (section 8) before it can happen.
- **PRODUCTION GO: NO-GO.** No production signed bundle exists, the production trust store is not configured, the
  remote staging service is not verified, and the repository is linked to the production project.

## 8. Decisions and approvals required (stop point)

I have not performed any of the following. Each needs your explicit approval, with the exact resource and cost stated.

1. **Reuse or replace the `audit` service in `aigov-staging`.** Reuse: change its image to the hardened, digest-pinned
   build and review its billing and identity variables. Replace: create a new service in `aigov-staging`. Cost: the
   Railway plan and usage for the service; the plan is not visible from the CLI, so please confirm it.
2. **Staging credentials.** Create `GOVAI_API_KEYS` and `GOVAI_API_KEYS_JSON` values for staging only, and a
   staging-only trust store (public keys) and signed bundle. These are credential changes.
3. **GitHub `staging` environment.** Create it with required reviewers, the secret `RAILWAY_STAGING_TOKEN` scoped
   to `aigov-staging`, and the variables listed in the runbook. This is an external account change.
4. **Image-source binding.** Configure the Railway `audit` service to deploy the digest from GHCR. This is an
   infrastructure change; the deploy step stays closed until it is done.
5. **Repository link.** Separate the repository's Railway link from production before any Railway configuration
   is added to the repository.
6. **Deployment authorization.** Approve one deployment of a named commit to `aigov-staging`, after items 1 to 4.

## Stop point

Remote deployment and all external changes stop here, pending the decisions above. The repository-side work
(workflow, runbook, threat model, sanitized probe evidence, this report) is complete and ready for review.
