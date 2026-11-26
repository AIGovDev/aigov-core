# Remote staging: architecture, threat model, and runbook

Status: 2026-11-24. Applies to the isolated staging environment only. Production is out of scope and
must not be changed through any path in this document.

## 1. What exists today (discovered, read-only)

| Item | Finding |
|------|---------|
| Repository link | The repository's Railway link points at project `daring-embrace`, environment `production`. **Do not run `railway up` or any deploy command from this repository.** |
| Staging project | Railway project `aigov-staging` (created 2026-11-24). Environments `staging` and `production`, services `Postgres` and `audit`. |
| Staging `audit` service | Deployed, latest deployment reported `SUCCESS`, built from `rust/Dockerfile`, public HTTPS endpoint `https://audit-staging-96c34140.up.railway.app`, volume at `/data`. |
| Live probes (no credentials) | HTTP redirects to HTTPS (301); TLS verifies; `/health` and `/ready` return 200; unauthenticated `POST /evidence` and `GET /compliance-summary` return 401. Recorded in `artifacts/remote-staging/probes.json` (not committed). |
| Unknown | The commit and image the service runs (deployment metadata does not expose it), and which policy bundle it loads. The live verification cannot establish either. |
| Concerns in the service configuration (names only; values withheld) | `AIGOV_BILLING_ENFORCEMENT`, `AIGOV_IDENTITY_ISSUER=aigov-dashboard`, and `AIGOV_METRICS_TOKEN` are set, which are not part of this repository's staging contract. `AIGOV_POLICY_DIR=/app` and `AIGOV_AUTO_MIGRATE=true` are set. |
| Project `production` environment | Exists inside `aigov-staging`. Treat it as production: do not deploy to it, and do not share credentials with it. |

Decision needed (section 6): whether to reuse the existing `audit` service or create a new service in
`aigov-staging` from the hardened image.

## 2. Deployment architecture (target)

```
GitHub (staging branch, commit SHA)
  └─ staging-deploy workflow (protected `staging` environment, required reviewers)
       ├─ preflight  → commit on staging, required checks green
       ├─ build      → docker build --no-cache from the commit; container tests against it
       ├─ publish    → ghcr.io/aigovdev/aigov-core@sha256:<digest>
       └─ deploy     → Railway project aigov-staging, environment staging, service audit
                         image by digest; HTTPS domain; volume /data
Railway staging environment
  ├─ audit (hardened image, non-root, read-only root, cap_drop ALL, no-new-privileges)
  │     mounts: policy bundle (read-only), trust store (environment, public keys only)
  └─ Postgres (private networking only; no public domain)
```

Required configuration (names only):

- Service variables: `AIGOV_ENVIRONMENT=staging`, `AIGOV_POLICY_BUNDLE_FILE`, `AIGOV_POLICY_TRUST_ED25519_JSON`
  (public keys only), `AIGOV_POLICY_DIR`, `GOVAI_API_KEYS`, `GOVAI_API_KEYS_JSON` (staging keys only),
  `DATABASE_URL` (the staging Postgres private URL), `GOVAI_AUTO_MIGRATE`, `AIGOV_LEDGER_DIR`.
- GitHub `staging` environment: secret `RAILWAY_STAGING_TOKEN` (scoped to `aigov-staging`); variables
  `STAGING_DEPLOY_ENABLED`, `RAILWAY_STAGING_PROJECT_ID`, `RAILWAY_STAGING_ENVIRONMENT_ID`,
  `RAILWAY_STAGING_SERVICE_ID`.

## 3. Threat model

| Threat | Control | Status |
|--------|---------|--------|
| Deploying an unreviewed or failing commit | preflight requires a staging commit and green required checks | in workflow; not yet exercised |
| Deploying to production | workflow targets only the `staging` environment and the staging project IDs; production link is not used | in workflow; the deploy step is not yet bound (fails closed) |
| Mutable image tag substituted after review | the image is referenced by digest; the digest is recorded | in workflow |
| Signing key exposure | no signing key in the image, the service, or the environment; `prepare` never writes the seed | verified locally |
| Unsigned or tampered policy accepted | fail-closed startup; invalid bundles refused in the image | verified locally, and on the local staging stack |
| Unsigned production fallback | production requires a signed bundle; override variables refused | verified in the image |
| Unauthorized access | API keys required; unauthenticated requests 401 | verified remotely (probes) |
| Human approval bypass | approver allowlist in the signed bundle | verified locally and on the local stack; **not verified remotely** (needs the staging key and a known bundle) |
| Database exposure | Postgres on private networking only | **not verified**; requires inspection of the Railway network settings |
| Concurrent deploys | workflow concurrency group, `cancel-in-progress: false` | in workflow |
| Secret leakage through logs | no secret is printed; evidence records names, hashes, and statuses only | practice; the workflow writes only commit and digest |
| Container compromise | non-root, read-only root, cap_drop ALL, no-new-privileges (in compose and Kubernetes; **Railway's platform settings must be checked**) | partly verified |

Residual risks: the existing service's unknown commit and bundle; the non-staging configuration names above;
the Railway platform's own container settings (read-only root and capability dropping are not configurable from
the repository); no replay protection on bundles; no rollback record beyond the GitHub deployment record.

## 4. Live verification scope

`scripts/staging_policy_verify.py --target-kind remote` checks infrastructure behavior with a staging API key.
Bundle-dependent checks run only when the deployed bundle's identity is verified. A remote host's mounted bundle
cannot be hashed from outside, so those checks are recorded as blocked until an operator provides the bundle's
identity out of band. A blocked check is never counted as passed.

## 5. Operator runbook

**Deploy (after approval):**

1. Confirm the commit SHA on `staging` and that its required checks are green.
2. Run the `staging-deploy` workflow with that SHA. Approve the `staging` environment when prompted.
3. Read the job summary: the commit and the image digest. Record both with the run ID.
4. Run `scripts/staging_policy_verify.py --target-kind remote --base-url https://<staging host>` with the staging
   key in `GOVAI_STAGING_API_KEY`. Store the evidence under `artifacts/`; do not commit it.

**Rollback:**

1. Identify the previous good digest from the deployment record.
2. Re-run the deploy workflow with the commit that produced that digest. Its publish step recreates the same
   digest from the same commit. Do not edit the service's image by hand.
3. Re-run the live verification. A rollback is complete only when the probes pass again.

**Incident:** disable the deploy path by setting `STAGING_DEPLOY_ENABLED` to `false`. Revoke `RAILWAY_STAGING_TOKEN`
if it may be exposed. The service can be stopped in the Railway staging environment only.

## 6. Decisions needed before any external change

1. **Reuse or replace the existing `audit` service.** Reuse means its variables and image are changed to the
   hardened, digest-pinned build; its billing and identity variables must be reviewed first. Replacement means a
   new service in `aigov-staging`. Both need your approval.
2. **Railway image source.** The deploy step is not bound to an image source yet. Binding it requires a Railway
   configuration change that I have not made.
3. **Staging API keys and bundle.** The staging keys and the signed bundle's trust store must be created and set
   in Railway. This is a credential change and needs approval.
4. **GitHub environment.** Creating the `staging` environment with required reviewers and its secrets needs
   approval.
5. **Costs.** `aigov-staging` services may incur Railway usage charges. The exact plan and cost are not visible
   from the CLI. Confirm the plan before any new service is created.

Until these are approved, the workflow is inert and no external system has been changed.
